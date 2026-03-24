"""
agents/exfiltration_agent.py
=============================
Exfiltration detection agent for the SC4063 Security Analysis Pipeline.

Uses Zeek connection and DNS logs (already downloaded by the ingestion
layer) plus the PCAP via tshark to hunt for data exfiltration.

Architecture: LangGraph ReAct loop with Ollama (llama3.2) and a set of
tshark/Zeek-based tools.  Returns ExfiltrationFindings into PipelineState.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter
from pathlib import Path
from typing import Annotated, Any, Optional, Sequence, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from shared.data_contract import (
    IOC,
    ExfiltrationFindings,
    PipelineState,
    ZeekContext,
    get_zeek_context,
    set_exfiltration,
)
from shared.pcap_api import stream_zeek

# ──────────────────────────────────────────────────────────────────────────────
# Internal agent state
# ──────────────────────────────────────────────────────────────────────────────

class ExfilAgentState(TypedDict):
    """Typed state for the internal ReAct loop — add_messages ensures ToolNode appends correctly."""
    messages: Annotated[list[BaseMessage], add_messages]
    steps: int


# Module-level globals set before each agent invocation
_PCAP_PATH: str = ""
_TSHARK: str = "tshark"
_ZEEK_CONN: Optional[str] = None
_ZEEK_DNS: Optional[str] = None
_ATTACK_CONTEXT: dict = {}

SYSTEM_PROMPT = """\
You are an expert network forensic analyst specialising in data exfiltration detection.
You are analysing network traffic from a compromised enterprise network.

GOAL: Detect and document any data exfiltration attempts or confirmed exfiltration.

METHODOLOGY:
1. Call large_outbound_flows to find conversations with unusually high outbound bytes.
2. Call suspicious_dns to look for DNS tunnelling or beaconing to unknown domains.
3. Call http_post_analysis to check for HTTP-based exfiltration.
4. Call ssl_destinations to map encrypted outbound connections.
5. Synthesise evidence into an ExfiltrationFindings structured report.

Focus on:
- Large outbound data transfers to external IPs (non-RFC1918)
- Unusual or high-frequency DNS queries (potential DNS tunnelling)
- HTTP POST requests with large bodies
- Connections to known C2/exfil infrastructure
- Beaconing patterns (regular periodic connections)

If no exfiltration is observed, state this clearly with supporting evidence.
"""

RFC1918 = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
           "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
           "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")


def _is_external(ip: str) -> bool:
    return not any(ip.startswith(p) for p in RFC1918)


def _run_tshark(args: list[str], timeout: int = 120) -> str:
    try:
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout
        if r.returncode != 0 and r.stderr:
            out += f"\n[STDERR]: {r.stderr[:500]}"
        return out[:15_000]
    except subprocess.TimeoutExpired:
        return "[ERROR] tshark timed out"
    except Exception as exc:
        return f"[ERROR] {exc}"


# ──────────────────────────────────────────────────────────────────────────────
# Tools
# ──────────────────────────────────────────────────────────────────────────────

@tool
def large_outbound_flows(min_bytes: int = 1_000_000, top_n: int = 20) -> str:
    """
    Find TCP conversations with large outbound byte counts (internal→external).
    Useful for detecting bulk data exfiltration.
    """
    output = _run_tshark(["-q", "-z", "conv,tcp"])
    lines = output.strip().split("\n")
    results = []
    for line in lines:
        if "<->" not in line:
            continue
        parts = line.split()
        try:
            # tshark conv format: A <-> B  frames_ab bytes_ab frames_ba bytes_ba ...
            src = parts[0]
            dst = parts[2]
            bytes_ab = int(parts[4].replace(",", ""))
            bytes_ba = int(parts[6].replace(",", ""))
        except (IndexError, ValueError):
            continue

        # Internal src → external dst with high outbound bytes
        if _is_external(dst.split(":")[0]) and bytes_ab >= min_bytes:
            results.append({
                "src": src, "dst": dst,
                "outbound_bytes": bytes_ab,
                "inbound_bytes": bytes_ba,
            })

    results.sort(key=lambda x: x["outbound_bytes"], reverse=True)
    return json.dumps(results[:top_n], indent=2)


@tool
def suspicious_dns(min_query_count: int = 50, top_n: int = 30) -> str:
    """
    Analyse DNS queries for tunnelling patterns (high query rates, unusually
    long labels, queries to unknown domains). Uses Zeek DNS log if available,
    otherwise falls back to tshark.
    """
    if _ZEEK_DNS and Path(_ZEEK_DNS).exists():
        counter: Counter = Counter()
        long_labels: list[str] = []
        for rec in stream_zeek(_ZEEK_DNS, max_lines=100_000):
            q = rec.get("query", "")
            if q:
                counter[q] += 1
                if len(q) > 60:
                    long_labels.append(q)
        top = [(q, c) for q, c in counter.most_common(top_n) if c >= min_query_count]
        return json.dumps({
            "high_frequency_queries": top,
            "long_label_examples": long_labels[:20],
            "note": "from Zeek DNS log",
        }, indent=2)

    # Fallback: tshark
    output = _run_tshark(
        ["-Y", "dns.qry.name", "-T", "fields", "-e", "dns.qry.name", "-c", "20000"],
        timeout=60,
    )
    counter = Counter(l for l in output.strip().split("\n") if l.strip())
    top = [(q, c) for q, c in counter.most_common(top_n) if c >= min_query_count]
    return json.dumps({"high_frequency_queries": top, "note": "from tshark"}, indent=2)


@tool
def http_post_analysis(top_n: int = 20) -> str:
    """
    Identify HTTP POST requests with large bodies — a classic exfiltration channel.
    """
    output = _run_tshark([
        "-Y", "http.request.method == POST",
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "http.host",
        "-e", "http.request.uri", "-e", "http.content_length",
        "-e", "frame.time",
        "-c", "500",
    ])
    rows = []
    for line in output.strip().split("\n"):
        parts = line.split("\t")
        if len(parts) >= 5:
            try:
                cl = int(parts[4]) if parts[4] else 0
            except ValueError:
                cl = 0
            rows.append({
                "src": parts[0], "dst": parts[1],
                "host": parts[2], "uri": parts[3],
                "content_length": cl,
                "time": parts[5] if len(parts) > 5 else "",
            })
    rows.sort(key=lambda x: x["content_length"], reverse=True)
    return json.dumps(rows[:top_n], indent=2)


@tool
def ssl_destinations(top_n: int = 30) -> str:
    """
    Map SSL/TLS connections to external IPs — encrypted channels are a
    common exfiltration pathway. Returns top destinations by bytes.
    """
    output = _run_tshark(["-q", "-z", "conv,tcp,ssl"])
    lines = output.strip().split("\n")
    results = []
    for line in lines:
        if "<->" not in line:
            continue
        parts = line.split()
        try:
            src = parts[0]
            dst = parts[2]
            bytes_out = int(parts[4].replace(",", ""))
            bytes_in = int(parts[6].replace(",", ""))
        except (IndexError, ValueError):
            continue
        dst_ip = dst.split(":")[0]
        if _is_external(dst_ip):
            results.append({
                "src": src, "dst": dst,
                "bytes_out": bytes_out, "bytes_in": bytes_in,
            })
    results.sort(key=lambda x: x["bytes_out"], reverse=True)
    return json.dumps(results[:top_n], indent=2)


@tool
def zeek_connection_summary() -> str:
    """
    Use the Zeek connection log to get a summary of outbound traffic volumes
    per external destination.
    """
    if not _ZEEK_CONN or not Path(_ZEEK_CONN).exists():
        return json.dumps({"error": "Zeek connection log not available."})

    from shared.pcap_api import summarise_zeek_connections
    summary = summarise_zeek_connections(_ZEEK_CONN, max_lines=200_000)
    # Filter top destinations to external only
    ext_dsts = [
        (ip, cnt) for ip, cnt in summary["top_destinations"]
        if _is_external(ip)
    ]
    return json.dumps({
        "total_connections": summary["total_connections"],
        "total_bytes": summary["total_bytes"],
        "top_external_destinations": ext_dsts[:20],
        "top_ports": summary["top_ports"][:15],
    }, indent=2)


# ──────────────────────────────────────────────────────────────────────────────
# Internal ReAct graph
# ──────────────────────────────────────────────────────────────────────────────

def _build_exfil_graph():
    tools = [
        large_outbound_flows,
        suspicious_dns,
        http_post_analysis,
        ssl_destinations,
        zeek_connection_summary,
    ]
    llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0,
    ).bind_tools(tools)
    tool_node = ToolNode(tools=tools)

    def agent_node(s: ExfilAgentState) -> dict:
        msgs = s.get("messages", [])
        resp = llm.invoke(msgs)
        # Return only the new message — add_messages reducer appends it
        return {"messages": [resp], "steps": s.get("steps", 0) + 1}

    def should_continue(s: ExfilAgentState) -> str:
        msgs = s.get("messages", [])
        last = msgs[-1] if msgs else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            if s.get("steps", 0) < 15:
                return "tools"
        return "end"

    g = StateGraph(ExfilAgentState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.set_entry_point("agent")
    g.add_conditional_edges("agent", should_continue, {"tools": "tools", "end": END})
    g.add_edge("tools", "agent")
    return g.compile()


def _parse_findings_from_conversation(messages: list) -> ExfiltrationFindings:
    """
    Parse the agent conversation to produce an ExfiltrationFindings object.
    The last AIMessage is expected to contain a JSON block.
    """
    findings = ExfiltrationFindings()

    for msg in reversed(messages):
        if isinstance(msg, AIMessage) and msg.content:
            content = msg.content
            # Try to extract JSON
            try:
                start = content.find("{")
                end = content.rfind("}") + 1
                if start >= 0 and end > start:
                    d = json.loads(content[start:end])
                    findings.detected = d.get("detected", False)
                    findings.summary = d.get("summary", "")
                    findings.destination_ips = d.get("destination_ips", [])
                    findings.destination_domains = d.get("destination_domains", [])
                    findings.protocols_used = d.get("protocols_used", [])
                    findings.report_markdown = d.get("report_markdown", content)
                    break
            except Exception:
                # Use raw content as summary
                findings.summary = content[:1000]
                findings.report_markdown = content
                break

    # Build IOCs from destination IPs
    for ip in findings.destination_ips:
        findings.iocs.append(
            IOC(
                ioc_type="ip",
                value=ip,
                source_agent="exfiltration",
                confidence="medium",
                notes="Identified as exfiltration destination",
            )
        )

    return findings


# ──────────────────────────────────────────────────────────────────────────────
# Pipeline node
# ──────────────────────────────────────────────────────────────────────────────

def exfiltration_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node — runs exfiltration analysis and writes ExfiltrationFindings
    back into PipelineState.
    """
    global _PCAP_PATH, _TSHARK, _ZEEK_CONN, _ZEEK_DNS, _ATTACK_CONTEXT

    # ── Resolve PCAP and tshark ────────────────────────────────────────────
    import shutil as _shutil

    pcap_path = state.get("pcap_file", "")
    zeek_ctx = get_zeek_context(state)
    if not pcap_path and zeek_ctx:
        pcap_path = zeek_ctx.pcap_path

    tshark = os.environ.get("TSHARK_PATH") or _shutil.which("tshark") or "tshark"

    # Populate module globals (simple injection — avoids threading issues for
    # the sequential pipeline)
    _PCAP_PATH = pcap_path
    _TSHARK = tshark
    _ATTACK_CONTEXT = state.get("attack_context", {})

    if zeek_ctx:
        _ZEEK_CONN = zeek_ctx.zeek_files.get("zeek.connection.ndjson")
        _ZEEK_DNS = zeek_ctx.zeek_files.get("zeek.dns.ndjson")

    print("\n" + "─" * 60)
    print("  [Exfiltration] Starting analysis…")
    if zeek_ctx:
        print(f"  Zeek conn: {_ZEEK_CONN or 'n/a'}")
        print(f"  Zeek DNS : {_ZEEK_DNS or 'n/a'}")
    print("─" * 60)

    # ── Build initial prompt with attack context ───────────────────────────
    ctx_json = json.dumps(state.get("attack_context", {}), indent=2, default=str)
    ia_findings = state.get("initial_access_findings", {})
    lm_findings = state.get("lateral_movement_findings", {})

    seed_prompt = (
        f"Analyse this PCAP for data exfiltration.\n\n"
        f"PCAP: {pcap_path}\n\n"
        f"Upstream pipeline context:\n```json\n{ctx_json}\n```\n\n"
        f"Initial access summary: {ia_findings.get('attack_vector', 'unknown')}, "
        f"patient zero: {ia_findings.get('patient_zero', 'unknown')}\n"
        f"Lateral movement: {lm_findings.get('summary', 'not yet analysed')}\n\n"
        f"Now use the available tools to detect exfiltration. After completing "
        f"your investigation, respond with a JSON block:\n"
        f'{{"detected": bool, "summary": str, "destination_ips": [...], '
        f'"destination_domains": [...], "protocols_used": [...], '
        f'"report_markdown": str}}'
    )

    # ── Run ReAct graph ───────────────────────────────────────────────────
    graph = _build_exfil_graph()
    init_messages = [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=seed_prompt)]
    result = graph.invoke({"messages": init_messages, "steps": 0})

    findings = _parse_findings_from_conversation(result.get("messages", []))

    # ── Persist canonical update ───────────────────────────────────────────
    canonical = set_exfiltration(state, findings)
    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"[ExfiltrationAgent] Analysis complete.\n"
                f"Detected: {findings.detected}\n"
                f"Summary: {findings.summary[:300]}"
            )
        )
    )

    return {
        **state,
        **canonical,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["exfiltration"],
    }
