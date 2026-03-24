"""
lateral_movement/lateral_movement.py
======================================
Lateral Movement Detection Agent

Uses Zeek SMB, RDP, NTLM, Kerberos, and DCE/RPC logs (plus tshark fallback)
to detect host-to-host lateral movement within the network.

Architecture: LangGraph ReAct loop with Ollama (llama3.2).

Interface expected by agents/lateral_movement_adapter.py:
    from lateral_movement.lateral_movement import lateral_movement_agent_node
    result = lateral_movement_agent_node(state_dict)
    # result["lateral_movement_findings"] -> dict
    # result["attack_context"]            -> dict (updated)
"""

from __future__ import annotations

import json
import os
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

# ── Module-level globals (set per invocation, sequential pipeline only) ────────

_PCAP_PATH: str = ""
_TSHARK: str = "tshark"
_ZEEK_FILES: dict[str, str] = {}
_ATTACK_CTX: dict = {}

RFC1918 = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

SYSTEM_PROMPT = """\
You are an expert network forensic analyst specialising in lateral movement detection.
You are investigating a compromised enterprise network.

GOAL: Identify all lateral movement from the initial foothold to other internal systems.

METHODOLOGY:
1. Call smb_lateral_movement to find SMB-based spread (PsExec, file shares, admin$).
2. Call rdp_lateral_movement to find RDP connections between internal hosts.
3. Call ntlm_auth_events to detect pass-the-hash / credential relay.
4. Call kerberos_events to detect pass-the-ticket / kerberoasting / AS-REP roasting.
5. Call dce_rpc_events to detect remote service creation (SCM) and WMI execution.
6. Synthesise into a JSON report.

Focus on:
- Internal → internal connections only (RFC1918 to RFC1918)
- Authentication using previously-seen attacker credentials
- Remote execution patterns (SCM, WMI, DCOM, PsExec)
- Movement chain from patient zero to other hosts

If no lateral movement is observed, say so with supporting evidence.
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918)


def _run_tshark(args: list[str], timeout: int = 120) -> str:
    if not _PCAP_PATH:
        return "[ERROR] No PCAP path set."
    try:
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        out = r.stdout or ""
        if r.returncode != 0 and r.stderr:
            out += f"\n[STDERR]: {r.stderr[:300]}"
        return out[:12_000]
    except subprocess.TimeoutExpired:
        return "[ERROR] tshark timed out"
    except Exception as exc:
        return f"[ERROR] {exc}"


def _stream_zeek(zeek_path: str, max_lines: int = 50_000):
    """Yield parsed NDJSON records from a Zeek log file."""
    count = 0
    try:
        with open(zeek_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
                count += 1
                if count >= max_lines:
                    break
    except Exception:
        return


# ── Tools ─────────────────────────────────────────────────────────────────────

@tool
def smb_lateral_movement(top_n: int = 20) -> str:
    """
    Detect SMB-based lateral movement: file-share access, PsExec artifacts,
    remote admin share connections (ADMIN$, IPC$, C$).
    Uses Zeek SMB logs if available, otherwise falls back to tshark.
    """
    smb_files_path = _ZEEK_FILES.get("zeek.smb_files.ndjson")
    smb_map_path   = _ZEEK_FILES.get("zeek.smb_mapping.ndjson")

    if smb_files_path and Path(smb_files_path).exists():
        pair_counts: dict[tuple, int] = defaultdict(int)
        ops: list[dict] = []
        for rec in _stream_zeek(smb_files_path):
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            if src and dst and _is_internal(src) and _is_internal(dst) and src != dst:
                pair_counts[(src, dst)] += 1
                action = rec.get("action", "")
                name   = rec.get("name", "")
                if action and name:
                    ops.append({"src": src, "dst": dst, "action": action, "file": name,
                                "ts": rec.get("ts", "")})

        admin_shares: list[dict] = []
        if smb_map_path and Path(smb_map_path).exists():
            for rec in _stream_zeek(smb_map_path):
                share = rec.get("path", "")
                if any(s in share.upper() for s in ["ADMIN$", "IPC$", "C$"]):
                    admin_shares.append({
                        "src": rec.get("id.orig_h", ""),
                        "dst": rec.get("id.resp_h", ""),
                        "share": share,
                        "ts": rec.get("ts", ""),
                    })

        return json.dumps({
            "host_pairs": [
                {"src": k[0], "dst": k[1], "ops": v}
                for k, v in sorted(pair_counts.items(), key=lambda x: -x[1])[:top_n]
            ],
            "file_ops": ops[:top_n],
            "admin_shares": admin_shares[:top_n],
            "source": "zeek.smb",
        }, indent=2)

    # tshark fallback
    out = _run_tshark([
        "-Y", "smb or smb2", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "smb.cmd", "-e", "smb2.cmd",
        "-c", "2000",
    ])
    return json.dumps({"smb_events": out[:4000], "source": "tshark"}, indent=2)


@tool
def rdp_lateral_movement(top_n: int = 20) -> str:
    """
    Find RDP connections between internal hosts — a common lateral movement path.
    Uses Zeek RDP log if available, otherwise tshark.
    """
    rdp_path = _ZEEK_FILES.get("zeek.rdp.ndjson")

    if rdp_path and Path(rdp_path).exists():
        sessions: list[dict] = []
        for rec in _stream_zeek(rdp_path):
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            if src and dst and _is_internal(src) and _is_internal(dst) and src != dst:
                sessions.append({
                    "src": src, "dst": dst,
                    "ts": rec.get("ts", ""),
                    "duration": rec.get("duration", 0),
                    "auth_success": rec.get("auth_success"),
                    "cookie": rec.get("cookie", ""),
                })
        return json.dumps({
            "internal_rdp_sessions": sessions[:top_n],
            "total": len(sessions),
            "source": "zeek.rdp",
        }, indent=2)

    out = _run_tshark([
        "-Y", "tcp.dstport == 3389", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "frame.time_relative",
        "-c", "500",
    ])
    lines = [l.split("\t") for l in out.strip().split("\n") if "\t" in l]
    internal = [l for l in lines if len(l) >= 2
                and _is_internal(l[0]) and _is_internal(l[1])]
    return json.dumps({"rdp_internal": internal[:top_n], "source": "tshark"}, indent=2)


@tool
def ntlm_auth_events(top_n: int = 30) -> str:
    """
    Detect NTLM authentication: look for pass-the-hash, credential relay,
    and spray patterns. Uses Zeek NTLM log if available.
    """
    ntlm_path = _ZEEK_FILES.get("zeek.ntlm.ndjson")

    if ntlm_path and Path(ntlm_path).exists():
        events: list[dict] = []
        user_counter: Counter = Counter()
        for rec in _stream_zeek(ntlm_path):
            src  = rec.get("id.orig_h", "")
            dst  = rec.get("id.resp_h", "")
            user = rec.get("username", "")
            events.append({
                "src": src, "dst": dst,
                "user": user,
                "domain": rec.get("domainname", ""),
                "success": rec.get("success"),
                "ts": rec.get("ts", ""),
            })
            if user:
                user_counter[user] += 1

        failures = [e for e in events if e["success"] is False]
        return json.dumps({
            "total_events": len(events),
            "failure_count": len(failures),
            "top_users": user_counter.most_common(10),
            "failures": failures[:top_n],
            "all_events": events[:top_n],
            "source": "zeek.ntlm",
        }, indent=2)

    out = _run_tshark([
        "-Y", "ntlmssp", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "ntlmssp.messagetype", "-e", "ntlmssp.auth.username",
        "-c", "2000",
    ])
    return json.dumps({"ntlm_raw": out[:4000], "source": "tshark"}, indent=2)


@tool
def kerberos_events(top_n: int = 20) -> str:
    """
    Detect Kerberos anomalies: pass-the-ticket, AS-REP roasting (no pre-auth),
    kerberoasting (TGS-REQ for service accounts), overpass-the-hash.
    """
    kerb_path = _ZEEK_FILES.get("zeek.kerberos.ndjson")

    if kerb_path and Path(kerb_path).exists():
        events: list[dict] = []
        failures: list[dict] = []
        for rec in _stream_zeek(kerb_path):
            ev = {
                "ts": rec.get("ts", ""),
                "src": rec.get("id.orig_h", ""),
                "dst": rec.get("id.resp_h", ""),
                "client": rec.get("client", ""),
                "service": rec.get("service", ""),
                "success": rec.get("success"),
                "error": rec.get("error_msg", ""),
                "request_type": rec.get("request_type", ""),
            }
            events.append(ev)
            if not rec.get("success"):
                failures.append(ev)

        return json.dumps({
            "total_events": len(events),
            "failure_count": len(failures),
            "failures": failures[:top_n],
            "sample_events": events[:top_n],
            "source": "zeek.kerberos",
        }, indent=2)

    out = _run_tshark([
        "-Y", "kerberos", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "kerberos.msg_type", "-e", "kerberos.CNameString",
        "-c", "1000",
    ])
    return json.dumps({"kerberos_raw": out[:4000], "source": "tshark"}, indent=2)


@tool
def dce_rpc_events(top_n: int = 20) -> str:
    """
    Detect DCE/RPC calls for remote execution: SCM (service creation),
    WMI (IWbemServices), DCOM, Task Scheduler — common PsExec / impacket artefacts.
    """
    dce_path = _ZEEK_FILES.get("zeek.dce_rpc.ndjson")

    if dce_path and Path(dce_path).exists():
        events: list[dict] = []
        op_counter: Counter = Counter()
        for rec in _stream_zeek(dce_path):
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            endpoint  = rec.get("endpoint", "")
            operation = rec.get("operation", "")
            if src and dst and _is_internal(src) and _is_internal(dst):
                events.append({
                    "src": src, "dst": dst,
                    "endpoint": endpoint, "operation": operation,
                    "ts": rec.get("ts", ""),
                })
                if endpoint:
                    op_counter[f"{endpoint}::{operation}"] += 1

        return json.dumps({
            "total_events": len(events),
            "top_operations": op_counter.most_common(10),
            "events": events[:top_n],
            "source": "zeek.dce_rpc",
        }, indent=2)

    out = _run_tshark([
        "-Y", "dcerpc", "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst", "-e", "dcerpc.opnum",
        "-c", "1000",
    ])
    return json.dumps({"dce_rpc_raw": out[:4000], "source": "tshark"}, indent=2)


# ── Internal ReAct graph ──────────────────────────────────────────────────────

class _LMState(TypedDict):
    """Typed state for the internal ReAct loop."""
    messages: Annotated[list[BaseMessage], add_messages]
    steps: int


def _build_lm_graph():
    tools_list = [
        smb_lateral_movement,
        rdp_lateral_movement,
        ntlm_auth_events,
        kerberos_events,
        dce_rpc_events,
    ]
    llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0,
    ).bind_tools(tools_list)
    tool_node = ToolNode(tools=tools_list)

    def agent_node(s: _LMState) -> dict:
        resp = llm.invoke(s["messages"])
        return {"messages": [resp], "steps": s.get("steps", 0) + 1}

    def should_continue(s: _LMState) -> str:
        last = s["messages"][-1] if s["messages"] else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            if s.get("steps", 0) < 12:
                return "tools"
        return "end"

    g = StateGraph(_LMState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.set_entry_point("agent")
    g.add_conditional_edges("agent", should_continue, {"tools": "tools", "end": END})
    g.add_edge("tools", "agent")
    return g.compile()


def _parse_conversation(messages: list) -> dict[str, Any]:
    """Extract structured lateral movement findings from the final AI message."""
    defaults: dict[str, Any] = {
        "summary": "Lateral movement analysis completed.",
        "bottom_line": "",
        "observed": [],
        "not_observed": [],
        "limitations": [],
        "evidence_highlights": [],
        "tacticalrmm_assessment": "",
        "compromised_hosts": [],
        "techniques": [],
        "report_markdown": "",
    }

    for msg in reversed(messages):
        if not (isinstance(msg, AIMessage) and msg.content):
            continue
        content = str(msg.content)
        # Try JSON extraction
        start = content.find("{")
        end   = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                parsed = json.loads(content[start:end])
                defaults.update(parsed)
                return defaults
            except json.JSONDecodeError:
                pass
        # Plain-text fallback
        defaults["summary"]         = content[:500]
        defaults["report_markdown"] = content
        return defaults

    return defaults


# ── Public pipeline node ───────────────────────────────────────────────────────

def lateral_movement_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node — runs lateral movement analysis.

    Reads  : pcap_file, zeek_context, initial_access_findings, attack_context
    Writes : lateral_movement_findings (dict), attack_context (updated dict)
    """
    global _PCAP_PATH, _TSHARK, _ZEEK_FILES, _ATTACK_CTX
    import shutil as _shutil

    _PCAP_PATH  = state.get("pcap_file", "")
    _TSHARK     = os.environ.get("TSHARK_PATH") or _shutil.which("tshark") or "tshark"
    _ATTACK_CTX = state.get("attack_context", {})

    zeek_ctx_dict = state.get("zeek_context", {})
    _ZEEK_FILES   = zeek_ctx_dict.get("zeek_files", {})

    ia           = state.get("initial_access_findings", {})
    patient_zero = ia.get("patient_zero") or _ATTACK_CTX.get("patient_zero", "unknown")
    attacker_ip  = ia.get("attacker_ip", "")

    seed_prompt = (
        f"Analyse this capture for lateral movement.\n\n"
        f"PCAP          : {_PCAP_PATH}\n"
        f"Patient zero  : {patient_zero}\n"
        f"Attacker IP   : {attacker_ip or 'unknown'}\n\n"
        f"Attack context so far:\n```json\n"
        f"{json.dumps(_ATTACK_CTX, indent=2, default=str)}\n```\n\n"
        f"Use the available tools to map all lateral movement. "
        f"After completing your investigation, respond with a JSON block:\n"
        f'{{"summary": "...", "bottom_line": "...", '
        f'"observed": ["technique1", ...], '
        f'"not_observed": ["technique1", ...], '
        f'"limitations": ["..."], '
        f'"evidence_highlights": ["host_a → host_b via SMB", ...], '
        f'"compromised_hosts": ["10.x.x.x", ...], '
        f'"techniques": ["T1021.001", ...], '
        f'"tacticalrmm_assessment": "...", '
        f'"report_markdown": "## Lateral Movement\\n..."}}'
    )

    graph = _build_lm_graph()
    result = graph.invoke({
        "messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=seed_prompt)],
        "steps": 0,
    })

    raw_findings = _parse_conversation(result.get("messages", []))

    # Update shared attack_context
    ctx = dict(_ATTACK_CTX)
    if raw_findings.get("compromised_hosts"):
        existing = ctx.get("compromised_hosts", [])
        ctx["compromised_hosts"] = list(set(existing + raw_findings["compromised_hosts"]))
    if raw_findings.get("techniques"):
        ctx.setdefault("techniques", [])
        ctx["techniques"] = list(set(ctx["techniques"] + raw_findings["techniques"]))

    return {
        **state,
        "lateral_movement_findings": raw_findings,
        "attack_context": ctx,
    }
