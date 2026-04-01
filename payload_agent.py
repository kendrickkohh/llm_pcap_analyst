"""
payload_agent.py
================
Payload / ransomware deployment detection agent.

Analyses Zeek logs for signs of ransomware delivery:
  - SMB file drops (executables, scripts, archives written to hosts)
  - RDP sessions FROM domain controllers (attacker deploying via RDP)
  - WinRM / WMI remote execution (port 5985, IWbemServices)
  - Suspicious HTTP downloads (executables, archives from external)
  - 7-Zip / archive indicators in SMB or HTTP traffic

Works entirely from Zeek logs — no PCAPs required.
"""

from __future__ import annotations

import json
import os
from collections import Counter, defaultdict
from pathlib import Path
from typing import Annotated, Any, Sequence, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

from shared.ecs_compat import normalize_record

# ── Module-level globals (set per invocation) ────────────────────────────────

_ZEEK_FILES: dict[str, str] = {}
_ATTACK_CTX: dict = {}

RFC1918 = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
    "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
    "172.28.", "172.29.", "172.30.", "172.31.",
)

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js",
    ".scr", ".pif", ".msi", ".hta", ".wsf",
    ".7z", ".zip", ".rar", ".tar", ".gz",
    ".enc", ".locked", ".crypt",
}

SYSTEM_PROMPT = """\
You are an expert malware and ransomware deployment analyst.
You are investigating a network compromised by the Lynx ransomware group.

GOAL: Determine HOW the ransomware payload was deployed to target hosts.

METHODOLOGY:
1. Call smb_file_drops to find executables/scripts/archives written via SMB.
2. Call rdp_from_dc to find RDP sessions originating FROM domain controllers
   (indicates attacker using DC to deploy payloads via remote desktop).
3. Call remote_execution_events to find WinRM, WMI, and remote service
   creation that could be used to push/execute payloads.
4. Call http_payload_downloads to find suspicious file downloads from
   external hosts.
5. Synthesise into a JSON report.

Focus on:
- Files written from the DC or compromised hosts to other internal hosts
- Executable or archive files appearing on hosts that weren't there before
- Remote execution patterns that could push/launch ransomware
- Timeline: payload deployment should come AFTER lateral movement

Respond with a JSON block:
{"summary": "...", "deployment_method": "...", "payload_files": [...],
 "source_host": "...", "target_hosts": [...], "techniques": ["T1021.001", ...],
 "evidence_highlights": [...], "report_markdown": "..."}
"""


def _stream_zeek(zeek_path: str, max_lines: int = 50_000):
    """Yield normalised NDJSON records from a Zeek log file."""
    count = 0
    try:
        with open(zeek_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield normalize_record(json.loads(line))
                except json.JSONDecodeError:
                    continue
                count += 1
                if count >= max_lines:
                    break
    except Exception:
        return


def _is_internal(ip: str) -> bool:
    return any(ip.startswith(p) for p in RFC1918)


# ── Tools ─────────────────────────────────────────────────────────────────────

@tool
def smb_file_drops(top_n: int = 30) -> str:
    """
    Find suspicious files written/opened via SMB: executables, scripts,
    archives, or files with ransomware-related names.
    """
    smb_path = _ZEEK_FILES.get("zeek.smb_files.ndjson")
    if not smb_path or not Path(smb_path).exists():
        return json.dumps({"error": "zeek.smb_files.ndjson not available"})

    suspicious: list[dict] = []
    all_ops: list[dict] = []

    for rec in _stream_zeek(smb_path):
        src = rec.get("id.orig_h", "")
        dst = rec.get("id.resp_h", "")
        name = rec.get("name", "")
        action = rec.get("action", "")
        ts = rec.get("ts", "")

        if not (src and dst and name):
            continue

        name_lower = name.lower()
        is_suspicious = any(name_lower.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS)
        # Also flag files with ransomware indicators in name
        if any(kw in name_lower for kw in ["ransom", "encrypt", "decrypt", "readme",
                                            "lynx", "locker", "crypt", "restore"]):
            is_suspicious = True

        if is_suspicious:
            suspicious.append({
                "src": src, "dst": dst, "action": action,
                "file": name, "ts": ts,
            })

        # Track all file ops for volume analysis
        all_ops.append({"src": src, "dst": dst})

    # Count ops per host pair
    pair_counts: Counter = Counter()
    for op in all_ops:
        pair_counts[(op["src"], op["dst"])] += 1

    return json.dumps({
        "suspicious_files": suspicious[:top_n],
        "total_file_ops": len(all_ops),
        "top_host_pairs": [
            {"src": k[0], "dst": k[1], "ops": v}
            for k, v in pair_counts.most_common(10)
        ],
        "source": "zeek.smb_files",
    }, indent=2)


@tool
def rdp_from_dc(top_n: int = 20) -> str:
    """
    Find RDP sessions originating FROM domain controllers or known
    compromised hosts to other internal hosts — indicates payload deployment.
    """
    rdp_path = _ZEEK_FILES.get("zeek.rdp.ndjson")
    conn_path = _ZEEK_FILES.get("zeek.connection.ndjson")

    # Identify likely DCs from attack context
    known_dcs: set[str] = set()
    patient_zero = _ATTACK_CTX.get("patient_zero", "")
    compromised = _ATTACK_CTX.get("compromised_hosts", [])
    # DCs are typically the hosts that others connect to on 88/389/445
    # For now, use attack context
    if patient_zero:
        known_dcs.add(patient_zero)
    for h in compromised:
        known_dcs.add(h)

    sessions: list[dict] = []

    if rdp_path and Path(rdp_path).exists():
        for rec in _stream_zeek(rdp_path):
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            if src and dst and _is_internal(src) and _is_internal(dst) and src != dst:
                sessions.append({
                    "src": src, "dst": dst,
                    "ts": rec.get("ts", ""),
                    "cookie": rec.get("cookie", ""),
                    "from_dc_or_compromised": src in known_dcs,
                })

    # Also check connection log for large internal RDP sessions
    large_rdp: list[dict] = []
    if conn_path and Path(conn_path).exists():
        for rec in _stream_zeek(conn_path):
            if rec.get("id.resp_p") != 3389:
                continue
            src = rec.get("id.orig_h", "")
            dst = rec.get("id.resp_h", "")
            if not (_is_internal(src) and _is_internal(dst) and src != dst):
                continue
            total = int(rec.get("orig_bytes") or 0) + int(rec.get("resp_bytes") or 0)
            if total > 50000:  # significant data transfer
                large_rdp.append({
                    "src": src, "dst": dst,
                    "total_bytes": total,
                    "duration": rec.get("duration", 0),
                    "ts": rec.get("ts", ""),
                    "from_dc_or_compromised": src in known_dcs,
                })

    large_rdp.sort(key=lambda s: s["total_bytes"], reverse=True)

    return json.dumps({
        "internal_rdp_sessions": sessions[:top_n],
        "large_internal_rdp": large_rdp[:top_n],
        "known_dcs_and_compromised": list(known_dcs),
        "source": "zeek.rdp + zeek.connection",
    }, indent=2)


@tool
def remote_execution_events(top_n: int = 20) -> str:
    """
    Detect remote execution mechanisms used for payload deployment:
    - WinRM (HTTP POST to port 5985/5986)
    - WMI (IWbemServices::ExecQuery/ExecMethod via DCE-RPC)
    - Service creation (svcctl::CreateServiceW via DCE-RPC)
    - PsExec-like (svcctl + remote file write)
    """
    events: list[dict] = []

    # Check DCE-RPC for WMI and service creation
    dce_path = _ZEEK_FILES.get("zeek.dce_rpc.ndjson")
    if dce_path and Path(dce_path).exists():
        exec_ops = {
            "IWbemServices": "WMI remote query/execution",
            "IWbemLevel1Login": "WMI login",
            "svcctl": "Remote service management (PsExec-like)",
            "IRemoteSCMActivator": "DCOM remote activation",
            "ITaskSchedulerService": "Remote scheduled task",
        }
        for rec in _stream_zeek(dce_path):
            endpoint = rec.get("endpoint", "")
            operation = rec.get("operation", "")
            for pattern, description in exec_ops.items():
                if pattern.lower() in endpoint.lower():
                    src = rec.get("id.orig_h", "")
                    dst = rec.get("id.resp_h", "")
                    if src and dst and _is_internal(src) and _is_internal(dst):
                        events.append({
                            "src": src, "dst": dst,
                            "endpoint": endpoint, "operation": operation,
                            "category": description,
                            "ts": rec.get("ts", ""),
                        })

    # Check HTTP for WinRM (port 5985/5986)
    http_path = _ZEEK_FILES.get("zeek.http.ndjson")
    if http_path and Path(http_path).exists():
        for rec in _stream_zeek(http_path):
            port = rec.get("id.resp_p", 0)
            if port in (5985, 5986):
                events.append({
                    "src": rec.get("id.orig_h", ""),
                    "dst": rec.get("id.resp_h", ""),
                    "endpoint": f"WinRM (port {port})",
                    "operation": rec.get("method", ""),
                    "category": "WinRM remote command execution",
                    "ts": rec.get("ts", ""),
                    "host": rec.get("host", ""),
                    "uri": rec.get("uri", ""),
                })

    # Count by category
    cat_counts: Counter = Counter(e["category"] for e in events)

    return json.dumps({
        "total_events": len(events),
        "by_category": dict(cat_counts),
        "events": events[:top_n],
        "source": "zeek.dce_rpc + zeek.http",
    }, indent=2)


@tool
def http_payload_downloads(top_n: int = 20) -> str:
    """
    Find HTTP downloads of executables, archives, or large files from
    external hosts that could be payload delivery.
    """
    http_path = _ZEEK_FILES.get("zeek.http.ndjson")
    if not http_path or not Path(http_path).exists():
        return json.dumps({"error": "zeek.http.ndjson not available"})

    downloads: list[dict] = []

    for rec in _stream_zeek(http_path):
        src = rec.get("id.orig_h", "")
        dst = rec.get("id.resp_h", "")
        method = (rec.get("method", "") or "").upper()
        uri = rec.get("uri", "")
        host = rec.get("host", "")
        resp_bytes = int(rec.get("response_body_len") or 0)
        port = rec.get("id.resp_p", 80)

        # Skip internal-only or WinRM
        if port in (5985, 5986):
            continue

        uri_lower = uri.lower()
        is_suspicious = False
        reason = ""

        # Executable download
        if any(uri_lower.endswith(ext) for ext in [".exe", ".dll", ".msi", ".bat",
                                                     ".ps1", ".7z", ".zip", ".rar"]):
            is_suspicious = True
            reason = "suspicious file extension in URI"

        # Large download from non-standard host
        if resp_bytes > 1_000_000 and not any(safe in (host or "").lower()
                                               for safe in ["microsoft", "windows",
                                                            "google", "gvt1"]):
            is_suspicious = True
            reason = f"large download ({resp_bytes:,} bytes) from {host}"

        # Download from IP address (no domain)
        if host and host.replace(".", "").replace(":", "").isdigit():
            is_suspicious = True
            reason = f"download from raw IP {host}"

        if is_suspicious:
            downloads.append({
                "src": src, "dst": dst,
                "method": method, "host": host,
                "uri": uri[:200], "response_bytes": resp_bytes,
                "reason": reason,
                "ts": rec.get("ts", ""),
            })

    return json.dumps({
        "suspicious_downloads": downloads[:top_n],
        "source": "zeek.http",
    }, indent=2)


# ── PCAP-based tools (Pass 2 only) ────────────────────────────────────────────

_PCAP_PATH: str = ""
_TSHARK: str = "tshark"


def _run_tshark(args: list[str], timeout: int = 120) -> str:
    import subprocess
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


@tool
def extract_http_objects() -> str:
    """
    Extract HTTP objects (files transferred via HTTP) from the PCAP using
    tshark --export-objects. Returns list of extracted files with sizes.
    """
    import tempfile
    export_dir = tempfile.mkdtemp(prefix="http_objects_")
    try:
        import subprocess
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH, "--export-objects", f"http,{export_dir}"],
            capture_output=True, text=True, timeout=300,
        )
        files = []
        for f in Path(export_dir).iterdir():
            if f.is_file():
                size = f.stat().st_size
                # Read first 8 bytes for magic number
                with open(f, "rb") as fh:
                    magic = fh.read(8).hex().upper()
                files.append({
                    "name": f.name,
                    "size": size,
                    "magic_hex": magic[:16],
                    "is_pe": magic.startswith("4D5A"),  # MZ header
                    "is_7z": magic.startswith("377ABCAF"),  # 7-Zip
                    "is_zip": magic.startswith("504B"),  # ZIP/PK
                    "is_gzip": magic.startswith("1F8B"),  # gzip
                    "path": str(f),
                })
        files.sort(key=lambda x: x["size"], reverse=True)
        return json.dumps({
            "extracted_files": files[:30],
            "total_files": len(files),
            "export_dir": export_dir,
            "source": "tshark --export-objects http",
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool
def extract_smb_objects() -> str:
    """
    Extract SMB objects (files transferred via SMB/CIFS) from the PCAP.
    Returns list of extracted files with sizes and magic numbers.
    """
    import tempfile
    export_dir = tempfile.mkdtemp(prefix="smb_objects_")
    try:
        import subprocess
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH, "--export-objects", f"smb,{export_dir}"],
            capture_output=True, text=True, timeout=300,
        )
        files = []
        for f in Path(export_dir).iterdir():
            if f.is_file():
                size = f.stat().st_size
                with open(f, "rb") as fh:
                    magic = fh.read(8).hex().upper()
                files.append({
                    "name": f.name,
                    "size": size,
                    "magic_hex": magic[:16],
                    "is_pe": magic.startswith("4D5A"),
                    "is_7z": magic.startswith("377ABCAF"),
                    "is_zip": magic.startswith("504B"),
                    "path": str(f),
                })
        files.sort(key=lambda x: x["size"], reverse=True)
        return json.dumps({
            "extracted_files": files[:30],
            "total_files": len(files),
            "export_dir": export_dir,
            "source": "tshark --export-objects smb",
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool
def inspect_file(file_path: str) -> str:
    """
    Inspect an extracted file: compute SHA256 hash, entropy, size,
    magic number, and check for executable or archive indicators.
    """
    import hashlib
    import math
    from collections import Counter as ByteCounter

    p = Path(file_path)
    if not p.exists():
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        data = p.read_bytes()
        size = len(data)
        if size == 0:
            return json.dumps({"error": "File is empty"})

        # SHA256
        sha256 = hashlib.sha256(data).hexdigest()

        # Magic number
        magic_hex = data[:8].hex().upper()
        detected_type = "Unknown"
        if data[:2] == b"MZ":
            detected_type = "Windows PE (EXE/DLL)"
        elif data[:4] == b"\x7fELF":
            detected_type = "ELF (Linux)"
        elif data[:2] == b"PK":
            detected_type = "ZIP archive"
        elif data[:6] == b"7z\xbc\xaf\x27\x1c":
            detected_type = "7-Zip archive"
        elif data[:2] == b"\x1f\x8b":
            detected_type = "gzip compressed"
        elif data[:3] == b"Rar":
            detected_type = "RAR archive"

        # Entropy
        byte_counts = ByteCounter(data)
        entropy = -sum(
            (c / size) * math.log2(c / size) for c in byte_counts.values()
        )

        return json.dumps({
            "file_path": file_path,
            "file_name": p.name,
            "size_bytes": size,
            "sha256": sha256,
            "magic_hex": magic_hex,
            "detected_type": detected_type,
            "entropy": round(entropy, 4),
            "is_high_entropy": entropy > 7.0,
            "verdict": (
                f"SUSPICIOUS: {detected_type}, entropy={entropy:.1f}"
                if detected_type != "Unknown" or entropy > 7.0
                else f"LOW RISK: Unknown type, entropy={entropy:.1f}"
            ),
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": str(exc)})


@tool
def search_pcap_for_pattern(display_filter: str, fields: str = "", max_packets: int = 100) -> str:
    """
    Run a custom tshark query on the PCAP. Use display filters to search
    for specific patterns like 7-Zip magic bytes, specific IPs, or protocols.
    fields: comma-separated tshark field names (e.g. "ip.src,ip.dst,frame.time")
    """
    max_packets = min(max_packets, 500)
    args = ["-Y", display_filter, "-c", str(max_packets)]
    if fields:
        args.extend(["-T", "fields"])
        for f in fields.split(","):
            args.extend(["-e", f.strip()])
    return _run_tshark(args)


# ── Internal ReAct graph ──────────────────────────────────────────────────────

class _PayloadState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    steps: int


def _build_payload_graph(pcap_available: bool = False):
    # Zeek-based tools always available
    tools_list = [smb_file_drops, rdp_from_dc, remote_execution_events, http_payload_downloads]

    # Add PCAP tools when a PCAP is available (Pass 2)
    if pcap_available:
        tools_list.extend([extract_http_objects, extract_smb_objects, inspect_file, search_pcap_for_pattern])
    llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0,
    ).bind_tools(tools_list)
    tool_node = ToolNode(tools=tools_list)

    def agent_node(s: _PayloadState) -> dict:
        resp = llm.invoke(s["messages"])
        return {"messages": [resp], "steps": s.get("steps", 0) + 1}

    max_steps = 15 if pcap_available else 8

    def should_continue(s: _PayloadState) -> str:
        last = s["messages"][-1] if s["messages"] else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            if s.get("steps", 0) < max_steps:
                return "tools"
        return "end"

    g = StateGraph(_PayloadState)
    g.add_node("agent", agent_node)
    g.add_node("tools", tool_node)
    g.set_entry_point("agent")
    g.add_conditional_edges("agent", should_continue, {"tools": "tools", "end": END})
    g.add_edge("tools", "agent")
    return g.compile()


def _parse_conversation(messages: list) -> dict[str, Any]:
    """Extract structured payload findings from the final AI message."""
    defaults: dict[str, Any] = {
        "summary": "Payload analysis completed.",
        "deployment_method": "",
        "payload_files": [],
        "source_host": "",
        "target_hosts": [],
        "techniques": [],
        "evidence_highlights": [],
        "report_markdown": "",
    }

    for msg in reversed(messages):
        if not (isinstance(msg, AIMessage) and msg.content):
            continue
        content = str(msg.content)
        start = content.find("{")
        end = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                parsed = json.loads(content[start:end])
                defaults.update(parsed)
                return defaults
            except json.JSONDecodeError:
                pass
        defaults["summary"] = content[:500]
        defaults["report_markdown"] = content
        return defaults

    return defaults


# ── Public pipeline node ───────────────────────────────────────────────────────

def payload_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph node — runs payload / ransomware deployment analysis.

    Pass 1 (Zeek): Uses Zeek tools only (smb_file_drops, rdp_from_dc, etc.)
    Pass 2 (PCAP): Also uses tshark tools (extract_http_objects, extract_smb_objects, etc.)

    Reads  : zeek_context, attack_context, pcap_file
    Writes : payload_findings (dict)
    """
    global _ZEEK_FILES, _ATTACK_CTX, _PCAP_PATH, _TSHARK
    import shutil as _shutil

    _ATTACK_CTX = state.get("attack_context", {})

    zeek_ctx_dict = state.get("zeek_context", {})
    _ZEEK_FILES = zeek_ctx_dict.get("zeek_files", {})

    # Set PCAP path if available (Pass 2)
    pcap_file = state.get("pcap_file", "")
    pcap_available = bool(pcap_file and Path(pcap_file).is_file())
    _PCAP_PATH = pcap_file if pcap_available else ""
    _TSHARK = os.environ.get("TSHARK_PATH") or _shutil.which("tshark") or "tshark"

    if not _ZEEK_FILES:
        print("  [Payload] WARNING: no Zeek files available")
        return {
            **state,
            "payload_findings": {"summary": "No Zeek data available for payload analysis."},
            "completed_agents": list(state.get("completed_agents", [])) + ["payload"],
        }

    patient_zero = _ATTACK_CTX.get("patient_zero", "unknown")
    compromised = _ATTACK_CTX.get("compromised_hosts", [])

    if pcap_available:
        mode_instructions = (
            "You have BOTH Zeek logs AND a PCAP file available.\n"
            "1. First call the Zeek tools (smb_file_drops, rdp_from_dc, "
            "remote_execution_events, http_payload_downloads).\n"
            "2. Then use extract_http_objects and extract_smb_objects to "
            "extract actual files from the PCAP.\n"
            "3. For any extracted files, call inspect_file to check magic "
            "numbers, entropy, and hashes.\n"
            "4. Use search_pcap_for_pattern if you need to look for specific "
            "patterns (e.g., '7z magic bytes: data[0:6] == 37:7a:bc:af:27:1c').\n"
            "5. Produce your JSON report."
        )
    else:
        mode_instructions = (
            "You have Zeek logs only (no PCAP).\n"
            "Call all four Zeek tools, then produce your JSON report."
        )

    seed_prompt = (
        f"Analyse for ransomware payload deployment.\n\n"
        f"Patient zero  : {patient_zero}\n"
        f"Compromised   : {', '.join(compromised) or 'unknown'}\n"
        f"PCAP available: {pcap_available}\n\n"
        f"Attack context:\n```json\n"
        f"{json.dumps(_ATTACK_CTX, indent=2, default=str)}\n```\n\n"
        f"{mode_instructions}"
    )

    graph = _build_payload_graph(pcap_available=pcap_available)
    result = graph.invoke({
        "messages": [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(content=seed_prompt),
        ],
        "steps": 0,
    })

    findings = _parse_conversation(result["messages"])

    messages = list(state.get("messages", []))
    messages.append(HumanMessage(content=(
        f"[PayloadAgent] Analysis complete.\n"
        f"Deployment method: {findings.get('deployment_method', 'unknown')}\n"
        f"Summary: {findings.get('summary', '')[:300]}"
    )))

    return {
        **state,
        "payload_findings": findings,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["payload"],
    }
