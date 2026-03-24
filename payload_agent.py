"""
payload_agent.py
=================
Payload Analysis Agent

Identifies files transferred in the PCAP (via SMB/HTTP) and analyses them
for maliciousness using:
    - tshark --export-objects to extract transferred files
    - SHA-256 hashing + Shannon entropy (high entropy → packed/encrypted)
    - VirusTotal hash lookup (if VIRUSTOTAL_API_KEY is set)

Architecture: LangGraph ReAct loop with Ollama (llama3.2).

Interface expected by agents/payload_agent_adapter.py:
    from payload_agent import payload_agent_node
    result = payload_agent_node(state_dict)
    # result["payload_findings"] -> dict with "summary" key
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Annotated, Any, Optional, TypedDict

from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, SystemMessage
from langchain_core.tools import tool
from langchain_openai import AzureChatOpenAI
from langgraph.graph import END, StateGraph
from langgraph.graph.message import add_messages
from langgraph.prebuilt import ToolNode

# ── Module-level globals ──────────────────────────────────────────────────────

_PCAP_PATH: str = ""
_TSHARK: str = "tshark"
_ZEEK_FILES: dict[str, str] = {}
_WORK_DIR: str = "/tmp/sc4063/payload"
_VT_KEY: Optional[str] = None

SYSTEM_PROMPT = """\
You are an expert malware analyst and network forensics specialist.
You are investigating files transferred during a network intrusion.

GOAL: Identify and classify all potentially malicious files transferred in the PCAP.

METHODOLOGY:
1. Call list_smb_transfers to find files transferred over SMB (common for lateral movement tools).
2. Call list_http_transfers to find files transferred over HTTP (common for payload drops).
3. Call export_and_hash_files to extract files and compute SHA-256 hashes + entropy.
4. Call virustotal_lookup to check any suspicious hashes against VirusTotal.
5. Synthesise findings into a structured report.

Classification guidance:
- MALICIOUS : VirusTotal detections > 3, or filename is known malware (mimikatz, psexec, etc.)
- HIGH RISK : Executable with high entropy (> 7.0), or binary disguised as text
- SUSPICIOUS: Unknown executable, scripts (ps1, bat, vbs), or unusual archive
- CLEAN     : Office docs, images, text files with low entropy

If no files are identified, state this clearly.
"""


# ── Helpers ───────────────────────────────────────────────────────────────────

def _run_tshark(args: list[str], timeout: int = 120) -> str:
    if not _PCAP_PATH:
        return "[ERROR] No PCAP path set."
    try:
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH] + args,
            capture_output=True, text=True, timeout=timeout,
        )
        return (r.stdout or "")[:12_000]
    except subprocess.TimeoutExpired:
        return "[ERROR] tshark timed out"
    except Exception as exc:
        return f"[ERROR] {exc}"


def _sha256(path: str) -> str:
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ""


def _entropy(path: str) -> float:
    """Shannon entropy of a file (bits per byte, max 8.0)."""
    try:
        counts = [0] * 256
        total  = 0
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                for byte in chunk:
                    counts[byte] += 1
                total += len(chunk)
        if total == 0:
            return 0.0
        ent = 0.0
        for c in counts:
            if c > 0:
                p = c / total
                ent -= p * math.log2(p)
        return round(ent, 3)
    except Exception:
        return 0.0


def _stream_zeek(zeek_path: str, max_lines: int = 20_000):
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
def list_smb_transfers(top_n: int = 30) -> str:
    """
    List files transferred over SMB — primary channel for lateral movement tools
    (PsExec service binary, Mimikatz, reverse shells, etc.).
    Uses Zeek SMB file log if available, otherwise tshark.
    """
    smb_path = _ZEEK_FILES.get("zeek.smb_files.ndjson")

    if smb_path and Path(smb_path).exists():
        files: list[dict] = []
        for rec in _stream_zeek(smb_path):
            action = rec.get("action", "")
            name   = rec.get("name", "")
            size   = rec.get("size", 0)
            if "WRITE" in action.upper() or "READ" in action.upper():
                files.append({
                    "src": rec.get("id.orig_h", ""),
                    "dst": rec.get("id.resp_h", ""),
                    "action": action,
                    "filename": name,
                    "size_bytes": size,
                    "ts": rec.get("ts", ""),
                    "mime_type": rec.get("mime_type", ""),
                })
        return json.dumps({
            "smb_file_transfers": files[:top_n],
            "total": len(files),
            "source": "zeek.smb_files",
        }, indent=2)

    # tshark fallback — list SMB2 CREATE requests (file opens / writes)
    out = _run_tshark([
        "-Y", "smb2.cmd == 5",  # SMB2 CREATE
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "smb2.filename", "-e", "frame.time_relative",
        "-c", "500",
    ])
    return json.dumps({"smb2_creates": out[:4000], "source": "tshark"}, indent=2)


@tool
def list_http_transfers(top_n: int = 30) -> str:
    """
    List files transferred over HTTP — used for payload drops from attacker
    infrastructure or C2 callbacks with embedded files.
    Uses Zeek HTTP log if available, otherwise tshark.
    """
    http_path = _ZEEK_FILES.get("zeek.http.ndjson")

    if http_path and Path(http_path).exists():
        transfers: list[dict] = []
        for rec in _stream_zeek(http_path):
            resp_mime  = rec.get("resp_mime_types", []) or []
            resp_fnames = rec.get("orig_filenames", []) or []
            uri        = rec.get("uri", "")
            method     = rec.get("method", "")
            resp_bytes  = rec.get("resp_body_len", 0) or 0
            if resp_bytes > 1000 or any(
                x in str(resp_mime).lower()
                for x in ["octet-stream", "executable", "zip", "gzip", "x-msdos"]
            ):
                transfers.append({
                    "src": rec.get("id.orig_h", ""),
                    "dst": rec.get("id.resp_h", ""),
                    "method": method,
                    "host": rec.get("host", ""),
                    "uri": uri,
                    "resp_mime": resp_mime,
                    "resp_bytes": resp_bytes,
                    "filenames": resp_fnames,
                    "ts": rec.get("ts", ""),
                })
        transfers.sort(key=lambda x: x["resp_bytes"], reverse=True)
        return json.dumps({
            "http_file_transfers": transfers[:top_n],
            "total": len(transfers),
            "source": "zeek.http",
        }, indent=2)

    out = _run_tshark([
        "-Y", "http.response and http.content_length > 1000",
        "-T", "fields",
        "-e", "ip.src", "-e", "ip.dst",
        "-e", "http.host", "-e", "http.request.uri",
        "-e", "http.content_length", "-e", "http.content_type",
        "-c", "200",
    ])
    return json.dumps({"http_responses": out[:4000], "source": "tshark"}, indent=2)


@tool
def export_and_hash_files(protocol: str = "smb") -> str:
    """
    Use tshark --export-objects to extract transferred files from the PCAP,
    then compute SHA-256 hashes and entropy for each extracted file.
    protocol: 'smb' or 'http' (default: 'smb').
    Returns a list of {filename, size, sha256, entropy, risk_level}.
    """
    if protocol not in ("smb", "http"):
        return json.dumps({"error": "protocol must be 'smb' or 'http'"})

    export_dir = Path(_WORK_DIR) / f"extracted_{protocol}"
    export_dir.mkdir(parents=True, exist_ok=True)

    try:
        r = subprocess.run(
            [_TSHARK, "-r", _PCAP_PATH,
                "--export-objects", f"{protocol},{export_dir}"],
            capture_output=True, text=True, timeout=180,
        )
    except subprocess.TimeoutExpired:
        return json.dumps({"error": "tshark export timed out"})
    except Exception as exc:
        return json.dumps({"error": str(exc)})

    results: list[dict] = []
    try:
        for f in sorted(export_dir.iterdir()):
            if not f.is_file():
                continue
            size = f.stat().st_size
            sha  = _sha256(str(f))
            ent  = _entropy(str(f))
            name_lower = f.name.lower()

            # Heuristic risk classification
            if any(name_lower.endswith(ext) for ext in
                    [".exe", ".dll", ".sys", ".drv", ".scr"]):
                if ent > 7.0:
                    risk = "HIGH RISK (high-entropy executable)"
                else:
                    risk = "SUSPICIOUS (executable)"
            elif any(name_lower.endswith(ext) for ext in
                        [".ps1", ".vbs", ".bat", ".cmd", ".js", ".hta"]):
                risk = "SUSPICIOUS (script)"
            elif ent > 7.5:
                risk = "SUSPICIOUS (high entropy — possible encrypted/packed)"
            else:
                risk = "UNKNOWN"

            results.append({
                "filename": f.name,
                "size_bytes": size,
                "sha256": sha,
                "entropy": ent,
                "risk_level": risk,
                "path": str(f),
            })
    except Exception as exc:
        return json.dumps({"error": f"Could not list exported files: {exc}"})

    return json.dumps({
        "protocol": protocol,
        "export_dir": str(export_dir),
        "files": results,
        "total_extracted": len(results),
    }, indent=2)


@tool
def virustotal_lookup(sha256_hash: str) -> str:
    """
    Look up a SHA-256 hash on VirusTotal.
    Requires VIRUSTOTAL_API_KEY environment variable.
    Returns detection count, verdict, and known malware names.
    """
    api_key = _VT_KEY or os.environ.get("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        return json.dumps({"error": "VIRUSTOTAL_API_KEY not set — skipping VT lookup."})
    if len(sha256_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in sha256_hash):
        return json.dumps({"error": f"Invalid SHA-256 hash: {sha256_hash!r}"})

    try:
        import requests as _req
        resp = _req.get(
            f"https://www.virustotal.com/api/v3/files/{sha256_hash}",
            headers={"x-apikey": api_key},
            timeout=30,
        )
        if resp.status_code == 404:
            return json.dumps({"hash": sha256_hash, "verdict": "NOT_FOUND",
                                "detections": 0, "note": "Hash not in VT database."})
        resp.raise_for_status()
        data  = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        names = data.get("data", {}).get("attributes", {}).get("popular_threat_name", "")
        total     = sum(stats.values()) if stats else 0
        malicious = stats.get("malicious", 0)
        verdict   = "MALICIOUS" if malicious > 3 else ("SUSPICIOUS" if malicious > 0 else "CLEAN")
        return json.dumps({
            "hash": sha256_hash,
            "verdict": verdict,
            "detections": malicious,
            "total_engines": total,
            "popular_threat_name": names,
            "stats": stats,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"error": f"VirusTotal lookup failed: {exc}"})


@tool
def known_tool_signatures(filename: str) -> str:
    """
    Check if a filename matches known offensive security tools / malware families.
    Returns a risk assessment based on filename heuristics.
    """
    name_lower = filename.lower()
    signatures = {
        "mimikatz": "Credential dumper (Mimikatz)",
        "mimi":     "Possible Mimikatz variant",
        "psexec":   "Remote execution tool (PsExec)",
        "psexesvc": "PsExec service binary",
        "wce":      "Windows Credential Editor",
        "procdump": "Process memory dumper",
        "cobaltstrike": "Cobalt Strike beacon",
        "beacon":   "Possible C2 beacon (Cobalt Strike / Metasploit)",
        "meterpreter": "Metasploit Meterpreter payload",
        "empire":   "PowerShell Empire agent",
        "invoke-":  "PowerShell offensive module (Invoke-*)",
        "sharphound": "BloodHound AD collector",
        "rubeus":   "Kerberos attack toolkit",
        "certify":  "AD CS exploitation tool",
        "seatbelt": "Host enumeration tool",
        "sharpup":  "Privilege escalation tool",
        "lazagne":  "Credential harvester",
        "nanodump": "LSASS memory dumper",
        "pypykatz": "Python Mimikatz",
    }
    matches = [desc for kw, desc in signatures.items() if kw in name_lower]
    return json.dumps({
        "filename": filename,
        "matches": matches,
        "verdict": "MALICIOUS" if matches else "NO_MATCH",
    }, indent=2)


# ── Internal ReAct graph ──────────────────────────────────────────────────────

class _PAState(TypedDict):
    messages: Annotated[list[BaseMessage], add_messages]
    steps: int


def _build_payload_graph():
    tools_list = [
        list_smb_transfers,
        list_http_transfers,
        export_and_hash_files,
        virustotal_lookup,
        known_tool_signatures,
    ]
    llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0,
    ).bind_tools(tools_list)
    tool_node = ToolNode(tools=tools_list)

    def agent_node(s: _PAState) -> dict:
        resp = llm.invoke(s["messages"])
        return {"messages": [resp], "steps": s.get("steps", 0) + 1}

    def should_continue(s: _PAState) -> str:
        last = s["messages"][-1] if s["messages"] else None
        if isinstance(last, AIMessage) and getattr(last, "tool_calls", None):
            if s.get("steps", 0) < 12:
                return "tools"
        return "end"

    g = StateGraph(_PAState)
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
        "files_analysed": [],
        "malicious_files": [],
        "suspicious_files": [],
        "clean_files": [],
        "report_markdown": "",
    }
    for msg in reversed(messages):
        if not (isinstance(msg, AIMessage) and msg.content):
            continue
        content = str(msg.content)
        start = content.find("{")
        end   = content.rfind("}") + 1
        if start >= 0 and end > start:
            try:
                parsed = json.loads(content[start:end])
                defaults.update(parsed)
                return defaults
            except json.JSONDecodeError:
                pass
        defaults["summary"]         = content[:1000]
        defaults["report_markdown"] = content
        return defaults
    return defaults


# ── Public pipeline node ──────────────────────────────────────────────────────

def payload_agent_node(state: dict[str, Any]) -> dict[str, Any]:
    """
    LangGraph pipeline node — runs payload analysis.

    Reads  : pcap_file, zeek_context, attack_context, work_dir
    Writes : payload_findings (dict with "summary" key)
    """
    global _PCAP_PATH, _TSHARK, _ZEEK_FILES, _WORK_DIR, _VT_KEY
    import shutil as _shutil

    _PCAP_PATH  = state.get("pcap_file", "")
    _TSHARK     = os.environ.get("TSHARK_PATH") or _shutil.which("tshark") or "tshark"
    _VT_KEY     = os.environ.get("VIRUSTOTAL_API_KEY")

    zeek_ctx_dict = state.get("zeek_context", {})
    _ZEEK_FILES   = zeek_ctx_dict.get("zeek_files", {})

    work_dir   = state.get("work_dir", "/tmp/sc4063")
    _WORK_DIR  = str(Path(work_dir) / "payload")
    Path(_WORK_DIR).mkdir(parents=True, exist_ok=True)

    ctx = state.get("attack_context", {})
    ia  = state.get("initial_access_findings", {})
    lm  = state.get("lateral_movement_findings", {})

    seed_prompt = (
        f"Analyse this PCAP for malicious file transfers and payloads.\n\n"
        f"PCAP: {_PCAP_PATH}\n\n"
        f"Attack context:\n```json\n{json.dumps(ctx, indent=2, default=str)}\n```\n\n"
        f"Initial access vector: {ia.get('attack_vector', 'unknown')}\n"
        f"Compromised hosts: {lm.get('compromised_hosts', [])}\n\n"
        f"Use the available tools to:\n"
        f"1. List all SMB and HTTP file transfers\n"
        f"2. Export files from the PCAP and compute hashes/entropy\n"
        f"3. Check hashes against VirusTotal if available\n"
        f"4. Classify each file\n\n"
        f"After completing your investigation, respond with a JSON block:\n"
        f'{{"summary": "...", '
        f'"files_analysed": ["filename1", ...], '
        f'"malicious_files": [{{"path": "...", "sha256": "...", "verdict": "MALICIOUS", '
        f'"detected_type": "...", "entropy": 0.0}}], '
        f'"suspicious_files": [...], '
        f'"clean_files": [...], '
        f'"report_markdown": "## Payload Analysis\\n..."}}'
    )

    graph = _build_payload_graph()
    result = graph.invoke({
        "messages": [SystemMessage(content=SYSTEM_PROMPT), HumanMessage(content=seed_prompt)],
        "steps": 0,
    })

    findings = _parse_conversation(result.get("messages", []))

    return {
        **state,
        "payload_findings": findings,
    }
