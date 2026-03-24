"""
agents/initial_access_adapter.py
=================================
Wraps the existing ForensicAgent (agent.py) to fit the PipelineState
data contract.

The original agent takes (pcap_path, azure_config, tshark_path) and
returns a Markdown report string via submit_report.  This adapter:
  1. Reads pcap_file and zeek_context from PipelineState
  2. Runs ForensicAgent
  3. Parses the Markdown report to extract structured IOCs / metadata
  4. Writes an InitialAccessFindings back into PipelineState via the
     canonical helpers in shared/data_contract.py
"""

from __future__ import annotations

import os
import re
import shutil
import time
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage

from shared.data_contract import (
    IOC,
    InitialAccessFindings,
    PipelineState,
    get_zeek_context,
    set_initial_access,
)

# ── tshark auto-detection (mirrors agent.py logic) ────────────────────────────

def _find_tshark() -> str | None:
    env = os.environ.get("TSHARK_PATH")
    if env and os.path.isfile(env):
        return env
    path = shutil.which("tshark")
    if path:
        return path
    for candidate in [
        "/opt/homebrew/opt/wireshark/bin/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ]:
        if os.path.isfile(candidate):
            return candidate
    return None


# ── Markdown report parser ─────────────────────────────────────────────────────

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HASH_RE = re.compile(r"\b[0-9a-fA-F]{64}\b")


def _parse_report(report: str) -> InitialAccessFindings:
    """
    Best-effort extraction of structured fields from the Markdown report
    produced by ForensicAgent.submit_report.
    """
    findings = InitialAccessFindings(report_markdown=report, raw={"full_report": report})

    # Patient Zero — look for "Patient Zero" heading/line
    pz_match = re.search(
        r"patient zero[^\n]*?[:\-–]\s*([0-9.]+)", report, re.I
    )
    if pz_match:
        findings.patient_zero = pz_match.group(1).strip()

    # Attacker IP — look for "attacker IP" / "successful login from"
    for pattern in [
        r"attacker ip[^\n]*?[:\-–]\s*([0-9.]+)",
        r"successful (?:login|session) from\s+([0-9.]+)",
        r"logged in (?:from|using)\s+([0-9.]+)",
    ]:
        m = re.search(pattern, report, re.I)
        if m:
            findings.attacker_ip = m.group(1).strip()
            break

    # Exposed service / port
    port_match = re.search(r"port\s+(\d{1,5})", report, re.I)
    if port_match:
        findings.attacker_port = int(port_match.group(1))
    svc_match = re.search(
        r"(?:service|protocol|via)[^\n]*?[:\-–]\s*([A-Z]{2,6}(?:/\d+)?)",
        report,
        re.I,
    )
    if svc_match:
        findings.exposed_service = svc_match.group(1).strip()
    elif findings.attacker_port == 3389:
        findings.exposed_service = "RDP/3389"

    # Attack vector
    for kw in [
        "brute.force",
        "phishing",
        "exploit",
        "credential stuffing",
        "password spray",
        "drive.by",
    ]:
        if re.search(kw, report, re.I):
            findings.attack_vector = re.sub(r"\.", " ", kw).strip()
            break

    # Brute force count
    bf_match = re.search(r"(\d[\d,]+)\s+(?:syn|brute.force|failed)", report, re.I)
    if bf_match:
        findings.brute_force_count = int(bf_match.group(1).replace(",", ""))

    # Session size
    sz_match = re.search(r"(\d[\d,]+)\s+bytes?", report, re.I)
    if sz_match:
        findings.successful_session_bytes = int(sz_match.group(1).replace(",", ""))

    # Pre-existing compromise
    if re.search(r"pre.existing|c2 beacon|rmm tool|return visit", report, re.I):
        findings.pre_existing_compromise = True

    # IOCs — collect unique IPs mentioned in an IOC section
    ioc_section = re.search(
        r"(?:indicators? of compromise|ioc)[^\n]*\n(.*?)(?:\n#|\Z)",
        report,
        re.I | re.S,
    )
    seen_ips: set[str] = set()
    if ioc_section:
        for ip in _IP_RE.findall(ioc_section.group(1)):
            if ip not in seen_ips:
                seen_ips.add(ip)
                confidence = "high" if ip == findings.attacker_ip else "medium"
                findings.iocs.append(
                    IOC(
                        ioc_type="ip",
                        value=ip,
                        source_agent="initial_access",
                        confidence=confidence,
                    )
                )

    # Timestamps — very rough
    ts_match = re.search(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})", report)
    if ts_match:
        findings.session_start = ts_match.group(1)

    return findings


# ── Main pipeline node ─────────────────────────────────────────────────────────

def initial_access_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node that runs ForensicAgent and writes InitialAccessFindings
    back to PipelineState.
    """
    # ── Resolve PCAP path ──────────────────────────────────────────────────
    pcap_path = state.get("pcap_file", "")
    if not pcap_path:
        ctx = get_zeek_context(state)
        if ctx:
            pcap_path = ctx.pcap_path

    if not pcap_path or not Path(pcap_path).is_file():
        msg = f"[InitialAccess] PCAP not found: {pcap_path!r}"
        findings = InitialAccessFindings(
            summary=msg, report_markdown=msg, raw={"error": msg}
        )
        return {
            **set_initial_access(state, findings),
            "messages": list(state.get("messages", []))
            + [HumanMessage(content=msg)],
            "completed_agents": list(state.get("completed_agents", [])) + ["initial_access"],
        }

    # ── Find tshark ───────────────────────────────────────────────────────
    tshark = _find_tshark()
    if not tshark:
        msg = "[InitialAccess] tshark not found. Install Wireshark/tshark."
        findings = InitialAccessFindings(
            report_markdown=msg, raw={"error": msg}
        )
        return {
            **set_initial_access(state, findings),
            "messages": list(state.get("messages", []))
            + [HumanMessage(content=msg)],
            "completed_agents": list(state.get("completed_agents", [])) + ["initial_access"],
        }

    # ── Azure OpenAI config ───────────────────────────────────────────────
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    deployment = os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")

    if not endpoint or not api_key:
        msg = (
            "[InitialAccess] AZURE_OPENAI_ENDPOINT / AZURE_OPENAI_API_KEY "
            "not set. Skipping initial access analysis."
        )
        findings = InitialAccessFindings(report_markdown=msg, raw={"error": msg})
        return {
            **set_initial_access(state, findings),
            "messages": list(state.get("messages", []))
            + [HumanMessage(content=msg)],
            "completed_agents": list(state.get("completed_agents", [])) + ["initial_access"],
        }

    # ── Import and run the original ForensicAgent ─────────────────────────
    # Import here to avoid circular dependency and allow agent.py to live
    # anywhere on the Python path.
    from agent import ForensicAgent  # type: ignore

    work_dir = state.get("work_dir", "/tmp/sc4063")
    report_path = str(Path(work_dir) / "initial_access_report.md")

    azure_config = {
        "endpoint": endpoint,
        "api_key": api_key,
        "deployment": deployment,
    }

    print(f"\n{'─' * 60}")
    print("  [InitialAccess] Starting ForensicAgent…")
    print(f"  PCAP : {pcap_path}")
    print(f"{'─' * 60}")

    t0 = time.time()
    agent = ForensicAgent(
        pcap_path=pcap_path,
        azure_config=azure_config,
        tshark_path=tshark,
        output_path=report_path,
    )
    report = agent.run()
    elapsed = time.time() - t0

    print(f"\n  [InitialAccess] Done in {elapsed:.0f}s")

    # ── Parse report into structured findings ─────────────────────────────
    findings = _parse_report(report or "")
    if not findings.report_markdown:
        findings.report_markdown = report or ""

    # ── Persist back to state ─────────────────────────────────────────────
    update = set_initial_access(state, findings)
    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"[InitialAccessAgent] Analysis complete ({elapsed:.0f}s).\n"
                f"Patient Zero: {findings.patient_zero or 'unknown'}\n"
                f"Attacker IP: {findings.attacker_ip or 'unknown'}\n"
                f"Vector: {findings.attack_vector or 'unknown'}"
            )
        )
    )

    return {
        **state,
        **update,
        "pcap_file": pcap_path,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["initial_access"],
    }
