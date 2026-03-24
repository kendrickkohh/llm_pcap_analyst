"""
agents/payload_agent_adapter.py
=================================
Adapter that wraps payload_agent.payload_agent_node to fit the canonical
PipelineState data contract.

The original payload_agent_node already speaks a dict-based state.  This
adapter:
  1. Maps PipelineState into the format payload_agent.py expects
  2. Calls payload_agent_node
  3. Parses its output into a canonical PayloadFindings
  4. Writes findings back into PipelineState
"""

from __future__ import annotations

import json
import re
from typing import Any

from langchain_core.messages import HumanMessage

from shared.data_contract import (
    IOC,
    PayloadFindings,
    PipelineState,
    get_zeek_context,
    set_payload,
)


def _parse_payload_summary(summary: str) -> PayloadFindings:
    """
    Parse the free-text summary produced by payload_agent into structured
    PayloadFindings.  The summary typically contains verdicts like:
      "MALICIOUS: Flagged by N engines…"
      "HIGH RISK: File is named…"
      "HIGH ENTROPY: …"
    """
    findings = PayloadFindings(summary=summary, report_markdown=summary)

    # Extract file paths mentioned
    for path in re.findall(r'["\']?(/[\w/.\-_]+\.\w+)["\']?', summary):
        if path not in findings.files_analysed:
            findings.files_analysed.append(path)

    # Classify files
    for block in re.split(r"\n(?=file_path|File:)", summary, flags=re.I):
        path_m = re.search(r'file_path["\s:]+([^\s,"\']+)', block, re.I)
        sha_m = re.search(r'sha256["\s:]+([0-9a-fA-F]{64})', block, re.I)
        malicious_m = re.search(r'MALICIOUS|HIGH RISK', block)
        suspicious_m = re.search(r'SUSPICIOUS|HIGH ENTROPY|CRITICAL', block)

        file_rec = {
            "path": path_m.group(1) if path_m else "",
            "sha256": sha_m.group(1) if sha_m else "",
            "verdict": "",
        }

        if malicious_m:
            file_rec["verdict"] = malicious_m.group(0)
            findings.malicious_files.append(file_rec)
        elif suspicious_m:
            file_rec["verdict"] = suspicious_m.group(0)
            findings.suspicious_files.append(file_rec)
        elif file_rec["path"]:
            file_rec["verdict"] = "CLEAN"
            findings.clean_files.append(file_rec)

    # Build IOCs from malicious file hashes
    for f_rec in findings.malicious_files:
        if f_rec.get("sha256"):
            findings.iocs.append(
                IOC(
                    ioc_type="hash",
                    value=f_rec["sha256"],
                    source_agent="payload",
                    confidence="high",
                    notes=f_rec.get("verdict", ""),
                )
            )
        if f_rec.get("path"):
            findings.iocs.append(
                IOC(
                    ioc_type="file",
                    value=f_rec["path"],
                    source_agent="payload",
                    confidence="high",
                )
            )

    return findings


def payload_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node — runs the payload sub-agent and normalises its output.
    """
    # ── Resolve PCAP path ──────────────────────────────────────────────────
    pcap_file = state.get("pcap_file", "")
    if not pcap_file:
        ctx = get_zeek_context(state)
        if ctx:
            pcap_file = ctx.pcap_path

    # ── Build the input state for the original payload_agent_node ─────────
    # payload_agent expects dict with "messages" key
    payload_input: dict[str, Any] = {
        **state,
        "pcap_file": pcap_file,
        "messages": list(state.get("messages", [])),
    }

    print("\n" + "─" * 60)
    print("  [Payload] Starting payload analysis…")
    print("─" * 60)

    # ── Call original node ─────────────────────────────────────────────────
    from payload_agent import payload_agent_node as _pa_node  # type: ignore

    result = _pa_node(payload_input)

    # ── Parse output ───────────────────────────────────────────────────────
    raw: dict[str, Any] = result.get("payload_findings", {})
    summary: str = raw.get("summary", "Payload analysis completed.")

    findings = _parse_payload_summary(summary)
    findings.raw = raw

    # ── Write canonical update ─────────────────────────────────────────────
    canonical = set_payload(state, findings)

    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"[PayloadAgent] Analysis complete.\n"
                f"Files analysed: {len(findings.files_analysed)}\n"
                f"Malicious: {len(findings.malicious_files)}, "
                f"Suspicious: {len(findings.suspicious_files)}, "
                f"Clean: {len(findings.clean_files)}"
            )
        )
    )

    return {
        **state,
        **canonical,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["payload"],
    }
