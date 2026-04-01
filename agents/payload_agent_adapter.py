"""
agents/payload_agent_adapter.py
=================================
Adapter that wraps payload_agent.payload_agent_node to fit the canonical
PipelineState data contract.
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage

from shared.data_contract import (
    IOC,
    PayloadFindings,
    PipelineState,
    get_zeek_context,
    set_payload,
)


def payload_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node — runs the payload sub-agent and normalises its output.
    """
    print("\n" + "─" * 60)
    print("  [Payload] Starting payload analysis…")
    print("─" * 60)

    from payload_agent import payload_agent_node as _pa_node  # type: ignore

    result = _pa_node(state)

    # ── Parse output ───────────────────────────────────────────────────────
    raw: dict[str, Any] = result.get("payload_findings", {})

    findings = PayloadFindings(
        summary=raw.get("summary", "Payload analysis completed."),
        report_markdown=raw.get("report_markdown", raw.get("summary", "")),
        raw=raw,
    )

    # Extract structured fields from the new Zeek-based payload agent
    deployment = raw.get("deployment_method", "")
    if deployment:
        findings.summary = f"Deployment: {deployment}. {findings.summary}"

    # Payload files detected
    for pf in raw.get("payload_files", []):
        if isinstance(pf, str):
            findings.files_analysed.append(pf)
            findings.suspicious_files.append({"path": pf, "verdict": "payload candidate"})
        elif isinstance(pf, dict):
            path = pf.get("file", pf.get("path", ""))
            if path:
                findings.files_analysed.append(path)
                findings.suspicious_files.append(pf)

    # Build IOCs from target hosts and evidence
    for host in raw.get("target_hosts", []):
        findings.iocs.append(IOC(
            ioc_type="ip",
            value=host,
            source_agent="payload",
            confidence="medium",
            notes="Payload deployment target",
        ))

    source_host = raw.get("source_host", "")
    if source_host:
        findings.iocs.append(IOC(
            ioc_type="ip",
            value=source_host,
            source_agent="payload",
            confidence="high",
            notes="Payload deployment source",
        ))

    # ── Write canonical update ─────────────────────────────────────────────
    canonical = set_payload(state, findings)

    messages = list(state.get("messages", []))
    messages.append(HumanMessage(content=(
        f"[PayloadAgent] Analysis complete.\n"
        f"Deployment: {deployment or 'unknown'}\n"
        f"Summary: {findings.summary[:300]}"
    )))

    return {
        **state,
        **canonical,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["payload"],
    }
