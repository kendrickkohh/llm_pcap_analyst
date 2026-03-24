"""
agents/lateral_movement_adapter.py
====================================
Adapter that connects lateral_movement.lateral_movement_agent_node to
the canonical PipelineState data contract.

The original lateral_movement_agent_node already reads
  state["pcap_file"], state["initial_access_findings"], state["attack_context"]
and writes state["lateral_movement_findings"] as a raw dict.

This adapter:
  1. Translates PipelineState → the format lateral_movement.py expects
  2. Calls lateral_movement_agent_node
  3. Parses its output into LateralMovementFindings
  4. Propagates IOCs and updates attack_context via canonical helpers
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage

from shared.data_contract import (
    IOC,
    LateralMovementFindings,
    PipelineState,
    get_zeek_context,
    set_lateral_movement,
)


def lateral_movement_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node — runs the lateral movement sub-graph and normalises
    its output into the pipeline's canonical schema.
    """
    # ── Ensure pcap_file is set ────────────────────────────────────────────
    pcap_file = state.get("pcap_file", "")
    if not pcap_file:
        ctx = get_zeek_context(state)
        if ctx:
            pcap_file = ctx.pcap_path

    # The lateral_movement module expects state["pcap_file"] to be set
    lm_input: dict[str, Any] = {
        **state,
        "pcap_file": pcap_file,
    }

    # ── Call original lateral movement node ───────────────────────────────
    from lateral_movement.lateral_movement import (  # type: ignore
        lateral_movement_agent_node as _lm_node,
    )

    print("\n" + "─" * 60)
    print("  [LateralMovement] Starting analysis…")
    print("─" * 60)

    result = _lm_node(lm_input)

    # ── Extract raw findings dict ─────────────────────────────────────────
    raw: dict[str, Any] = result.get("lateral_movement_findings", {})

    # ── Build canonical LateralMovementFindings ────────────────────────────
    findings = LateralMovementFindings(
        summary=raw.get("summary", "Lateral movement analysis completed."),
        bottom_line=raw.get("bottom_line", ""),
        observed=raw.get("observed", []),
        not_observed=raw.get("not_observed", []),
        limitations=raw.get("limitations", []),
        evidence_highlights=raw.get("evidence_highlights", []),
        tacticalrmm_assessment=raw.get("tacticalrmm_assessment", ""),
        report_markdown=raw.get("report_markdown", ""),
        raw=raw,
    )

    # Extract compromised hosts from attack context propagation
    new_ctx = result.get("attack_context", {})
    findings.compromised_hosts = new_ctx.get("compromised_hosts", [])
    findings.techniques = new_ctx.get("techniques", [])

    # Extract movement paths from evidence highlights if not explicit
    for highlight in findings.evidence_highlights:
        import re
        pairs = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})\s*→\s*(\d{1,3}(?:\.\d{1,3}){3})", highlight)
        for src, dst in pairs:
            if (src, dst) not in findings.movement_paths:
                findings.movement_paths.append((src, dst))

    # Build IOCs from compromised hosts
    for host in findings.compromised_hosts:
        findings.iocs.append(
            IOC(
                ioc_type="ip",
                value=host,
                source_agent="lateral_movement",
                confidence="high",
                notes="Identified as laterally compromised host",
            )
        )

    # ── Write canonical update ────────────────────────────────────────────
    canonical_update = set_lateral_movement(state, findings)

    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"[LateralMovementAgent] Analysis complete.\n"
                f"Bottom line: {findings.bottom_line or findings.summary[:200]}\n"
                f"Compromised hosts: {', '.join(findings.compromised_hosts) or 'none identified'}\n"
                f"Techniques: {', '.join(findings.techniques) or 'none identified'}"
            )
        )
    )

    return {
        **state,
        **canonical_update,
        "pcap_file": pcap_file,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["lateral_movement"],
    }
