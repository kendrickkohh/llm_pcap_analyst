"""
master_pipeline.py
==================
SC4063 Security Analysis Pipeline — Master Orchestrator

Pipeline stages:
    ingest          → PCAP API: fetch Zeek logs + PCAP for target day
    supervisor      → decides which analysis agent runs next
    initial_access  → ForensicAgent (agent.py) — identifies entry point
    lateral_movement → LateralMovement agent — tracks host-to-host spread
    exfiltration    → Exfiltration agent     — detects data theft
    payload         → Payload agent          — analyses malicious files
    report_writing  → Synthesises all findings into a final Markdown report

Data contract:
    All agents read/write through shared.data_contract.PipelineState using
    the canonical accessors.  No ad-hoc dict keys between agents.

Usage:
    python master_pipeline.py --day 2025-03-06

    # Or run a single agent for debugging:
    python master_pipeline.py --day 2025-03-06 --only initial_access
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Literal

from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_openai import AzureChatOpenAI
from langgraph.graph import END, StateGraph

load_dotenv()

# ── Pipeline imports ───────────────────────────────────────────────────────────
# Add repository root and sub-directories to path so agent modules resolve.
_REPO_ROOT = Path(__file__).parent
sys.path.insert(0, str(_REPO_ROOT))
sys.path.insert(0, str(_REPO_ROOT / "agents"))
sys.path.insert(0, str(_REPO_ROOT / "shared"))

from shared.data_contract import (          # noqa: E402
    PipelineState,
    get_exfiltration,
    get_initial_access,
    get_lateral_movement,
    get_payload,
    get_zeek_context,
    initial_pipeline_state,
    merge_all_iocs,
    set_zeek_context,
)
from shared.pcap_api import ingest_day, list_days      # noqa: E402

from agents.initial_access_adapter import initial_access_agent_node    # noqa: E402
from agents.lateral_movement_adapter import lateral_movement_agent_node  # noqa: E402
from agents.exfiltration_agent import exfiltration_agent_node           # noqa: E402
from agents.payload_agent_adapter import payload_agent_node             # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# Ingestion node
# ──────────────────────────────────────────────────────────────────────────────

def ingest_node(state: PipelineState) -> dict[str, Any]:
    """
    Downloads Zeek logs and the PCAP for the target day via the SC4063 API.
    Populates state["zeek_context"] and state["pcap_file"].
    """
    day = state["target_day"]
    work_dir = state.get("work_dir", "/tmp/sc4063")

    print(f"\n{'═' * 60}")
    print(f"  [Ingest] Starting data collection for {day}")
    print(f"{'═' * 60}")

    ctx = ingest_day(day=day, work_dir=work_dir)

    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(
            content=(
                f"[IngestNode] Day {day} ingested.\n"
                f"PCAP: {ctx.pcap_path}\n"
                f"Zeek datasets: {list(ctx.zeek_files.keys())}"
            )
        )
    )

    update = set_zeek_context(state, ctx)
    return {
        **state,
        **update,
        "pcap_file": ctx.pcap_path,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["ingest"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Supervisor node
# ──────────────────────────────────────────────────────────────────────────────

_AGENT_ORDER = ["initial_access", "lateral_movement", "exfiltration", "payload"]

def supervisor_node(state: PipelineState) -> dict[str, Any]:
    """
    Orchestrator: decides which agent runs next based on what has been completed.
    Uses deterministic ordering for reliability (can be swapped for LLM-based
    routing by uncommenting the LLM section below).
    """
    completed = set(state.get("completed_agents", []))

    # Deterministic routing: run agents in logical forensic order
    for agent in _AGENT_ORDER:
        if agent not in completed:
            print(f"\n  [Supervisor] → routing to: {agent}")
            return {**state, "next_agent": agent}

    print("\n  [Supervisor] → all agents complete, routing to report_writing")
    return {**state, "next_agent": "FINISH"}


def route_from_supervisor(
    state: PipelineState,
) -> Literal["initial_access", "lateral_movement", "exfiltration", "payload", "report_writing"]:
    next_agent = state.get("next_agent", "initial_access")
    if next_agent == "FINISH":
        return "report_writing"
    return next_agent  # type: ignore[return-value]


# ──────────────────────────────────────────────────────────────────────────────
# Report writing node
# ──────────────────────────────────────────────────────────────────────────────

_REPORT_TEMPLATE = """\
You are a senior security analyst writing an incident report.
Synthesise all findings into a professional, actionable report.

Return ONLY the Markdown report. No preamble, no JSON wrapping.

Use this structure:
# Security Incident Report — {day}

## 1. Executive Summary
## 2. Attack Timeline
## 3. Initial Access
## 4. Lateral Movement
## 5. Exfiltration
## 6. Payload Analysis
## 7. Indicators of Compromise (IOCs)
## 8. Affected Systems
## 9. Recommendations
"""

def report_writing_node(state: PipelineState) -> dict[str, Any]:
    """
    Uses an LLM to synthesise all agent findings into a cohesive Markdown report.
    """
    day = state.get("target_day", "unknown")
    ia = get_initial_access(state)
    lm = get_lateral_movement(state)
    ex = get_exfiltration(state)
    pa = get_payload(state)
    iocs = merge_all_iocs(state)
    ctx = state.get("attack_context", {})

    report_prompt = f"""{_REPORT_TEMPLATE.format(day=day)}

---
ATTACK CONTEXT:
{json.dumps(ctx, indent=2, default=str)}

INITIAL ACCESS FINDINGS:
{json.dumps(ia.to_dict() if ia else {}, indent=2, default=str)}

LATERAL MOVEMENT FINDINGS:
{json.dumps(lm.to_dict() if lm else {}, indent=2, default=str)}

EXFILTRATION FINDINGS:
{json.dumps(ex.to_dict() if ex else {}, indent=2, default=str)}

PAYLOAD ANALYSIS FINDINGS:
{json.dumps(pa.to_dict() if pa else {}, indent=2, default=str)}

CONSOLIDATED IOCs ({len(iocs)} total):
{json.dumps(iocs, indent=2, default=str)}

---
Now write the complete incident report as Markdown.
"""

    print(f"\n{'─' * 60}")
    print("  [ReportWriter] Generating final report…")
    print(f"{'─' * 60}")

    report_llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0.1,
        max_tokens=4000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

    # Save report to work dir
    work_dir = state.get("work_dir", "/tmp/sc4063")
    report_path = Path(work_dir) / day / "incident_report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_content, encoding="utf-8")

    print(f"\n  ✓ Report saved → {report_path}")
    print(f"  Length: {len(report_content):,} chars")

    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(content=f"[ReportWriter] Final report generated ({len(report_content):,} chars).")
    )

    return {
        **state,
        "final_report": report_content,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["report_writing"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# Multi-day pipeline helpers
# ──────────────────────────────────────────────────────────────────────────────

_COMBINED_REPORT_TEMPLATE = """\
You are a senior security analyst writing a multi-day incident report.
Synthesise findings across ALL days into a single professional, actionable report.

Return ONLY the Markdown report. No preamble, no JSON wrapping.

Use this structure:
# Security Incident Report — {date_range}

## 1. Executive Summary
## 2. Campaign Overview (cross-day patterns)
## 3. Attack Timeline (chronological across all days)
## 4. Initial Access (per-day summary)
## 5. Lateral Movement (per-day summary)
## 6. Exfiltration (per-day summary)
## 7. Payload Analysis (per-day summary)
## 8. Consolidated Indicators of Compromise (IOCs)
## 9. Affected Systems
## 10. Recommendations
"""


def write_combined_report(
    all_day_results: list[dict],
    work_dir: str,
) -> str:
    """
    Call the LLM once with findings from all days to produce a single
    consolidated incident report.
    """
    days = [r["day"] for r in all_day_results]
    date_range = f"{days[0]} to {days[-1]}" if len(days) > 1 else days[0]

    sections = []
    all_iocs: list[dict] = []
    seen_ioc_keys: set[tuple] = set()

    for r in all_day_results:
        day = r["day"]
        sections.append(f"\n{'─'*50}\n## DAY: {day}\n{'─'*50}")
        sections.append(f"ATTACK CONTEXT:\n{json.dumps(r['attack_context'], indent=2, default=str)}")
        sections.append(f"INITIAL ACCESS:\n{json.dumps(r['initial_access_findings'], indent=2, default=str)}")
        sections.append(f"LATERAL MOVEMENT:\n{json.dumps(r['lateral_movement_findings'], indent=2, default=str)}")
        sections.append(f"EXFILTRATION:\n{json.dumps(r['exfiltration_findings'], indent=2, default=str)}")
        sections.append(f"PAYLOAD:\n{json.dumps(r['payload_findings'], indent=2, default=str)}")

        for ioc in r.get("iocs", []):
            key = (ioc.get("ioc_type"), ioc.get("value"))
            if key not in seen_ioc_keys:
                seen_ioc_keys.add(key)
                all_iocs.append(ioc)

    report_prompt = (
        _COMBINED_REPORT_TEMPLATE.format(date_range=date_range)
        + "\n---\n"
        + "\n".join(sections)
        + f"\n\nCONSOLIDATED IOCs ({len(all_iocs)} unique):\n"
        + json.dumps(all_iocs, indent=2, default=str)
        + "\n\n---\nNow write the complete multi-day incident report as Markdown."
    )

    print(f"\n{'─' * 60}")
    print(f"  [CombinedReport] Generating report for {len(days)} days…")
    print(f"{'─' * 60}")

    report_llm = AzureChatOpenAI(
        azure_endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
        api_key=os.environ["AZURE_OPENAI_API_KEY"],
        azure_deployment=os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini"),
        api_version="2024-02-01",
        temperature=0.1,
        max_tokens=6000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

    report_path = Path(work_dir) / "combined_incident_report.md"
    report_path.write_text(report_content, encoding="utf-8")
    print(f"\n  ✓ Combined report saved → {report_path}")

    return report_content


def run_all_days_pipeline(
    pipeline: Any,
    work_dir: str,
) -> list[dict]:
    """
    Fetch all available days from the API, run the analysis pipeline for each
    day (skipping per-day report writing), and return accumulated per-day
    findings for the final combined report.
    """
    days_meta = list_days()
    if not days_meta:
        raise RuntimeError("No days returned from API.")

    days = [d["day"] for d in days_meta]
    print(f"\n  [AllDays] Found {len(days)} days: {days[0]} … {days[-1]}")

    all_day_results: list[dict] = []

    for day in days:
        print(f"\n{'=' * 60}")
        print(f"  [AllDays] Processing {day}  ({days.index(day)+1}/{len(days)})")
        print(f"{'=' * 60}")

        state = initial_pipeline_state(target_day=day, work_dir=work_dir)

        # Run pipeline — collect the last state snapshot that has agent findings
        final_day_state: dict[str, Any] = {}
        for step_state in pipeline.stream(state):
            node_name = list(step_state.keys())[0]
            node_data = step_state[node_name]
            completed = node_data.get("completed_agents", [])
            print(f"    ✓ {node_name}  |  completed: {completed}")
            # Accumulate state (last writer wins, same as LangGraph reduce)
            final_day_state.update(node_data)

        all_day_results.append({
            "day": day,
            "attack_context":             final_day_state.get("attack_context", {}),
            "initial_access_findings":    final_day_state.get("initial_access_findings", {}),
            "lateral_movement_findings":  final_day_state.get("lateral_movement_findings", {}),
            "exfiltration_findings":      final_day_state.get("exfiltration_findings", {}),
            "payload_findings":           final_day_state.get("payload_findings", {}),
            "iocs":                       merge_all_iocs(final_day_state),  # type: ignore[arg-type]
        })

    return all_day_results


# ──────────────────────────────────────────────────────────────────────────────
# Graph assembly
# ──────────────────────────────────────────────────────────────────────────────

def build_pipeline(skip_report: bool = False) -> Any:
    """
    Compile the master LangGraph pipeline.

    skip_report=True: omit the report_writing node and terminate after all
    agents complete.  Used when running --all-days so we only write one
    combined report at the end instead of nine individual ones.
    """
    workflow = StateGraph(PipelineState)

    # Nodes
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("initial_access", initial_access_agent_node)
    workflow.add_node("lateral_movement", lateral_movement_agent_node)
    workflow.add_node("exfiltration", exfiltration_agent_node)
    workflow.add_node("payload", payload_agent_node)

    if not skip_report:
        workflow.add_node("report_writing", report_writing_node)

    # Entry: always start with ingestion
    workflow.set_entry_point("ingest")

    # ingest → supervisor
    workflow.add_edge("ingest", "supervisor")

    if skip_report:
        # When all agents are done the supervisor sets next_agent="FINISH";
        # route that straight to END.
        def route_no_report(state: PipelineState):
            next_agent = state.get("next_agent", "initial_access")
            if next_agent == "FINISH":
                return END
            return next_agent  # type: ignore[return-value]

        workflow.add_conditional_edges(
            "supervisor",
            route_no_report,
            {
                "initial_access":   "initial_access",
                "lateral_movement": "lateral_movement",
                "exfiltration":     "exfiltration",
                "payload":          "payload",
                END:                END,
            },
        )
    else:
        workflow.add_conditional_edges(
            "supervisor",
            route_from_supervisor,
            {
                "initial_access":   "initial_access",
                "lateral_movement": "lateral_movement",
                "exfiltration":     "exfiltration",
                "payload":          "payload",
                "report_writing":   "report_writing",
            },
        )
        workflow.add_edge("report_writing", END)

    # Each agent loops back to supervisor
    for agent in _AGENT_ORDER:
        workflow.add_edge(agent, "supervisor")

    return workflow.compile()


# ──────────────────────────────────────────────────────────────────────────────
# CLI entry point
# ──────────────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="SC4063 Security Analysis Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python master_pipeline.py --day 2025-03-06
    python master_pipeline.py --all-days
    python master_pipeline.py --all-days --work-dir ./data
    python master_pipeline.py --day 2025-03-06 --work-dir ./data
    python master_pipeline.py --day 2025-03-06 --only exfiltration

    Environment variables (.env or shell):
    AZURE_OPENAI_ENDPOINT     Azure endpoint for initial_access agent
    AZURE_OPENAI_API_KEY      Azure key
    AZURE_OPENAI_DEPLOYMENT   Deployment name (default: gpt-4o-mini)
    VIRUSTOTAL_API_KEY        VirusTotal key for payload agent
    TSHARK_PATH               Path to tshark binary (auto-detected)
        """,
    )
    day_group = parser.add_mutually_exclusive_group(required=True)
    day_group.add_argument(
        "--day",
        help="Single day to analyse in YYYY-MM-DD format",
    )
    day_group.add_argument(
        "--all-days", action="store_true",
        help="Fetch all available days from the API and run the full pipeline "
             "for each, then produce one combined incident report",
    )
    parser.add_argument(
        "--work-dir", default="/tmp/sc4063",
        help="Directory for downloads and outputs (default: /tmp/sc4063)",
    )
    parser.add_argument(
        "--pcap-index", type=int, default=0,
        help="Which PCAP to pick from the day's list (0-based, default: 0)",
    )
    parser.add_argument(
        "--only", default=None,
        choices=["initial_access", "lateral_movement", "exfiltration", "payload", "report"],
        help="Run only one agent (useful for debugging; assumes PCAP already downloaded). "
             "Ignored when --all-days is used.",
    )
    parser.add_argument(
        "--pcap", default=None,
        help="Skip ingestion and use this local PCAP path directly. "
             "Ignored when --all-days is used.",
    )
    args = parser.parse_args()

    t_start = time.time()

    # ── All-days mode ─────────────────────────────────────────────────────
    if args.all_days:
        print(f"\n{'=' * 60}")
        print(f"  SC4063 Security Analysis Pipeline — ALL DAYS")
        print(f"  Work dir: {args.work_dir}")
        print(f"{'=' * 60}\n")

        # Build pipeline without per-day report writing
        pipeline = build_pipeline(skip_report=True)

        all_day_results = run_all_days_pipeline(pipeline, args.work_dir)

        combined_report = write_combined_report(all_day_results, args.work_dir)

        elapsed = time.time() - t_start
        report_path = Path(args.work_dir) / "combined_incident_report.md"
        print(f"\n{'=' * 60}")
        print(f"  All-days pipeline complete in {elapsed:.0f}s")
        print(f"  Days processed : {len(all_day_results)}")
        print(f"  Combined report: {report_path}")
        print(f"{'=' * 60}\n")
        print(combined_report[:3000])
        if len(combined_report) > 3000:
            print(f"\n  … [truncated — see {report_path} for full report]")
        return

    # ── Single-day mode ───────────────────────────────────────────────────
    state = initial_pipeline_state(
        target_day=args.day,
        work_dir=args.work_dir,
    )

    # If a local PCAP is provided, skip ingestion
    if args.pcap:
        from shared.data_contract import ZeekContext
        ctx = ZeekContext(day=args.day, pcap_path=os.path.abspath(args.pcap))
        state.update(set_zeek_context(state, ctx))
        state["pcap_file"] = ctx.pcap_path
        state["completed_agents"] = ["ingest"]

    print(f"\n{'=' * 60}")
    print(f"  SC4063 Security Analysis Pipeline")
    print(f"  Day     : {args.day}")
    print(f"  Run ID  : {state['run_id']}")
    print(f"  Work dir: {args.work_dir}")
    print(f"{'=' * 60}\n")

    pipeline = build_pipeline()

    # ── Single-agent debug mode ────────────────────────────────────────────
    if args.only:
        agent_map = {
            "initial_access": initial_access_agent_node,
            "lateral_movement": lateral_movement_agent_node,
            "exfiltration": exfiltration_agent_node,
            "payload": payload_agent_node,
            "report": report_writing_node,
        }
        node_fn = agent_map[args.only]
        print(f"  [DEBUG] Running single agent: {args.only}")
        result = node_fn(state)
        elapsed = time.time() - t_start
        print(f"\n  Done in {elapsed:.0f}s")
        if args.only == "report":
            print("\n" + result.get("final_report", ""))
        return

    # ── Full single-day pipeline ───────────────────────────────────────────
    final_state = None
    for step_state in pipeline.stream(state):
        node_name = list(step_state.keys())[0]
        node_data = step_state[node_name]
        completed = node_data.get("completed_agents", [])
        print(f"\n  ✓ Step complete: {node_name}  |  completed: {completed}")

        if "final_report" in node_data and node_data["final_report"]:
            final_state = node_data

    elapsed = time.time() - t_start

    print(f"\n{'=' * 60}")
    print(f"  Pipeline complete in {elapsed:.0f}s")
    print(f"{'=' * 60}\n")

    if final_state and final_state.get("final_report"):
        report_path = (
            Path(args.work_dir) / args.day / "incident_report.md"
        )
        print(f"  Final report: {report_path}")
        print(f"\n{'─' * 60}")
        # Print first 3000 chars of report
        print(final_state["final_report"][:3000])
        if len(final_state["final_report"]) > 3000:
            print(f"\n  … [truncated — see {report_path} for full report]")


if __name__ == "__main__":
    main()
