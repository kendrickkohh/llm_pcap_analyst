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
from shared.pcap_api import (                           # noqa: E402
    ingest_day,
    list_days,
    ingest_all_alerts,
    score_alerts,
    score_all_pcaps,
    download_selected_pcaps,
    download_zeek_for_days,
)
from shared.disk_manager import (                       # noqa: E402
    init_disk_manager,
    get_disk_manager,
    init_provenance,
    get_provenance,
    ALERT,
    ZEEK,
    PCAP,
)

from agents.initial_access_adapter import initial_access_agent_node    # noqa: E402
from agents.lateral_movement_adapter import lateral_movement_agent_node  # noqa: E402
from agents.exfiltration_agent import exfiltration_agent_node           # noqa: E402
from agents.payload_agent_adapter import payload_agent_node             # noqa: E402


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK data loading (lazy, cached)
# ──────────────────────────────────────────────────────────────────────────────

_MITRE_JSON_PATH = _REPO_ROOT / "mitre_reference" / "enterprise-attack.json"
_MITRE_BY_ATTACK_ID: dict[str, dict] = {}
_MITRE_BY_STIX_ID: dict[str, dict] = {}
_MITRE_GROUP_TECH_MAP: dict[str, list[str]] = {}
_MITRE_LOADED = False


def _load_mitre() -> None:
    global _MITRE_LOADED
    if _MITRE_LOADED:
        return
    print("  [MITRE] Loading enterprise-attack.json…")
    with open(_MITRE_JSON_PATH, encoding="utf-8") as f:
        data = json.load(f)
    objects = data["objects"]
    _MITRE_BY_STIX_ID.update({o["id"]: o for o in objects})
    for o in objects:
        if o.get("type") == "attack-pattern":
            for ref in o.get("external_references", []):
                if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
                    _MITRE_BY_ATTACK_ID[ref["external_id"]] = o
    for o in objects:
        if (o.get("type") == "relationship"
                and o.get("relationship_type") == "uses"
                and o.get("source_ref", "").startswith("intrusion-set")
                and o.get("target_ref", "").startswith("attack-pattern")):
            _MITRE_GROUP_TECH_MAP.setdefault(o["source_ref"], []).append(o["target_ref"])
    _MITRE_LOADED = True
    print(f"  [MITRE] Loaded {len(_MITRE_BY_ATTACK_ID)} techniques, "
          f"{len(_MITRE_GROUP_TECH_MAP)} threat groups")


_KEYWORD_TO_TECHNIQUE_IDS: dict[str, list[str]] = {
    "rdp": ["T1021.001", "T1110.001"],
    "remote desktop": ["T1021.001"],
    "brute": ["T1110", "T1110.001"],
    "password": ["T1110", "T1078"],
    "credential": ["T1003", "T1110"],
    "smb": ["T1021.002", "T1570"],
    "smb_file": ["T1021.002", "T1570"],
    "dce_rpc": ["T1021.003"],
    "rpc": ["T1021.003"],
    "ntlm": ["T1187", "T1550.002"],
    "kerberos": ["T1558"],
    "dns": ["T1071.004"],
    "http": ["T1071.001", "T1048.003"],
    "https": ["T1071.001"],
    "exfil": ["T1041", "T1048"],
    "exfiltration": ["T1041", "T1048"],
    "temp.sh": ["T1567.002", "T1048"],
    "upload": ["T1048", "T1567"],
    "7zip": ["T1560.001"],
    "7-zip": ["T1560.001"],
    "compress": ["T1560"],
    "archive": ["T1560"],
    "scan": ["T1046"],
    "discovery": ["T1046", "T1018"],
    "file transfer": ["T1105"],
    "download": ["T1105"],
    "payload": ["T1105", "T1059"],
    "domain controller": ["T1018", "T1078.002"],
    "pass the hash": ["T1550.002"],
    "psexec": ["T1569.002"],
    "wmi": ["T1047"],
    "powershell": ["T1059.001"],
    "ssl": ["T1573"],
    "tls": ["T1573"],
    "persistence": ["T1547"],
    "privilege": ["T1068"],
}


# ──────────────────────────────────────────────────────────────────────────────
# Ingestion node
# ──────────────────────────────────────────────────────────────────────────────

def ingest_node(state: PipelineState) -> dict[str, Any]:
    """
    Downloads Zeek logs and the PCAP for the target day via the SC4063 API.
    Populates state["zeek_context"] and state["pcap_file"].

    In --all-days mode the multi-day orchestrator pre-populates
    zeek_context and pcap_file, then marks "ingest" as completed.
    When that has happened we must NOT re-run ingest_day() because
    a redundant API call could return fewer datasets (rate-limiting)
    and overwrite the zeek_context with incomplete data.
    """
    # ── Skip if already completed (multi-day mode) ────────────────────────
    completed = state.get("completed_agents", [])
    if "ingest" in completed and state.get("zeek_context"):
        print(f"\n{'═' * 60}")
        print(f"  [Ingest] Already completed — skipping redundant ingestion")
        print(f"{'═' * 60}")
        return {**state}

    day = state["target_day"]
    work_dir = state.get("work_dir", "data")

    print(f"\n{'═' * 60}")
    print(f"  [Ingest] Starting data collection for {day}")
    print(f"{'═' * 60}")

    ctx = ingest_day(day=day, work_dir=work_dir)

    # Record provenance for single-day ingestion
    prov = get_provenance()
    if prov:
        prov.record_day_analysed(day)
        prov.record_pcap(
            day, Path(ctx.pcap_path).name, ctx.pcap_path,
            ctx.pcap_metadata.get("size", 0),
        )
        prov.record_zeek_files(day, list(ctx.zeek_files.keys()))

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
) -> Literal["initial_access", "lateral_movement", "exfiltration", "payload", "mitre_enrichment"]:
    next_agent = state.get("next_agent", "initial_access")
    if next_agent == "FINISH":
        return "mitre_enrichment"
    return next_agent  # type: ignore[return-value]


# ──────────────────────────────────────────────────────────────────────────────
# MITRE ATT&CK enrichment node
# ──────────────────────────────────────────────────────────────────────────────

def _extract_technique_ids(state: PipelineState) -> list[str]:
    """Extract ATT&CK technique IDs from agent findings via keyword matching."""
    text_parts: list[str] = []
    for key in ("initial_access_findings", "lateral_movement_findings",
                "exfiltration_findings", "payload_findings"):
        findings = state.get(key, {})
        if not findings:
            continue
        text_parts.append(json.dumps(findings, default=str))
    ctx = state.get("attack_context", {})
    if ctx:
        text_parts.append(json.dumps(ctx, default=str))
    combined = " ".join(text_parts).lower()
    matched: set[str] = set()
    for keyword, tech_ids in _KEYWORD_TO_TECHNIQUE_IDS.items():
        if keyword.lower() in combined:
            matched.update(tech_ids)
    return sorted(matched)


def mitre_enrichment_node(state: PipelineState) -> dict[str, Any]:
    """Maps agent findings to MITRE ATT&CK techniques and threat groups."""
    print(f"\n{'─' * 60}")
    print("  [MITRE] Enriching findings with ATT&CK context…")
    print(f"{'─' * 60}")
    _load_mitre()

    matched_ids = _extract_technique_ids(state)
    print(f"  [MITRE] Matched {len(matched_ids)} technique IDs: {matched_ids}")

    # Build technique detail list
    techniques: list[dict] = []
    matched_stix: set[str] = set()
    for att_id in matched_ids:
        obj = _MITRE_BY_ATTACK_ID.get(att_id)
        if not obj:
            continue
        matched_stix.add(obj["id"])
        tactics = [p["phase_name"] for p in obj.get("kill_chain_phases", [])]
        techniques.append({
            "attack_id": att_id,
            "name": obj.get("name", ""),
            "tactics": tactics,
            "description": obj.get("description", "")[:300],
        })

    # Find threat groups using ≥2 of the matched techniques
    groups: list[dict] = []
    for group_stix_id, tech_stix_ids in _MITRE_GROUP_TECH_MAP.items():
        overlap = matched_stix & set(tech_stix_ids)
        if len(overlap) < 2:
            continue
        group_obj = _MITRE_BY_STIX_ID.get(group_stix_id, {})
        ext_id = next(
            (r.get("external_id") for r in group_obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"), ""
        )
        overlap_names = []
        for sid in overlap:
            t = _MITRE_BY_STIX_ID.get(sid, {})
            aid = next((r.get("external_id") for r in t.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), "")
            if aid:
                overlap_names.append(aid)
        groups.append({
            "group_id": ext_id,
            "name": group_obj.get("name", ""),
            "aliases": group_obj.get("aliases", []),
            "description": group_obj.get("description", "")[:300],
            "matching_techniques": sorted(overlap_names),
            "overlap_count": len(overlap),
        })
    groups.sort(key=lambda g: g["overlap_count"], reverse=True)
    top_groups = groups[:10]

    print(f"  [MITRE] {len(techniques)} techniques, {len(top_groups)} candidate threat groups")
    for g in top_groups[:3]:
        print(f"    → {g['name']} ({g['group_id']}): {g['overlap_count']} overlapping techniques")

    enrichment = {
        "matched_techniques": techniques,
        "candidate_threat_groups": top_groups,
        "technique_ids": matched_ids,
    }
    messages = list(state.get("messages", []))
    messages.append(HumanMessage(content=(
        f"[MITRE] Enrichment complete: {len(techniques)} techniques, "
        f"{len(top_groups)} candidate groups."
    )))
    return {
        **state,
        "mitre_enrichment": enrichment,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["mitre_enrichment"],
    }


# ──────────────────────────────────────────────────────────────────────────────
# PDF export helper
# ──────────────────────────────────────────────────────────────────────────────

def _save_pdf(path: Path, content: str) -> None:
    """Render Markdown report to PDF using reportlab platypus."""
    import re as _re
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, HRFlowable

    path.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(str(path), pagesize=A4,
                            leftMargin=2*cm, rightMargin=2*cm,
                            topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle('H1', parent=styles['Heading1'], fontSize=18, spaceAfter=12, spaceBefore=20)
    h2 = ParagraphStyle('H2', parent=styles['Heading2'], fontSize=14, spaceAfter=8, spaceBefore=16)
    h3 = ParagraphStyle('H3', parent=styles['Heading3'], fontSize=12, spaceAfter=6, spaceBefore=12)
    body = ParagraphStyle('Body', parent=styles['Normal'], fontSize=10, spaceAfter=6, leading=14)
    bullet = ParagraphStyle('Bullet', parent=body, leftIndent=20, spaceAfter=3)
    code = ParagraphStyle('Code', parent=styles['Code'], fontSize=8, leftIndent=20, spaceAfter=6)

    def esc(t: str) -> str:
        return t.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

    def fmt(t: str) -> str:
        t = _re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', t)
        t = _re.sub(r'\*(.+?)\*', r'<i>\1</i>', t)
        t = _re.sub(r'`(.+?)`', r'<font name="Courier">\1</font>', t)
        return t

    story: list = []
    in_code = False
    code_lines: list[str] = []

    for line in content.splitlines():
        if line.strip().startswith('```'):
            if in_code:
                if code_lines:
                    story.append(Paragraph(esc('\n'.join(code_lines)), code))
                code_lines = []
            in_code = not in_code
            continue
        if in_code:
            code_lines.append(line)
            continue
        s = line.strip()
        if not s:
            story.append(Spacer(1, 6))
        elif s.startswith('# '):
            story.append(Paragraph(esc(s[2:]), h1))
            story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#333333')))
        elif s.startswith('## '):
            story.append(Paragraph(esc(s[3:]), h2))
        elif s.startswith('### '):
            story.append(Paragraph(esc(s[4:]), h3))
        elif s.startswith(('- ', '* ', '+ ')):
            story.append(Paragraph('• ' + fmt(esc(s[2:])), bullet))
        elif s.startswith('|'):
            if _re.match(r'^[\s|:\-]+$', s):
                continue
            story.append(Paragraph(esc(s.replace('|', ' | ').strip()), code))
        elif s.startswith('---') or s.startswith('==='):
            story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#aaaaaa')))
        else:
            story.append(Paragraph(fmt(esc(s)), body))

    doc.build(story)


# ──────────────────────────────────────────────────────────────────────────────
# Report writing node
# ──────────────────────────────────────────────────────────────────────────────

_REPORT_SYSTEM_PROMPT = """\
You are a senior incident response report writer for an SC4063-style network forensics case.

Core requirements:
- Produce a complete report with the exact sections below in this order:
  1) Title/Cover Page
  2) Table of Contents
  3) Executive Summary (C-suite audience: root cause, business impact, recommendations)
  4) Detailed Findings
  5) Conclusion and Recommendations (prioritized High/Medium/Low)
  6) Appendix - Timeline
  7) Appendix - Additional Technical Details
  8) Evidence Gaps

Detailed Findings requirements:
- Map observations to MITRE ATT&CK tactics, techniques, and sub-techniques.
  Use the provided MITRE enrichment data for accurate technique IDs and names.
- Cover at minimum: Initial Access, Lateral Movement and Discovery, Exfiltration, Payload.
- For each candidate threat group, assess likelihood based on technique overlap.
- Explicitly identify assumptions, confidence level, and scope limits.
- Include tools used by adversary and analyst where evidence supports it.

Evidence and anti-hallucination rules:
- Every significant claim must include supporting evidence references.
- Prefer concrete references: 5-tuples, host/user identifiers, timestamps, log sources.
- If evidence is missing, write "Insufficient evidence" rather than guessing.
- Never fabricate packet IDs, hashes, users, hosts, ATT&CK IDs, or timestamps.

Exfiltration specifics to check when present:
- Outbound spikes to file-sharing services (especially temp.sh)
- Large HTTP POST transfers
- Compression indicators (e.g., 7-Zip magic bytes)

Initial access and movement specifics to check when present:
- External source into RDP/VPN followed by changed traffic behavior
- Noisy scans over SMB/RPC (ports 445/135)
- DCERPC patterns suggesting user/group modifications
- Potential RDP-based payload drop after domain controller control

Writing style:
- Professional and concise. Use markdown headings and tables when useful.
- Separate facts from analyst interpretation.
- Keep recommendations actionable and prioritized.

CRITICAL Markdown formatting rules:
- Table cells MUST be single-line. NEVER put line breaks, bullet points, or
  multi-line content inside a table cell. If a cell needs multiple items,
  separate them with semicolons or commas on ONE line.
  WRONG: | Evidence |\n| - item1\n- item2 |
  RIGHT: | Evidence |\n| item1; item2; item3 |
- Each table row must be exactly ONE line of text.
- Use the correct number of column separators (|) — every row must have the
  same number of | characters as the header row.
- For detailed evidence that doesn't fit in a table, use a bullet list BELOW
  the table under a "Supporting Evidence:" sub-heading instead.

Return ONLY the Markdown report. No preamble, no JSON wrapping.\
"""


def report_writing_node(state: PipelineState) -> dict[str, Any]:
    """Synthesises all agent findings + MITRE enrichment into a report, saved as PDF."""
    day = state.get("target_day", "unknown")
    ia = get_initial_access(state)
    lm = get_lateral_movement(state)
    ex = get_exfiltration(state)
    pa = get_payload(state)
    iocs = merge_all_iocs(state)
    ctx = state.get("attack_context", {})
    mitre = state.get("mitre_enrichment", {})

    report_prompt = f"""{_REPORT_SYSTEM_PROMPT}

---
DAY: {day}

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

MITRE ATT&CK ENRICHMENT — Matched Techniques:
{json.dumps(mitre.get('matched_techniques', []), indent=2, default=str)}

MITRE ATT&CK ENRICHMENT — Candidate Threat Groups:
{json.dumps(mitre.get('candidate_threat_groups', []), indent=2, default=str)}

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
        max_tokens=16000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

    # Append provenance appendix if tracking is enabled
    prov = get_provenance()
    if prov and prov.enabled:
        report_content += "\n\n" + prov.to_markdown()

    # Save both to project directory under reports/<run_id>/
    run_id = state.get("run_id", "unknown")
    run_dir = _REPO_ROOT / "reports" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    md_path = run_dir / f"incident_report_{day}.md"
    md_path.write_text(report_content, encoding="utf-8")

    pdf_path = run_dir / f"incident_report_{day}.pdf"
    _save_pdf(pdf_path, report_content)

    print(f"\n  ✓ Markdown → {md_path}")
    print(f"  ✓ PDF      → {pdf_path}")
    print(f"  Length: {len(report_content):,} chars")

    messages = list(state.get("messages", []))
    messages.append(
        HumanMessage(content=f"[ReportWriter] Report generated ({len(report_content):,} chars). PDF → {pdf_path}")
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

def write_combined_report(
    all_day_results: list[dict],
    work_dir: str,
    run_id: str = "unknown",
) -> str:
    """
    Call the LLM once with findings from all days to produce a single
    consolidated incident report. Saves both Markdown and PDF.
    """
    days = [r["day"] for r in all_day_results]
    date_range = f"{days[0]} to {days[-1]}" if len(days) > 1 else days[0]

    sections: list[str] = []
    all_iocs: list[dict] = []
    all_mitre_techniques: list[dict] = []
    all_mitre_groups: list[dict] = []
    seen_ioc_keys: set[tuple] = set()
    seen_tech_ids: set[str] = set()
    seen_group_ids: set[str] = set()

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

        mitre = r.get("mitre_enrichment", {})
        for t in mitre.get("matched_techniques", []):
            if t.get("attack_id") not in seen_tech_ids:
                seen_tech_ids.add(t["attack_id"])
                all_mitre_techniques.append(t)
        for g in mitre.get("candidate_threat_groups", []):
            if g.get("group_id") not in seen_group_ids:
                seen_group_ids.add(g["group_id"])
                all_mitre_groups.append(g)

    report_prompt = (
        _REPORT_SYSTEM_PROMPT
        + f"\n\n---\nMulti-day report covering: {date_range}\n"
        + "\n".join(sections)
        + f"\n\nMITRE ATT&CK — Matched Techniques ({len(all_mitre_techniques)}):\n"
        + json.dumps(all_mitre_techniques, indent=2, default=str)
        + f"\n\nMITRE ATT&CK — Candidate Threat Groups ({len(all_mitre_groups)}):\n"
        + json.dumps(all_mitre_groups[:10], indent=2, default=str)
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
        max_tokens=16000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

    # Append provenance appendix if tracking is enabled
    prov = get_provenance()
    if prov and prov.enabled:
        report_content += "\n\n" + prov.to_markdown()

    run_dir = _REPO_ROOT / "reports" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    md_path = run_dir / "combined_incident_report.md"
    md_path.write_text(report_content, encoding="utf-8")

    pdf_path = run_dir / "combined_incident_report.pdf"
    _save_pdf(pdf_path, report_content)

    print(f"\n  ✓ Markdown → {md_path}")
    print(f"  ✓ PDF      → {pdf_path}")

    return report_content


def _checkpoint_path(work_dir: str) -> Path:
    return Path(work_dir) / ".pipeline_checkpoint.json"


def _save_checkpoint(
    work_dir: str,
    scoring: dict,
    chosen_pcaps: list[dict],
    chosen_days: list[str],
    all_day_results: list[dict],
    all_logs: dict,
    *,
    drilldown_days: list[str] | None = None,
    sweep_done: bool = False,
):
    """Persist pipeline state so a crashed run can resume."""
    cp = {
        "scoring": scoring,
        "chosen_pcaps": chosen_pcaps,
        "chosen_days": chosen_days,
        "completed_days": [r["day"] for r in all_day_results],
        "all_day_results": all_day_results,
        "drilldown_days": drilldown_days or [],
        "sweep_done": sweep_done,
        "all_logs": all_logs,
    }
    # Also checkpoint provenance
    prov = get_provenance()
    if prov:
        cp["provenance"] = prov.to_dict()
    path = _checkpoint_path(work_dir)
    path.write_text(json.dumps(cp, indent=2, default=str), encoding="utf-8")
    print(f"  [checkpoint] Saved — {len(cp['completed_days'])} day(s) complete")


def _load_checkpoint(work_dir: str) -> dict | None:
    path = _checkpoint_path(work_dir)
    if not path.exists():
        return None
    try:
        cp = json.loads(path.read_text(encoding="utf-8"))
        if cp.get("completed_days"):
            print(f"  [checkpoint] Found — {len(cp['completed_days'])} day(s) already complete: "
                  f"{', '.join(cp['completed_days'])}")
        return cp
    except (json.JSONDecodeError, KeyError):
        return None



def _zeek_triage_initial_access(zeek_files: dict[str, str], day: str) -> dict:
    """
    Fast Zeek-based initial access triage — no LLM, no tshark.

    Scans Zeek RDP and connection logs to detect brute-force campaigns and
    identify the most likely successful login session (largest byte count).
    Returns a partial InitialAccessFindings dict.
    """
    import json
    from pathlib import Path
    from shared.ecs_compat import normalize_record

    RFC1918 = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
               "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
               "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.")

    def _is_internal(ip: str) -> bool:
        return any(ip.startswith(p) for p in RFC1918)

    rdp_path = zeek_files.get("zeek.rdp.ndjson")
    conn_path = zeek_files.get("zeek.connection.ndjson")

    brute_force_count = 0
    unique_sources: set[str] = set()
    patient_zero = None
    attacker_ip = None
    best_session_bytes = 0
    best_session_ts = ""

    # Scan RDP log for external connection count
    if rdp_path and Path(rdp_path).exists():
        with open(rdp_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = normalize_record(json.loads(line))
                except (json.JSONDecodeError, TypeError):
                    continue
                src = rec.get("id.orig_h", "")
                if src and not _is_internal(src):
                    brute_force_count += 1
                    unique_sources.add(src)

    # Scan connection log for largest RDP session (likely successful login)
    if conn_path and Path(conn_path).exists():
        with open(conn_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = normalize_record(json.loads(line))
                except (json.JSONDecodeError, TypeError):
                    continue
                if rec.get("id.resp_p") != 3389:
                    continue
                orig_bytes = int(rec.get("orig_bytes") or 0)
                resp_bytes = int(rec.get("resp_bytes") or 0)
                total = orig_bytes + resp_bytes
                if total > best_session_bytes:
                    best_session_bytes = total
                    attacker_ip = rec.get("id.orig_h", "")
                    patient_zero = rec.get("id.resp_h", "")
                    best_session_ts = rec.get("ts", "")

    # If best session attacker is internal, it might be lateral movement
    if attacker_ip and _is_internal(attacker_ip):
        attacker_ip = None

    summary = (
        f"[Zeek triage {day}] {brute_force_count} external RDP attempts from "
        f"{len(unique_sources)} unique IPs"
    )
    if best_session_bytes > 10000:
        summary += f"; largest session {best_session_bytes:,} bytes from {attacker_ip}"

    return {
        "summary": summary,
        "patient_zero": patient_zero,
        "attacker_ip": attacker_ip,
        "attack_vector": "brute force" if brute_force_count > 100 else None,
        "exposed_service": "RDP/3389" if brute_force_count > 0 else None,
        "brute_force_count": brute_force_count,
        "successful_session_bytes": best_session_bytes if best_session_bytes > 10000 else None,
        "session_start": best_session_ts,
        "report_markdown": summary,
    }


def _needs_pcap_drilldown(day_result: dict, day_alert_count: int) -> tuple[bool, str]:
    """
    Determine if a day needs PCAP drill-down based on Zeek sweep findings.
    Errs on the side of caution — drills down if ANYTHING looks suspicious.
    """
    reasons: list[str] = []

    ia = day_result.get("initial_access_findings", {})
    lm = day_result.get("lateral_movement_findings", {})
    ex = day_result.get("exfiltration_findings", {})

    if ia.get("successful_session_bytes") and ia["successful_session_bytes"] > 10000:
        reasons.append(f"successful RDP session ({ia['successful_session_bytes']:,} bytes)")

    if ia.get("brute_force_count", 0) > 1000:
        reasons.append(f"heavy brute-force ({ia['brute_force_count']:,} attempts)")

    lm_observed = lm.get("observed", [])
    lm_hosts = lm.get("compromised_hosts", [])
    if lm_observed or lm_hosts:
        reasons.append(f"lateral movement detected ({len(lm_hosts)} hosts)")

    if ex.get("detected"):
        reasons.append("exfiltration detected")

    if day_alert_count > 50:
        reasons.append(f"{day_alert_count} alerts")

    if reasons:
        return True, "; ".join(reasons)
    return False, "no significant findings"


def run_all_days_pipeline(
    pipeline: Any,
    work_dir: str,
) -> list[dict]:
    """
    Two-pass architecture: Zeek sweep → targeted PCAP drill-down.

    Pass 1 (Zeek Sweep): Download Zeek + alerts for ALL days. Run
        lateral_movement + exfiltration (Zeek-based) plus a fast Zeek
        initial access triage.  No PCAPs downloaded — fast and lossless.

    Pass 2 (PCAP Drill-down): For days flagged as suspicious by Pass 1,
        download 1 PCAP and run initial_access (tshark) + payload agents.

    Every day is checked.  No day is skipped.  PCAPs are only downloaded
    when Zeek + alerts indicate something worth investigating deeper.

    Sliding window: at most 1 day's Zeek + 1 PCAP on disk at a time.
    """
    from shared.data_contract import ZeekContext

    # ── Check for existing checkpoint ─────────────────────────────────────
    checkpoint = _load_checkpoint(work_dir)

    if checkpoint and checkpoint.get("completed_days"):
        scoring = checkpoint["scoring"]
        all_day_results = checkpoint["all_day_results"]
        all_logs = checkpoint.get("all_logs", {})
        completed_set = set(checkpoint["completed_days"])
        drilldown_days = checkpoint.get("drilldown_days", [])
        sweep_done = checkpoint.get("sweep_done", False)

        prov = get_provenance()
        if prov and checkpoint.get("provenance"):
            from shared.disk_manager import ProvenanceLog
            restored = ProvenanceLog.from_dict(checkpoint["provenance"])
            prov.pcaps = restored.pcaps
            prov.zeek_files = restored.zeek_files
            prov.agent_sources = restored.agent_sources
            prov.days_analysed = restored.days_analysed

        suspect_ips = scoring.get("suspect_ips", [])
        all_days = sorted(all_logs.keys())

        print(f"\n{'═' * 60}")
        print(f"  Resuming from checkpoint — {len(completed_set)} day(s) done, sweep_done={sweep_done}")
        print(f"{'═' * 60}")

    else:
        completed_set = set()
        all_day_results = []
        drilldown_days = []
        sweep_done = False

        # ── Phase 1: Download alerts (lightweight) ───────────────────────
        all_logs = ingest_all_alerts(work_dir=work_dir)

        # ── Phase 2: Score alerts ────────────────────────────────────────
        print(f"\n{'═' * 60}")
        print(f"  Phase 2: Scoring alerts across {len(all_logs)} days")
        print(f"{'═' * 60}")
        scoring = score_alerts(all_logs)

        suspect_ips = scoring.get("suspect_ips", [])
        print(f"\n  Top suspect IPs:")
        for s in suspect_ips[:5]:
            print(f"    {s['ip']:20s}  score={s['score']:6d}  "
                  f"({s['alert_count']} alerts)  {s['top_signatures'][0][:60]}")

        all_days = sorted(all_logs.keys())

    # ══════════════════════════════════════════════════════════════════════
    # PASS 1: ZEEK SWEEP — all days, no PCAPs
    # ══════════════════════════════════════════════════════════════════════

    if not sweep_done:
        print(f"\n{'═' * 60}")
        print(f"  Pass 1: Zeek Sweep — analysing {len(all_days)} days (no PCAPs)")
        print(f"{'═' * 60}")

        # Accumulate attack context across days for chronological correlation
        rolling_attack_ctx: dict[str, Any] = {}

        for i, day in enumerate(all_days):
            sweep_tag = f"sweep:{day}"
            if sweep_tag in completed_set:
                for r in all_day_results:
                    if r["day"] == day:
                        rolling_attack_ctx.update(r.get("attack_context", {}))
                print(f"\n  [{i+1}/{len(all_days)}] {day}: already swept (checkpoint)")
                continue

            print(f"\n{'─' * 60}")
            print(f"  [{i+1}/{len(all_days)}] {day}: Zeek sweep")
            print(f"{'─' * 60}")

            # ── Evict previous day's data ────────────────────────────────
            dm = get_disk_manager()
            if dm:
                dm.evict_to_budget()

            # ── Download Zeek logs only ──────────────────────────────────
            zeek_by_day = download_zeek_for_days([day], work_dir=work_dir)
            zeek_files = zeek_by_day.get(day, {})
            all_logs[day]["zeek_files"] = zeek_files

            dm = get_disk_manager()
            if dm:
                dm.evict_to_budget()
                dm.print_status()

            if not zeek_files:
                print(f"  [!] No Zeek files for {day} — skipping")
                continue

            ctx = ZeekContext(
                day=day,
                pcap_path="",
                alerts_path=all_logs[day].get("alerts_path"),
                zeek_files=zeek_files,
            )

            state = initial_pipeline_state(target_day=day, work_dir=work_dir)
            state.update(set_zeek_context(state, ctx))
            state["pcap_file"] = ""
            state["alert_scoring"] = scoring
            state["attack_context"] = dict(rolling_attack_ctx)

            # ── Zeek triage: fast initial access detection ───────────────
            print(f"  [IA triage] Scanning Zeek RDP + conn logs…")
            ia_findings = _zeek_triage_initial_access(zeek_files, day)
            state["initial_access_findings"] = ia_findings

            if ia_findings.get("patient_zero"):
                state["attack_context"]["patient_zero"] = ia_findings["patient_zero"]
            if ia_findings.get("attacker_ip"):
                state["attack_context"].setdefault("attacker_ips", [])
                if ia_findings["attacker_ip"] not in state["attack_context"]["attacker_ips"]:
                    state["attack_context"]["attacker_ips"].append(ia_findings["attacker_ip"])

            print(f"    {ia_findings['summary']}")

            # ── Run lateral_movement agent (Zeek-based) ──────────────────
            print(f"  [LM] Running lateral movement agent…")
            lm_result = lateral_movement_agent_node(state)
            state.update(lm_result)

            # ── Run exfiltration agent (Zeek-based) ──────────────────────
            print(f"  [Exfil] Running exfiltration agent…")
            exfil_result = exfiltration_agent_node(state)
            state.update(exfil_result)

            # ── Run payload agent (Zeek-based) ───────────────────────────
            print(f"  [Payload] Running payload agent…")
            payload_result = payload_agent_node(state)
            state.update(payload_result)

            # ── MITRE enrichment ─────────────────────────────────────────
            mitre_result = mitre_enrichment_node(state)
            state.update(mitre_result)

            # ── Update rolling attack context ────────────────────────────
            rolling_attack_ctx.update(state.get("attack_context", {}))

            # ── Collect results ──────────────────────────────────────────
            agent_zeek_ctx = state.get("zeek_context", {})

            day_result = {
                "day": day,
                "pass": "zeek_sweep",
                "attack_context":             state.get("attack_context", {}),
                "initial_access_findings":    state.get("initial_access_findings", {}),
                "lateral_movement_findings":  state.get("lateral_movement_findings", {}),
                "exfiltration_findings":      state.get("exfiltration_findings", {}),
                "payload_findings":           state.get("payload_findings", {}),
                "mitre_enrichment":           state.get("mitre_enrichment", {}),
                "iocs":                       merge_all_iocs(state),
                "pcap_files":                 [],
                "alert_scoring_summary": {
                    "suspect_ips": suspect_ips[:5],
                    "day_alerts": scoring.get("per_day", {}).get(day, {}).get("total_alerts", 0),
                },
                "data_diagnostics": {
                    "zeek_context": agent_zeek_ctx,
                    "pcap_file_used": "",
                    "pcap_file_existed": False,
                },
            }
            all_day_results.append(day_result)
            completed_set.add(sweep_tag)

            # ── Determine drill-down ─────────────────────────────────────
            day_alerts = scoring.get("per_day", {}).get(day, {}).get("total_alerts", 0)
            needs_drill, reason = _needs_pcap_drilldown(day_result, day_alerts)
            if needs_drill:
                drilldown_days.append(day)
                print(f"  [→ PCAP drill-down needed: {reason}]")
            else:
                print(f"  [→ No PCAP drill-down needed: {reason}]")

            # ── Provenance ───────────────────────────────────────────────
            prov = get_provenance()
            if prov:
                prov.record_day_analysed(day)
                prov.record_zeek_files(day, list(zeek_files.keys()))
                prov.record_agent_access(day, "lateral_movement", list(zeek_files.values()))
                prov.record_agent_access(day, "exfiltration", list(zeek_files.values()))

            # ── Release Zeek for this day ────────────────────────────────
            dm = get_disk_manager()
            if dm:
                dm.release_day(day, artifact_types=[ALERT, ZEEK])
                dm.evict_to_budget()

            # ── Checkpoint ───────────────────────────────────────────────
            _save_checkpoint(
                work_dir, scoring, [], all_days,
                all_day_results, all_logs,
                drilldown_days=drilldown_days, sweep_done=False,
            )

        sweep_done = True
        print(f"\n{'═' * 60}")
        print(f"  Pass 1 complete: {len(all_days)} days swept")
        print(f"  Drill-down needed: {len(drilldown_days)} days → {drilldown_days}")
        print(f"{'═' * 60}")

        _save_checkpoint(
            work_dir, scoring, [], all_days,
            all_day_results, all_logs,
            drilldown_days=drilldown_days, sweep_done=True,
        )

    # ══════════════════════════════════════════════════════════════════════
    # PASS 2: PCAP DRILL-DOWN — targeted days only
    # ══════════════════════════════════════════════════════════════════════

    if drilldown_days:
        print(f"\n{'═' * 60}")
        print(f"  Pass 2: PCAP Drill-down — {len(drilldown_days)} days")
        print(f"{'═' * 60}")

        ranked_pcaps = score_all_pcaps(scoring)
        best_pcap_per_day: dict[str, dict] = {}
        for p in ranked_pcaps:
            if p["day"] not in best_pcap_per_day:
                best_pcap_per_day[p["day"]] = p

        for i, day in enumerate(drilldown_days):
            drill_tag = f"drill:{day}"
            if drill_tag in completed_set:
                print(f"\n  [{i+1}/{len(drilldown_days)}] {day}: drill-down already complete")
                continue

            day_idx = next(
                (j for j, r in enumerate(all_day_results) if r["day"] == day), None
            )
            if day_idx is None:
                continue

            print(f"\n{'─' * 60}")
            print(f"  [{i+1}/{len(drilldown_days)}] {day}: PCAP drill-down")
            print(f"{'─' * 60}")

            dm = get_disk_manager()
            if dm:
                dm.evict_to_budget()

            # ── Download best PCAP for this day ──────────────────────────
            pcap_entry = best_pcap_per_day.get(day)
            if not pcap_entry:
                print(f"  [!] No ranked PCAP for {day} — skipping drill-down")
                continue

            day_pcap_paths = download_selected_pcaps([pcap_entry], work_dir=work_dir)
            day_pcaps = day_pcap_paths.get(day, [])
            if not day_pcaps:
                print(f"  [!] PCAP download failed for {day} — skipping")
                continue

            primary_pcap = day_pcaps[0]

            # ── Re-download Zeek for initial_access seed queries ─────────
            zeek_by_day = download_zeek_for_days([day], work_dir=work_dir)
            zeek_files = zeek_by_day.get(day, {})

            dm = get_disk_manager()
            if dm:
                dm.evict_to_budget()

            # ── Build state from Pass 1 results ──────────────────────────
            existing = all_day_results[day_idx]
            ctx = ZeekContext(
                day=day,
                pcap_path=primary_pcap,
                alerts_path=all_logs.get(day, {}).get("alerts_path"),
                zeek_files=zeek_files,
            )

            state = initial_pipeline_state(target_day=day, work_dir=work_dir)
            state.update(set_zeek_context(state, ctx))
            state["pcap_file"] = primary_pcap
            state["pcap_files"] = day_pcaps
            state["alert_scoring"] = scoring
            state["attack_context"] = existing.get("attack_context", {})
            state["lateral_movement_findings"] = existing.get("lateral_movement_findings", {})
            state["exfiltration_findings"] = existing.get("exfiltration_findings", {})
            state["completed_agents"] = ["ingest"]

            # ── Run initial_access with PCAP (full tshark agent) ─────────
            print(f"  [IA] Running initial access with PCAP…")
            ia_result = initial_access_agent_node(state)
            state.update(ia_result)

            # ── Run payload agent with PCAP ──────────────────────────────
            print(f"  [Payload] Running payload agent…")
            payload_result = payload_agent_node(state)
            state.update(payload_result)

            # ── Re-run MITRE with combined findings ──────────────────────
            mitre_result = mitre_enrichment_node(state)
            state.update(mitre_result)

            # ── Merge drill-down results into existing day entry ─────────
            all_day_results[day_idx]["initial_access_findings"] = state.get("initial_access_findings", {})
            all_day_results[day_idx]["payload_findings"] = state.get("payload_findings", {})
            all_day_results[day_idx]["mitre_enrichment"] = state.get("mitre_enrichment", {})
            all_day_results[day_idx]["attack_context"] = state.get("attack_context", {})
            all_day_results[day_idx]["iocs"] = merge_all_iocs(state)
            all_day_results[day_idx]["pcap_files"] = day_pcaps
            all_day_results[day_idx]["pass"] = "drilldown_done"
            all_day_results[day_idx]["data_diagnostics"]["pcap_file_used"] = primary_pcap
            all_day_results[day_idx]["data_diagnostics"]["pcap_file_existed"] = Path(primary_pcap).exists()
            completed_set.add(drill_tag)

            # ── Provenance ───────────────────────────────────────────────
            prov = get_provenance()
            if prov:
                prov.record_pcap(
                    day, Path(primary_pcap).name, primary_pcap,
                    pcap_entry.get("size_mb", 0) * 1e6,
                )
                prov.record_agent_access(day, "initial_access", [primary_pcap])
                prov.record_agent_access(day, "payload", [primary_pcap])

            # ── Release PCAP + Zeek immediately ──────────────────────────
            dm = get_disk_manager()
            if dm:
                dm.release_day(day, artifact_types=[PCAP, ZEEK, ALERT])
                dm.evict_to_budget()
                dm.print_status()

            # ── Checkpoint ───────────────────────────────────────────────
            _save_checkpoint(
                work_dir, scoring, [], all_days,
                all_day_results, all_logs,
                drilldown_days=drilldown_days, sweep_done=True,
            )

    return all_day_results



# ──────────────────────────────────────────────────────────────────────────────
# Graph assembly
# ──────────────────────────────────────────────────────────────────────────────

def build_pipeline(skip_report: bool = False) -> Any:
    """
    Compile the master LangGraph pipeline.

    skip_report=True: still runs MITRE enrichment but omits report_writing.
    Used when running --all-days so we only write one combined report at
    the end instead of nine individual ones.
    """
    workflow = StateGraph(PipelineState)

    # Nodes
    workflow.add_node("ingest", ingest_node)
    workflow.add_node("supervisor", supervisor_node)
    workflow.add_node("initial_access", initial_access_agent_node)
    workflow.add_node("lateral_movement", lateral_movement_agent_node)
    workflow.add_node("exfiltration", exfiltration_agent_node)
    workflow.add_node("payload", payload_agent_node)
    workflow.add_node("mitre_enrichment", mitre_enrichment_node)

    if not skip_report:
        workflow.add_node("report_writing", report_writing_node)

    # Entry: always start with ingestion
    workflow.set_entry_point("ingest")

    # ingest → supervisor
    workflow.add_edge("ingest", "supervisor")

    # supervisor → agents or mitre_enrichment (when all agents done)
    workflow.add_conditional_edges(
        "supervisor",
        route_from_supervisor,
        {
            "initial_access":    "initial_access",
            "lateral_movement":  "lateral_movement",
            "exfiltration":      "exfiltration",
            "payload":           "payload",
            "mitre_enrichment":  "mitre_enrichment",
        },
    )

    # Each agent loops back to supervisor
    for agent in _AGENT_ORDER:
        workflow.add_edge(agent, "supervisor")

    # mitre_enrichment → report_writing or END
    if skip_report:
        workflow.add_edge("mitre_enrichment", END)
    else:
        workflow.add_edge("mitre_enrichment", "report_writing")
        workflow.add_edge("report_writing", END)

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
        "--work-dir", default=str(_REPO_ROOT / "data"),
        help="Directory for downloads and outputs (default: ./data)",
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
    parser.add_argument(
        "--no-provenance", action="store_true",
        help="Disable PCAP/Zeek provenance tracking in the report.",
    )
    parser.add_argument(
        "--disk-soft-gb", type=float, default=5.0,
        help="Soft disk budget in GB (default: 5). Best-effort target.",
    )
    parser.add_argument(
        "--disk-hard-gb", type=float, default=8.0,
        help="Hard disk budget in GB (default: 8). Warns if exceeded.",
    )
    args = parser.parse_args()

    t_start = time.time()

    # ── Initialise disk budget manager + provenance ──────────────────────
    _gb = 1 << 30
    init_disk_manager(
        args.work_dir,
        soft_limit=int(args.disk_soft_gb * _gb),
        hard_limit=int(args.disk_hard_gb * _gb),
    )
    init_provenance(enabled=not args.no_provenance)

    # ── All-days mode (two-phase ingestion + HITL) ──────────────────────
    if args.all_days:
        print(f"\n{'=' * 60}")
        print(f"  SC4063 Security Analysis Pipeline — ALL DAYS")
        print(f"  Work dir: {args.work_dir}")
        print(f"{'=' * 60}\n")

        import uuid
        run_id = str(uuid.uuid4())[:8]

        print(f"  Run ID : {run_id}")

        # Build pipeline without per-day report writing
        pipeline = build_pipeline(skip_report=True)

        all_day_results = run_all_days_pipeline(pipeline, args.work_dir)

        combined_report = write_combined_report(
            all_day_results, args.work_dir, run_id=run_id
        )

        # ── Remove checkpoint on successful completion ────────────────────
        cp_path = _checkpoint_path(args.work_dir)
        if cp_path.exists():
            cp_path.unlink()
            print("  [checkpoint] Cleared — pipeline completed successfully")

        # ── Final disk cleanup: release everything except reports ─────────
        dm = get_disk_manager()
        if dm:
            dm.release_all()
            dm.evict_to_budget()
            print(f"  [disk] Final: {dm.usage_str()}")

        elapsed = time.time() - t_start
        run_dir = _REPO_ROOT / "reports" / run_id
        print(f"\n{'=' * 60}")
        print(f"  All-days pipeline complete in {elapsed:.0f}s")
        print(f"  Days processed : {len(all_day_results)}")
        print(f"  Reports        : {run_dir}")
        print(f"{'=' * 60}\n")
        print(combined_report[:3000])
        if len(combined_report) > 3000:
            print(f"\n  … [truncated — see {run_dir} for full report]")
        return

    # ── Single-day mode ───────────────────────────────────────────────────
    state = initial_pipeline_state(
        target_day=args.day,
        work_dir=args.work_dir,
    )

    # If a local PCAP is provided, skip ingestion
    if args.pcap:
        from shared.data_contract import ZeekContext
        pcap_abs = os.path.abspath(args.pcap)

        # Auto-discover Zeek files on disk next to the PCAP
        zeek_files: dict[str, str] = {}
        zeek_dir = Path(args.work_dir) / args.day / "zeek"
        if zeek_dir.is_dir():
            for f in zeek_dir.iterdir():
                if f.suffix in (".ndjson", ".log") and f.stat().st_size > 0:
                    zeek_files[f.name] = str(f.resolve())
            if zeek_files:
                print(f"  [pcap-mode] Auto-discovered {len(zeek_files)} Zeek files "
                      f"in {zeek_dir}")

        # Auto-discover alerts
        alerts_path = Path(args.work_dir) / args.day / "alerts.ndjson"
        alerts_str = str(alerts_path) if alerts_path.exists() else None

        ctx = ZeekContext(
            day=args.day,
            pcap_path=pcap_abs,
            alerts_path=alerts_str,
            zeek_files=zeek_files,
        )
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
    _prev_completed: list[str] = list(state.get("completed_agents", []))
    for step_state in pipeline.stream(state):
        node_name = list(step_state.keys())[0]
        node_data = step_state[node_name]
        completed = node_data.get("completed_agents", [])
        print(f"\n  ✓ Step complete: {node_name}  |  completed: {completed}")

        # ── Record provenance for newly completed agents ──────────────
        prov = get_provenance()
        if prov:
            new_agents = [a for a in completed if a not in _prev_completed and a != "ingest"]
            zeek_ctx_d = node_data.get("zeek_context") or state.get("zeek_context") or {}
            pcap_file = node_data.get("pcap_file") or state.get("pcap_file", "")
            zeek_file_paths = list(zeek_ctx_d.get("zeek_files", {}).values())
            for agent in new_agents:
                if agent in ("initial_access", "payload"):
                    sources = [pcap_file] if pcap_file else []
                elif agent in ("lateral_movement", "exfiltration"):
                    sources = zeek_file_paths
                else:
                    sources = []
                if sources:
                    prov.record_agent_access(args.day, agent, sources)
            _prev_completed = list(completed)

        if "final_report" in node_data and node_data["final_report"]:
            final_state = node_data

    # ── Disk cleanup after single-day analysis ───────────────────────────
    dm = get_disk_manager()
    if dm:
        dm.release_all()
        dm.evict_to_budget()

    elapsed = time.time() - t_start

    print(f"\n{'=' * 60}")
    print(f"  Pipeline complete in {elapsed:.0f}s")
    print(f"{'=' * 60}\n")

    if final_state and final_state.get("final_report"):
        run_dir = _REPO_ROOT / "reports" / state["run_id"]
        print(f"  Reports: {run_dir}")
        print(f"\n{'─' * 60}")
        print(final_state["final_report"][:3000])
        if len(final_state["final_report"]) > 3000:
            print(f"\n  … [truncated — see {run_dir} for full report]")


if __name__ == "__main__":
    main()
