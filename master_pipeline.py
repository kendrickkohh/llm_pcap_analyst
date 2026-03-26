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
    ingest_all_logs,
    score_alerts,
    score_all_pcaps,
    download_selected_pcaps,
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
    """
    day = state["target_day"]
    work_dir = state.get("work_dir", "data")

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
        max_tokens=6000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

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
        max_tokens=8000,
    )
    response = report_llm.invoke([HumanMessage(content=report_prompt)])
    report_content = response.content

    run_dir = _REPO_ROOT / "reports" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    md_path = run_dir / "combined_incident_report.md"
    md_path.write_text(report_content, encoding="utf-8")

    pdf_path = run_dir / "combined_incident_report.pdf"
    _save_pdf(pdf_path, report_content)

    print(f"\n  ✓ Markdown → {md_path}")
    print(f"  ✓ PDF      → {pdf_path}")

    return report_content


def run_all_days_pipeline(
    pipeline: Any,
    work_dir: str,
) -> list[dict]:
    """
    Two-phase ingestion + human-in-the-loop PCAP selection + per-day analysis:

    Phase 1: Download Zeek + Suricata logs for all days (lightweight)
    Phase 2: Score alerts across all days, rank all PCAPs globally
    HITL:    Present ranked PCAPs to user, user picks how many to ingest
    Phase 3: Download chosen PCAPs
    Phase 4: Run agent pipeline per day with pre-downloaded data

    Returns accumulated per-day findings for the final combined report.
    """
    from shared.data_contract import ZeekContext

    # ── Phase 1: Download all logs ────────────────────────────────────────
    all_logs = ingest_all_logs(work_dir=work_dir)

    # ── Phase 2: Score alerts across all days ─────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  Phase 2: Scoring alerts across {len(all_logs)} days")
    print(f"{'═' * 60}")
    scoring = score_alerts(all_logs)

    suspect_ips = scoring.get("suspect_ips", [])
    print(f"\n  Top suspect IPs:")
    for s in suspect_ips[:5]:
        print(f"    {s['ip']:20s}  score={s['score']:6d}  "
              f"({s['alert_count']} alerts)  {s['top_signatures'][0][:60]}")

    # ── Phase 2b: Rank all PCAPs globally ─────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  Phase 2b: Scoring all PCAPs across all days")
    print(f"{'═' * 60}")
    ranked_pcaps = score_all_pcaps(scoring)

    if not ranked_pcaps:
        raise RuntimeError("No PCAPs with suspect activity found across any day.")

    # ── HITL: Present ranked PCAPs to user ────────────────────────────────
    print(f"\n{'═' * 60}")
    print(f"  Ranked PCAPs by suspect alert density ({len(ranked_pcaps)} with activity)")
    print(f"{'═' * 60}")
    print(f"  {'Rank':<6}{'Day':<14}{'PCAP':<8}{'Score':<10}{'Size':<10}{'Name'}")
    print(f"  {'─'*6}{'─'*14}{'─'*8}{'─'*10}{'─'*10}{'─'*40}")
    for i, p in enumerate(ranked_pcaps):
        print(f"  {i+1:<6}{p['day']:<14}[{p['pcap_index']}]{'':<5}"
              f"{p['score']:<10}{p['size_mb']:<10.0f}{p['pcap_name'][:40]}")

    total_mb = sum(p["size_mb"] for p in ranked_pcaps)
    print(f"\n  Total if all selected: {len(ranked_pcaps)} PCAPs, {total_mb:.0f} MB")

    while True:
        user_input = input(f"\n  How many PCAPs to ingest? (1-{len(ranked_pcaps)}, or 'all'): ").strip()
        if user_input.lower() == "all":
            n_chosen = len(ranked_pcaps)
            break
        try:
            n_chosen = int(user_input)
            if 1 <= n_chosen <= len(ranked_pcaps):
                break
            print(f"  Please enter a number between 1 and {len(ranked_pcaps)}.")
        except ValueError:
            print(f"  Please enter a number or 'all'.")

    chosen_pcaps = ranked_pcaps[:n_chosen]
    chosen_mb = sum(p["size_mb"] for p in chosen_pcaps)
    chosen_days = sorted(set(p["day"] for p in chosen_pcaps))
    print(f"\n  → Selected top {n_chosen} PCAPs ({chosen_mb:.0f} MB) across {len(chosen_days)} days")

    # ── Phase 3: Download selected PCAPs ──────────────────────────────────
    pcap_paths = download_selected_pcaps(chosen_pcaps, work_dir=work_dir)

    # ── Phase 4: Run agent pipeline per day (only days with PCAPs) ───────
    all_day_results: list[dict] = []
    days = sorted(pcap_paths.keys())

    for i, day in enumerate(days):
        print(f"\n{'=' * 60}")
        print(f"  [Phase 4] Agent analysis: {day}  ({i+1}/{len(days)})")
        print(f"{'=' * 60}")

        day_pcaps = pcap_paths.get(day, [])
        day_logs = all_logs[day]

        if not day_pcaps:
            print(f"  [!] No PCAPs for {day} — skipping agent analysis")
            continue

        # Use the first selected PCAP as the primary (agents use pcap_file)
        primary_pcap = day_pcaps[0]

        # Build ZeekContext from pre-downloaded data
        ctx = ZeekContext(
            day=day,
            pcap_path=primary_pcap,
            alerts_path=day_logs.get("alerts_path"),
            zeek_files=day_logs.get("zeek_files", {}),
        )

        # Create state with pre-populated ingestion data
        state = initial_pipeline_state(target_day=day, work_dir=work_dir)
        state.update(set_zeek_context(state, ctx))
        state["pcap_file"] = primary_pcap
        state["pcap_files"] = day_pcaps
        state["alert_scoring"] = scoring
        state["completed_agents"] = ["ingest"]  # skip ingest node

        # Run the pipeline (ingest already done, starts at supervisor)
        final_day_state: dict[str, Any] = {}
        for step_state in pipeline.stream(state):
            node_name = list(step_state.keys())[0]
            node_data = step_state[node_name]
            completed = node_data.get("completed_agents", [])
            print(f"    ✓ {node_name}  |  completed: {completed}")
            final_day_state.update(node_data)

        all_day_results.append({
            "day": day,
            "attack_context":             final_day_state.get("attack_context", {}),
            "initial_access_findings":    final_day_state.get("initial_access_findings", {}),
            "lateral_movement_findings":  final_day_state.get("lateral_movement_findings", {}),
            "exfiltration_findings":      final_day_state.get("exfiltration_findings", {}),
            "payload_findings":           final_day_state.get("payload_findings", {}),
            "mitre_enrichment":           final_day_state.get("mitre_enrichment", {}),
            "iocs":                       merge_all_iocs(final_day_state),  # type: ignore[arg-type]
            "pcap_files":                 day_pcaps,
            "alert_scoring_summary": {
                "suspect_ips": suspect_ips[:5],
                "day_alerts": scoring.get("per_day", {}).get(day, {}).get("total_alerts", 0),
            },
        })

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
    args = parser.parse_args()

    t_start = time.time()

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
        run_dir = _REPO_ROOT / "reports" / state["run_id"]
        print(f"  Reports: {run_dir}")
        print(f"\n{'─' * 60}")
        print(final_state["final_report"][:3000])
        if len(final_state["final_report"]) > 3000:
            print(f"\n  … [truncated — see {run_dir} for full report]")


if __name__ == "__main__":
    main()
