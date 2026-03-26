"""
agents/exfiltration_agent.py
=============================
Exfiltration detection agent for the SC4063 Security Analysis Pipeline.

Uses the original exfil package (exfil/) which analyses Zeek logs directly:
  - exfiltration_tool     : volume-based spike detection + beaconing
  - dns_exfiltration      : DNS tunneling detection
  - http_exfiltration     : HTTP upload detection
  - exfiltration_summarizer : LLM narrative with hallucination guard

A zeek_root adapter maps the NDJSON files downloaded by the ingest layer
(zeek.connection.ndjson, zeek.dns.ndjson, …) to the standard Zeek log
filenames expected by the analysis modules (conn.log, dns.log, …).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage

from shared.data_contract import (
    IOC,
    ExfiltrationFindings,
    PipelineState,
    get_zeek_context,
    set_exfiltration,
)

# ── NDJSON → standard Zeek log name mapping ───────────────────────────────────

_NDJSON_TO_LOG = {
    "zeek.connection.ndjson": "conn.log",
    "zeek.dns.ndjson":        "dns.log",
    "zeek.ssl.ndjson":        "ssl.log",
    "zeek.http.ndjson":       "http.log",
    "zeek.files.ndjson":      "files.log",
}


def _prepare_zeek_root(zeek_ctx, work_dir: str) -> str:
    """
    Create a directory containing standard Zeek log filenames as symlinks
    (or copies) pointing to the NDJSON files downloaded by the ingest layer.

    The exfil analysis modules expect conn.log, dns.log, ssl.log, http.log,
    files.log.  The pipeline stores them as zeek.connection.ndjson, etc.
    """
    zeek_compat = Path(work_dir) / "zeek_compat"
    zeek_compat.mkdir(parents=True, exist_ok=True)

    if not zeek_ctx:
        return str(zeek_compat)

    for ndjson_name, log_name in _NDJSON_TO_LOG.items():
        src = zeek_ctx.zeek_files.get(ndjson_name)
        if not src or not Path(src).exists():
            continue
        dst = zeek_compat / log_name
        if dst.exists():
            continue
        try:
            os.symlink(str(Path(src).resolve()), str(dst))
        except OSError:
            import shutil as _shutil
            _shutil.copy2(src, dst)

    return str(zeek_compat)


# ── Findings builder ──────────────────────────────────────────────────────────

def _build_exfiltration_findings(pipeline_result: dict) -> ExfiltrationFindings:
    """Map run_exfiltration_pipeline output to ExfiltrationFindings."""
    findings = ExfiltrationFindings()

    if pipeline_result.get("error") and not pipeline_result.get("combined_suspected"):
        findings.summary = pipeline_result["error"]
        return findings

    exfil_r = pipeline_result.get("exfil_analysis") or {}
    dns_r   = pipeline_result.get("dns_analysis")   or {}
    http_r  = pipeline_result.get("http_analysis")  or {}
    llm_r   = pipeline_result.get("llm_summary")    or {}

    findings.detected   = bool(pipeline_result.get("combined_suspected"))
    findings.confidence = pipeline_result.get("combined_confidence", "LOW")

    # Summary from LLM narrative
    narrative = llm_r.get("narrative", {})
    if isinstance(narrative, dict):
        findings.summary = narrative.get("executive_summary", "")
    if not findings.summary:
        findings.summary = (
            f"Suspected: {findings.detected}, Confidence: {findings.confidence}"
        )

    # Destination IPs / domains
    dest_set: set[str] = set()
    for row in exfil_r.get("suspicious_only_evidence", []):
        ip = row.get("external_ip")
        if ip:
            dest_set.add(ip)
    for row in dns_r.get("suspicious_only_evidence", []):
        dom = row.get("base_domain")
        if dom:
            dest_set.add(dom)
    for row in http_r.get("suspicious_only_evidence", []):
        host = row.get("upload_host") or row.get("external_ip")
        if host:
            dest_set.add(host)
    findings.destination_ips = list(dest_set)

    # Protocols used
    proto_set: set[str] = set()
    for t in pipeline_result.get("all_mitre_techniques", []):
        proto_set.add(t.get("name", ""))
    findings.protocols_used = [p for p in proto_set if p]

    # Markdown report
    llm_text = (
        json.dumps(narrative, indent=2)
        if isinstance(narrative, dict) and narrative
        else ""
    )
    findings.report_markdown = llm_text or f"Exfiltration analysis: {findings.summary}"

    # IOCs
    for dest in findings.destination_ips:
        ioc_type = "ip" if ("." in dest and dest.replace(".", "").isdigit()) else "domain"
        findings.iocs.append(IOC(
            ioc_type=ioc_type,
            value=dest,
            source_agent="exfiltration",
            confidence="medium",
            notes="Identified as exfiltration destination",
        ))

    return findings


# ── Pipeline node ─────────────────────────────────────────────────────────────

def exfiltration_agent_node(state: PipelineState) -> dict[str, Any]:
    """
    LangGraph node — runs the original exfiltration pipeline and writes
    ExfiltrationFindings back into PipelineState.
    """
    from exfil.exfiltration_pipeline_runner import run_exfiltration_pipeline

    pcap_path = state.get("pcap_file", "")
    zeek_ctx  = get_zeek_context(state)
    if not pcap_path and zeek_ctx:
        pcap_path = zeek_ctx.pcap_path

    work_dir  = state.get("work_dir", "data")
    zeek_root = _prepare_zeek_root(zeek_ctx, work_dir)

    print("\n" + "─" * 60)
    print("  [Exfiltration] Starting analysis…")
    print(f"  zeek_root : {zeek_root}")
    files_found = [f for f in Path(zeek_root).iterdir()] if Path(zeek_root).exists() else []
    print(f"  log files : {[f.name for f in files_found]}")
    print("─" * 60)

    pipeline_result = run_exfiltration_pipeline(
        zeek_root=zeek_root,
        run_llm_summary=True,
        llm_provider="azure",
    )

    findings = _build_exfiltration_findings(pipeline_result)

    canonical = set_exfiltration(state, findings)
    messages  = list(state.get("messages", []))
    messages.append(HumanMessage(content=(
        f"[ExfiltrationAgent] Analysis complete.\n"
        f"Detected: {findings.detected}\n"
        f"Confidence: {findings.confidence}\n"
        f"Summary: {(findings.summary or '')[:300]}"
    )))

    return {
        **state,
        **canonical,
        "messages": messages,
        "completed_agents": list(state.get("completed_agents", [])) + ["exfiltration"],
    }
