# src/exfiltration_langchain_tools.py
"""
LangChain tool wrappers for the exfiltration module.

These tools are designed to be dropped directly into a LangChain agent
(ReAct, function-calling, etc.) as part of a larger forensic pipeline.

Available tools
---------------
pcap_to_zeek              Convert PCAP file(s) to Zeek JSON logs.
exfiltration_analyze      Detect volume-based exfiltration from Zeek logs.
dns_exfiltration_analyze  Detect DNS tunneling / covert exfiltration.
exfiltration_summarize    LLM narrative + MITRE mapping + hallucination guard.
exfiltration_pipeline     End-to-end: PCAP → Zeek → analysis → LLM summary.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from langchain_core.tools import tool

from exfil.pcap_ingestor import ingest_pcaps, check_zeek_available
from exfil.exfiltration_pipeline_runner import run_exfiltration_pipeline
from exfil.exfiltration_tool import analyze_exfiltration
from exfil.dns_exfiltration import analyze_dns_exfiltration
from exfil.http_exfiltration import analyze_http_exfiltration
from exfil.exfiltration_summarizer import summarize_exfiltration
from exfil.shard_api_client import DEFAULT_API_BASE_URL


# ---------------------------------------------------------------------------
# Tool 1: PCAP → Zeek
# ---------------------------------------------------------------------------

@tool
def pcap_to_zeek(
    pcap_paths: List[str],
    zeek_out: str = "zeek_out",
    merge_first: bool = True,
    timeout_seconds: int = 600,
) -> Dict[str, Any]:
    """
    Convert one or more PCAP / PCAPNG files into Zeek JSON log files.

    Requires Zeek to be installed and available in PATH.
    Outputs conn.log, ssl.log, dns.log (and others) under zeek_out/<chunk_NNNN>/.

    Parameters
    ----------
    pcap_paths      : List of absolute or relative paths to PCAP files.
    zeek_out        : Output directory for Zeek logs (default: "zeek_out").
    merge_first     : If True, attempt to merge multiple PCAPs before processing.
    timeout_seconds : Per-Zeek-run timeout in seconds.

    Returns
    -------
    {success, message, zeek_out, zeek_available, zeek_version}
    """
    available, version = check_zeek_available()
    if not available:
        return {
            "success": False,
            "message": f"Zeek check failed: {version}",
            "zeek_out": zeek_out,
            "zeek_available": False,
            "zeek_version": None,
        }

    success, message, out_path = ingest_pcaps(
        pcap_paths=pcap_paths,
        zeek_out=zeek_out,
        merge_first=merge_first,
        timeout_seconds=timeout_seconds,
    )
    return {
        "success": success,
        "message": message,
        "zeek_out": str(out_path),
        "zeek_available": True,
        "zeek_version": version,
    }


# ---------------------------------------------------------------------------
# Tool 2: Exfiltration analysis
# ---------------------------------------------------------------------------

@tool
def exfiltration_analyze(
    zeek_root: str = "zeek_out",
    bucket_seconds: int = 300,
    top_spikes_to_keep: int = 20,
    top_evidence_spikes: int = 12,
    allowlist_domain_substrings: Optional[List[str]] = None,
    beacon_cv_threshold: float = 0.30,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect data exfiltration by analysing outbound byte volume spikes in Zeek conn.log.

    Also performs beaconing detection (periodic connections to the same external IP)
    and maps findings to MITRE ATT&CK techniques (T1048, T1567, T1020).

    Parameters
    ----------
    zeek_root                   : Path to Zeek log directory (default: "zeek_out").
    bucket_seconds              : Spike detection bucket size in seconds (default: 300 = 5 min).
    top_spikes_to_keep          : Number of top volume spikes to retain.
    top_evidence_spikes         : How many spikes to escalate to full evidence items.
    allowlist_domain_substrings : Domain substrings to suppress (default: Microsoft/Apple telemetry).
    beacon_cv_threshold         : Connections with inter-arrival CV below this are flagged as beaconing.
    max_workers                 : Parallel workers for chunk processing (None = auto).
    write_output_path           : Optional path to write JSON output.

    Returns
    -------
    Structured result with suspected, confidence, mitre_techniques, evidence,
    suspicious_only_evidence, and debug fields.
    """
    return analyze_exfiltration(
        zeek_root=zeek_root,
        bucket_seconds=bucket_seconds,
        top_spikes_to_keep=top_spikes_to_keep,
        top_evidence_spikes=top_evidence_spikes,
        allowlist_domain_substrings=allowlist_domain_substrings,
        beacon_cv_threshold=beacon_cv_threshold,
        max_workers=max_workers,
        write_output_path=write_output_path,
    )


# ---------------------------------------------------------------------------
# Tool 3: DNS exfiltration analysis
# ---------------------------------------------------------------------------

@tool
def dns_exfiltration_analyze(
    zeek_root: str = "zeek_out",
    entropy_threshold: float = 3.5,
    label_length_threshold: int = 40,
    query_rate_threshold: int = 200,
    allowlist_domain_substrings: Optional[List[str]] = None,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect DNS tunneling and covert DNS exfiltration from Zeek dns.log.

    Detection methods:
    - Shannon entropy on subdomain labels (high entropy → base64/hex payload)
    - Long subdomain labels (encoded data)
    - High query rate bursts to a single base domain
    - Anomalous query types (TXT, NULL, ANY)

    Maps to MITRE ATT&CK T1071.004 and T1048.003.

    Parameters
    ----------
    zeek_root               : Path to Zeek log directory.
    entropy_threshold       : Bits/char above which subdomain is considered encoded (default: 3.5).
    label_length_threshold  : Characters above which a label is flagged as long (default: 40).
    query_rate_threshold    : Queries per 5-minute bucket above which rate is flagged (default: 200).
    allowlist_domain_substrings : Suppress known-good domains.
    max_workers             : Parallel workers for chunk processing (None = auto).
    write_output_path       : Optional path to write JSON output.

    Returns
    -------
    Structured result with suspected, confidence, mitre_techniques, evidence,
    suspicious_only_evidence, and debug fields.
    """
    return analyze_dns_exfiltration(
        zeek_root=zeek_root,
        entropy_threshold=entropy_threshold,
        label_length_threshold=label_length_threshold,
        query_rate_threshold=query_rate_threshold,
        allowlist_domain_substrings=allowlist_domain_substrings,
        max_workers=max_workers,
        write_output_path=write_output_path,
    )


@tool
def http_exfiltration_analyze(
    zeek_root: str = "zeek_out",
    allowlist_domain_substrings: Optional[List[str]] = None,
    request_body_threshold: int = 500_000,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Detect outbound HTTP/web-service uploads from Zeek http.log and files.log.

    Focuses on:
    - POST / PUT / PATCH uploads
    - large request bodies
    - known file-sharing services (e.g. temp.sh)
    - archive hints in URI, filename, or MIME metadata
    """
    return analyze_http_exfiltration(
        zeek_root=zeek_root,
        allowlist_domain_substrings=allowlist_domain_substrings,
        request_body_threshold=request_body_threshold,
        max_workers=max_workers,
        write_output_path=write_output_path,
    )


# ---------------------------------------------------------------------------
# Tool 4: LLM summarizer
# ---------------------------------------------------------------------------

@tool
def exfiltration_summarize(
    exfil_result: Optional[Dict[str, Any]] = None,
    dns_result:   Optional[Dict[str, Any]] = None,
    llm_provider: str = "azure",
    model:        Optional[str] = None,
    temperature:  float = 0.1,
) -> Dict[str, Any]:
    """
    Generate a structured forensic narrative from exfiltration analysis results using an LLM.

    Includes a hallucination / grounding guard: every IP address and domain
    cited by the LLM is verified against the source evidence. A grounding_score
    of 1.0 means every entity is traceable to the evidence data.

    Parameters
    ----------
    exfil_result  : Output from exfiltration_analyze tool.
    dns_result    : Output from dns_exfiltration_analyze tool (optional).
    llm_provider  : "azure" (requires AZURE_OPENAI_API_KEY + AZURE_OPENAI_ENDPOINT), "anthropic", or "openai".
    model         : Override the default model name.
    temperature   : LLM sampling temperature (default 0.1 for deterministic forensic output).

    Returns
    -------
    {
      narrative         : { executive_summary, key_findings, mitre_techniques,
                            risk_assessment, recommendations }
      grounding_score   : float (1.0 = fully grounded in evidence)
      ungrounded_claims : List of entities the LLM cited that were not in the evidence
      hallucination_risk: LOW / MEDIUM / HIGH
      latency_seconds   : float
      error             : str or None
    }
    """
    return summarize_exfiltration(
        exfil_result=exfil_result,
        dns_result=dns_result,
        llm_provider=llm_provider,
        model=model,
        temperature=temperature,
    )


# ---------------------------------------------------------------------------
# Tool 5: End-to-end pipeline
# ---------------------------------------------------------------------------

@tool
def exfiltration_pipeline(
    pcap_paths: Optional[List[str]] = None,
    zeek_root: str = "zeek_out",
    api_day: Optional[str] = None,
    api_base_url: str = DEFAULT_API_BASE_URL,
    api_datasets: Optional[List[str]] = None,
    run_llm_summary: bool = True,
    llm_provider: str = "azure",
    write_outputs: bool = True,
    allowlist_domain_substrings: Optional[List[str]] = None,
    max_workers: Optional[int] = None,
) -> Dict[str, Any]:
    """
    End-to-end exfiltration analysis pipeline: PCAP → Zeek → analysis → LLM summary.

    Steps performed:
      1. (Optional) Convert PCAP files to Zeek logs via pcap_to_zeek.
      2. Run exfiltration_analyze on Zeek logs.
      3. Run dns_exfiltration_analyze on Zeek logs.
      4. (Optional) Call exfiltration_summarize to generate LLM narrative.

    Parameters
    ----------
    pcap_paths              : PCAP file paths. If None, assumes Zeek logs already exist.
    zeek_root               : Zeek log directory (used as output for Zeek, input for analysis).
    api_day                 : Optional shard day (`YYYY-MM-DD`) to download from the SC4063 API.
    api_base_url            : API base URL for shard retrieval.
    api_datasets            : Zeek datasets to download for that day (default: connection/dns/ssl).
    run_llm_summary         : Whether to call the LLM summarizer.
    llm_provider            : "azure", "anthropic", or "openai".
    write_outputs           : If True, write JSON outputs to outputs/ directory.
    allowlist_domain_substrings : Domain allowlist passed to both analysis tools.
    max_workers             : Parallel workers for chunk processing (None = auto).

    Returns
    -------
    {
      pcap_ingestion    : result from pcap_to_zeek (or None if skipped),
      exfil_analysis    : result from exfiltration_analyze,
      dns_analysis      : result from dns_exfiltration_analyze,
      llm_summary       : result from exfiltration_summarize (or None if skipped),
      combined_suspected: bool,
      combined_confidence: str,
      all_mitre_techniques: list,
    }
    """
    exfil_out = "outputs/exfiltration.json" if write_outputs else None
    dns_out = "outputs/dns_exfiltration.json" if write_outputs else None
    return run_exfiltration_pipeline(
        pcap_paths=pcap_paths,
        zeek_root=zeek_root,
        api_day=api_day,
        api_base_url=api_base_url,
        api_datasets=api_datasets,
        run_llm_summary=run_llm_summary,
        llm_provider=llm_provider,
        allowlist_domain_substrings=allowlist_domain_substrings,
        max_workers=max_workers,
        write_exfil_output_path=exfil_out,
        write_dns_output_path=dns_out,
    )
