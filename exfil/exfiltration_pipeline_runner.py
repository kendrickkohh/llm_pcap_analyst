from __future__ import annotations

from typing import Any, Dict, List, Optional

from exfil.dns_exfiltration import analyze_dns_exfiltration
from exfil.http_exfiltration import analyze_http_exfiltration
from exfil.exfiltration_summarizer import summarize_exfiltration
from exfil.exfiltration_tool import analyze_exfiltration
from exfil.pcap_ingestor import check_zeek_available, ingest_pcaps
from exfil.shard_api_client import DEFAULT_API_BASE_URL, download_zeek_day


def run_exfiltration_pipeline(
    *,
    pcap_paths: Optional[List[str]] = None,
    zeek_root: str = "zeek_out",
    api_day: Optional[str] = None,
    api_base_url: str = DEFAULT_API_BASE_URL,
    api_datasets: Optional[List[str]] = None,
    run_llm_summary: bool = True,
    llm_provider: str = "azure",
    llm_model: Optional[str] = None,
    llm_temperature: float = 0.1,
    allowlist_domain_substrings: Optional[List[str]] = None,
    max_workers: Optional[int] = None,
    write_exfil_output_path: Optional[str] = None,
    write_dns_output_path: Optional[str] = None,
    write_http_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    pcap_result = None
    api_result = None
    api_base_url = api_base_url or DEFAULT_API_BASE_URL
    analysis_zeek_root = zeek_root

    if pcap_paths:
        available, version = check_zeek_available()
        if not available:
            return {
                "pcap_ingestion": {
                    "success": False,
                    "message": f"Zeek not available: {version}",
                    "zeek_out": zeek_root,
                    "pcap_paths": pcap_paths,
                },
                "api_retrieval": None,
                "exfil_analysis": None,
                "dns_analysis": None,
                "http_analysis": None,
                "llm_summary": None,
                "combined_suspected": False,
                "combined_confidence": "LOW",
                "all_mitre_techniques": [],
                "error": f"Zeek not available: {version}",
            }

        ok, msg, out_path = ingest_pcaps(
            pcap_paths=pcap_paths,
            zeek_out=zeek_root,
        )
        pcap_result = {
            "success": ok,
            "message": msg,
            "zeek_out": str(out_path),
            "pcap_paths": pcap_paths,
        }
        analysis_zeek_root = str(out_path)
        if not ok:
            return {
                "pcap_ingestion": pcap_result,
                "api_retrieval": None,
                "exfil_analysis": None,
                "dns_analysis": None,
                "http_analysis": None,
                "llm_summary": None,
                "combined_suspected": False,
                "combined_confidence": "LOW",
                "all_mitre_techniques": [],
                "error": f"PCAP ingestion failed: {msg}",
            }
    elif api_day:
        try:
            api_result = download_zeek_day(
                base_url=api_base_url,
                day=api_day,
                zeek_root=zeek_root,
                datasets=api_datasets,
            )
        except Exception as exc:
            return {
                "pcap_ingestion": None,
                "api_retrieval": {
                    "success": False,
                    "message": str(exc),
                    "day": api_day,
                    "api_base_url": api_base_url,
                    "requested_datasets": api_datasets or [],
                    "zeek_root": zeek_root,
                },
                "exfil_analysis": None,
                "dns_analysis": None,
                "http_analysis": None,
                "llm_summary": None,
                "combined_suspected": False,
                "combined_confidence": "LOW",
                "all_mitre_techniques": [],
                "error": f"API shard retrieval failed: {exc}",
            }

        analysis_zeek_root = api_result["zeek_root"]
        if not api_result.get("success"):
            return {
                "pcap_ingestion": None,
                "api_retrieval": api_result,
                "exfil_analysis": None,
                "dns_analysis": None,
                "http_analysis": None,
                "llm_summary": None,
                "combined_suspected": False,
                "combined_confidence": "LOW",
                "all_mitre_techniques": [],
                "error": api_result["message"],
            }

    exfil_result = analyze_exfiltration(
        zeek_root=analysis_zeek_root,
        allowlist_domain_substrings=allowlist_domain_substrings,
        max_workers=max_workers,
        write_output_path=write_exfil_output_path,
    )
    dns_result = analyze_dns_exfiltration(
        zeek_root=analysis_zeek_root,
        allowlist_domain_substrings=allowlist_domain_substrings,
        max_workers=max_workers,
        write_output_path=write_dns_output_path,
    )
    http_result = analyze_http_exfiltration(
        zeek_root=analysis_zeek_root,
        allowlist_domain_substrings=allowlist_domain_substrings,
        max_workers=max_workers,
        write_output_path=write_http_output_path,
    )

    llm_result = None
    if run_llm_summary:
        llm_result = summarize_exfiltration(
            exfil_result=exfil_result,
            dns_result=dns_result,
            http_result=http_result,
            llm_provider=llm_provider,
            model=llm_model,
            temperature=llm_temperature,
        )

    all_mitre: Dict[str, Dict[str, Any]] = {}
    for technique in exfil_result.get("mitre_techniques", []):
        technique_id = technique.get("id")
        if technique_id:
            all_mitre[str(technique_id)] = technique
    for technique in dns_result.get("mitre_techniques", []):
        technique_id = technique.get("id")
        if technique_id:
            all_mitre[str(technique_id)] = technique
    for technique in http_result.get("mitre_techniques", []):
        technique_id = technique.get("id")
        if technique_id:
            all_mitre[str(technique_id)] = technique

    confidence_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    combined_confidence = max(
        exfil_result.get("confidence", "LOW"),
        dns_result.get("confidence", "LOW"),
        http_result.get("confidence", "LOW"),
        key=lambda value: confidence_order.get(value, 0),
    )

    return {
        "pcap_ingestion": pcap_result,
        "api_retrieval": api_result,
        "exfil_analysis": exfil_result,
        "dns_analysis": dns_result,
        "http_analysis": http_result,
        "llm_summary": llm_result,
        "combined_suspected": bool(
            exfil_result.get("suspected")
            or dns_result.get("suspected")
            or http_result.get("suspected")
        ),
        "combined_confidence": combined_confidence,
        "all_mitre_techniques": sorted(all_mitre.values(), key=lambda item: item["id"]),
        "error": None,
    }
