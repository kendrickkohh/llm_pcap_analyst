from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

UTC = timezone.utc

MITRE_T1048 = {"id": "T1048", "name": "Exfiltration Over Alternative Protocol"}
MITRE_T1567 = {"id": "T1567", "name": "Exfiltration Over Web Service"}
MITRE_T1567_002 = {"id": "T1567.002", "name": "Exfiltration to Cloud Storage"}
MITRE_T1020 = {"id": "T1020", "name": "Automated Exfiltration"}

_UPLOAD_METHODS = {"POST", "PUT", "PATCH"}
_REQUEST_BODY_THRESHOLD = 500_000
_LARGE_UPLOAD_THRESHOLD = 5_000_000
_SUSPICIOUS_SERVICE_KEYWORDS = (
    "temp.sh",
    "transfer.sh",
    "file.io",
    "gofile",
    "anonfiles",
    "catbox.moe",
    "0x0.st",
    "paste.rs",
)
_ARCHIVE_HINTS = (".7z", ".zip", ".rar", ".tar", ".gz", ".tgz")
_ARCHIVE_MIME_KEYWORDS = ("7z", "zip", "rar", "tar", "gzip", "octet-stream")


@dataclass
class HttpExfilEvidence:
    ts_utc: str
    internal_ip: str
    external_ip: str
    external_port: int
    method: str
    upload_host: Optional[str]
    uri: str
    request_bytes: int
    response_bytes: int
    status_code: Optional[int]
    user_agent: Optional[str]
    file_name: Optional[str]
    mime_type: Optional[str]
    tags: List[str]
    risk_level: str
    mitre_techniques: List[Dict[str, str]]
    reason: str


def _read_json_lines(path: Path) -> Iterable[dict]:
    if not path.exists():
        return
    try:
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def _is_private_ip(ip: str) -> bool:
    return (
        ip.startswith("10.")
        or ip.startswith("192.168.")
        or any(ip.startswith(f"172.{n}.") for n in range(16, 32))
        or ip.startswith("127.")
        or ip.startswith("169.254.")
        or ip.startswith("::1")
        or ip.startswith("fc")
        or ip.startswith("fd")
    )


def _iter_chunk_dirs(zeek_root: Path) -> List[Path]:
    if not zeek_root.is_dir():
        return []
    if (zeek_root / "http.log").exists() or (zeek_root / "files.log").exists():
        return [zeek_root]
    return sorted((p for p in zeek_root.iterdir() if p.is_dir()), key=lambda p: p.name)


def _resolve_zeek_root(zeek_root: str) -> Path:
    candidate = Path(zeek_root)
    if candidate.is_absolute():
        return candidate
    cwd_path = (Path.cwd() / candidate).resolve()
    if cwd_path.exists():
        return cwd_path
    return (Path(__file__).resolve().parents[1] / candidate).resolve()


def _parallel_workers(max_workers: Optional[int], item_count: int) -> int:
    if item_count <= 1:
        return 1
    if isinstance(max_workers, int) and max_workers > 0:
        return min(max_workers, item_count)
    cpu = os.cpu_count() or 4
    return max(1, min(item_count, cpu * 2))


def _is_allowlisted(host: Optional[str], allowlist: Tuple[str, ...]) -> bool:
    if not host:
        return False
    normalized = host.lower()
    return any(item.lower() in normalized for item in allowlist)


def _scan_http_chunk(chunk_dir: Path) -> Dict[str, Any]:
    files_by_fuid: Dict[str, Dict[str, str]] = {}
    http_rows: List[Dict[str, Any]] = []

    files_log = chunk_dir / "files.log"
    if files_log.exists():
        for row in _read_json_lines(files_log):
            fuid = str(row.get("fuid") or "")
            if not fuid:
                continue
            files_by_fuid[fuid] = {
                "mime_type": str(row.get("mime_type") or ""),
                "filename": str(row.get("filename") or ""),
                "seen_bytes": str(row.get("seen_bytes") or ""),
            }

    http_log = chunk_dir / "http.log"
    if http_log.exists():
        for row in _read_json_lines(http_log):
            http_rows.append(row)

    return {
        "files_by_fuid": files_by_fuid,
        "http_rows": http_rows,
    }


def _score_risk(tags: List[str], request_bytes: int) -> str:
    if "known_file_sharing_service" in tags and request_bytes >= _REQUEST_BODY_THRESHOLD:
        return "HIGH"
    if "archive_hint" in tags and request_bytes >= _REQUEST_BODY_THRESHOLD:
        return "HIGH"
    if request_bytes >= _LARGE_UPLOAD_THRESHOLD:
        return "HIGH"
    if "known_file_sharing_service" in tags or request_bytes >= _REQUEST_BODY_THRESHOLD:
        return "MEDIUM"
    if "archive_hint" in tags:
        return "MEDIUM"
    return "LOW"


def analyze_http_exfiltration(
    zeek_root: str,
    allowlist_domain_substrings: Optional[List[str]] = None,
    request_body_threshold: int = _REQUEST_BODY_THRESHOLD,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyse Zeek http.log / files.log for outbound upload-style web exfiltration.
    """
    zeek_path = _resolve_zeek_root(zeek_root)
    chunk_dirs = _iter_chunk_dirs(zeek_path)

    _default_allowlist = (
        "microsoft.com",
        "windowsupdate.com",
        "apple.com",
        "icloud.com",
        "ocsp.apple.com",
    )
    allowlist = tuple(allowlist_domain_substrings) if allowlist_domain_substrings else _default_allowlist
    threshold = request_body_threshold if isinstance(request_body_threshold, int) and request_body_threshold > 0 else _REQUEST_BODY_THRESHOLD

    workers = _parallel_workers(max_workers, len(chunk_dirs))
    if workers == 1:
        chunk_stats = [_scan_http_chunk(c) for c in chunk_dirs]
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            chunk_stats = list(ex.map(_scan_http_chunk, chunk_dirs))

    files_by_fuid: Dict[str, Dict[str, str]] = {}
    http_rows: List[Dict[str, Any]] = []
    for stats in chunk_stats:
        files_by_fuid.update(stats["files_by_fuid"])
        http_rows.extend(stats["http_rows"])

    evidence: List[HttpExfilEvidence] = []
    for row in http_rows:
        method = str(row.get("method") or "").upper()
        if method not in _UPLOAD_METHODS:
            continue

        internal_ip = str(row.get("id.orig_h") or "")
        external_ip = str(row.get("id.resp_h") or "")
        if not internal_ip or not external_ip:
            continue
        if not (_is_private_ip(internal_ip) and not _is_private_ip(external_ip)):
            continue

        host = str(row.get("host") or row.get("server_name") or "")
        uri = str(row.get("uri") or "")
        try:
            ts_f = float(row.get("ts"))
        except (TypeError, ValueError):
            continue

        try:
            request_bytes = int(row.get("request_body_len") or 0)
        except (TypeError, ValueError):
            request_bytes = 0
        try:
            response_bytes = int(row.get("response_body_len") or 0)
        except (TypeError, ValueError):
            response_bytes = 0
        try:
            status_code = int(row.get("status_code")) if row.get("status_code") is not None else None
        except (TypeError, ValueError):
            status_code = None
        try:
            external_port = int(row.get("id.resp_p") or 80)
        except (TypeError, ValueError):
            external_port = 80

        fuids = row.get("orig_fuids") or row.get("fuids") or []
        if isinstance(fuids, str):
            fuids = [fuids]

        file_name = None
        mime_type = None
        for fuid in fuids:
            file_meta = files_by_fuid.get(str(fuid))
            if not file_meta:
                continue
            file_name = file_name or file_meta.get("filename") or None
            mime_type = mime_type or file_meta.get("mime_type") or None

        host_l = host.lower()
        uri_l = uri.lower()
        file_name_l = (file_name or "").lower()
        mime_type_l = (mime_type or "").lower()

        tags: List[str] = []
        if any(keyword in host_l for keyword in _SUSPICIOUS_SERVICE_KEYWORDS):
            tags.append("known_file_sharing_service")
        if request_bytes >= threshold:
            tags.append("large_upload")
        if (
            any(hint in uri_l for hint in _ARCHIVE_HINTS)
            or any(hint in file_name_l for hint in _ARCHIVE_HINTS)
            or any(keyword in mime_type_l for keyword in _ARCHIVE_MIME_KEYWORDS)
        ):
            tags.append("archive_hint")
        if status_code and 200 <= status_code < 300:
            tags.append("successful_upload")

        allowlisted = _is_allowlisted(host or None, allowlist)
        if allowlisted:
            tags.append("allowlisted_domain")

        # Promote known suspicious services even when body size is unavailable in http.log.
        if not tags or (tags == ["allowlisted_domain"]):
            continue
        if "known_file_sharing_service" not in tags and "large_upload" not in tags:
            continue

        mitre = [MITRE_T1048, MITRE_T1567]
        if "known_file_sharing_service" in tags:
            mitre.append(MITRE_T1567_002)
        if request_bytes >= _LARGE_UPLOAD_THRESHOLD:
            mitre.append(MITRE_T1020)

        evidence.append(HttpExfilEvidence(
            ts_utc=datetime.fromtimestamp(ts_f, UTC).isoformat().replace("+00:00", "Z"),
            internal_ip=internal_ip,
            external_ip=external_ip,
            external_port=external_port,
            method=method,
            upload_host=host or None,
            uri=uri,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            status_code=status_code,
            user_agent=str(row.get("user_agent") or "") or None,
            file_name=file_name,
            mime_type=mime_type,
            tags=tags,
            risk_level=_score_risk(tags, request_bytes),
            mitre_techniques=mitre,
            reason="http_upload_candidate",
        ))

    suspicious_evidence = [e for e in evidence if "allowlisted_domain" not in e.tags]
    suspected = len(suspicious_evidence) > 0
    confidence = "LOW"
    if any(e.risk_level == "HIGH" for e in suspicious_evidence):
        confidence = "HIGH"
    elif any(e.risk_level == "MEDIUM" for e in suspicious_evidence):
        confidence = "MEDIUM"

    all_mitre: Dict[str, Dict[str, str]] = {}
    for item in suspicious_evidence:
        for technique in item.mitre_techniques:
            all_mitre[technique["id"]] = technique

    result: Dict[str, Any] = {
        "module": "http_exfiltration",
        "version": "tool_v1_http_uploads",
        "suspected": suspected,
        "confidence": confidence,
        "mitre_techniques": sorted(all_mitre.values(), key=lambda item: item["id"]),
        "evidence": [asdict(item) for item in evidence],
        "suspicious_only_evidence": [asdict(item) for item in suspicious_evidence],
        "top_uploads": [
            {
                "upload_host": item.upload_host,
                "external_ip": item.external_ip,
                "request_bytes": item.request_bytes,
                "method": item.method,
                "risk_level": item.risk_level,
            }
            for item in sorted(evidence, key=lambda ev: ev.request_bytes, reverse=True)[:10]
        ],
        "debug": {
            "zeek_root": str(zeek_path),
            "zeek_root_exists": zeek_path.exists(),
            "zeek_chunk_dirs_seen": len(chunk_dirs),
            "http_rows_seen": len(http_rows),
            "files_rows_seen": len(files_by_fuid),
            "request_body_threshold": threshold,
            "allowlist_domain_substrings": list(allowlist),
            "max_workers": workers,
        },
        "notes": [
            "Reads Zeek http.log and files.log when present.",
            "Targets outbound POST/PUT/PATCH uploads to web services.",
            "Known file-sharing domains and archive hints raise suspicion.",
            "suspicious_only_evidence excludes allowlisted destinations.",
        ],
    }

    if write_output_path:
        out_path = Path(write_output_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result
