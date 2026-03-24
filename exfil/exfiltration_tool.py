# src/exfiltration_tool.py
"""
Core exfiltration detection engine.

Reads Zeek conn.log / ssl.log / dns.log JSON logs, buckets outbound bytes,
detects volume spikes, scores confidence, maps to MITRE ATT&CK, and
performs basic beaconing detection.
"""
from __future__ import annotations

import json
import os
import statistics
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
UTC = timezone.utc
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# MITRE ATT&CK technique references for exfiltration
# ---------------------------------------------------------------------------
# Domain-carrying fields in evidence output dicts produced by this module.
# Imported by exfiltration_summarizer._DOMAIN_ENTITY_KEYS to keep grounding
# coverage in sync with the actual schema — add new domain fields here.
_EVIDENCE_DOMAIN_FIELDS: frozenset = frozenset({
    "domain_hint",   # resolved domain for external IP (from ssl.log SNI or dns.log answer)
})

MITRE_T1048 = {"id": "T1048",     "name": "Exfiltration Over Alternative Protocol"}
MITRE_T1048_001 = {"id": "T1048.001", "name": "Exfiltration Over Symmetric Encrypted Non-C2 Protocol"}
MITRE_T1048_002 = {"id": "T1048.002", "name": "Exfiltration Over Asymmetric Encrypted Non-C2 Protocol"}
MITRE_T1048_003 = {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"}
MITRE_T1567   = {"id": "T1567",     "name": "Exfiltration Over Web Service"}
MITRE_T1020   = {"id": "T1020",     "name": "Automated Exfiltration"}  # flagged if beaconing detected

# Ports that suggest encrypted exfiltration (asymmetric)
_ASYMMETRIC_PORTS = {443, 8443, 9443}
# Ports that suggest plaintext (high risk if exfiltrating)
_PLAINTEXT_PORTS  = {80, 8080, 21, 23, 25, 110, 143}
# Well-known CDN/service ports that lower suspicion
_STANDARD_PORTS   = {80, 443}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class BeaconingInfo:
    connection_count: int
    mean_interval_seconds: float
    cv: float            # coefficient of variation (std/mean); lower = more regular
    is_beaconing: bool   # True if cv < threshold and count is sufficient
    jitter_seconds: float


@dataclass
class EvidenceItem:
    bucket_start_utc: str
    bucket_seconds: int
    internal_ip: str
    external_ip: str
    external_port: int
    proto: str
    bytes_out: int
    domain_hint: Optional[str]
    allowlisted: bool
    tags: List[str]
    reason: str
    risk_level: str                          # CRITICAL / HIGH / MEDIUM / LOW
    mitre_techniques: List[Dict[str, str]]
    beaconing: Optional[Dict]                # BeaconingInfo as dict, or None


# ---------------------------------------------------------------------------
# Private utilities
# ---------------------------------------------------------------------------

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


def _bucket_start(ts: float, bucket_seconds: int) -> int:
    return int(ts // bucket_seconds) * bucket_seconds


def _is_allowlisted(domain: Optional[str], allowlist: Tuple[str, ...]) -> bool:
    if not domain:
        return False
    d = domain.lower()
    return any(sub.lower() in d for sub in allowlist)


def _iter_chunk_dirs(zeek_root: Path) -> List[Path]:
    if not zeek_root.is_dir():
        return []
    if (zeek_root / "conn.log").exists() or (zeek_root / "dns.log").exists() or (zeek_root / "ssl.log").exists():
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


def _domain_maps_for_chunk(chunk_dir: Path) -> Tuple[Dict[str, str], Dict[str, str]]:
    ip_to_sni: Dict[str, str] = {}
    ip_to_dns: Dict[str, str] = {}

    ssl_log = chunk_dir / "ssl.log"
    if ssl_log.exists():
        for r in _read_json_lines(ssl_log):
            ip = r.get("id.resp_h")
            sni = r.get("server_name")
            if ip and sni and not _is_private_ip(str(ip)):
                ip_to_sni.setdefault(str(ip), str(sni))

    dns_log = chunk_dir / "dns.log"
    if dns_log.exists():
        for r in _read_json_lines(dns_log):
            q = r.get("query")
            answers = r.get("answers")
            if not q or not answers:
                continue
            for a in (answers if isinstance(answers, list) else [answers]):
                a_str = str(a)
                if a_str and not _is_private_ip(a_str):
                    ip_to_dns.setdefault(a_str, str(q))
    return ip_to_sni, ip_to_dns


def _build_domain_maps(
    chunk_dirs: List[Path],
    max_workers: Optional[int] = None,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    ip_to_sni: Dict[str, str] = {}
    ip_to_dns: Dict[str, str] = {}
    workers = _parallel_workers(max_workers, len(chunk_dirs))

    if workers == 1:
        for chunk_dir in chunk_dirs:
            sni_map, dns_map = _domain_maps_for_chunk(chunk_dir)
            for ip, sni in sni_map.items():
                ip_to_sni.setdefault(ip, sni)
            for ip, dom in dns_map.items():
                ip_to_dns.setdefault(ip, dom)
        return ip_to_sni, ip_to_dns

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for sni_map, dns_map in ex.map(_domain_maps_for_chunk, chunk_dirs):
            for ip, sni in sni_map.items():
                ip_to_sni.setdefault(ip, sni)
            for ip, dom in dns_map.items():
                ip_to_dns.setdefault(ip, dom)
    return ip_to_sni, ip_to_dns


def _scan_conn_chunk(chunk_dir: Path, bucket_seconds: int) -> Dict[str, Any]:
    totals_external: Dict[str, int] = {}
    totals_internal: Dict[str, int] = {}
    bucket_bytes: Dict[Tuple[str, int], int] = {}
    bucket_internal: Dict[Tuple[str, int], Dict[str, int]] = {}
    bucket_port: Dict[Tuple[str, int], Dict[int, int]] = {}
    bucket_proto: Dict[Tuple[str, int], Dict[str, int]] = {}
    pair_timestamps: Dict[Tuple[str, str], List[float]] = {}
    rows_seen = rows_used = internal_external_rows = 0

    conn_log = chunk_dir / "conn.log"
    if not conn_log.exists():
        return {
            "totals_external": totals_external,
            "totals_internal": totals_internal,
            "bucket_bytes": bucket_bytes,
            "bucket_internal": bucket_internal,
            "bucket_port": bucket_port,
            "bucket_proto": bucket_proto,
            "pair_timestamps": pair_timestamps,
            "rows_seen": 0,
            "rows_used": 0,
            "internal_external_rows": 0,
        }

    for r in _read_json_lines(conn_log):
        rows_seen += 1
        ts = r.get("ts")
        try:
            ts_f = float(ts)
        except (TypeError, ValueError):
            continue

        orig_h = r.get("id.orig_h")
        resp_h = r.get("id.resp_h")
        if not orig_h or not resp_h:
            continue

        orig_private = _is_private_ip(str(orig_h))
        resp_private = _is_private_ip(str(resp_h))
        if orig_private == resp_private:
            continue
        internal_external_rows += 1

        proto = str(r.get("proto") or "unknown")
        resp_p = int(r.get("id.resp_p", 0) or 0)
        orig_p = int(r.get("id.orig_p", 0) or 0)

        try:
            ob = int(r["orig_bytes"]) if r.get("orig_bytes") is not None else 0
            rb = int(r["resp_bytes"]) if r.get("resp_bytes") is not None else 0
        except (TypeError, ValueError):
            continue

        # Exfiltration scoring should focus on outbound sessions initiated by
        # internal hosts. Counting resp_bytes on inbound connections causes
        # externally initiated sessions (e.g. RDP brute-force / interactive
        # access) to be mislabeled as outbound exfiltration.
        if not (orig_private and not resp_private):
            continue

        internal_ip, external_ip = str(orig_h), str(resp_h)
        bytes_out, external_port = ob, resp_p

        if bytes_out <= 0:
            continue
        rows_used += 1

        totals_external[external_ip] = totals_external.get(external_ip, 0) + bytes_out
        totals_internal[internal_ip] = totals_internal.get(internal_ip, 0) + bytes_out

        bstart = _bucket_start(ts_f, bucket_seconds)
        key = (external_ip, bstart)
        bucket_bytes[key] = bucket_bytes.get(key, 0) + bytes_out

        _bi = bucket_internal.setdefault(key, {})
        _bi[internal_ip] = _bi.get(internal_ip, 0) + bytes_out

        _bp = bucket_port.setdefault(key, {})
        _bp[external_port] = _bp.get(external_port, 0) + bytes_out

        _bpr = bucket_proto.setdefault(key, {})
        _bpr[proto] = _bpr.get(proto, 0) + bytes_out

        pair_timestamps.setdefault((internal_ip, external_ip), []).append(ts_f)

    return {
        "totals_external": totals_external,
        "totals_internal": totals_internal,
        "bucket_bytes": bucket_bytes,
        "bucket_internal": bucket_internal,
        "bucket_port": bucket_port,
        "bucket_proto": bucket_proto,
        "pair_timestamps": pair_timestamps,
        "rows_seen": rows_seen,
        "rows_used": rows_used,
        "internal_external_rows": internal_external_rows,
    }


def _score_risk(bytes_out: int, allowlisted: bool, has_domain: bool, port: int) -> str:
    """Graduated risk scoring for an individual evidence item."""
    if allowlisted:
        return "LOW"
    if bytes_out >= 100_000_000:          # ≥ 100 MB
        return "CRITICAL"
    if bytes_out >= 10_000_000:           # ≥ 10 MB
        return "HIGH"
    if bytes_out >= 1_000_000:            # ≥ 1 MB
        return "MEDIUM"
    return "LOW"


def _get_mitre(port: int, proto: str, beaconing: bool) -> List[Dict[str, str]]:
    """Map evidence characteristics to MITRE ATT&CK techniques."""
    techniques = [MITRE_T1048.copy()]

    if port in _ASYMMETRIC_PORTS:
        techniques.append(MITRE_T1048_002.copy())
    elif port in _PLAINTEXT_PORTS:
        techniques.append(MITRE_T1048_003.copy())
    else:
        # Non-standard port — also flag unencrypted unless proven otherwise
        techniques.append(MITRE_T1048_003.copy())

    if port == 443:
        techniques.append(MITRE_T1567.copy())

    if beaconing:
        techniques.append(MITRE_T1020.copy())

    # deduplicate by id
    seen: set = set()
    deduped = []
    for t in techniques:
        if t["id"] not in seen:
            seen.add(t["id"])
            deduped.append(t)
    return deduped


def _compute_beaconing(
    timestamps: List[float],
    beacon_cv_threshold: float = 0.30,
    min_connections: int = 4,
) -> BeaconingInfo:
    """
    Compute beaconing score from a sorted list of connection timestamps.

    Low coefficient of variation (CV = stdev/mean) of inter-arrival times
    indicates regular, scheduled connections — a hallmark of beaconing.
    """
    if len(timestamps) < min_connections:
        return BeaconingInfo(
            connection_count=len(timestamps),
            mean_interval_seconds=0.0,
            cv=1.0,
            is_beaconing=False,
            jitter_seconds=0.0,
        )
    sorted_ts = sorted(timestamps)
    intervals = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts) - 1)]
    mean_iv = statistics.mean(intervals)
    stdev_iv = statistics.stdev(intervals) if len(intervals) > 1 else 0.0
    cv = (stdev_iv / mean_iv) if mean_iv > 0 else 1.0

    return BeaconingInfo(
        connection_count=len(timestamps),
        mean_interval_seconds=round(mean_iv, 2),
        cv=round(cv, 4),
        is_beaconing=(cv < beacon_cv_threshold and len(timestamps) >= min_connections),
        jitter_seconds=round(stdev_iv, 2),
    )


def _overall_confidence(suspicious_evidence: List[EvidenceItem]) -> str:
    """
    Aggregate confidence across all suspicious evidence items.
    Returns: CRITICAL / HIGH / MEDIUM / LOW
    """
    if not suspicious_evidence:
        return "LOW"

    risk_levels = [e.risk_level for e in suspicious_evidence]
    if "CRITICAL" in risk_levels:
        return "CRITICAL"
    if "HIGH" in risk_levels or len(suspicious_evidence) >= 3:
        return "HIGH"
    return "MEDIUM"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_exfiltration(
    zeek_root: str,
    bucket_seconds: int = 300,
    top_spikes_to_keep: int = 20,
    top_evidence_spikes: int = 12,
    allowlist_domain_substrings: Optional[List[str]] = None,
    beacon_cv_threshold: float = 0.30,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyze Zeek logs for data exfiltration candidates.

    Parameters
    ----------
    zeek_root               : Path to Zeek log directory containing chunk sub-dirs.
    bucket_seconds          : Time bucket size for spike detection (default 5 min).
    top_spikes_to_keep      : Number of top volume spikes to surface.
    top_evidence_spikes     : How many spikes to promote to full evidence items.
    allowlist_domain_substrings : Domains to suppress (default: Microsoft telemetry).
    beacon_cv_threshold     : CV below which connections are flagged as beaconing.
    write_output_path       : If set, write JSON result to this path.

    Returns
    -------
    Structured result dict with suspected, confidence, evidence, mitre_techniques,
    suspicious_only_evidence, and debug fields.
    """
    zeek_path = _resolve_zeek_root(zeek_root)
    chunk_dirs = _iter_chunk_dirs(zeek_path)

    # --- Allowlist ---
    _default_allowlist = (
        "events.data.microsoft.com",
        "events.endpoint.security.microsoft.com",
        "security.microsoft.com",
        "microsoft.com",
        "windowsupdate.com",
        "update.microsoft.com",
        "apple.com",
        "icloud.com",
        "ocsp.apple.com",
    )
    allowlist = tuple(allowlist_domain_substrings) if allowlist_domain_substrings else _default_allowlist

    # --- Normalise parameters ---
    bsec   = bucket_seconds     if isinstance(bucket_seconds, int)     and bucket_seconds     > 0 else 300
    ntop   = top_spikes_to_keep if isinstance(top_spikes_to_keep, int) and top_spikes_to_keep > 0 else 20
    nevid  = top_evidence_spikes if isinstance(top_evidence_spikes, int) and top_evidence_spikes > 0 else 12

    # --- Accumulators ---
    total_bytes_by_external: Dict[str, int] = {}
    total_bytes_by_internal: Dict[str, int] = {}
    bucket_bytes:     Dict[Tuple[str, int], int]             = {}
    bucket_internal:  Dict[Tuple[str, int], Dict[str, int]]  = {}
    bucket_port:      Dict[Tuple[str, int], Dict[int, int]]  = {}
    bucket_proto:     Dict[Tuple[str, int], Dict[str, int]]  = {}

    # For beaconing: timestamps per (internal_ip, external_ip)
    pair_timestamps: Dict[Tuple[str, str], List[float]] = {}

    rows_seen = rows_used = internal_external_rows = 0

    workers = _parallel_workers(max_workers, len(chunk_dirs))
    if workers == 1:
        chunk_stats = [_scan_conn_chunk(c, bsec) for c in chunk_dirs]
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            chunk_stats = list(ex.map(lambda c: _scan_conn_chunk(c, bsec), chunk_dirs))

    for stats in chunk_stats:
        rows_seen += int(stats["rows_seen"])
        rows_used += int(stats["rows_used"])
        internal_external_rows += int(stats["internal_external_rows"])

        for ip, b in stats["totals_external"].items():
            total_bytes_by_external[ip] = total_bytes_by_external.get(ip, 0) + b
        for ip, b in stats["totals_internal"].items():
            total_bytes_by_internal[ip] = total_bytes_by_internal.get(ip, 0) + b
        for key, b in stats["bucket_bytes"].items():
            bucket_bytes[key] = bucket_bytes.get(key, 0) + b
        for key, mapping in stats["bucket_internal"].items():
            target = bucket_internal.setdefault(key, {})
            for ip, b in mapping.items():
                target[ip] = target.get(ip, 0) + b
        for key, mapping in stats["bucket_port"].items():
            target = bucket_port.setdefault(key, {})
            for port, b in mapping.items():
                target[port] = target.get(port, 0) + b
        for key, mapping in stats["bucket_proto"].items():
            target = bucket_proto.setdefault(key, {})
            for proto, b in mapping.items():
                target[proto] = target.get(proto, 0) + b
        for pair, ts_list in stats["pair_timestamps"].items():
            pair_timestamps.setdefault(pair, []).extend(ts_list)

    # --- Top senders / destinations ---
    top_external = sorted(total_bytes_by_external.items(), key=lambda x: x[1], reverse=True)[:15]
    top_internal = sorted(total_bytes_by_internal.items(), key=lambda x: x[1], reverse=True)[:15]

    # --- Spike list ---
    spikes = sorted(bucket_bytes.items(), key=lambda x: x[1], reverse=True)[:ntop]
    spike_list = [
        {
            "external_ip": ext,
            "bucket_start_epoch": bstart,
            "bucket_start_utc": datetime.fromtimestamp(bstart, UTC).isoformat().replace("+00:00", "Z"),
            "bucket_seconds": bsec,
            "bytes_out": b,
        }
        for (ext, bstart), b in spikes
    ]

    # --- Domain resolution ---
    ip_to_sni, ip_to_dns = _build_domain_maps(chunk_dirs, max_workers=max_workers)

    # --- Beaconing: pre-compute for top external IPs ---
    # We compute per (internal, external) pair, keyed by external_ip for quick lookup
    beaconing_by_pair: Dict[Tuple[str, str], BeaconingInfo] = {
        pair: _compute_beaconing(ts_list, beacon_cv_threshold)
        for pair, ts_list in pair_timestamps.items()
        if len(ts_list) >= 4
    }

    # --- Build evidence items ---
    evidence: List[EvidenceItem] = []
    for s in spike_list[:nevid]:
        ext    = s["external_ip"]
        bstart = s["bucket_start_epoch"]
        key    = (ext, bstart)

        internal_map = bucket_internal.get(key, {})
        internal_ip  = max(internal_map.items(), key=lambda x: x[1])[0] if internal_map else "unknown"

        port_map  = bucket_port.get(key, {})
        top_port  = max(port_map.items(),  key=lambda x: x[1])[0] if port_map  else 0

        proto_map = bucket_proto.get(key, {})
        top_proto = max(proto_map.items(), key=lambda x: x[1])[0] if proto_map else "unknown"

        domain_hint  = ip_to_sni.get(ext) or ip_to_dns.get(ext)
        allowlisted  = _is_allowlisted(domain_hint, allowlist)
        risk_level   = _score_risk(s["bytes_out"], allowlisted, domain_hint is not None, top_port)

        # Beaconing info for the dominant (internal, external) pair in this bucket
        beacon_info  = beaconing_by_pair.get((internal_ip, ext))
        beaconing_d  = asdict(beacon_info) if beacon_info else None

        tags: List[str] = []
        if domain_hint is None:
            tags.append("no_domain_mapping")
        if allowlisted:
            tags.append("allowlisted_domain")
        if top_port not in _STANDARD_PORTS:
            tags.append("non_standard_port")
        if beacon_info and beacon_info.is_beaconing:
            tags.append("beaconing_detected")
        if s["bytes_out"] >= 10_000_000:
            tags.append("large_volume")

        is_beaconing = bool(beacon_info and beacon_info.is_beaconing)
        mitre = _get_mitre(top_port, top_proto, is_beaconing)

        evidence.append(EvidenceItem(
            bucket_start_utc   = s["bucket_start_utc"],
            bucket_seconds     = bsec,
            internal_ip        = internal_ip,
            external_ip        = ext,
            external_port      = top_port,
            proto              = top_proto,
            bytes_out          = s["bytes_out"],
            domain_hint        = domain_hint,
            allowlisted        = allowlisted,
            tags               = tags,
            reason             = "outbound_spike_bucket_attributed",
            risk_level         = risk_level,
            mitre_techniques   = mitre,
            beaconing          = beaconing_d,
        ))

    suspicious_evidence = [e for e in evidence if not e.allowlisted]
    suspected           = len(suspicious_evidence) > 0
    confidence          = _overall_confidence(suspicious_evidence)

    # Aggregate MITRE techniques across all suspicious evidence (deduplicated)
    all_mitre: Dict[str, Dict] = {}
    for e in suspicious_evidence:
        for t in e.mitre_techniques:
            all_mitre[t["id"]] = t
    mitre_summary = sorted(all_mitre.values(), key=lambda x: x["id"])

    result: Dict[str, Any] = {
        "module":                  "exfiltration",
        "version":                 "tool_v3_mitre_beaconing",
        "suspected":               suspected,
        "confidence":              confidence,
        "mitre_techniques":        mitre_summary,
        "top_internal_senders":    [{"internal_ip": ip, "bytes_out": b} for ip, b in top_internal],
        "top_external_destinations": [{"external_ip": ip, "bytes_out": b} for ip, b in top_external],
        "top_outbound_spike_buckets": spike_list,
        "evidence":                [asdict(e) for e in evidence],
        "suspicious_only_evidence": [asdict(e) for e in suspicious_evidence],
        "debug": {
            "zeek_root":                       str(zeek_path),
            "zeek_root_exists":                zeek_path.exists(),
            "zeek_chunk_dirs_seen":            len(chunk_dirs),
            "conn_rows_seen":                  rows_seen,
            "internal_external_rows":          internal_external_rows,
            "conn_rows_used_directional_bytes": rows_used,
            "unique_external_ips":             len(total_bytes_by_external),
            "unique_internal_ips":             len(total_bytes_by_internal),
            "sni_ip_mappings":                 len(ip_to_sni),
            "dns_ip_mappings":                 len(ip_to_dns),
            "beaconing_pairs_analysed":        len(beaconing_by_pair),
            "bucket_seconds":                  bsec,
            "top_spikes_to_keep":              ntop,
            "top_evidence_spikes":             nevid,
            "beacon_cv_threshold":             beacon_cv_threshold,
            "allowlist_domain_substrings":     list(allowlist),
            "max_workers":                     workers,
        },
        "notes": [
            "Reads Zeek conn/ssl/dns logs. PCAP → Zeek via pcap_ingestor.py.",
            "suspicious_only_evidence excludes allowlisted destinations.",
            "beaconing detection uses coefficient of variation of inter-arrival times.",
            "LLM summarizer should ground all claims in suspicious_only_evidence.",
        ],
    }

    if write_output_path:
        out = Path(write_output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result


if __name__ == "__main__":
    import sys
    root = sys.argv[1] if len(sys.argv) > 1 else "zeek_out"
    r = analyze_exfiltration(zeek_root=root, write_output_path="outputs/exfiltration.json")
    print(f"suspected={r['suspected']}  confidence={r['confidence']}  "
          f"suspicious_count={len(r['suspicious_only_evidence'])}")
    for t in r["mitre_techniques"]:
        print(f"  MITRE {t['id']}: {t['name']}")
