# src/dns_exfiltration.py
"""
DNS-specific exfiltration and tunneling detection.

Analyses Zeek dns.log for indicators of DNS tunneling / covert channel exfiltration:
  - Unusually long subdomain labels (encoded payload)
  - High Shannon entropy on subdomain labels (base64 / hex encoding)
  - Abnormally high query rate to a single base domain
  - Anomalous use of TXT / NULL / ANY record types

MITRE ATT&CK:
  T1071.004  Application Layer Protocol: DNS
  T1048.003  Exfiltration Over Unencrypted Non-C2 Protocol  (when DNS tunneling suspected)
"""
from __future__ import annotations

import json
import math
import re
import os
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
UTC = timezone.utc
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Thresholds  (tuned conservatively to reduce false positives)
# ---------------------------------------------------------------------------
# Domain-carrying fields in evidence output dicts produced by this module.
# Imported by exfiltration_summarizer._DOMAIN_ENTITY_KEYS to keep grounding
# coverage in sync with the actual schema — add new domain fields here.
_EVIDENCE_DOMAIN_FIELDS: frozenset = frozenset({
    "base_domain",   # base domain of the DNS tunneling target
})

_ENTROPY_THRESHOLD      = 3.5    # bits/char; typical base64 ≈ 4.0, English ≈ 3.0
_LABEL_LENGTH_THRESHOLD = 40     # characters; legitimate subdomains rarely exceed this
_QUERY_RATE_THRESHOLD   = 200    # queries to same base domain per 5-min bucket
_SUSPICIOUS_QTYPES      = {"TXT", "NULL", "ANY", "AAAA"}   # less common in normal traffic
_SUSPICIOUS_DOMAIN_KEYWORDS = (
    "oast",
    "burpcollaborator",
    "interactsh",
    "canarytokens",
)

_BUCKET_SECONDS = 300

MITRE_T1071_004 = {"id": "T1071.004", "name": "Application Layer Protocol: DNS"}
MITRE_T1048_003 = {"id": "T1048.003", "name": "Exfiltration Over Unencrypted Non-C2 Protocol"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class DnsEvidence:
    base_domain: str
    internal_ip: str
    total_queries: int
    unique_subdomains: int
    max_subdomain_length: int
    mean_subdomain_length: float
    max_entropy: float
    mean_entropy: float
    suspicious_qtype_count: int
    bucket_start_utc: str          # bucket with highest query rate
    bucket_query_count: int
    tags: List[str]
    risk_level: str
    mitre_techniques: List[Dict[str, str]]
    reason: str


# ---------------------------------------------------------------------------
# Helpers
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
    )


def _entropy(s: str) -> float:
    """Shannon entropy in bits/character."""
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in freq.values())


def _extract_base_domain(fqdn: str) -> str:
    """
    Naive public-suffix extraction: return the last two labels.
    e.g. 'abc.def.evil.com' → 'evil.com'
    """
    parts = fqdn.rstrip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return fqdn


def _is_local_or_internal_base_domain(base_domain: str) -> bool:
    base = base_domain.rstrip(".").lower()
    if not base or "." not in base:
        return True
    if base.endswith((".local", ".internal", ".home", ".lan", ".arpa")):
        return True
    if re.fullmatch(r"\d+(?:\.\d+)+", base):
        return True
    labels = base.split(".")
    if all(label.isdigit() for label in labels):
        return True
    return False


def _extract_subdomain(fqdn: str, base_domain: str) -> str:
    """Return everything before the base domain."""
    base = "." + base_domain
    if fqdn.endswith(base):
        return fqdn[: -len(base)]
    return ""


def _bucket_start(ts: float) -> int:
    return int(ts // _BUCKET_SECONDS) * _BUCKET_SECONDS


def _iter_chunk_dirs(zeek_root: Path) -> List[Path]:
    if not zeek_root.is_dir():
        return []
    if (zeek_root / "dns.log").exists() or (zeek_root / "conn.log").exists():
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


def _score_risk(tags: List[str]) -> str:
    if "high_rate" in tags and ("high_entropy" in tags or "long_subdomain" in tags):
        return "HIGH"
    if "high_entropy" in tags and "long_subdomain" in tags:
        return "HIGH"
    if "repeated_nxdomain" in tags and ("high_entropy" in tags or "high_rate" in tags):
        return "HIGH"
    if any(t in tags for t in ("high_rate", "high_entropy", "long_subdomain", "suspicious_qtype", "suspicious_domain")):
        return "MEDIUM"
    if "repeated_nxdomain" in tags:
        return "MEDIUM"
    return "LOW"


def _parallel_workers(max_workers: Optional[int], item_count: int) -> int:
    if item_count <= 1:
        return 1
    if isinstance(max_workers, int) and max_workers > 0:
        return min(max_workers, item_count)
    cpu = os.cpu_count() or 4
    return max(1, min(item_count, cpu * 2))


def _scan_dns_chunk(chunk_dir: Path) -> Dict[str, Any]:
    rows_seen = 0
    aggregated: Dict[Tuple[str, str], Dict[str, List[Any]]] = {}

    dns_log = chunk_dir / "dns.log"
    if not dns_log.exists():
        return {"rows_seen": 0, "aggregated": aggregated}

    for r in _read_json_lines(dns_log):
        rows_seen += 1
        query = r.get("query")
        if not query:
            continue

        ts_raw = r.get("ts")
        try:
            ts_f = float(ts_raw)
        except (TypeError, ValueError):
            continue

        orig_h = str(r.get("id.orig_h", ""))
        qtype = str(r.get("qtype_name") or r.get("qtype") or "")

        base = _extract_base_domain(query)
        subdomain = _extract_subdomain(query, base)
        key = (base, orig_h)

        if key not in aggregated:
            aggregated[key] = {"subdomains": [], "timestamps": [], "qtypes": [], "rcodes": [], "queries": []}
        entry = aggregated[key]

        if subdomain:
            entry["subdomains"].append(subdomain)
        entry["timestamps"].append(ts_f)
        entry["queries"].append(str(query))
        if qtype:
            entry["qtypes"].append(qtype.upper())
        rcode_name = str(r.get("rcode_name") or "").upper()
        if rcode_name:
            entry["rcodes"].append(rcode_name)

    return {"rows_seen": rows_seen, "aggregated": aggregated}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_dns_exfiltration(
    zeek_root: str,
    entropy_threshold: float = _ENTROPY_THRESHOLD,
    label_length_threshold: int = _LABEL_LENGTH_THRESHOLD,
    query_rate_threshold: int = _QUERY_RATE_THRESHOLD,
    allowlist_domain_substrings: Optional[List[str]] = None,
    max_workers: Optional[int] = None,
    write_output_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Analyse Zeek dns.log files for DNS tunneling / exfiltration.

    Returns structured result dict with:
      - suspected (bool)
      - confidence (str)
      - evidence (list of DnsEvidence dicts)
      - suspicious_only_evidence (non-allowlisted)
      - mitre_techniques
      - debug
    """
    zeek_path  = _resolve_zeek_root(zeek_root)
    chunk_dirs = _iter_chunk_dirs(zeek_path)

    _default_allowlist = (
        # Microsoft services — use hash-based subdomains that trigger entropy/length checks
        "microsoft.com",
        "windowsupdate.com",
        "windows.net",
        "azure.com",          # hash subdomains up to 75 chars, entropy ~4.76 — confirmed FP
        "azurefd.net",
        "azureedge.net",
        "azurewebsites.net",
        "trafficmanager.net", # Azure Traffic Manager — high-entropy GUIDs in subdomains
        "live.com",           # Microsoft Live — hash subdomains, entropy ~3.65
        "skype.com",
        "office.com",
        "office365.com",
        "microsoftonline.com",
        # Akamai CDN — hash subdomains, entropy ~4.17, labels up to 46 chars — confirmed FP
        "akadns.net",
        "akamaiedge.net",
        "akamaitechnologies.com",
        "edgekey.net",        # Akamai edge — entropy ~3.85, labels up to 49 chars
        "edgesuite.net",
        "a-msedge.net",       # Microsoft/Akamai edge — entropy ~4.08
        "l-msedge.net",
        "ax-msedge.net",
        "t-msedge.net",
        # Apple
        "apple.com",
        "icloud.com",
        # Google
        "google.com",
        "googleapis.com",
        "gstatic.com",
        "google.internal",    # GCP internal resolver — suspicious_qtype FP in GCP environments
        "tacticalrmm.io",     # TacticalRMM beaconing belongs to lateral movement, not DNS exfil
        "cqloud.com",         # Qwilt CDN lookups in this dataset; long labels but not exfiltration
        # AWS / CDN
        "amazonaws.com",
        "cloudfront.net",
        "awswaf.com",         # AWS WAF health checks — hash subdomains, entropy ~4.18
        "fastly.net",
        # Linux package managers — suspicious_qtype FP from update checks
        "ubuntu.com",
        "canonical.com",
        "launchpad.net",
        "centos.org",
        "fedoraproject.org",
        "snapcraft.io",
        "fwupd.org",
        # Misc infra seen in dataset
        "elastic.co",         # Elasticsearch telemetry — suspicious_qtype FP
        "docker.com",
        "fcix.net",           # CDN / peering exchange
        "in-addr.arpa",       # Reverse DNS lookups — expected high unique subdomain count
        "nagios.com",         # Monitoring — suspicious_qtype FP
        "openvpn.net",        # VPN client update checks
    )
    allowlist = tuple(allowlist_domain_substrings) if allowlist_domain_substrings else _default_allowlist

    # Per base-domain statistics
    # domain → internal_ip → {subdomains, timestamps, qtypes}
    domain_stats: Dict[str, Dict[str, Any]] = defaultdict(lambda: defaultdict(lambda: {
        "subdomains": [],
        "timestamps": [],
        "qtypes": [],
        "rcodes": [],
        "queries": [],
    }))

    rows_seen = 0
    workers = _parallel_workers(max_workers, len(chunk_dirs))
    if workers == 1:
        scans = [_scan_dns_chunk(c) for c in chunk_dirs]
    else:
        with ThreadPoolExecutor(max_workers=workers) as ex:
            scans = list(ex.map(_scan_dns_chunk, chunk_dirs))

    for scan in scans:
        rows_seen += int(scan["rows_seen"])
        for (base, internal_ip), entry in scan["aggregated"].items():
            target = domain_stats[base][internal_ip]
            target["subdomains"].extend(entry["subdomains"])
            target["timestamps"].extend(entry["timestamps"])
            target["qtypes"].extend(entry["qtypes"])
            target["rcodes"].extend(entry["rcodes"])
            target["queries"].extend(entry["queries"])

    # --- Build evidence per domain ---
    evidence: List[DnsEvidence] = []

    for base_domain, per_ip in domain_stats.items():
        if _is_local_or_internal_base_domain(base_domain):
            continue
        is_allowlisted = any(sub.lower() in base_domain.lower() for sub in allowlist)
        base_domain_is_suspicious = any(
            keyword in base_domain.lower() for keyword in _SUSPICIOUS_DOMAIN_KEYWORDS
        )

        for internal_ip, data in per_ip.items():
            subdomains: List[str] = data["subdomains"]
            timestamps: List[float] = data["timestamps"]
            qtypes: List[str]   = data["qtypes"]
            rcodes: List[str]   = data["rcodes"]
            queries: List[str]  = data["queries"]

            if len(timestamps) < 5 and not base_domain_is_suspicious:
                continue  # not enough data to be meaningful

            # Subdomain statistics
            if subdomains:
                lengths   = [len(s) for s in subdomains]
                entropies = [_entropy(s) for s in subdomains]
                max_len   = max(lengths)
                mean_len  = sum(lengths) / len(lengths)
                max_ent   = max(entropies)
                mean_ent  = sum(entropies) / len(entropies)
            else:
                max_len = mean_len = max_ent = mean_ent = 0.0

            # Peak query rate per bucket
            bucket_counts: Dict[int, int] = {}
            for ts in timestamps:
                b = _bucket_start(ts)
                bucket_counts[b] = bucket_counts.get(b, 0) + 1
            peak_bucket, peak_count = max(bucket_counts.items(), key=lambda x: x[1])

            suspicious_qtypes = sum(1 for q in qtypes if q in _SUSPICIOUS_QTYPES)
            unique_subs = len(set(subdomains))
            nxdomain_count = sum(1 for r in rcodes if r == "NXDOMAIN")
            nxdomain_ratio = (nxdomain_count / len(rcodes)) if rcodes else 0.0
            repeated_single_query = Counter(queries).most_common(1)[0][1] if queries else 0

            # Tag generation
            tags: List[str] = []
            if max_ent >= entropy_threshold:
                tags.append("high_entropy")
            if max_len >= label_length_threshold:
                tags.append("long_subdomain")
            if peak_count >= query_rate_threshold:
                tags.append("high_rate")
            if suspicious_qtypes > 0:
                tags.append("suspicious_qtype")
            if unique_subs > 50:
                tags.append("many_unique_subdomains")
            if base_domain_is_suspicious:
                tags.append("suspicious_domain")
            if (
                len(timestamps) >= 50
                and repeated_single_query >= 50
                and nxdomain_ratio >= 0.80
                and not is_allowlisted
            ):
                tags.append("repeated_nxdomain")
            if is_allowlisted:
                tags.append("allowlisted_domain")

            # Only surface items with at least one suspicious tag (excluding allowlist)
            suspicious_tags = [t for t in tags if t != "allowlisted_domain"]
            if not suspicious_tags:
                continue

            risk_level = _score_risk(tags) if not is_allowlisted else "LOW"

            mitre: List[Dict] = [MITRE_T1071_004.copy()]
            if "high_entropy" in tags or "long_subdomain" in tags:
                mitre.append(MITRE_T1048_003.copy())

            evidence.append(DnsEvidence(
                base_domain           = base_domain,
                internal_ip           = internal_ip,
                total_queries         = len(timestamps),
                unique_subdomains     = unique_subs,
                max_subdomain_length  = int(max_len),
                mean_subdomain_length = round(float(mean_len), 2),
                max_entropy           = round(float(max_ent), 4),
                mean_entropy          = round(float(mean_ent), 4),
                suspicious_qtype_count = suspicious_qtypes,
                bucket_start_utc      = datetime.fromtimestamp(peak_bucket, UTC).isoformat().replace("+00:00", "Z"),
                bucket_query_count    = peak_count,
                tags                  = tags,
                risk_level            = risk_level,
                mitre_techniques      = mitre,
                reason                = "dns_anomaly_detected",
            ))

    # Sort by risk then query count
    _order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    evidence.sort(key=lambda e: (_order.get(e.risk_level, 3), -e.total_queries))

    suspicious_evidence = [e for e in evidence if not any("allowlisted" in t for t in e.tags)]
    suspected = any(e.risk_level in ("HIGH", "MEDIUM") for e in suspicious_evidence)
    confidence = (
        "HIGH"   if any(e.risk_level == "HIGH" for e in suspicious_evidence) else
        "MEDIUM" if suspicious_evidence else
        "LOW"
    )

    all_mitre: Dict[str, Dict] = {}
    for e in suspicious_evidence:
        for t in e.mitre_techniques:
            all_mitre[t["id"]] = t
    mitre_summary = sorted(all_mitre.values(), key=lambda x: x["id"])

    result: Dict[str, Any] = {
        "module":                   "dns_exfiltration",
        "version":                  "tool_v1_entropy_rate",
        "suspected":                suspected,
        "confidence":               confidence,
        "mitre_techniques":         mitre_summary,
        "evidence":                 [asdict(e) for e in evidence],
        "suspicious_only_evidence": [asdict(e) for e in suspicious_evidence],
        "debug": {
            "zeek_root":            str(zeek_path),
            "zeek_root_exists":     zeek_path.exists(),
            "zeek_chunk_dirs_seen": len(chunk_dirs),
            "dns_rows_seen":        rows_seen,
            "base_domains_seen":    len(domain_stats),
            "evidence_items":       len(evidence),
            "entropy_threshold":    entropy_threshold,
            "label_length_threshold": label_length_threshold,
            "query_rate_threshold": query_rate_threshold,
            "allowlist_substrings": list(allowlist),
            "max_workers": workers,
        },
        "notes": [
            "DNS tunneling is flagged by high subdomain entropy, long labels, and query bursts.",
            "High entropy alone can be caused by CDN hash subdomains — correlate with volume.",
            "LLM should ground claims in evidence fields: base_domain, internal_ip, max_entropy.",
        ],
    }

    if write_output_path:
        out = Path(write_output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2), encoding="utf-8")

    return result
