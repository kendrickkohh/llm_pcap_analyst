"""
shared/pcap_api.py
==================
SC4063 PCAP API client extracted from sc4063_pcap_api_demo_updated.ipynb.

Responsibilities:
  1. Query the Google Apps Script API to discover available days, Zeek
     datasets, alerts, and PCAP files.
  2. Download the relevant artifacts to a local work directory.
  3. Return a populated ZeekContext for the pipeline.

The intended workflow mirrors the notebook:
    alerts / zeek_datasets → identify relevant evidence → download PCAP
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin

import requests
from tqdm.auto import tqdm

from shared.data_contract import ZeekContext
from shared.disk_manager import get_disk_manager, get_provenance, ALERT, ZEEK, PCAP
from shared.api_config import get_api_base, mark_endpoint_failed

# ──────────────────────────────────────────────────────────────────────────────
# API configuration
# ──────────────────────────────────────────────────────────────────────────────

# Zeek datasets that are most useful for each agent.
# The ingestion layer downloads ALL of these by default; agents read what
# they need from zeek_context.zeek_files.
PRIORITY_ZEEK_DATASETS = [
    "zeek.connection.ndjson",
    "zeek.dns.ndjson",
    "zeek.rdp.ndjson",
    "zeek.http.ndjson",
    "zeek.smb_files.ndjson",
    "zeek.smb_mapping.ndjson",
    "zeek.dce_rpc.ndjson",
    "zeek.kerberos.ndjson",
    "zeek.ssl.ndjson",
    "zeek.notice.ndjson",
    "zeek.weird.ndjson",         # protocol anomalies — useful for evasion detection
]


# ──────────────────────────────────────────────────────────────────────────────
# Low-level HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

def _call_api(params: dict, timeout: int = 60, retries: int = 3) -> dict:
    """GET the API endpoint with retry + failover across endpoints."""
    last_exc: Exception | None = None
    for attempt in range(1, retries + 1):
        api_base = get_api_base()
        try:
            r = requests.get(api_base, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            last_exc = exc
            mark_endpoint_failed(api_base)
            if attempt < retries:
                wait = 2 ** attempt
                print(f"  [api] Attempt {attempt} failed ({exc}). Trying next endpoint in {wait}s…")
                time.sleep(wait)
    raise RuntimeError(
        f"API call failed after {retries} attempts across all endpoints: {last_exc}"
    ) from last_exc


def _looks_like_html(response: requests.Response) -> bool:
    return "text/html" in response.headers.get("content-type", "").lower()


def _extract_confirm_url(
    html: str, base_url: str
) -> tuple[Optional[str], Optional[dict]]:
    """Extract the confirmed download URL from a Google Drive virus-scan page."""
    form_match = re.search(
        r'<form[^>]+action="([^"]+)"[^>]*>(.*?)</form>', html, re.S | re.I
    )
    if form_match:
        action = form_match.group(1)
        form_body = form_match.group(2)
        inputs = re.findall(
            r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', form_body, re.I
        )
        params = {name: value for name, value in inputs}
        if action:
            return urljoin(base_url, action), params

    href_match = re.search(r'href="([^"]*confirm[^"]*)"', html, re.I)
    if href_match:
        return urljoin(base_url, href_match.group(1)), None

    return None, None


_MIN_PCAP_SIZE = 10_000  # 10 KB — any PCAP smaller than this is corrupt/HTML

# ── Quota latch: once any public link hits quota, skip all public links ──────
_quota_latched = False


def _is_quota_error(html: str) -> bool:
    """Check if an HTML response is a Google Drive quota exceeded page."""
    lower = html.lower()
    return "quota" in lower or "can&#39;t view or download" in lower


def _extract_drive_file_id(url: str) -> Optional[str]:
    """Extract Google Drive file ID from a download URL."""
    if "id=" in url:
        return url.split("id=")[-1].split("&")[0]
    return None


def _try_authenticated_download(
    file_id: str,
    out_path: Path,
    filename: str,
    chunk_size: int = 10 * 1024 * 1024,
) -> bool:
    """
    Download a file via the authenticated Google Drive API.
    Bypasses per-file sharing quota (uses per-user API quota instead).
    Returns True on success, False if auth is unavailable.
    """
    token_path = Path(__file__).parent.parent / "oauth-token.json"
    if not token_path.exists():
        return False

    try:
        from google.oauth2.credentials import Credentials
        from google.auth.transport.requests import Request as GRequest
        from googleapiclient.discovery import build
        from googleapiclient.http import MediaIoBaseDownload

        creds = Credentials.from_authorized_user_file(str(token_path), ["https://www.googleapis.com/auth/drive"])
        if creds.expired and creds.refresh_token:
            creds.refresh(GRequest())
            token_path.write_text(creds.to_json())

        drive = build("drive", "v3", credentials=creds)
        request = drive.files().get_media(fileId=file_id)

        with open(out_path, "wb") as f:
            downloader = MediaIoBaseDownload(f, request, chunksize=chunk_size)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                if status:
                    pct = int(status.progress() * 100)
                    if pct % 20 == 0:
                        print(f"    [api-dl] {filename}: {pct}%")

        print(f"  [api-dl] {filename}: complete")
        return True
    except ImportError:
        return False
    except Exception as exc:
        print(f"  [api-dl] {filename}: failed — {exc}")
        if out_path.exists():
            out_path.unlink(missing_ok=True)
        return False


def _try_download_url(
    url: str,
    out_path: Path,
    filename: str,
    is_pcap: bool,
    chunk_size: int = 1024 * 1024,
) -> Path:
    """
    Attempt a single download from a URL.  Handles virus-scan confirm pages.
    Raises RuntimeError on quota or other failures.
    """
    session = requests.Session()
    response = session.get(url, stream=True, timeout=120)
    response.raise_for_status()

    if _looks_like_html(response):
        html = response.text

        if _is_quota_error(html):
            raise RuntimeError(f"Google Drive quota exceeded for {filename}")

        confirm_url, confirm_params = _extract_confirm_url(html, response.url)
        if not confirm_url:
            raise RuntimeError(
                "Received HTML instead of file; could not extract confirm URL."
            )
        response.close()
        response = session.get(
            confirm_url, params=confirm_params, stream=True, timeout=120
        )
        response.raise_for_status()

        if _looks_like_html(response):
            error_text = response.text[:500]
            if _is_quota_error(error_text):
                raise RuntimeError(f"Google Drive quota exceeded for {filename}")
            raise RuntimeError(
                f"Still received HTML after confirm redirect: {error_text[:200]}"
            )

    total = int(response.headers.get("content-length", 0))
    written = 0

    with open(out_path, "wb") as f, tqdm(
        total=total if total > 0 else None,
        unit="B",
        unit_scale=True,
        desc=filename,
    ) as bar:
        for chunk in response.iter_content(chunk_size=chunk_size):
            if not chunk:
                continue
            f.write(chunk)
            written += len(chunk)
            bar.update(len(chunk))

    response.close()

    if total > 0 and written != total:
        raise IOError(f"Incomplete download: expected {total} B, got {written} B")

    if is_pcap and written < _MIN_PCAP_SIZE:
        raise RuntimeError(
            f"Downloaded PCAP is too small ({written} B) — likely an error page."
        )

    return out_path


def download_file(
    url: str,
    filename: str,
    out_dir: str,
    attempts: int = 2,
    chunk_size: int = 1024 * 1024,
    resolve_alt_url: Optional[Any] = None,
) -> Path:
    """
    Download a file from a URL with Google Drive interstitial handling.
    Skips download if the file already exists and passes size validation.

    If a download hits Google Drive quota and resolve_alt_url is provided,
    it will be called to get a fresh download URL from a different API
    endpoint (which may point to a different Drive file copy with fresh quota).

    resolve_alt_url: callable(endpoint_index) -> str|None
        Returns a fresh download URL for the same logical file from a
        different API endpoint, or None if no more endpoints.
    """
    out_path = Path(out_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    is_pcap = filename.lower().endswith(".pcap")

    # Cache check — also validates that PCAPs aren't tiny HTML error pages
    if out_path.exists():
        size = out_path.stat().st_size
        if size > 0 and (not is_pcap or size > _MIN_PCAP_SIZE):
            print(f"  [cache] {filename} already downloaded — skipping.")
            return out_path
        else:
            print(f"  [cache] {filename} exists but looks corrupt ({size} B) — re-downloading.")
            out_path.unlink()

    # Build list of URLs to try: original + alternatives from other endpoints
    urls_to_try = [url]
    if resolve_alt_url:
        from shared.api_config import get_all_endpoints
        for idx in range(len(get_all_endpoints())):
            alt = resolve_alt_url(idx)
            if alt and alt != url and alt not in urls_to_try:
                urls_to_try.append(alt)

    last_error: Optional[Exception] = None
    global _quota_latched

    # ── If quota latch is set, skip all public links ─────────────────
    if _quota_latched:
        pass  # fall through to authenticated API below
    else:
        for url_idx, try_url in enumerate(urls_to_try):
            if url_idx > 0:
                print(f"  [dl] Trying endpoint {url_idx + 1}/{len(urls_to_try)} for {filename}")
            for attempt in range(1, attempts + 1):
                try:
                    print(f"  [dl] Attempt {attempt}/{attempts}: {filename}")
                    _try_download_url(try_url, out_path, filename, is_pcap, chunk_size)
                    print(f"  [dl] Saved → {out_path}")
                    return out_path

                except Exception as exc:
                    last_error = exc
                    print(f"  [dl] Attempt {attempt} failed: {exc}")
                    if out_path.exists():
                        try:
                            out_path.unlink()
                        except Exception:
                            pass

                    # On quota error, latch and skip all public links
                    if "quota" in str(exc).lower():
                        if not _quota_latched:
                            _quota_latched = True
                            print("  [dl] Quota hit — switching to authenticated API for all downloads")
                        break

                    if attempt < attempts:
                        print("  [dl] Retrying…")

    # ── Authenticated Drive API download ─────────────────────────────
    all_file_ids = set()
    for try_url in urls_to_try:
        fid = _extract_drive_file_id(try_url)
        if fid:
            all_file_ids.add(fid)

    for fid in all_file_ids:
        print(f"  [dl] Trying authenticated Drive API for {filename} (id={fid[:15]}...)")
        if _try_authenticated_download(fid, out_path, filename):
            # Validate
            if out_path.exists():
                size = out_path.stat().st_size
                if size > 0 and (not is_pcap or size > _MIN_PCAP_SIZE):
                    print(f"  [dl] Saved → {out_path}")
                    return out_path
                else:
                    out_path.unlink(missing_ok=True)

    raise RuntimeError(
        f"Download failed for {filename} after trying {len(urls_to_try)} endpoint(s) + API"
    ) from last_error


def _make_alt_resolver(api_params: dict, url_extractor) -> Any:
    """
    Build a resolve_alt_url callback for download_file.

    api_params  : params to send to each API endpoint (e.g. {"action": "alerts", "day": "..."})
    url_extractor : callable(response_json) -> str|None  — extracts the download URL from the response

    Returns a function(endpoint_index) -> str|None that queries each
    API endpoint for an alternative Drive file URL.
    """
    def resolver(ep_idx):
        from shared.api_config import get_all_endpoints
        eps = get_all_endpoints()
        if ep_idx >= len(eps):
            return None
        try:
            r = requests.get(eps[ep_idx], params=api_params, timeout=30)
            return url_extractor(r.json())
        except Exception:
            return None
    return resolver


# ──────────────────────────────────────────────────────────────────────────────
# High-level API wrappers
# ──────────────────────────────────────────────────────────────────────────────

def list_days() -> list[dict]:
    """Return available shard days as [{"day": "YYYY-MM-DD", "shortDay": "YYMMDD"}, …]."""
    data = _call_api({"action": "days"})
    return data.get("days", [])


def get_alerts_metadata(day: str) -> dict:
    """Return file metadata dict for alerts.ndjson on the given day."""
    data = _call_api({"action": "alerts", "day": day})
    return data.get("file", {})


def list_zeek_datasets(day: str) -> list[dict]:
    """Return list of Zeek dataset file metadata dicts for the given day."""
    data = _call_api({"action": "zeek_datasets", "day": day})
    return data.get("datasets", [])


def get_zeek_file_metadata(day: str, dataset_name: str) -> Optional[dict]:
    """Return file metadata for a specific Zeek dataset by name."""
    data = _call_api({"action": "zeek_file", "day": day, "dataset": dataset_name})
    return data.get("file")


def list_pcaps(day: str) -> list[dict]:
    """Return list of PCAP file metadata dicts for the given day."""
    data = _call_api({"action": "pcaps", "day": day})
    return data.get("pcaps", [])


def get_file_metadata(file_id: str) -> dict:
    """Return metadata for any file by its Drive file ID."""
    data = _call_api({"action": "file", "id": file_id})
    return data.get("file", {})


# ──────────────────────────────────────────────────────────────────────────────
# Ingestion orchestrator — called by the pipeline's ingest node
# ──────────────────────────────────────────────────────────────────────────────

def ingest_day(
    day: str,
    work_dir: str = "data",
    zeek_datasets: Optional[list[str]] = None,
    pcap_index: int = 0,
    skip_zeek: bool = False,
) -> ZeekContext:
    """
    Full ingestion for a given day:
      1. Download alerts.ndjson
      2. Download requested Zeek datasets (default: PRIORITY_ZEEK_DATASETS)
      3. Download one PCAP (pcap_index selects which one from the day's list)

    Returns a ZeekContext ready to be stored in PipelineState.

    Parameters
    ----------
    day         : "YYYY-MM-DD"
    work_dir    : scratch directory for all downloads
    zeek_datasets : list of dataset names to download; None = PRIORITY_ZEEK_DATASETS
    pcap_index  : which PCAP to pick from the day's list (0 = first)
    skip_zeek   : if True, skip Zeek downloads (useful when resuming)
    """
    datasets_to_fetch = zeek_datasets or PRIORITY_ZEEK_DATASETS
    day_dir = Path(work_dir) / day
    day_dir.mkdir(parents=True, exist_ok=True)

    print(f"\n{'═' * 60}")
    print(f"  SC4063 PCAP Ingestion — Day: {day}")
    print(f"  Work dir: {day_dir}")
    print(f"{'═' * 60}\n")

    # ── 1. Alerts ──────────────────────────────────────────────────────────
    print("[1/3] Fetching alerts.ndjson…")
    alerts_meta = get_alerts_metadata(day)
    alerts_path: Optional[str] = None
    if alerts_meta.get("downloadUrl"):
        p = download_file(
            alerts_meta["downloadUrl"],
            "alerts.ndjson",
            str(day_dir),
            resolve_alt_url=_make_alt_resolver(
                {"action": "alerts", "day": day},
                lambda j: j.get("file", {}).get("downloadUrl"),
            ),
        )
        alerts_path = str(p)
        dm = get_disk_manager()
        if dm:
            dm.register(str(p), ALERT, day)
    else:
        print("  [!] No alerts file found for this day.")

    # ── 2. Zeek datasets ───────────────────────────────────────────────────
    zeek_files: dict[str, str] = {}
    if not skip_zeek:
        print(f"\n[2/3] Fetching {len(datasets_to_fetch)} Zeek datasets…")
        available = {ds["name"]: ds for ds in list_zeek_datasets(day)}
        for name in datasets_to_fetch:
            if name not in available:
                print(f"  [skip] {name} not available for {day}")
                continue
            meta = available[name]
            p = download_file(
                meta["downloadUrl"],
                name,
                str(day_dir / "zeek"),
                resolve_alt_url=_make_alt_resolver(
                    {"action": "zeek_file", "day": day, "dataset": name},
                    lambda j: j.get("file", {}).get("downloadUrl"),
                ),
            )
            zeek_files[name] = str(p)
            dm = get_disk_manager()
            if dm:
                dm.register(str(p), ZEEK, day)
    else:
        print("\n[2/3] Skipping Zeek downloads (skip_zeek=True).")

    # ── 3. PCAP ────────────────────────────────────────────────────────────
    print(f"\n[3/3] Fetching PCAP (index={pcap_index})…")
    pcaps = list_pcaps(day)
    if not pcaps:
        raise RuntimeError(f"No PCAPs available for day {day}")

    chosen = pcaps[min(pcap_index, len(pcaps) - 1)]
    print(f"  Chosen: {chosen.get('name')} ({chosen.get('size', 0) / 1e6:.1f} MB)")

    pcap_path = download_file(
        chosen["downloadUrl"],
        chosen["name"],
        str(day_dir / "pcap"),
        resolve_alt_url=_make_alt_resolver(
            {"action": "pcaps", "day": day},
            lambda j: j.get("pcaps", [{}])[min(pcap_index, len(j.get("pcaps", [{}])) - 1)].get("downloadUrl"),
        ),
    )
    dm = get_disk_manager()
    if dm:
        dm.register(str(pcap_path), PCAP, day)
    prov = get_provenance()
    if prov:
        prov.record_pcap(day, chosen.get("name", ""), str(pcap_path), chosen.get("size", 0))

    ctx = ZeekContext(
        day=day,
        pcap_path=str(pcap_path),
        alerts_path=alerts_path,
        zeek_files=zeek_files,
        pcap_metadata=chosen,
    )

    print(f"\n✓ Ingestion complete for {day}")
    print(f"  PCAP      : {ctx.pcap_path}")
    print(f"  Alerts    : {ctx.alerts_path or 'n/a'}")
    print(f"  Zeek logs : {len(ctx.zeek_files)} files")
    return ctx


# ──────────────────────────────────────────────────────────────────────────────
# Zeek log streaming helpers — used by agents
# ──────────────────────────────────────────────────────────────────────────────

def stream_zeek(zeek_path: str, max_lines: int = 5000):
    """
    Generator: yield parsed NDJSON records from a Zeek log file.
    Stops after max_lines records.
    """
    count = 0
    with open(zeek_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue
            count += 1
            if count >= max_lines:
                break


def summarise_zeek_dns(
    zeek_path: str,
    max_lines: int = 50_000,
    top_n: int = 30,
) -> dict[str, Any]:
    """
    Quick statistical summary of a Zeek DNS log.
    Returns a dict with top queried domains, unique resolvers, etc.
    """
    from collections import Counter
    query_counter: Counter = Counter()
    resolver_counter: Counter = Counter()
    total = 0

    for rec in stream_zeek(zeek_path, max_lines=max_lines):
        total += 1
        q = rec.get("query") or rec.get("dns.qry.name")
        src = rec.get("id.orig_h") or rec.get("ip.src")
        if q:
            query_counter[q] += 1
        if src:
            resolver_counter[src] += 1

    return {
        "total_dns_records": total,
        "top_queries": query_counter.most_common(top_n),
        "top_resolvers": resolver_counter.most_common(top_n),
    }


def summarise_zeek_connections(
    zeek_path: str,
    max_lines: int = 100_000,
    top_n: int = 20,
) -> dict[str, Any]:
    """
    Quick summary of Zeek connection log: top talkers, top ports, protocols.
    """
    from collections import Counter
    src_counter: Counter = Counter()
    dst_counter: Counter = Counter()
    port_counter: Counter = Counter()
    proto_counter: Counter = Counter()
    total_bytes = 0
    total = 0

    for rec in stream_zeek(zeek_path, max_lines=max_lines):
        total += 1
        src = rec.get("id.orig_h") or rec.get("id", {}).get("orig_h", "")
        dst = rec.get("id.resp_h") or rec.get("id", {}).get("resp_h", "")
        dport = rec.get("id.resp_p") or rec.get("id", {}).get("resp_p")
        proto = rec.get("proto", "")
        ob = rec.get("orig_bytes", 0) or 0
        rb = rec.get("resp_bytes", 0) or 0

        if src:
            src_counter[src] += 1
        if dst:
            dst_counter[dst] += 1
        if dport:
            port_counter[str(dport)] += 1
        if proto:
            proto_counter[proto] += 1
        total_bytes += ob + rb

    return {
        "total_connections": total,
        "total_bytes": total_bytes,
        "top_sources": src_counter.most_common(top_n),
        "top_destinations": dst_counter.most_common(top_n),
        "top_ports": port_counter.most_common(top_n),
        "protocols": dict(proto_counter),
    }


# ──────────────────────────────────────────────────────────────────────────────
# Two-phase ingestion: logs first, then smart PCAP selection
# ──────────────────────────────────────────────────────────────────────────────

def ingest_all_alerts(
    work_dir: str = "data",
) -> dict[str, dict]:
    """
    Phase 1: Download ONLY Suricata alerts for ALL available days.
    Zeek logs are deferred to Phase 3 (only for selected days).
    Returns {day: {"alerts_path": ..., "zeek_files": {}}} for each day.
    """
    days_meta = list_days()
    if not days_meta:
        raise RuntimeError("No days returned from API.")

    days = [d["day"] for d in days_meta]
    print(f"\n{'═' * 60}")
    print(f"  Phase 1: Downloading Suricata alerts for {len(days)} days")
    print(f"  Days: {days[0]} → {days[-1]}")
    print(f"{'═' * 60}\n")

    all_logs: dict[str, dict] = {}

    for i, day in enumerate(days):
        day_dir = Path(work_dir) / day
        day_dir.mkdir(parents=True, exist_ok=True)

        print(f"  [{i+1}/{len(days)}] {day}", end="")

        alerts_path: Optional[str] = None
        alerts_meta = get_alerts_metadata(day)
        if alerts_meta.get("downloadUrl"):
            p = download_file(
                alerts_meta["downloadUrl"], "alerts.ndjson", str(day_dir),
                resolve_alt_url=_make_alt_resolver(
                    {"action": "alerts", "day": day},
                    lambda j: j.get("file", {}).get("downloadUrl"),
                ),
            )
            alerts_path = str(p)
            dm = get_disk_manager()
            if dm:
                dm.register(str(p), ALERT, day)
            print(f"  ✓")
        else:
            print(f"  [!] No alerts file")

        all_logs[day] = {
            "alerts_path": alerts_path,
            "zeek_files": {},
        }
    print(f"\n  ✓ Phase 1 complete: alerts downloaded for {len(all_logs)} days")
    return all_logs


def download_zeek_for_days(
    days: list[str],
    work_dir: str = "data",
    zeek_datasets: Optional[list[str]] = None,
) -> dict[str, dict[str, str]]:
    """
    Phase 3b: Download Zeek logs only for the selected days.
    Returns {day: {"zeek.connection.ndjson": "/path/...", ...}}
    """
    datasets_to_fetch = zeek_datasets or PRIORITY_ZEEK_DATASETS

    print(f"\n{'═' * 60}")
    print(f"  Phase 3b: Downloading Zeek logs for {len(days)} selected days")
    print(f"{'═' * 60}")

    result: dict[str, dict[str, str]] = {}

    for i, day in enumerate(days):
        day_dir = Path(work_dir) / day
        day_dir.mkdir(parents=True, exist_ok=True)

        print(f"\n  [{i+1}/{len(days)}] {day}")

        zeek_files: dict[str, str] = {}
        available = {ds["name"]: ds for ds in list_zeek_datasets(day)}
        for name in datasets_to_fetch:
            if name not in available:
                continue
            meta = available[name]

            p = download_file(
                meta["downloadUrl"], name, str(day_dir / "zeek"),
                resolve_alt_url=_make_alt_resolver(
                    {"action": "zeek_file", "day": day, "dataset": name},
                    lambda j: j.get("file", {}).get("downloadUrl"),
                ),
            )
            zeek_files[name] = str(p)
            dm = get_disk_manager()
            if dm:
                dm.register(str(p), ZEEK, day)

        result[day] = zeek_files
        prov = get_provenance()
        if prov:
            prov.record_zeek_files(day, list(zeek_files.keys()))
        print(f"    ✓ {len(zeek_files)} Zeek files")

    print(f"\n  ✓ Phase 3b complete: Zeek logs for {len(result)} days")
    return result


def score_alerts(
    all_logs: dict[str, dict],
    top_n_ips: int = 10,
) -> dict[str, Any]:
    """
    Analyse Suricata alerts across all days.
    Returns a scoring summary with top suspect IPs and per-day per-hour
    alert density for PCAP selection.

    Returns:
        {
            "suspect_ips": [{"ip": ..., "score": ..., "alert_count": ..., "signatures": [...]}, ...],
            "per_day": {
                "2025-03-01": {
                    "total_alerts": ...,
                    "hourly_density": {"2025-03-01T18": count, ...},
                    "suspect_hourly": {"2025-03-01T18": count, ...},
                }
            }
        }
    """
    from collections import Counter

    # Accumulate across all days
    ip_scores: dict[str, int] = {}
    ip_counts: Counter = Counter()
    ip_signatures: dict[str, Counter] = {}
    per_day: dict[str, dict] = {}

    for day, logs in sorted(all_logs.items()):
        alerts_path = logs.get("alerts_path")
        if not alerts_path or not Path(alerts_path).exists():
            per_day[day] = {"total_alerts": 0, "hourly_density": {}, "suspect_hourly": {}}
            continue

        hourly: Counter = Counter()
        day_count = 0

        with open(alerts_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except json.JSONDecodeError:
                    continue

                day_count += 1
                ip = a.get("source", {}).get("ip", "")
                sev = a.get("event", {}).get("severity", 3)
                sig = a.get("rule", {}).get("name", "")
                ts = a.get("@timestamp", "")[:13]  # "YYYY-MM-DDTHH"

                # Score: severity 1 = 3 pts, 2 = 2 pts, 3 = 1 pt
                score = max(1, 4 - sev)
                ip_scores[ip] = ip_scores.get(ip, 0) + score
                ip_counts[ip] += 1

                if ip not in ip_signatures:
                    ip_signatures[ip] = Counter()
                ip_signatures[ip][sig] += 1

                if ts:
                    hourly[ts] += 1

        per_day[day] = {
            "total_alerts": day_count,
            "hourly_density": dict(sorted(hourly.items())),
        }

    # Rank IPs by score
    ranked = sorted(ip_scores.items(), key=lambda x: -x[1])[:top_n_ips]
    suspect_ips = []
    suspect_ip_set = set()
    for ip, score in ranked:
        suspect_ip_set.add(ip)
        top_sigs = [sig for sig, _ in ip_signatures.get(ip, Counter()).most_common(5)]
        suspect_ips.append({
            "ip": ip,
            "score": score,
            "alert_count": ip_counts[ip],
            "top_signatures": top_sigs,
        })

    # Re-scan to build suspect-IP hourly density per day
    for day, logs in sorted(all_logs.items()):
        alerts_path = logs.get("alerts_path")
        if not alerts_path or not Path(alerts_path).exists():
            per_day[day]["suspect_hourly"] = {}
            continue

        suspect_hourly: Counter = Counter()
        with open(alerts_path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    a = json.loads(line)
                except json.JSONDecodeError:
                    continue
                ip = a.get("source", {}).get("ip", "")
                ts = a.get("@timestamp", "")[:13]
                if ip in suspect_ip_set and ts:
                    suspect_hourly[ts] += 1

        per_day[day]["suspect_hourly"] = dict(sorted(suspect_hourly.items()))

    return {
        "suspect_ips": suspect_ips,
        "per_day": per_day,
    }


def score_all_pcaps(
    scoring: dict[str, Any],
) -> list[dict]:
    """
    Phase 2: Score every PCAP across all days by suspect-IP alert density.

    Returns a globally ranked list (highest score first):
    [
        {"day": "2025-03-01", "pcap_index": 2, "pcap_name": "...", "score": 1450, "size_mb": 396.7},
        {"day": "2025-03-01", "pcap_index": 5, "pcap_name": "...", "score": 1100, "size_mb": 330.4},
        ...
    ]

    PCAPs with score 0 are excluded.
    """
    per_day = scoring.get("per_day", {})
    all_scored: list[dict] = []

    for day in sorted(per_day.keys()):
        day_info = per_day[day]
        suspect_hourly = day_info.get("suspect_hourly", {})

        pcaps = list_pcaps(day)
        if not pcaps:
            continue
        n_pcaps = len(pcaps)

        if not suspect_hourly:
            continue

        hours = sorted(suspect_hourly.keys())
        if not hours:
            continue

        # Map hours to PCAP buckets proportionally
        bucket_scores: dict[int, int] = {}
        for i, hour in enumerate(hours):
            pcap_idx = min(int(i * n_pcaps / len(hours)), n_pcaps - 1)
            bucket_scores[pcap_idx] = bucket_scores.get(pcap_idx, 0) + suspect_hourly[hour]

        for pcap_idx, pcap_score in bucket_scores.items():
            if pcap_score <= 0:
                continue
            pcap_meta = pcaps[pcap_idx]
            all_scored.append({
                "day": day,
                "pcap_index": pcap_idx,
                "pcap_name": pcap_meta.get("name", ""),
                "score": pcap_score,
                "size_mb": round(pcap_meta.get("size", 0) / 1e6, 1),
            })

    # Sort globally by score descending
    all_scored.sort(key=lambda x: -x["score"])
    return all_scored


def download_selected_pcaps(
    chosen_pcaps: list[dict],
    work_dir: str = "data",
) -> dict[str, list[str]]:
    """
    Phase 3: Download PCAPs from the chosen list.

    Parameters
    ----------
    chosen_pcaps : list of dicts from score_all_pcaps(), each with
                   "day", "pcap_index", "pcap_name", "score", "size_mb"
    work_dir     : scratch directory

    Returns: {"2025-03-01": ["/tmp/.../pcap1.pcap"], ...}
    """
    result: dict[str, list[str]] = {}
    total = len(chosen_pcaps)

    total_mb = sum(p.get("size_mb", 0) for p in chosen_pcaps)
    print(f"\n{'═' * 60}")
    print(f"  Phase 3: Downloading {total} selected PCAPs ({total_mb:.0f} MB)")
    print(f"{'═' * 60}")

    # Group by day to batch API calls
    by_day: dict[str, list[dict]] = {}
    for p in chosen_pcaps:
        by_day.setdefault(p["day"], []).append(p)

    downloaded = 0
    for day in sorted(by_day.keys()):
        pcap_list = list_pcaps(day)
        if not pcap_list:
            print(f"  [!] No PCAPs available for {day}")
            result[day] = []
            continue

        day_dir = Path(work_dir) / day / "pcap"
        day_paths: list[str] = []

        for entry in by_day[day]:
            idx = entry["pcap_index"]
            chosen = pcap_list[min(idx, len(pcap_list) - 1)]
            downloaded += 1
            print(f"\n  [{downloaded}/{total}] {day} PCAP[{idx}]: "
                  f"{chosen.get('name')} ({chosen.get('size', 0) / 1e6:.0f} MB)  "
                  f"score={entry['score']}")
            try:
                p = download_file(
                    chosen["downloadUrl"],
                    chosen["name"],
                    str(day_dir),
                    resolve_alt_url=_make_alt_resolver(
                        {"action": "pcaps", "day": day},
                        lambda j, _idx=idx: (
                            j.get("pcaps", [{}])[min(_idx, len(j.get("pcaps", [{}])) - 1)].get("downloadUrl")
                            if j.get("pcaps") else None
                        ),
                    ),
                )
                day_paths.append(str(p))
                dm = get_disk_manager()
                if dm:
                    dm.register(str(p), PCAP, day)
                prov = get_provenance()
                if prov:
                    prov.record_pcap(day, chosen.get("name", ""), str(p), chosen.get("size", 0))
            except RuntimeError as exc:
                print(f"  [!] Skipping {chosen.get('name')}: {exc}")

        result.setdefault(day, []).extend(day_paths)

    print(f"\n  ✓ Phase 3 complete: {downloaded} PCAPs downloaded")
    return result
