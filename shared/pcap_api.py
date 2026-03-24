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

# ──────────────────────────────────────────────────────────────────────────────
# API configuration
# ──────────────────────────────────────────────────────────────────────────────

API_BASE = (
    "https://script.google.com/macros/s/"
    "AKfycbxpkayBZGiYl-dbQ1P8SpLmjn4P8F9ZhPg3djTMSIv9Aj3C106uiOsRTC9zWQ2w0nl6/exec"
)

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
    "zeek.ntlm.ndjson",
    "zeek.kerberos.ndjson",
    "zeek.ssl.ndjson",
    "zeek.notice.ndjson",
]


# ──────────────────────────────────────────────────────────────────────────────
# Low-level HTTP helpers
# ──────────────────────────────────────────────────────────────────────────────

def _call_api(params: dict, timeout: int = 60, retries: int = 3) -> dict:
    """GET the API endpoint with retry logic."""
    for attempt in range(1, retries + 1):
        try:
            r = requests.get(API_BASE, params=params, timeout=timeout)
            r.raise_for_status()
            return r.json()
        except Exception as exc:
            if attempt == retries:
                raise RuntimeError(
                    f"API call failed after {retries} attempts: {exc}"
                ) from exc
            wait = 2 ** attempt
            print(f"  [api] Attempt {attempt} failed ({exc}). Retrying in {wait}s…")
            time.sleep(wait)


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


def download_file(
    url: str,
    filename: str,
    out_dir: str,
    attempts: int = 2,
    chunk_size: int = 1024 * 1024,
) -> Path:
    """
    Download a file from a URL with Google Drive interstitial handling.
    Skips download if the file already exists and is non-empty.
    """
    out_path = Path(out_dir) / filename
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if out_path.exists() and out_path.stat().st_size > 0:
        print(f"  [cache] {filename} already downloaded — skipping.")
        return out_path

    session = requests.Session()
    last_error: Optional[Exception] = None

    for attempt in range(1, attempts + 1):
        try:
            print(f"  [dl] Attempt {attempt}/{attempts}: {filename}")
            response = session.get(url, stream=True, timeout=120)
            response.raise_for_status()

            if _looks_like_html(response):
                html = response.text
                confirm_url, confirm_params = _extract_confirm_url(
                    html, response.url
                )
                if not confirm_url:
                    raise RuntimeError(
                        "Received HTML instead of file; could not extract confirm URL."
                    )
                response.close()
                response = session.get(
                    confirm_url, params=confirm_params, stream=True, timeout=120
                )
                response.raise_for_status()

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
                raise IOError(
                    f"Incomplete download: expected {total} B, got {written} B"
                )

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
            if attempt < attempts:
                print("  [dl] Retrying…")

    raise RuntimeError(
        f"Download failed after {attempts} attempts"
    ) from last_error


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
    work_dir: str = "/tmp/sc4063",
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
        )
        alerts_path = str(p)
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
            )
            zeek_files[name] = str(p)
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
    )

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
