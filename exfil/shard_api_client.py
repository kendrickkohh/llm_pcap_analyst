from __future__ import annotations

import json
import re
from http.cookiejar import CookieJar
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlencode, urljoin, urlparse, parse_qsl
from urllib.request import HTTPCookieProcessor, Request, build_opener


DEFAULT_API_BASE_URL = (
    "https://script.google.com/macros/s/"
    "AKfycbxpkayBZGiYl-dbQ1P8SpLmjn4P8F9ZhPg3djTMSIv9Aj3C106uiOsRTC9zWQ2w0nl6/exec"
)

_DEFAULT_ZEEK_DATASETS = [
    "zeek.connection.ndjson",
    "zeek.dns.ndjson",
    "zeek.ssl.ndjson",
    "zeek.http.ndjson",
    "zeek.files.ndjson",
]
_DATASET_ALIASES = {
    "conn": "zeek.connection.ndjson",
    "connection": "zeek.connection.ndjson",
    "dns": "zeek.dns.ndjson",
    "ssl": "zeek.ssl.ndjson",
    "http": "zeek.http.ndjson",
    "files": "zeek.files.ndjson",
}
_LOCAL_DATASET_FILENAMES = {
    "zeek.connection.ndjson": "conn.log",
    "zeek.dns.ndjson": "dns.log",
    "zeek.ssl.ndjson": "ssl.log",
    "zeek.http.ndjson": "http.log",
    "zeek.files.ndjson": "files.log",
}


def _build_opener():
    return build_opener(HTTPCookieProcessor(CookieJar()))


def _normalize_dataset_name(dataset: str) -> str:
    key = dataset.strip().lower()
    return _DATASET_ALIASES.get(key, dataset.strip())


def _dataset_to_local_filename(dataset: str) -> str:
    normalized = _normalize_dataset_name(dataset)
    if normalized in _LOCAL_DATASET_FILENAMES:
        return _LOCAL_DATASET_FILENAMES[normalized]
    suffix = normalized
    if suffix.startswith("zeek."):
        suffix = suffix[len("zeek."):]
    if suffix.endswith(".ndjson"):
        suffix = suffix[:-len(".ndjson")]
    return f"{suffix}.log"


def _fetch_json(base_url: str, params: Dict[str, Any], timeout_seconds: int = 60) -> Dict[str, Any]:
    query = urlencode({k: v for k, v in params.items() if v is not None})
    url = f"{base_url}?{query}"
    request = Request(url, headers={"Accept": "application/json"})
    with _build_opener().open(request, timeout=timeout_seconds) as response:
        return json.loads(response.read().decode("utf-8"))


def _extract_confirm_download_url(html: str, base_url: str) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    form_match = re.search(r'<form[^>]+action="([^"]+)"[^>]*>(.*?)</form>', html, re.S | re.I)
    if form_match:
        action = form_match.group(1)
        form_body = form_match.group(2)
        inputs = re.findall(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', form_body, re.I)
        params = {name: value for name, value in inputs}
        if action:
            return urljoin(base_url, action), params

    href_match = re.search(r'href="([^"]*confirm[^"]*)"', html, re.I)
    if href_match:
        return urljoin(base_url, href_match.group(1)), None

    return None, None


def _append_query_params(url: str, params: Dict[str, str]) -> str:
    parsed = urlparse(url)
    query = dict(parse_qsl(parsed.query))
    query.update(params)
    encoded = urlencode(query)
    return parsed._replace(query=encoded).geturl()


def _download_file(url: str, destination: Path, timeout_seconds: int = 120) -> Path:
    opener = _build_opener()
    destination.parent.mkdir(parents=True, exist_ok=True)

    request = Request(url)
    with opener.open(request, timeout=timeout_seconds) as response:
        content_type = response.headers.get("Content-Type", "").lower()
        payload = response.read()

    if "text/html" in content_type:
        html = payload.decode("utf-8", errors="replace")
        confirm_url, confirm_params = _extract_confirm_download_url(html, url)
        if not confirm_url:
            raise RuntimeError("Received HTML instead of file bytes and could not extract a confirmed download URL.")
        if confirm_params:
            confirm_url = _append_query_params(confirm_url, confirm_params)
        with opener.open(Request(confirm_url), timeout=timeout_seconds) as response:
            payload = response.read()

    destination.write_bytes(payload)
    return destination


def download_zeek_day(
    *,
    base_url: str = DEFAULT_API_BASE_URL,
    day: str,
    zeek_root: str = "zeek_out",
    datasets: Optional[List[str]] = None,
    timeout_seconds: int = 60,
) -> Dict[str, Any]:
    requested = [_normalize_dataset_name(name) for name in (datasets or _DEFAULT_ZEEK_DATASETS)]
    dataset_listing = _fetch_json(
        base_url,
        {"action": "zeek_datasets", "day": day},
        timeout_seconds=timeout_seconds,
    )
    available = [
        str(item.get("name"))
        for item in dataset_listing.get("datasets", [])
        if item.get("name")
    ]

    target_root = Path(zeek_root)
    if not target_root.is_absolute():
        target_root = (Path.cwd() / target_root).resolve()
    day_root = target_root / f"api_{day}"
    day_root.mkdir(parents=True, exist_ok=True)

    downloaded_files: List[Dict[str, str]] = []
    missing_datasets: List[str] = []

    for dataset in requested:
        if dataset not in available:
            missing_datasets.append(dataset)
            continue
        file_data = _fetch_json(
            base_url,
            {"action": "zeek_file", "day": day, "dataset": dataset},
            timeout_seconds=timeout_seconds,
        )
        file_info = file_data.get("file") or {}
        download_url = file_info.get("downloadUrl")
        if not download_url:
            raise RuntimeError(f"API response for dataset {dataset!r} did not include downloadUrl.")
        destination = day_root / _dataset_to_local_filename(dataset)
        _download_file(str(download_url), destination, timeout_seconds=max(timeout_seconds, 120))
        downloaded_files.append({
            "dataset": dataset,
            "path": str(destination),
            "download_url": str(download_url),
        })

    success = bool(downloaded_files)
    if success and missing_datasets:
        message = (
            f"Downloaded {len(downloaded_files)} dataset(s) for {day}; "
            f"missing {len(missing_datasets)} requested dataset(s)."
        )
    elif success:
        message = f"Downloaded {len(downloaded_files)} dataset(s) for {day}."
    else:
        message = f"No requested Zeek datasets were available for {day}."

    return {
        "success": success,
        "message": message,
        "day": day,
        "api_base_url": base_url,
        "available_datasets": available,
        "requested_datasets": requested,
        "missing_datasets": missing_datasets,
        "downloaded_files": downloaded_files,
        "zeek_root": str(day_root),
    }
