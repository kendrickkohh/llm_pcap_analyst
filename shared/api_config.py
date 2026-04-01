"""
shared/api_config.py
====================
Centralised API endpoint configuration with automatic failover.

All API calls in the pipeline should use get_api_base() instead of
hardcoding URLs.  If the current endpoint fails (quota, 5xx, timeout),
call mark_endpoint_failed() to rotate to the next one.
"""

from __future__ import annotations

import time
from typing import Optional

# ── Endpoint pool (add more as needed) ────────────────────────────────────────

_API_ENDPOINTS = [
    (
        "https://script.google.com/macros/s/"
        "AKfycbxmTGLe87Im3GX8E-KInQmp4HIMX4zraA_0iJ7HBClBkKB7PvEJ_qFVzuGett9OWNGF/exec"
    ),
    (
        "https://script.google.com/macros/s/"
        "AKfycbwrFlDKFqYduZb0TE-iFs5ZAvqsCN48pHtonDpmc7JLcQuAnrYgZq0smg8RD18rzxmEdw/exec"
    ),
]

_current_index: int = 0
_fail_until: dict[int, float] = {}  # index → epoch when cooldown expires

_COOLDOWN_SECONDS = 300  # 5 min cooldown before retrying a failed endpoint


def get_api_base() -> str:
    """Return the current active API endpoint URL."""
    global _current_index
    now = time.time()

    # If current endpoint is in cooldown, try to find one that isn't
    if _current_index in _fail_until and _fail_until[_current_index] > now:
        for i in range(len(_API_ENDPOINTS)):
            if i not in _fail_until or _fail_until[i] <= now:
                _current_index = i
                print(f"  [api] Switched to endpoint {i + 1}/{len(_API_ENDPOINTS)}")
                break

    return _API_ENDPOINTS[_current_index]


def mark_endpoint_failed(url: Optional[str] = None):
    """
    Mark an endpoint as temporarily failed.  Rotates to the next one.

    Call this when you get a quota error, 5xx, or persistent timeout.
    """
    global _current_index
    now = time.time()

    if url:
        # Find the index of the failed URL
        for i, ep in enumerate(_API_ENDPOINTS):
            if ep == url:
                _fail_until[i] = now + _COOLDOWN_SECONDS
                break
    else:
        _fail_until[_current_index] = now + _COOLDOWN_SECONDS

    # Rotate to next available endpoint
    for i in range(len(_API_ENDPOINTS)):
        candidate = ((_current_index + 1 + i) % len(_API_ENDPOINTS))
        if candidate not in _fail_until or _fail_until[candidate] <= now:
            _current_index = candidate
            print(f"  [api] Endpoint failed, switched to {candidate + 1}/{len(_API_ENDPOINTS)}")
            return

    # All endpoints in cooldown — use the one whose cooldown expires soonest
    soonest = min(_fail_until, key=_fail_until.get)
    _current_index = soonest
    print(f"  [api] All endpoints in cooldown, using {soonest + 1}/{len(_API_ENDPOINTS)}")


def get_all_endpoints() -> list[str]:
    """Return all configured endpoint URLs."""
    return list(_API_ENDPOINTS)


def endpoint_count() -> int:
    return len(_API_ENDPOINTS)
