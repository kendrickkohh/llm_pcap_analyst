# src/pcap_ingestor.py
"""
PCAP → Zeek log ingestion helper.

Converts one or more PCAP files into Zeek JSON logs under zeek_out/<chunk_NNNN>/.
The resulting directory structure is consumed by exfiltration_tool and dns_exfiltration.

Requires Zeek (https://zeek.org/get-zeek/) to be installed and in PATH.
Optionally uses mergecap (ships with Wireshark) to combine multiple PCAPs before processing.
"""
from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

_ZEEK_NAMES = ("zeek", "bro")  # "bro" is the legacy name for Zeek
_ZEEK_JSON_FLAG = "LogAscii::use_json=T"
_DEFAULT_SCRIPTS = ["local"]


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------

def check_zeek_available() -> Tuple[bool, str]:
    """Return (True, version_string) if Zeek is installed, else (False, reason)."""
    zeek = _find_binary(_ZEEK_NAMES)
    if not zeek:
        return False, (
            "Zeek not found in PATH. "
            "Install guide: https://docs.zeek.org/en/master/install.html"
        )
    try:
        r = subprocess.run([zeek, "--version"], capture_output=True, text=True, timeout=10)
        version = (r.stdout or r.stderr).strip().splitlines()[0]
        return True, version
    except Exception as exc:
        return False, str(exc)


def ingest_pcaps(
    pcap_paths: List[str],
    zeek_out: str = "zeek_out",
    zeek_scripts: Optional[List[str]] = None,
    merge_first: bool = True,
    timeout_seconds: int = 600,
    clear_existing: bool = True,
) -> Tuple[bool, str, Path]:
    """
    Convert PCAP file(s) into Zeek JSON logs.

    Parameters
    ----------
    pcap_paths      : One or more paths to .pcap / .pcapng files.
    zeek_out        : Output root directory (default: "zeek_out").
    zeek_scripts    : Zeek scripts to load (default: ["local"]).
    merge_first     : If True and multiple PCAPs, attempt to merge with mergecap
                      before processing (produces a single chunk_0001 dir).
                      Falls back to per-file chunks if mergecap is unavailable.
    timeout_seconds : Per-Zeek-run timeout.
    clear_existing  : If True, remove any existing chunk_* directories in zeek_out
                      before ingesting. Prevents stale multi-run data from being
                      mixed into a new analysis.

    Returns
    -------
    (success, message, zeek_out_path)
    """
    zeek_bin = _find_binary(_ZEEK_NAMES)
    if not zeek_bin:
        return False, "Zeek not found in PATH.", Path(zeek_out)

    pcap_files = [Path(p).resolve() for p in pcap_paths]
    missing = [str(p) for p in pcap_files if not p.exists()]
    if missing:
        return False, f"PCAP file(s) not found: {missing}", Path(zeek_out)

    out_root = Path(zeek_out).resolve()
    scripts = zeek_scripts if zeek_scripts is not None else _DEFAULT_SCRIPTS

    if clear_existing and out_root.exists():
        for child in out_root.iterdir():
            if child.is_dir() and child.name.startswith("chunk_"):
                shutil.rmtree(child, ignore_errors=True)
            elif child.is_file() and child.name == "_merged_tmp.pcap":
                child.unlink(missing_ok=True)

    if merge_first and len(pcap_files) > 1:
        return _ingest_merged(pcap_files, out_root, zeek_bin, scripts, timeout_seconds)
    return _ingest_individual(pcap_files, out_root, zeek_bin, scripts, timeout_seconds)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _find_binary(names: tuple) -> Optional[str]:
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def _run_zeek(
    zeek_bin: str,
    pcap: Path,
    out_dir: Path,
    scripts: List[str],
    timeout: int,
) -> Tuple[bool, str]:
    out_dir.mkdir(parents=True, exist_ok=True)
    # -C disables IP checksum validation (common in captures)
    cmd = [zeek_bin, "-C", "-r", str(pcap), _ZEEK_JSON_FLAG] + scripts
    logger.debug("Running: %s", " ".join(cmd))
    try:
        r = subprocess.run(cmd, cwd=str(out_dir), capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return False, f"zeek exited {r.returncode}: {r.stderr[:800]}"
        return True, "ok"
    except subprocess.TimeoutExpired:
        return False, f"Zeek timed out after {timeout}s processing {pcap.name}"
    except Exception as exc:
        return False, str(exc)


def _ingest_individual(
    pcap_files: List[Path],
    out_root: Path,
    zeek_bin: str,
    scripts: List[str],
    timeout: int,
) -> Tuple[bool, str, Path]:
    errors: List[str] = []
    processed = 0
    for i, pcap in enumerate(pcap_files, start=1):
        chunk_dir = out_root / f"chunk_{i:04d}"
        ok, msg = _run_zeek(zeek_bin, pcap, chunk_dir, scripts, timeout)
        if ok:
            processed += 1
            logger.info("Processed %s → %s", pcap.name, chunk_dir.name)
        else:
            errors.append(f"{pcap.name}: {msg}")
            logger.error("Failed to process %s: %s", pcap.name, msg)

    if processed == 0:
        return False, f"All PCAPs failed. Errors: {errors}", out_root

    summary = f"Processed {processed}/{len(pcap_files)} PCAPs into {out_root}"
    if errors:
        summary += f" (errors: {errors})"
    return True, summary, out_root


def _ingest_merged(
    pcap_files: List[Path],
    out_root: Path,
    zeek_bin: str,
    scripts: List[str],
    timeout: int,
) -> Tuple[bool, str, Path]:
    mergecap = _find_binary(("mergecap",))
    if not mergecap:
        logger.warning("mergecap not found — falling back to per-file chunk processing")
        return _ingest_individual(pcap_files, out_root, zeek_bin, scripts, timeout)

    out_root.mkdir(parents=True, exist_ok=True)
    merged = out_root / "_merged_tmp.pcap"
    try:
        r = subprocess.run(
            [mergecap, "-w", str(merged)] + [str(p) for p in pcap_files],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode != 0:
            logger.warning("mergecap failed (%s) — falling back to per-file", r.stderr[:200])
            return _ingest_individual(pcap_files, out_root, zeek_bin, scripts, timeout)
    except Exception as exc:
        logger.warning("mergecap error (%s) — falling back to per-file", exc)
        return _ingest_individual(pcap_files, out_root, zeek_bin, scripts, timeout)

    chunk_dir = out_root / "chunk_0001"
    ok, msg = _run_zeek(zeek_bin, merged, chunk_dir, scripts, timeout)

    try:
        merged.unlink(missing_ok=True)
    except OSError:
        pass

    if ok:
        return True, f"Merged {len(pcap_files)} PCAPs and processed into {chunk_dir.name}", out_root
    return False, msg, out_root
