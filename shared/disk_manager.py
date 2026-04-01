"""
shared/disk_manager.py
======================
Disk budget management and PCAP provenance tracking for the SC4063 pipeline.

Two components:

  DiskBudgetManager — enforces a 5 GB soft / 8 GB hard limit on downloaded
      artifacts (alerts, Zeek logs, PCAPs) by tracking files in a manifest
      and evicting released ones oldest-first when budget is exceeded.

  ProvenanceLog — records which PCAPs and Zeek files were available to each
      agent per day.  Generates a Markdown appendix for the forensic report.
      Toggled via --track-provenance / --no-provenance CLI flag.

Lifecycle:
    register  →  mark_used  →  release  →  evict_to_budget
        │                          │
        └─ file downloaded         └─ day's analysis done, files expendable

Usage:
    from shared.disk_manager import (
        init_disk_manager, get_disk_manager,
        init_provenance, get_provenance,
    )
    dm = init_disk_manager(work_dir)      # once in main()
    dm.register(path, "pcap", "2025-03-06")
    dm.release_day("2025-03-06")
    dm.evict_to_budget()
"""

from __future__ import annotations

import json
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_GB = 1 << 30

SOFT_LIMIT = 5 * _GB   # 5 GB — best-effort target
HARD_LIMIT = 8 * _GB   # 8 GB — hard ceiling, warn if exceeded

# Artifact type constants
ALERT = "alert"
ZEEK = "zeek"
PCAP = "pcap"
ZEEK_DERIVED = "zeek_derived"  # zeek_out/chunk_* from pcap→zeek conversion
REPORT = "report"


# ──────────────────────────────────────────────────────────────────────────────
# Tracked file record
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class TrackedFile:
    path: str
    size_bytes: int
    artifact_type: str
    day: str
    registered_at: float
    last_used_at: float
    status: str = "active"  # active | released | evicted

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> TrackedFile:
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


# ──────────────────────────────────────────────────────────────────────────────
# Disk Budget Manager
# ──────────────────────────────────────────────────────────────────────────────

class DiskBudgetManager:
    """
    Tracks downloaded pipeline artifacts, enforces disk budget via LRU eviction.

    Files go through:  active → released → evicted (deleted from disk)
    Only *released* files are candidates for eviction.  Active files are
    never deleted — the pipeline must explicitly release them first.
    """

    def __init__(
        self,
        work_dir: str,
        soft_limit: int = SOFT_LIMIT,
        hard_limit: int = HARD_LIMIT,
    ):
        self.work_dir = Path(work_dir).resolve()
        self.soft_limit = soft_limit
        self.hard_limit = hard_limit
        self._manifest_path = self.work_dir / ".disk_manifest.json"
        self._files: Dict[str, TrackedFile] = {}
        self._load()

    # ── Persistence ──────────────────────────────────────────────────────────

    def _load(self):
        if not self._manifest_path.exists():
            return
        try:
            data = json.loads(self._manifest_path.read_text(encoding="utf-8"))
            for path, info in data.get("files", {}).items():
                if Path(path).exists():
                    self._files[path] = TrackedFile.from_dict(info)
        except (json.JSONDecodeError, KeyError, TypeError):
            self._files = {}

    def _save(self):
        self._manifest_path.parent.mkdir(parents=True, exist_ok=True)
        data = {
            "soft_limit_bytes": self.soft_limit,
            "hard_limit_bytes": self.hard_limit,
            "total_tracked_bytes": self.current_usage(),
            "file_count": len(self._files),
            "files": {p: f.to_dict() for p, f in self._files.items()},
        }
        self._manifest_path.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    # ── Registration ─────────────────────────────────────────────────────────

    def register(self, path: str, artifact_type: str, day: str):
        """Register a file for tracking.  Idempotent — updates last_used_at."""
        p = Path(path).resolve()
        key = str(p)
        if key in self._files:
            self._files[key].last_used_at = time.time()
            return
        if not p.exists():
            return
        size = p.stat().st_size if p.is_file() else _dir_size(p)
        now = time.time()
        self._files[key] = TrackedFile(
            path=key,
            size_bytes=size,
            artifact_type=artifact_type,
            day=day,
            registered_at=now,
            last_used_at=now,
        )
        self._save()

    def register_directory(self, dir_path: str, artifact_type: str, day: str):
        """Register every file under a directory."""
        d = Path(dir_path)
        if not d.is_dir():
            return
        for f in d.rglob("*"):
            if f.is_file():
                self.register(str(f), artifact_type, day)
        self._save()

    # ── Usage queries ────────────────────────────────────────────────────────

    def mark_used(self, path: str):
        key = str(Path(path).resolve())
        if key in self._files:
            self._files[key].last_used_at = time.time()

    def current_usage(self) -> int:
        """Total bytes of non-evicted tracked files that still exist on disk."""
        total = 0
        for f in self._files.values():
            if f.status != "evicted" and Path(f.path).exists():
                total += f.size_bytes
        return total

    def usage_str(self) -> str:
        gb = self.current_usage() / _GB
        return f"{gb:.2f} GB / {self.soft_limit / _GB:.0f} GB soft / {self.hard_limit / _GB:.0f} GB hard"

    # ── Release & Eviction ───────────────────────────────────────────────────

    def release(self, path: str):
        """Mark a single file as eligible for eviction."""
        key = str(Path(path).resolve())
        if key in self._files:
            self._files[key].status = "released"

    def release_day(
        self, day: str, artifact_types: Optional[List[str]] = None
    ):
        """Release all tracked files for a day, optionally filtered by type."""
        types = set(artifact_types) if artifact_types else None
        count = 0
        for f in self._files.values():
            if f.day == day and f.status == "active":
                if types is None or f.artifact_type in types:
                    f.status = "released"
                    count += 1
        if count:
            print(f"  [disk] Released {count} file(s) for {day}")
        self._save()

    def release_all(self, exclude_types: Optional[List[str]] = None):
        """Release everything except specified artifact types."""
        exclude = set(exclude_types) if exclude_types else set()
        for f in self._files.values():
            if f.status == "active" and f.artifact_type not in exclude:
                f.status = "released"
        self._save()

    def evict_to_budget(self) -> List[str]:
        """
        Delete released files oldest-first until under soft limit.

        Returns list of evicted file paths.  If still above hard limit
        after evicting all released files, prints a warning.
        """
        usage = self.current_usage()
        if usage <= self.soft_limit:
            return []

        releasable = sorted(
            [f for f in self._files.values() if f.status == "released"],
            key=lambda f: f.last_used_at,
        )

        evicted: List[str] = []
        freed = 0
        for f in releasable:
            if usage <= self.soft_limit:
                break
            p = Path(f.path)
            if p.exists():
                try:
                    if p.is_file():
                        p.unlink()
                    elif p.is_dir():
                        shutil.rmtree(p)
                except OSError as exc:
                    print(f"  [disk] Warning: could not delete {f.path}: {exc}")
                    continue
            usage -= f.size_bytes
            freed += f.size_bytes
            f.status = "evicted"
            evicted.append(f.path)

        # Remove empty parent directories up to work_dir
        for path in evicted:
            _cleanup_empty_parents(Path(path), self.work_dir)

        if evicted:
            print(
                f"  [disk] Evicted {len(evicted)} file(s), "
                f"freed {freed / _GB:.2f} GB  "
                f"(now {usage / _GB:.2f} GB)"
            )

        usage = self.current_usage()
        if usage > self.hard_limit:
            print(
                f"  [disk] WARNING: Usage {usage / _GB:.1f} GB exceeds "
                f"hard limit {self.hard_limit / _GB:.0f} GB after eviction. "
                f"Consider manual cleanup of {self.work_dir}"
            )

        self._save()
        return evicted

    def summary(self) -> Dict[str, Any]:
        by_type: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        for f in self._files.values():
            if f.status == "evicted":
                continue
            by_type[f.artifact_type] = by_type.get(f.artifact_type, 0) + f.size_bytes
            by_status[f.status] = by_status.get(f.status, 0) + f.size_bytes
        return {
            "total_gb": round(self.current_usage() / _GB, 2),
            "soft_limit_gb": self.soft_limit / _GB,
            "hard_limit_gb": self.hard_limit / _GB,
            "by_type_gb": {k: round(v / _GB, 2) for k, v in by_type.items()},
            "by_status_gb": {k: round(v / _GB, 2) for k, v in by_status.items()},
            "tracked_files": len([f for f in self._files.values() if f.status != "evicted"]),
        }

    def print_status(self):
        s = self.summary()
        print(f"  [disk] {s['total_gb']} GB used  |  "
              f"by type: {s['by_type_gb']}  |  "
              f"{s['tracked_files']} files tracked")


# ──────────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────────

def _dir_size(path: Path) -> int:
    return sum(f.stat().st_size for f in path.rglob("*") if f.is_file())


def _cleanup_empty_parents(path: Path, stop_at: Path):
    """Remove empty parent directories up to (but not including) stop_at."""
    parent = path.parent
    stop = stop_at.resolve()
    while parent.resolve() != stop and parent.exists():
        try:
            if not any(parent.iterdir()):
                parent.rmdir()
                parent = parent.parent
            else:
                break
        except OSError:
            break


# ──────────────────────────────────────────────────────────────────────────────
# Module-level singleton
# ──────────────────────────────────────────────────────────────────────────────

_manager: Optional[DiskBudgetManager] = None


def init_disk_manager(work_dir: str, **kwargs) -> DiskBudgetManager:
    """Create and store the global DiskBudgetManager instance."""
    global _manager
    _manager = DiskBudgetManager(work_dir, **kwargs)
    print(f"  [disk] Budget manager initialised — {_manager.usage_str()}")
    return _manager


def get_disk_manager() -> Optional[DiskBudgetManager]:
    """Return the global DiskBudgetManager, or None if not initialised."""
    return _manager


# ══════════════════════════════════════════════════════════════════════════════
# Provenance Log
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ProvenanceLog:
    """
    Tracks which PCAPs and Zeek files were available to each agent per day.
    Designed for "light" provenance — records file lists, not individual reads.
    """

    enabled: bool = True

    # day → [{"name", "path", "size_bytes"}]
    pcaps: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)

    # day → [zeek dataset names]
    zeek_files: Dict[str, List[str]] = field(default_factory=dict)

    # day → agent_name → [source file basenames]
    agent_sources: Dict[str, Dict[str, List[str]]] = field(default_factory=dict)

    days_analysed: List[str] = field(default_factory=list)

    # ── Recording methods ────────────────────────────────────────────────────

    def record_pcap(
        self, day: str, name: str, path: str, size_bytes: int = 0
    ):
        if not self.enabled:
            return
        self.pcaps.setdefault(day, [])
        if not any(p["path"] == path for p in self.pcaps[day]):
            self.pcaps[day].append(
                {"name": name, "path": path, "size_bytes": size_bytes}
            )

    def record_zeek_files(self, day: str, filenames: List[str]):
        if not self.enabled:
            return
        existing = set(self.zeek_files.get(day, []))
        self.zeek_files[day] = sorted(existing | set(filenames))

    def record_agent_access(self, day: str, agent: str, files: List[str]):
        if not self.enabled:
            return
        self.agent_sources.setdefault(day, {}).setdefault(agent, [])
        existing = set(self.agent_sources[day][agent])
        new_basenames = {Path(f).name for f in files}
        self.agent_sources[day][agent] = sorted(existing | new_basenames)

    def record_day_analysed(self, day: str):
        if not self.enabled:
            return
        if day not in self.days_analysed:
            self.days_analysed.append(day)
            self.days_analysed.sort()

    # ── Serialisation ────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return {
            "enabled": self.enabled,
            "pcaps": self.pcaps,
            "zeek_files": self.zeek_files,
            "agent_sources": self.agent_sources,
            "days_analysed": self.days_analysed,
        }

    @classmethod
    def from_dict(cls, d: dict) -> ProvenanceLog:
        return cls(
            enabled=d.get("enabled", True),
            pcaps=d.get("pcaps", {}),
            zeek_files=d.get("zeek_files", {}),
            agent_sources=d.get("agent_sources", {}),
            days_analysed=d.get("days_analysed", []),
        )

    # ── Markdown report section ──────────────────────────────────────────────

    def to_markdown(self) -> str:
        """Generate a Markdown appendix for the forensic report."""
        if not self.enabled:
            return ""

        lines = [
            "## Appendix: Evidence Provenance",
            "",
            "### PCAPs Analysed",
            "",
        ]

        if not self.pcaps:
            lines.append("No PCAPs recorded.")
        else:
            lines.append("| Day | PCAP File | Size |")
            lines.append("|-----|-----------|------|")
            for day in sorted(self.pcaps):
                for p in self.pcaps[day]:
                    size_mb = p["size_bytes"] / 1e6 if p["size_bytes"] else 0
                    lines.append(
                        f"| {day} | `{p['name']}` | {size_mb:.1f} MB |"
                    )

        lines += ["", "### Zeek Log Files Used", ""]
        if not self.zeek_files:
            lines.append("No Zeek files recorded.")
        else:
            lines.append("| Day | Datasets |")
            lines.append("|-----|----------|")
            for day in sorted(self.zeek_files):
                names = ", ".join(f"`{f}`" for f in self.zeek_files[day])
                lines.append(f"| {day} | {names} |")

        lines += ["", "### Per-Agent Source Files", ""]
        if not self.agent_sources:
            lines.append("No agent access recorded.")
        else:
            lines.append("| Day | Agent | Files Accessed |")
            lines.append("|-----|-------|----------------|")
            for day in sorted(self.agent_sources):
                for agent in sorted(self.agent_sources[day]):
                    files = self.agent_sources[day][agent]
                    fstr = ", ".join(f"`{f}`" for f in files)
                    lines.append(f"| {day} | {agent} | {fstr} |")

        lines += [
            "",
            f"**Days analysed**: {', '.join(self.days_analysed) or 'none'}",
        ]

        return "\n".join(lines)


# ── Module-level singleton ───────────────────────────────────────────────────

_provenance: Optional[ProvenanceLog] = None


def init_provenance(enabled: bool = True) -> ProvenanceLog:
    """Create and store the global ProvenanceLog instance."""
    global _provenance
    _provenance = ProvenanceLog(enabled=enabled)
    if enabled:
        print("  [provenance] Tracking enabled")
    return _provenance


def get_provenance() -> Optional[ProvenanceLog]:
    """Return the global ProvenanceLog, or None if not initialised."""
    return _provenance
