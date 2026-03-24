"""
shared/data_contract.py
=======================
Single source of truth for all data structures flowing through the
SC4063 Security Analysis Pipeline.

Every agent reads from and writes to PipelineState. No agent should
define its own ad-hoc dicts for inter-agent data — use this module.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, Sequence, TypedDict

from langchain_core.messages import BaseMessage, HumanMessage
from langgraph.graph.message import add_messages


# ──────────────────────────────────────────────────────────────────────────────
# Canonical finding schemas (dataclasses for validation + serialisation)
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class ZeekContext:
    """
    Pre-fetched Zeek data fed into every agent.
    Populated once by the PCAP ingestion layer, then treated as read-only.
    """
    day: str                        # "YYYY-MM-DD"
    pcap_path: str                  # local path of the downloaded PCAP
    alerts_path: Optional[str] = None          # local path of alerts.ndjson
    zeek_files: dict[str, str] = field(default_factory=dict)
    # e.g. {"zeek.dns.ndjson": "/tmp/zeek.dns.ndjson", ...}
    pcap_metadata: dict[str, Any] = field(default_factory=dict)
    # raw metadata block from the API

    def to_dict(self) -> dict:
        return {
            "day": self.day,
            "pcap_path": self.pcap_path,
            "alerts_path": self.alerts_path,
            "zeek_files": self.zeek_files,
            "pcap_metadata": self.pcap_metadata,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ZeekContext":
        return cls(**d)


@dataclass
class IOC:
    """A single Indicator of Compromise."""
    ioc_type: Literal["ip", "domain", "hash", "port", "file", "url", "user"]
    value: str
    source_agent: str
    confidence: Literal["high", "medium", "low"] = "medium"
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "ioc_type": self.ioc_type,
            "value": self.value,
            "source_agent": self.source_agent,
            "confidence": self.confidence,
            "notes": self.notes,
        }


@dataclass
class InitialAccessFindings:
    """Output schema for the Initial Access agent (agent.py / ForensicAgent)."""
    summary: str = ""                          # short description (or error msg)
    patient_zero: Optional[str] = None         # e.g. "10.0.0.50"
    attack_vector: Optional[str] = None        # e.g. "RDP brute-force"
    attacker_ip: Optional[str] = None
    attacker_port: Optional[int] = None
    exposed_service: Optional[str] = None      # e.g. "RDP/3389"
    brute_force_count: Optional[int] = None
    successful_session_bytes: Optional[int] = None
    session_start: Optional[str] = None        # ISO-8601
    session_end: Optional[str] = None
    pre_existing_compromise: bool = False
    iocs: list[IOC] = field(default_factory=list)
    report_markdown: str = ""
    raw: dict[str, Any] = field(default_factory=dict)  # raw agent output

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "patient_zero": self.patient_zero,
            "attack_vector": self.attack_vector,
            "attacker_ip": self.attacker_ip,
            "attacker_port": self.attacker_port,
            "exposed_service": self.exposed_service,
            "brute_force_count": self.brute_force_count,
            "successful_session_bytes": self.successful_session_bytes,
            "session_start": self.session_start,
            "session_end": self.session_end,
            "pre_existing_compromise": self.pre_existing_compromise,
            "iocs": [i.to_dict() for i in self.iocs],
            "report_markdown": self.report_markdown,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "InitialAccessFindings":
        iocs = [IOC(**i) for i in d.get("iocs", [])]
        return cls(
            summary=d.get("summary", ""),
            patient_zero=d.get("patient_zero"),
            attack_vector=d.get("attack_vector"),
            attacker_ip=d.get("attacker_ip"),
            attacker_port=d.get("attacker_port"),
            exposed_service=d.get("exposed_service"),
            brute_force_count=d.get("brute_force_count"),
            successful_session_bytes=d.get("successful_session_bytes"),
            session_start=d.get("session_start"),
            session_end=d.get("session_end"),
            pre_existing_compromise=d.get("pre_existing_compromise", False),
            iocs=iocs,
            report_markdown=d.get("report_markdown", ""),
            raw=d.get("raw", {}),
        )


@dataclass
class LateralMovementFindings:
    """Output schema for the Lateral Movement agent (lateral_movement.py)."""
    summary: str = ""
    bottom_line: str = ""
    observed: list[str] = field(default_factory=list)
    not_observed: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    evidence_highlights: list[str] = field(default_factory=list)
    tacticalrmm_assessment: str = ""
    compromised_hosts: list[str] = field(default_factory=list)
    movement_paths: list[tuple[str, str]] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    report_markdown: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "bottom_line": self.bottom_line,
            "observed": self.observed,
            "not_observed": self.not_observed,
            "limitations": self.limitations,
            "evidence_highlights": self.evidence_highlights,
            "tacticalrmm_assessment": self.tacticalrmm_assessment,
            "compromised_hosts": self.compromised_hosts,
            "movement_paths": [list(p) for p in self.movement_paths],
            "techniques": self.techniques,
            "iocs": [i.to_dict() for i in self.iocs],
            "report_markdown": self.report_markdown,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "LateralMovementFindings":
        iocs = [IOC(**i) for i in d.get("iocs", [])]
        return cls(
            summary=d.get("summary", ""),
            bottom_line=d.get("bottom_line", ""),
            observed=d.get("observed", []),
            not_observed=d.get("not_observed", []),
            limitations=d.get("limitations", []),
            evidence_highlights=d.get("evidence_highlights", []),
            tacticalrmm_assessment=d.get("tacticalrmm_assessment", ""),
            compromised_hosts=d.get("compromised_hosts", []),
            movement_paths=[tuple(p) for p in d.get("movement_paths", [])],
            techniques=d.get("techniques", []),
            iocs=iocs,
            report_markdown=d.get("report_markdown", ""),
            raw=d.get("raw", {}),
        )


@dataclass
class ExfiltrationFindings:
    """Output schema for the Exfiltration agent."""
    detected: bool = False
    summary: str = ""
    data_volume_bytes: Optional[int] = None
    destination_ips: list[str] = field(default_factory=list)
    destination_domains: list[str] = field(default_factory=list)
    protocols_used: list[str] = field(default_factory=list)
    timeframe: dict[str, str] = field(default_factory=dict)
    iocs: list[IOC] = field(default_factory=list)
    report_markdown: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "summary": self.summary,
            "data_volume_bytes": self.data_volume_bytes,
            "destination_ips": self.destination_ips,
            "destination_domains": self.destination_domains,
            "protocols_used": self.protocols_used,
            "timeframe": self.timeframe,
            "iocs": [i.to_dict() for i in self.iocs],
            "report_markdown": self.report_markdown,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ExfiltrationFindings":
        iocs = [IOC(**i) for i in d.get("iocs", [])]
        return cls(
            detected=d.get("detected", False),
            summary=d.get("summary", ""),
            data_volume_bytes=d.get("data_volume_bytes"),
            destination_ips=d.get("destination_ips", []),
            destination_domains=d.get("destination_domains", []),
            protocols_used=d.get("protocols_used", []),
            timeframe=d.get("timeframe", {}),
            iocs=iocs,
            report_markdown=d.get("report_markdown", ""),
            raw=d.get("raw", {}),
        )


@dataclass
class PayloadFindings:
    """Output schema for the Payload agent (payload_agent.py)."""
    summary: str = ""
    files_analysed: list[str] = field(default_factory=list)
    malicious_files: list[dict] = field(default_factory=list)
    # each dict: {"path", "sha256", "verdict", "detected_type", "entropy"}
    suspicious_files: list[dict] = field(default_factory=list)
    clean_files: list[dict] = field(default_factory=list)
    iocs: list[IOC] = field(default_factory=list)
    report_markdown: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "summary": self.summary,
            "files_analysed": self.files_analysed,
            "malicious_files": self.malicious_files,
            "suspicious_files": self.suspicious_files,
            "clean_files": self.clean_files,
            "iocs": [i.to_dict() for i in self.iocs],
            "report_markdown": self.report_markdown,
            "raw": self.raw,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PayloadFindings":
        iocs = [IOC(**i) for i in d.get("iocs", [])]
        return cls(
            summary=d.get("summary", ""),
            files_analysed=d.get("files_analysed", []),
            malicious_files=d.get("malicious_files", []),
            suspicious_files=d.get("suspicious_files", []),
            clean_files=d.get("clean_files", []),
            iocs=iocs,
            report_markdown=d.get("report_markdown", ""),
            raw=d.get("raw", {}),
        )


# ──────────────────────────────────────────────────────────────────────────────
# The master pipeline state — LangGraph TypedDict
# ──────────────────────────────────────────────────────────────────────────────

class PipelineState(TypedDict, total=False):
    """
    Canonical state object for the SC4063 Security Analysis Pipeline.

    ALL agents read from and write to this structure.
    Use helper functions below to safely read/write each section.
    """
    # ── Identity ──────────────────────────────────────────────────────────
    run_id: str                     # UUID for this pipeline run
    started_at: str                 # ISO-8601 timestamp

    # ── Input ─────────────────────────────────────────────────────────────
    target_day: str                 # "YYYY-MM-DD" — the day to investigate
    pcap_file: str                  # resolved local path to the PCAP
    work_dir: str                   # scratch directory for downloads

    # ── Zeek / API layer ──────────────────────────────────────────────────
    zeek_context: dict[str, Any]    # ZeekContext.to_dict() serialised

    # ── Shared attack context (accumulated across agents) ─────────────────
    attack_context: dict[str, Any]  # rolling shared facts
    # Keys agents should write: "patient_zero", "compromised_hosts",
    # "attacker_ips", "timeline_events" (list[{"time", "event", "source"}])

    # ── Per-agent findings (serialised dataclasses) ────────────────────────
    initial_access_findings: dict[str, Any]
    lateral_movement_findings: dict[str, Any]
    exfiltration_findings: dict[str, Any]
    payload_findings: dict[str, Any]

    # ── Report output ─────────────────────────────────────────────────────
    final_report: str

    # ── Supervisor routing ────────────────────────────────────────────────
    next_agent: str
    completed_agents: list[str]

    # ── LangGraph messages (append-only via add_messages) ─────────────────
    messages: Annotated[Sequence[BaseMessage], add_messages]


# ──────────────────────────────────────────────────────────────────────────────
# Helper accessors — safe typed reads/writes
# ──────────────────────────────────────────────────────────────────────────────

def get_zeek_context(state: PipelineState) -> Optional[ZeekContext]:
    d = state.get("zeek_context")
    return ZeekContext.from_dict(d) if d else None


def set_zeek_context(state: PipelineState, ctx: ZeekContext) -> dict:
    return {"zeek_context": ctx.to_dict()}


def get_initial_access(state: PipelineState) -> Optional[InitialAccessFindings]:
    d = state.get("initial_access_findings")
    return InitialAccessFindings.from_dict(d) if d else None


def set_initial_access(state: PipelineState, f: InitialAccessFindings) -> dict:
    ctx = dict(state.get("attack_context", {}))
    if f.patient_zero:
        ctx["patient_zero"] = f.patient_zero
    if f.attacker_ip:
        ctx.setdefault("attacker_ips", [])
        if f.attacker_ip not in ctx["attacker_ips"]:
            ctx["attacker_ips"].append(f.attacker_ip)
    return {
        "initial_access_findings": f.to_dict(),
        "attack_context": ctx,
    }


def get_lateral_movement(state: PipelineState) -> Optional[LateralMovementFindings]:
    d = state.get("lateral_movement_findings")
    return LateralMovementFindings.from_dict(d) if d else None


def set_lateral_movement(state: PipelineState, f: LateralMovementFindings) -> dict:
    ctx = dict(state.get("attack_context", {}))
    if f.compromised_hosts:
        existing = ctx.get("compromised_hosts", [])
        ctx["compromised_hosts"] = list(set(existing + f.compromised_hosts))
    if f.techniques:
        ctx.setdefault("techniques", [])
        ctx["techniques"] = list(set(ctx["techniques"] + f.techniques))
    return {
        "lateral_movement_findings": f.to_dict(),
        "attack_context": ctx,
    }


def get_exfiltration(state: PipelineState) -> Optional[ExfiltrationFindings]:
    d = state.get("exfiltration_findings")
    return ExfiltrationFindings.from_dict(d) if d else None


def set_exfiltration(state: PipelineState, f: ExfiltrationFindings) -> dict:
    ctx = dict(state.get("attack_context", {}))
    if f.destination_ips:
        ctx.setdefault("exfil_destinations", [])
        ctx["exfil_destinations"] = list(
            set(ctx["exfil_destinations"] + f.destination_ips)
        )
    return {
        "exfiltration_findings": f.to_dict(),
        "attack_context": ctx,
    }


def get_payload(state: PipelineState) -> Optional[PayloadFindings]:
    d = state.get("payload_findings")
    return PayloadFindings.from_dict(d) if d else None


def set_payload(state: PipelineState, f: PayloadFindings) -> dict:
    ctx = dict(state.get("attack_context", {}))
    hashes = [m.get("sha256") for m in f.malicious_files if m.get("sha256")]
    if hashes:
        ctx.setdefault("malicious_hashes", [])
        ctx["malicious_hashes"] = list(set(ctx["malicious_hashes"] + hashes))
    return {
        "payload_findings": f.to_dict(),
        "attack_context": ctx,
    }


def merge_all_iocs(state: PipelineState) -> list[dict]:
    """Collect and deduplicate IOCs from all agent findings."""
    seen = set()
    iocs = []
    for getter in [get_initial_access, get_lateral_movement, get_exfiltration, get_payload]:
        findings = getter(state)
        if findings:
            for ioc in findings.iocs:
                key = (ioc.ioc_type, ioc.value)
                if key not in seen:
                    seen.add(key)
                    iocs.append(ioc.to_dict())
    return iocs


def initial_pipeline_state(
    target_day: str,
    work_dir: str = "/tmp/sc4063",
    run_id: Optional[str] = None,
) -> PipelineState:
    """Create a clean initial pipeline state."""
    import uuid
    return PipelineState(
        run_id=run_id or str(uuid.uuid4()),
        started_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        target_day=target_day,
        pcap_file="",
        work_dir=work_dir,
        zeek_context={},
        attack_context={},
        initial_access_findings={},
        lateral_movement_findings={},
        exfiltration_findings={},
        payload_findings={},
        final_report="",
        next_agent="ingest",
        completed_agents=[],
        messages=[],
    )
