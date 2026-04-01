"""
shared/ecs_compat.py
====================
Normalise Elastic Common Schema (ECS) / Filebeat Zeek records into
standard flat Zeek JSON field names.

The SC4063 API serves Zeek logs in ECS format (Filebeat 7.x), but all
pipeline tools expect standard Zeek JSON fields (id.orig_h, id.resp_h,
ts, etc.).  This module bridges the gap.

Usage:
    from shared.ecs_compat import normalize_record

    for line in open(zeek_path):
        rec = json.loads(line)
        rec = normalize_record(rec)   # now has standard Zeek fields
        src = rec.get("id.orig_h")    # works!
"""

from __future__ import annotations

import json
from typing import Any, Optional


def _get(d: dict, *keys: str, default: Any = None) -> Any:
    """Safely traverse nested dicts: _get(d, "a", "b", "c") -> d["a"]["b"]["c"]."""
    cur = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
        if cur is None:
            return default
    return cur


def _detect_dataset(rec: dict) -> str:
    """Return the Zeek dataset name, e.g. 'connection', 'dns', 'rdp'."""
    ds = _get(rec, "event", "dataset") or ""
    # "zeek.dns" -> "dns", "zeek.smb_files" -> "smb_files"
    if ds.startswith("zeek."):
        return ds[5:]
    return ds


def is_ecs_format(rec: dict) -> bool:
    """Return True if the record uses ECS field layout."""
    return isinstance(rec.get("source"), dict) or "@timestamp" in rec


def normalize_record(rec: dict) -> dict:
    """
    If the record is in ECS/Filebeat format, flatten it to standard Zeek
    JSON field names.  If already in standard format, return as-is.

    The returned dict can be used with rec.get("id.orig_h"), rec.get("ts"),
    rec.get("query"), etc. — exactly as the tools expect.
    """
    if not is_ecs_format(rec):
        return rec

    # ── Try event.original first (contains raw Zeek JSON for some logs) ──
    original = _get(rec, "event", "original")
    if original and isinstance(original, str):
        try:
            parsed = json.loads(original)
            if isinstance(parsed, dict) and "id.orig_h" in parsed:
                return parsed
        except (json.JSONDecodeError, TypeError):
            pass

    # ── Build normalised record ──────────────────────────────────────────
    out: dict[str, Any] = {}

    # Common fields (all log types)
    out["id.orig_h"] = _get(rec, "source", "ip", default="")
    out["id.resp_h"] = _get(rec, "destination", "ip", default="")
    out["id.orig_p"] = _get(rec, "source", "port", default=0)
    out["id.resp_p"] = _get(rec, "destination", "port", default=0)
    out["ts"]        = rec.get("@timestamp", "")
    out["uid"]       = _get(rec, "zeek", "session_id", default="")
    out["proto"]     = _get(rec, "network", "transport", default="")

    # Byte / packet counts (connection log)
    src_bytes = _get(rec, "source", "bytes")
    dst_bytes = _get(rec, "destination", "bytes")
    if src_bytes is not None:
        out["orig_bytes"] = src_bytes
    if dst_bytes is not None:
        out["resp_bytes"] = dst_bytes
    src_pkts = _get(rec, "source", "packets")
    dst_pkts = _get(rec, "destination", "packets")
    if src_pkts is not None:
        out["orig_pkts"] = src_pkts
    if dst_pkts is not None:
        out["resp_pkts"] = dst_pkts

    # Duration (ECS stores in nanoseconds)
    duration_ns = _get(rec, "event", "duration")
    if duration_ns is not None:
        try:
            out["duration"] = float(duration_ns) / 1e9
        except (TypeError, ValueError):
            out["duration"] = duration_ns

    # Network-level
    net_bytes = _get(rec, "network", "bytes")
    if net_bytes is not None:
        out["total_bytes"] = net_bytes

    # ── Protocol-specific fields ─────────────────────────────────────────
    dataset = _detect_dataset(rec)
    zeek_proto = _get(rec, "zeek", dataset) or {}

    if dataset == "connection":
        out["conn_state"]   = zeek_proto.get("state", "")
        out["missed_bytes"] = zeek_proto.get("missed_bytes", 0)
        out["history"]      = zeek_proto.get("history", "")

    elif dataset == "dns":
        out["query"]      = zeek_proto.get("query", "")
        out["qtype_name"] = zeek_proto.get("qtype_name", "")
        out["qtype"]      = zeek_proto.get("qtype")
        out["rcode_name"] = zeek_proto.get("rcode_name", "")
        out["rcode"]      = zeek_proto.get("rcode")
        out["answers"]    = zeek_proto.get("answers", [])
        out["AA"]         = zeek_proto.get("AA")
        out["TC"]         = zeek_proto.get("TC")
        out["RD"]         = zeek_proto.get("RD")
        out["RA"]         = zeek_proto.get("RA")
        out["TTLs"]       = zeek_proto.get("TTLs", [])
        out["rejected"]   = zeek_proto.get("rejected")
        out["trans_id"]   = zeek_proto.get("trans_id")

    elif dataset == "rdp":
        out["cookie"]            = zeek_proto.get("cookie", "")
        out["result"]            = zeek_proto.get("result", "")
        out["security_protocol"] = zeek_proto.get("security_protocol", "")
        out["auth_success"]      = zeek_proto.get("auth_success")

    elif dataset == "kerberos":
        out["client"]       = zeek_proto.get("client", "")
        out["service"]      = zeek_proto.get("service", "")
        out["success"]      = zeek_proto.get("success")
        out["error_msg"]    = zeek_proto.get("error_msg", "")
        out["request_type"] = zeek_proto.get("request_type", "")
        out["cipher"]       = zeek_proto.get("cipher", "")

    elif dataset == "dce_rpc":
        out["endpoint"]  = zeek_proto.get("endpoint", "")
        out["operation"] = zeek_proto.get("operation", "")

    elif dataset == "smb_files":
        out["action"] = zeek_proto.get("action", "") or _get(rec, "event", "action", default="")
        out["name"]   = zeek_proto.get("name", "")
        out["size"]   = zeek_proto.get("size")

    elif dataset == "smb_mapping":
        out["path"]       = zeek_proto.get("path", "")
        out["share_type"] = zeek_proto.get("share_type", "")

    elif dataset == "http":
        out["method"]            = _get(rec, "event", "action", default="")
        out["host"]              = _get(rec, "url", "domain", default="")
        out["uri"]               = _get(rec, "url", "original", default="")
        out["status_code"]       = zeek_proto.get("status_code") or _get(rec, "http", "response", "status_code")
        out["status_msg"]        = zeek_proto.get("status_msg", "")
        out["request_body_len"]  = zeek_proto.get("request_body_len") or _get(rec, "http", "request", "body", "bytes")
        out["response_body_len"] = zeek_proto.get("response_body_len") or _get(rec, "http", "response", "body", "bytes")
        out["user_agent"]        = zeek_proto.get("user_agent") or _get(rec, "user_agent", "original", default="")
        out["orig_fuids"]        = zeek_proto.get("orig_fuids")
        out["fuids"]             = zeek_proto.get("fuids")
        out["trans_depth"]       = zeek_proto.get("trans_depth")

    elif dataset == "ssl":
        out["server_name"]       = zeek_proto.get("server_name") or _get(rec, "tls", "client", "server_name") or _get(rec, "destination", "domain", default="")
        out["version"]           = zeek_proto.get("version", "")
        out["cipher"]            = zeek_proto.get("cipher", "")
        out["established"]       = zeek_proto.get("established") or _get(rec, "tls", "established")
        out["cert_chain_fps"]    = zeek_proto.get("cert_chain_fps", [])
        out["validation_status"] = _get(rec, "zeek", "ssl", "validation", "status", default="")
        out["ja3"]               = _get(rec, "tls", "client", "ja3", default="")
        out["ja3s"]              = _get(rec, "tls", "server", "ja3s", default="")

    elif dataset == "notice":
        out["note"]         = zeek_proto.get("note", "")
        out["msg"]          = zeek_proto.get("msg", "")
        out["sub"]          = zeek_proto.get("sub", "")
        out["suppress_for"] = zeek_proto.get("suppress_for")
        out["fuid"]         = zeek_proto.get("fuid", "")

    elif dataset == "files":
        out["fuid"]      = zeek_proto.get("fuid", "") or _get(rec, "file", "uid", default="")
        out["mime_type"] = zeek_proto.get("mime_type") or _get(rec, "file", "mime_type", default="")
        out["filename"]  = zeek_proto.get("filename") or _get(rec, "file", "name", default="")
        out["seen_bytes"] = zeek_proto.get("seen_bytes") or _get(rec, "file", "size")

    elif dataset == "weird":
        out["name"]    = zeek_proto.get("name", "")
        out["addl"]    = zeek_proto.get("addl", "")
        out["notice"]  = zeek_proto.get("notice", False)
        out["peer"]    = zeek_proto.get("peer", "")

    # ── Geo enrichment (bonus — ECS has this, standard Zeek doesn't) ─────
    src_geo = _get(rec, "source", "geo")
    if src_geo:
        out["_src_geo"] = src_geo
    dst_geo = _get(rec, "destination", "geo")
    if dst_geo:
        out["_dst_geo"] = dst_geo
    src_as = _get(rec, "source", "as")
    if src_as:
        out["_src_as"] = src_as

    return out
