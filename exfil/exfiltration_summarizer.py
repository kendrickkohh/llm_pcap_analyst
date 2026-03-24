# src/exfiltration_summarizer.py
"""
LLM-powered narrative summarizer for exfiltration findings.

Takes the structured JSON output from exfiltration_tool and dns_exfiltration,
calls an LLM (Anthropic Claude via LangChain) to produce a natural-language
forensic summary, then validates the output for hallucinations by checking
that every IP address / domain cited by the LLM exists in the source evidence.

Guardrails implemented:
  1. System prompt restricts the LLM to evidence-only claims.
  2. Post-generation grounding check extracts all IPs and domains from the
     LLM response and verifies each against the evidence data.
  3. A grounding_score (0.0–1.0) and list of ungrounded_claims are returned
     alongside the narrative so downstream consumers can decide whether to
     trust the output.
  4. Token budget is capped to control cost.
"""
from __future__ import annotations

import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple

# LangChain imports — optional at import time so the rest of the codebase
# remains usable even if langchain_anthropic is not installed.
try:
    from langchain_anthropic import ChatAnthropic
    _LANGCHAIN_ANTHROPIC_AVAILABLE = True
except ImportError:
    _LANGCHAIN_ANTHROPIC_AVAILABLE = False

try:
    from langchain_openai import ChatOpenAI, AzureChatOpenAI
    _LANGCHAIN_OPENAI_AVAILABLE = True
except ImportError:
    _LANGCHAIN_OPENAI_AVAILABLE = False

try:
    from langchain_core.messages import HumanMessage, SystemMessage
    _LANGCHAIN_CORE_AVAILABLE = True
except ImportError:
    _LANGCHAIN_CORE_AVAILABLE = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_MAX_TOKENS    = 1500
_MODEL_CLAUDE  = "claude-sonnet-4-20250514"
_MODEL_GPT4    = "gpt-4o"
_MODEL_AZURE   = "gpt-4o"   # Azure deployment name — override with --model if yours differs

_SYSTEM_PROMPT = """\
You are a senior network forensic analyst producing a Phase 1 investigation report section.

STRICT GROUNDING RULE: You may ONLY reference IP addresses, domain names, timestamps,
and byte counts that appear verbatim in the EVIDENCE JSON provided. Do not infer, invent,
or generalise beyond what the data explicitly shows.

Output format — respond with valid JSON only, no markdown fences:
{
  "executive_summary": "<2-3 sentences for C-suite. State whether exfiltration is suspected, the highest-risk destination, and the recommended immediate action.>",
  "key_findings": [
    "<finding 1, citing specific evidence field values>",
    "<finding 2>",
    ...
  ],
  "mitre_techniques": [
    {"id": "<T-code>", "name": "<technique name>", "evidence": "<brief justification citing evidence>"},
    ...
  ],
  "risk_assessment": {
    "level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "justification": "<cite evidence fields>"
  },
  "recommendations": [
    "<prioritised, actionable recommendation 1>",
    "<recommendation 2>",
    ...
  ]
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_IPV4_RE     = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_DOMAIN_RE   = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
_RESERVED_WORDS = {"HIGH", "LOW", "MEDIUM", "CRITICAL", "DNS", "TCP", "UDP", "TLS", "SSL"}


# Fields within evidence dicts that are guaranteed to contain network entity
# values (IPs or domain names). Domain harvesting is restricted to these fields
# to prevent non-entity strings (MITRE names, tags, notes) from accidentally
# matching the domain regex and making the grounding check overly permissive.
#
# IPs are extracted via regex from ALL string values since the IPv4 pattern
# (d.d.d.d) is specific enough that accidental matches in metadata are
# negligible.
#
# If a new evidence field is added that contains a domain name, add its key
# here. This is intentionally explicit rather than automatic.
# Suffixes that identify domain-carrying fields by naming convention.
# Any evidence dict key ending with one of these suffixes is automatically
# treated as a domain field — no manual registration required.
# Convention: name new domain fields with one of these suffixes and harvesting
# is automatic. Adding a new suffix here covers all existing and future fields
# that follow the convention.
_DOMAIN_FIELD_SUFFIXES: tuple = (
    "_domain",    # e.g. base_domain
    "_hint",      # e.g. domain_hint
    "_hostname",  # e.g. resolved_hostname
    "_fqdn",      # e.g. target_fqdn
    "_host",      # e.g. remote_host
    "_sni",       # e.g. tls_sni
)


def _collect_evidence_entities(
    exfil_result: Optional[Dict],
    dns_result: Optional[Dict],
    http_result: Optional[Dict],
) -> Set[str]:
    """
    Collect every IP and domain that legitimately appears in evidence fields.

    IPs: extracted via regex from all string values (IPv4 pattern is specific
         enough that false matches in metadata are negligible).
    Domains: extracted from fields whose key ends with a suffix in
             _DOMAIN_FIELD_SUFFIXES (e.g. "_domain", "_hint", "_hostname").
             This prevents non-entity text (MITRE names, tags, notes) from
             matching the domain regex and silently grounding hallucinated claims,
             while requiring zero manual registration for new domain fields —
             just follow the naming convention.
    """
    entities: Set[str] = set()

    def _mine_ips(obj: Any) -> None:
        """Recursively extract IPv4 addresses from all string values."""
        if isinstance(obj, dict):
            for v in obj.values():
                _mine_ips(v)
        elif isinstance(obj, list):
            for item in obj:
                _mine_ips(item)
        elif isinstance(obj, str):
            entities.update(_IPV4_RE.findall(obj))

    def _mine_domains(obj: Any) -> None:
        """
        Extract domain strings from fields whose key ends with a known
        domain-field suffix. Automatically covers any future field that
        follows the naming convention — no manual registration required.
        """
        if isinstance(obj, dict):
            for k, v in obj.items():
                if isinstance(v, str) and v and k.endswith(_DOMAIN_FIELD_SUFFIXES):
                    entities.add(v.lower())
                else:
                    _mine_domains(v)
        elif isinstance(obj, list):
            for item in obj:
                _mine_domains(item)

    if exfil_result:
        for field in ("evidence", "suspicious_only_evidence",
                      "top_internal_senders", "top_external_destinations",
                      "top_outbound_spike_buckets"):
            _mine_ips(exfil_result.get(field, []))
            _mine_domains(exfil_result.get(field, []))

    if dns_result:
        for field in ("evidence", "suspicious_only_evidence"):
            _mine_ips(dns_result.get(field, []))
            _mine_domains(dns_result.get(field, []))

    if http_result:
        for field in ("evidence", "suspicious_only_evidence", "top_uploads"):
            _mine_ips(http_result.get(field, []))
            _mine_domains(http_result.get(field, []))

    return entities


def _domains_match(entity: str, known: str) -> bool:
    """
    Exact-match grounding check for domain entities.

    Rules:
    - IPs must match exactly.
    - Domains must match exactly OR the entity must be a subdomain of a known
      domain (i.e. entity ends with '.<known>'). This prevents 'example-evilsite.com'
      being grounded by 'evilsite.com' (no dot boundary), while still allowing
      'sub.evilsite.com' to be grounded by 'evilsite.com'.
    """
    if entity == known:
        return True
    # Allow subdomain relationship only — entity must end with '.' + known
    if entity.endswith("." + known):
        return True
    return False


def _grounding_check(
    llm_text: str,
    known_entities: Set[str],
) -> Tuple[float, List[str]]:
    """
    Extract all IPs and domain-like tokens from the LLM output, then verify
    each against the known evidence entities using exact / subdomain matching.

    Returns (grounding_score, ungrounded_claims).
    grounding_score = 1.0 means every entity the LLM cited was grounded in evidence.
    """
    mentioned_ips     = set(_IPV4_RE.findall(llm_text))
    mentioned_domains = {
        m.lower() for m in _DOMAIN_RE.findall(llm_text)
        if m.upper() not in _RESERVED_WORDS and len(m) > 5
    }
    mentioned = mentioned_ips | mentioned_domains

    if not mentioned:
        return 1.0, []

    ungrounded: List[str] = []
    for entity in mentioned:
        is_grounded = any(_domains_match(entity, known) for known in known_entities)
        if not is_grounded:
            ungrounded.append(entity)

    score = 1.0 - (len(ungrounded) / len(mentioned))
    return round(score, 4), ungrounded


def _build_prompt(
    exfil_result: Optional[Dict],
    dns_result: Optional[Dict],
    http_result: Optional[Dict],
) -> str:
    """Construct the user-facing prompt with trimmed evidence JSON."""

    sections: List[str] = ["Analyze the following network forensic evidence for exfiltration.\n"]

    if exfil_result:
        # Trim to what the LLM actually needs — avoid passing huge raw dumps
        trimmed_exfil = {
            "module":              exfil_result.get("module"),
            "suspected":           exfil_result.get("suspected"),
            "confidence":          exfil_result.get("confidence"),
            "mitre_techniques":    exfil_result.get("mitre_techniques", []),
            "suspicious_only_evidence": exfil_result.get("suspicious_only_evidence", [])[:10],
            "top_internal_senders":     exfil_result.get("top_internal_senders", [])[:5],
        }
        sections.append("=== EXFILTRATION ANALYSIS ===")
        sections.append(json.dumps(trimmed_exfil, indent=2))

    if dns_result and dns_result.get("suspected"):
        trimmed_dns = {
            "module":              dns_result.get("module"),
            "suspected":           dns_result.get("suspected"),
            "confidence":          dns_result.get("confidence"),
            "mitre_techniques":    dns_result.get("mitre_techniques", []),
            "suspicious_only_evidence": dns_result.get("suspicious_only_evidence", [])[:8],
        }
        sections.append("\n=== DNS EXFILTRATION / TUNNELING ANALYSIS ===")
        sections.append(json.dumps(trimmed_dns, indent=2))

    if http_result and http_result.get("suspected"):
        trimmed_http = {
            "module": http_result.get("module"),
            "suspected": http_result.get("suspected"),
            "confidence": http_result.get("confidence"),
            "mitre_techniques": http_result.get("mitre_techniques", []),
            "suspicious_only_evidence": http_result.get("suspicious_only_evidence", [])[:8],
        }
        sections.append("\n=== HTTP / WEB-SERVICE EXFILTRATION ANALYSIS ===")
        sections.append(json.dumps(trimmed_http, indent=2))

    sections.append("\nRespond with the JSON structure specified in the system prompt.")
    return "\n".join(sections)


# ---------------------------------------------------------------------------
# Internal helpers (exposed for testing)
# ---------------------------------------------------------------------------

def _strip_llm_fence(raw: str) -> str:
    """
    Remove markdown code fences from an LLM response string.

    Handles both ```json\n...\n``` and ```\n...\n``` variants.
    Extracted as a named helper so tests can assert against this function
    directly rather than duplicating the stripping logic.
    """
    clean = raw.strip()
    if clean.startswith("```json"):
        clean = clean[len("```json"):]
    elif clean.startswith("```"):
        clean = clean[len("```"):]
    if clean.endswith("```"):
        clean = clean[:-len("```")]
    return clean.strip()


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def summarize_exfiltration(
    exfil_result: Optional[Dict] = None,
    dns_result:   Optional[Dict] = None,
    http_result:  Optional[Dict] = None,
    llm_provider: str = "azure",         # "azure" | "anthropic" | "openai"
    model:        Optional[str] = None,
    temperature:  float = 0.1,           # low temperature for factual forensic output
    max_tokens:   int   = _MAX_TOKENS,
) -> Dict[str, Any]:
    """
    Generate an LLM-powered forensic narrative from exfiltration analysis results.

    Parameters
    ----------
    exfil_result  : Output dict from analyze_exfiltration().
    dns_result    : Output dict from analyze_dns_exfiltration(). Optional.
    http_result   : Output dict from analyze_http_exfiltration(). Optional.
    llm_provider  : "azure"      — uses AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT,
                                   AZURE_OPENAI_API_VERSION env vars.
                    "anthropic"  — uses ANTHROPIC_API_KEY.
                    "openai"     — uses OPENAI_API_KEY.
    model         : Override the default model / deployment name.
                    For Azure this is your deployment name (default: "gpt-4o").
    temperature   : LLM temperature (low = more deterministic).
    max_tokens    : Maximum tokens in LLM response.

    Required environment variables by provider
    ------------------------------------------
    azure:
        AZURE_OPENAI_API_KEY      — your Azure OpenAI key
        AZURE_OPENAI_ENDPOINT     — e.g. https://<resource>.openai.azure.com/
        AZURE_OPENAI_API_VERSION  — e.g. 2024-02-01  (optional, has default)
    anthropic:
        ANTHROPIC_API_KEY
    openai:
        OPENAI_API_KEY

    Returns
    -------
    {
      "narrative":          { ...structured JSON from LLM... },
      "grounding_score":    float,        # 1.0 = fully grounded
      "ungrounded_claims":  List[str],    # entities in LLM output not found in evidence
      "hallucination_risk": str,          # LOW / MEDIUM / HIGH
      "llm_provider":       str,
      "model":              str,
      "latency_seconds":    float,
      "error":              Optional[str],
    }
    """
    if not _LANGCHAIN_CORE_AVAILABLE:
        return _error_result("langchain_core not installed. Run: pip install langchain-core")

    # --- Select LLM ---
    llm = None
    used_model = model

    if llm_provider == "azure":
        if not _LANGCHAIN_OPENAI_AVAILABLE:
            return _error_result("langchain_openai not installed. Run: pip install langchain-openai")
        api_key  = os.environ.get("AZURE_OPENAI_API_KEY")
        endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
        api_ver  = os.environ.get("AZURE_OPENAI_API_VERSION", "2024-02-01")
        if not api_key:
            return _error_result("AZURE_OPENAI_API_KEY environment variable not set.")
        if not endpoint:
            return _error_result("AZURE_OPENAI_ENDPOINT environment variable not set.")
        used_model = model or _MODEL_AZURE
        llm = AzureChatOpenAI(
            azure_deployment=used_model,
            azure_endpoint=endpoint,
            api_key=api_key,
            api_version=api_ver,
            temperature=temperature,
            max_tokens=max_tokens,
        )

    elif llm_provider == "anthropic":
        if not _LANGCHAIN_ANTHROPIC_AVAILABLE:
            return _error_result("langchain_anthropic not installed. Run: pip install langchain-anthropic")
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            return _error_result("ANTHROPIC_API_KEY environment variable not set.")
        used_model = model or _MODEL_CLAUDE
        llm = ChatAnthropic(model=used_model, temperature=temperature, max_tokens=max_tokens, api_key=api_key)

    elif llm_provider == "openai":
        if not _LANGCHAIN_OPENAI_AVAILABLE:
            return _error_result("langchain_openai not installed. Run: pip install langchain-openai")
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return _error_result("OPENAI_API_KEY environment variable not set.")
        used_model = model or _MODEL_GPT4
        llm = ChatOpenAI(model=used_model, temperature=temperature, max_tokens=max_tokens, api_key=api_key)

    else:
        return _error_result(f"Unknown llm_provider: {llm_provider!r}. Choose 'azure', 'anthropic', or 'openai'.")

    # --- Build prompt ---
    prompt_text = _build_prompt(exfil_result, dns_result, http_result)
    messages = [SystemMessage(content=_SYSTEM_PROMPT), HumanMessage(content=prompt_text)]

    # --- Call LLM ---
    t0 = time.monotonic()
    try:
        response = llm.invoke(messages)
        raw_text = response.content
    except Exception as exc:
        return _error_result(f"LLM call failed: {exc}")
    latency = round(time.monotonic() - t0, 3)

    # --- Parse JSON response ---
    narrative: Dict = {}
    try:
        narrative = json.loads(_strip_llm_fence(raw_text))
    except json.JSONDecodeError:
        # Fallback: find the outermost JSON object via regex
        match = re.search(r'\{.*\}', raw_text, re.DOTALL)
        if match:
            try:
                narrative = json.loads(match.group())
            except json.JSONDecodeError:
                narrative = {"raw_llm_output": raw_text, "_parse_error": "Could not parse LLM JSON"}
        else:
            narrative = {"raw_llm_output": raw_text, "_parse_error": "No JSON found in LLM output"}

    # --- Grounding / hallucination check ---
    known_entities = _collect_evidence_entities(exfil_result, dns_result, http_result)
    grounding_score, ungrounded = _grounding_check(raw_text, known_entities)

    hallucination_risk = (
        "LOW"    if grounding_score >= 0.90 else
        "MEDIUM" if grounding_score >= 0.70 else
        "HIGH"
    )

    return {
        "narrative":          narrative,
        "grounding_score":    grounding_score,
        "ungrounded_claims":  ungrounded,
        "hallucination_risk": hallucination_risk,
        "llm_provider":       llm_provider,
        "model":              used_model,
        "latency_seconds":    latency,
        "error":              None,
    }


def _error_result(msg: str) -> Dict[str, Any]:
    return {
        "narrative":          {},
        "grounding_score":    0.0,
        "ungrounded_claims":  [],
        "hallucination_risk": "HIGH",
        "llm_provider":       "none",
        "model":              "none",
        "latency_seconds":    0.0,
        "error":              msg,
    }
