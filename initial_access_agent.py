#!/usr/bin/env python3
"""
SC4063 Part 2 — Agentic Network Forensic: Initial Access Analyzer

Autonomous PCAP analysis agent powered by Azure OpenAI GPT-4o-mini.
Ingests a PCAP file and produces a structured initial access forensic report.

Usage:
    python agent.py <pcap_file> [--output report.md]

Environment Variables:
    AZURE_OPENAI_ENDPOINT     Azure OpenAI endpoint URL
    AZURE_OPENAI_API_KEY      Azure OpenAI API key
    AZURE_OPENAI_DEPLOYMENT   Deployment name (default: gpt-4o-mini)
    TSHARK_PATH               Path to tshark binary (auto-detected if not set)
"""

import os
import sys
import json
import shutil
import subprocess
import argparse
import textwrap
import time
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from openai import AzureOpenAI

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Configuration
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MAX_AGENT_STEPS = 30
MAX_OUTPUT_CHARS = 15_000
API_VERSION = "2024-10-21"

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# System Prompt
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SYSTEM_PROMPT = """\
You are an expert network forensic analyst specialising in initial access \
vector identification. You are analysing a PCAP capture from a compromised \
enterprise network.

YOUR SOLE OBJECTIVE: Identify and document the **initial access** vector(s) \
used by the threat actor. Determine which host was first compromised \
("Patient Zero"), how the attacker got in, and from where.

═══ CRITICAL ANALYSIS PRINCIPLES ═══

• The IPs performing brute-force attacks are NOT necessarily the ones that \
  succeeded. The actual attacker who gains access may be a DIFFERENT IP \
  that logs in using credentials obtained from the brute-force campaign.
• A successful interactive session is DRAMATICALLY larger than a failed \
  login attempt. Failed RDP = 2-5 KB, ~20 frames, <10 s. Successful RDP = \
  50-500+ KB, hundreds of frames, minutes of duration.
• You MUST examine TCP conversations on the targeted port sorted by total \
  bytes to find the outlier session(s). The successful login will be \
  visibly larger than all the failed attempts.
• Always check whether C2 infrastructure was already active at the very \
  start of the capture — if so, the network was compromised BEFORE the \
  capture period, and what you see is a return visit.

═══ INVESTIGATION METHODOLOGY ═══

You have been given SEED DATA below from automatic pre-analysis. Study it \
carefully before making additional queries.

1. **Orientation** — Review the seed data (PCAP overview, brute-force \
   source IPs, TCP conversations on exposed service).
2. **Identify the successful session** — In the TCP conversations data, \
   find the session(s) with anomalously large byte counts and long \
   durations compared to the many small failed attempts. THIS IS THE \
   MOST IMPORTANT STEP. Do NOT skip it.
3. **Deep-dive the successful session** — For each suspected successful \
   session, query packet-level detail: first/last timestamps, bytes in \
   each direction (attacker→server vs server→attacker), frame counts, \
   how the session ended (FIN/RST).
4. **Characterise the attacker IP** — Check if the successful session IP \
   appears in the brute-force source list. If not, this suggests a \
   targeted follow-up by the actual threat actor using stolen creds.
5. **Pre-existing compromise** — Search for C2 beacons or suspicious DNS \
   queries (e.g., RMM tool domains, unusual subdomains) active from the \
   very start of the capture. Use dns queries to look for beacon patterns.
6. **Timeline construction** — Establish a timeline: When did brute-force \
   start? When did the successful login occur? When did C2 activity begin?

═══ MANDATORY CHECKLIST (before submitting report) ═══

You MUST have answers to ALL of these before calling submit_report:
☐ Which internal host is Patient Zero? (the one receiving external connections)
☐ What service was exposed? (port number, protocol)
☐ How many brute-force attempts? (SYN count, unique source IPs)
☐ Which IP successfully logged in? (NOT the brute-force IPs — find the \
  session with anomalously large bytes/duration in TCP conversations)
☐ Session details of the successful login: start time, end time, duration, \
  total bytes, bytes per direction, frame count
☐ How does the successful session compare to failed attempts? (size ratio)
☐ Is there evidence of pre-existing compromise? (C2 beacons, RMM tools)
☐ Complete IOC list: attacker IP, ports, timestamps

If you have NOT identified a specific successful session IP with detailed \
metrics, DO NOT submit the report — keep investigating.

═══ REPORT REQUIREMENTS ═══

When you have gathered sufficient evidence, call **submit_report** with a \
comprehensive Markdown report containing:
- Executive summary
- Patient Zero identification (host IP, role)
- Attack vector details (method, attacker IP, ports, timestamps)
- Evidence summary (packet counts, session sizes, durations)
- Comparison of successful vs. failed sessions (with specific byte counts)
- Attack timeline
- Pre-existing compromise evidence (if any)
- Indicators of Compromise (IOCs) — IPs, ports, signatures

IMPORTANT: You MUST call the submit_report tool to deliver your final report. \
Do NOT output the report as plain text.

Be thorough but efficient — avoid redundant queries. Think carefully about \
each result before deciding the next step.
"""

# ── Seed queries: automatically run before the agentic loop ──────────────
# These provide critical upfront data so the LLM can't miss key evidence.
SEED_QUERIES = [
    {
        "label": "PCAP Overview",
        "tool": "pcap_overview",
        "args": {},
    },
    {
        "label": "RDP Brute-Force Sources (SYN to port 3389, grouped by source IP)",
        "tool": "group_count",
        "args": {
            "display_filter": "tcp.dstport == 3389 && tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "group_by_field": "ip.src",
            "top_n": 25,
        },
    },
    {
        "label": "All TCP Conversations on Port 3389 (sorted by bytes — look for the outlier!)",
        "tool": "tcp_conversations",
        "args": {
            "display_filter": "tcp.port == 3389",
            "top_n": 50,
        },
    },
    {
        "label": "DNS queries for RMM/C2 domains at capture start (first 60 seconds)",
        "tool": "packet_query",
        "args": {
            "display_filter": "dns.qry.name contains \"rmm\" or dns.qry.name contains \"tactical\" or dns.qry.name contains \"mesh\"",
            "fields": ["frame.time", "ip.src", "dns.qry.name"],
            "max_packets": 50,
        },
    },
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool Definitions (OpenAI function-calling schema)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "pcap_overview",
            "description": (
                "Get basic PCAP capture statistics: file size, packet count, "
                "capture start/end time, duration, and encapsulation type."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "protocol_hierarchy",
            "description": (
                "Get the protocol hierarchy statistics showing every protocol "
                "in the capture with frame counts and byte totals."
            ),
            "parameters": {"type": "object", "properties": {}, "required": []},
        },
    },
    {
        "type": "function",
        "function": {
            "name": "ip_conversations",
            "description": (
                "List IP-level conversations sorted by total bytes. "
                "Shows source/destination IP, frames and bytes in each "
                "direction, start time, and duration."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top conversations to return (default 30).",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "tcp_conversations",
            "description": (
                "List TCP-level conversations (IP:port pairs) with optional "
                "display filter. Shows frames, bytes, start time, duration."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "display_filter": {
                        "type": "string",
                        "description": (
                            "Optional Wireshark display filter to restrict "
                            "conversations (e.g. 'tcp.port == 3389')."
                        ),
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Max conversations to return (default 30).",
                    },
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "packet_query",
            "description": (
                "Run a tshark query with a Wireshark display filter. "
                "Can extract specific fields, return packet summaries, "
                "or just count matching packets (count_only=true)."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "display_filter": {
                        "type": "string",
                        "description": (
                            "Wireshark display filter expression, e.g. "
                            "'tcp.dstport == 3389 && tcp.flags.syn == 1 "
                            "&& tcp.flags.ack == 0'."
                        ),
                    },
                    "fields": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": (
                            "Field names to extract, e.g. "
                            "['frame.time','ip.src','ip.dst','tcp.dstport']. "
                            "If omitted, returns one-line packet summaries."
                        ),
                    },
                    "count_only": {
                        "type": "boolean",
                        "description": "If true, only return the count of matching packets.",
                    },
                    "max_packets": {
                        "type": "integer",
                        "description": "Max packets to return (default 100, max 500). Ignored when count_only is true.",
                    },
                },
                "required": ["display_filter"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "group_count",
            "description": (
                "Count packets matching a filter, grouped by a field. "
                "Returns values sorted by count descending. "
                "Example: 'which source IPs sent the most RDP SYNs?'"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "display_filter": {
                        "type": "string",
                        "description": "Wireshark display filter expression.",
                    },
                    "group_by_field": {
                        "type": "string",
                        "description": "Field to group by (e.g. 'ip.src').",
                    },
                    "top_n": {
                        "type": "integer",
                        "description": "Number of top groups to return (default 20).",
                    },
                },
                "required": ["display_filter", "group_by_field"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_report",
            "description": (
                "Submit the final Initial Access forensic report. "
                "Call this ONLY when investigation is complete."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "report": {
                        "type": "string",
                        "description": "The complete forensic report in Markdown.",
                    }
                },
                "required": ["report"],
            },
        },
    },
]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Tool Implementations
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class PcapTools:
    """Wraps tshark / capinfos as callable tools for the forensic agent."""

    def __init__(self, pcap_path: str, tshark_path: str):
        self.pcap = pcap_path
        self.tshark = tshark_path
        self.capinfos = os.path.join(os.path.dirname(tshark_path), "capinfos")

    # ── helpers ────────────────────────────────────────────────────────────

    def _run(self, cmd: list[str], timeout: int = 300) -> str:
        """Run a shell command, return stdout (truncated if necessary)."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout
            if result.returncode != 0 and result.stderr:
                output += f"\n[STDERR]: {result.stderr[:1000]}"
            return self._truncate(output)
        except subprocess.TimeoutExpired:
            return f"[ERROR] Command timed out after {timeout}s"
        except Exception as e:
            return f"[ERROR] {e}"

    @staticmethod
    def _truncate(text: str) -> str:
        if len(text) > MAX_OUTPUT_CHARS:
            return (
                text[:MAX_OUTPUT_CHARS]
                + f"\n\n... [TRUNCATED — showing first {MAX_OUTPUT_CHARS} of {len(text)} chars]"
            )
        return text

    # ── tool: pcap_overview ────────────────────────────────────────────────

    def pcap_overview(self) -> str:
        if os.path.isfile(self.capinfos):
            return self._run([self.capinfos, self.pcap])
        # fallback
        return self._run([self.tshark, "-r", self.pcap, "-q", "-z", "io,stat,0"])

    # ── tool: protocol_hierarchy ───────────────────────────────────────────

    def protocol_hierarchy(self) -> str:
        return self._run([self.tshark, "-r", self.pcap, "-q", "-z", "io,phs"])

    # ── tool: ip_conversations ─────────────────────────────────────────────

    def ip_conversations(self, top_n: int = 30) -> str:
        output = self._run([self.tshark, "-r", self.pcap, "-q", "-z", "conv,ip"])
        return self._limit_conv_lines(output, top_n)

    # ── tool: tcp_conversations ────────────────────────────────────────────

    def tcp_conversations(self, display_filter: str | None = None, top_n: int = 30) -> str:
        stat = f"conv,tcp,{display_filter}" if display_filter else "conv,tcp"
        output = self._run([self.tshark, "-r", self.pcap, "-q", "-z", stat])
        return self._limit_conv_lines(output, top_n)

    @staticmethod
    def _limit_conv_lines(output: str, top_n: int) -> str:
        lines = output.strip().split("\n")
        result, conv_count = [], 0
        for line in lines:
            if "<->" in line:
                conv_count += 1
                if conv_count <= top_n:
                    result.append(line)
            else:
                result.append(line)
        if conv_count > top_n:
            result.append(f"\n... [{conv_count - top_n} more conversations not shown]")
        return "\n".join(result)

    # ── tool: packet_query ─────────────────────────────────────────────────

    def packet_query(
        self,
        display_filter: str,
        fields: list[str] | None = None,
        count_only: bool = False,
        max_packets: int = 100,
    ) -> str:
        max_packets = min(max_packets or 100, 500)

        if count_only:
            return self._count_packets(display_filter)

        cmd = [self.tshark, "-r", self.pcap, "-Y", display_filter, "-c", str(max_packets)]
        if fields:
            cmd.extend(["-T", "fields"])
            for f in fields:
                cmd.extend(["-e", f])
        return self._run(cmd)

    def _count_packets(self, display_filter: str) -> str:
        """Stream packets and count — avoids loading huge output into memory."""
        try:
            proc = subprocess.Popen(
                [self.tshark, "-r", self.pcap, "-Y", display_filter, "-T", "fields", "-e", "frame.number"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            count = sum(1 for line in proc.stdout if line.strip())
            proc.wait(timeout=300)
            return f"Matching packets: {count}"
        except subprocess.TimeoutExpired:
            proc.kill()
            return "[ERROR] Count query timed out"
        except Exception as e:
            return f"[ERROR] {e}"

    # ── tool: group_count ──────────────────────────────────────────────────

    def group_count(self, display_filter: str, group_by_field: str, top_n: int = 20) -> str:
        """Stream packets, group by field, return sorted counts."""
        try:
            proc = subprocess.Popen(
                [self.tshark, "-r", self.pcap, "-Y", display_filter, "-T", "fields", "-e", group_by_field],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            counts: dict[str, int] = {}
            for line in proc.stdout:
                val = line.strip()
                if val:
                    counts[val] = counts.get(val, 0) + 1
            proc.wait(timeout=300)

            sorted_counts = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:top_n]

            rows = [f"{'Value':<55} {'Count':>10}", "-" * 67]
            for val, cnt in sorted_counts:
                rows.append(f"{val:<55} {cnt:>10}")
            rows.append(f"\nTotal unique values: {len(counts)}")
            rows.append(f"Total matching packets: {sum(counts.values())}")
            return "\n".join(rows)

        except subprocess.TimeoutExpired:
            proc.kill()
            return "[ERROR] Query timed out"
        except Exception as e:
            return f"[ERROR] {e}"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Forensic Agent
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


class ForensicAgent:
    """
    Agentic loop: sends context to Azure OpenAI, executes tool calls
    returned by the model, feeds results back, repeats until the model
    calls submit_report.
    """

    def __init__(
        self,
        pcap_path: str,
        azure_config: dict,
        tshark_path: str,
        output_path: str,
    ):
        self.pcap_path = pcap_path
        self.output_path = output_path
        self.tools = PcapTools(pcap_path, tshark_path)

        self.client = AzureOpenAI(
            azure_endpoint=azure_config["endpoint"],
            api_key=azure_config["api_key"],
            api_version=API_VERSION,
        )
        self.deployment = azure_config["deployment"]

        self.messages: list[dict] = [
            {"role": "system", "content": SYSTEM_PROMPT},
        ]
        self.report: str | None = None

        # Run seed queries to build the initial context
        self._run_seed_queries()

    # ── seed queries ───────────────────────────────────────────────────────

    def _run_seed_queries(self):
        """Run mandatory pre-analysis queries and inject results as context."""
        print(f"\n{'─' * 64}")
        print("  Running seed queries (mandatory pre-analysis)...")
        print(f"{'─' * 64}")

        seed_results = []
        for i, sq in enumerate(SEED_QUERIES, 1):
            label = sq["label"]
            print(f"  [{i}/{len(SEED_QUERIES)}] {label}...", end=" ", flush=True)
            t0 = time.time()
            result = self._execute_tool(sq["tool"], sq["args"])
            elapsed = time.time() - t0
            print(f"({elapsed:.1f}s)")
            seed_results.append(f"### {label}\n```\n{result}\n```")

        seed_context = "\n\n".join(seed_results)
        self.messages.append({
            "role": "user",
            "content": (
                f"Analyze this PCAP file for initial access vectors and "
                f"produce a forensic report.\n\n"
                f"File: {os.path.basename(self.pcap_path)}\n"
                f"Path: {self.pcap_path}\n\n"
                f"═══ SEED DATA (auto-collected) ═══\n\n"
                f"{seed_context}\n\n"
                f"═══ INSTRUCTIONS ═══\n\n"
                f"Study the seed data above carefully. The TCP conversations "
                f"on port 3389 are sorted by total bytes. Look for the "
                f"session(s) that are DRAMATICALLY larger than the rest — "
                f"those are likely successful logins, not brute-force "
                f"failures. Investigate those specific sessions in detail "
                f"before writing your report.\n\n"
                f"Remember: the brute-force source IPs are NOT necessarily "
                f"the same IP that successfully logged in."
            ),
        })

        print(f"{'─' * 64}")
        print(f"  Seed data injected. Starting agentic analysis...")
        print(f"{'─' * 64}\n")

    # ── main loop ──────────────────────────────────────────────────────────

    def run(self) -> str:
        hdr = (
            f"\n{'=' * 64}\n"
            f"  SC4063 — Initial Access Forensic Agent\n"
            f"  PCAP : {os.path.basename(self.pcap_path)}\n"
            f"  Model: {self.deployment}\n"
            f"{'=' * 64}\n"
        )
        print(hdr)

        for step in range(1, MAX_AGENT_STEPS + 1):
            # ── nudge the LLM to wrap up when nearing the limit ──
            if step == MAX_AGENT_STEPS - 4:
                self.messages.append({
                    "role": "user",
                    "content": (
                        "⚠️ You are running low on remaining steps. "
                        "You MUST call submit_report within the next 3 steps "
                        "with whatever evidence you have gathered so far. "
                        "Summarise your findings and submit now."
                    ),
                })
                print(f"  [nudge] Injected wrap-up reminder")

            print(f"[Step {step:>2}/{MAX_AGENT_STEPS}] ", end="", flush=True)
            t0 = time.time()

            response = self._call_api()
            msg = response.choices[0].message

            # Serialise assistant message into history
            self.messages.append(self._serialise_msg(msg))

            if msg.tool_calls:
                names = []
                for tc in msg.tool_calls:
                    name = tc.function.name
                    names.append(name)
                    args = json.loads(tc.function.arguments) if tc.function.arguments else {}

                    # ── submit_report terminates the loop ──
                    if name == "submit_report":
                        elapsed = time.time() - t0
                        print(f"submit_report  ({elapsed:.1f}s)")
                        self.report = args.get("report", "")
                        self._save_report()
                        return self.report

                    # ── execute tool ──
                    result = self._execute_tool(name, args)
                    self.messages.append(
                        {"role": "tool", "tool_call_id": tc.id, "content": result}
                    )

                elapsed = time.time() - t0
                print(f"{', '.join(names)}  ({elapsed:.1f}s)")

            elif msg.content:
                elapsed = time.time() - t0
                print(f"thinking  ({elapsed:.1f}s)")
                # If the model accidentally produces a full report as text
                if "# " in msg.content and len(msg.content) > 500:
                    self.report = msg.content
                    self._save_report()
                    return self.report
            else:
                print("(no output)")
                break

        # ── Force a final report if the agent ran out of steps ──
        print(f"\n[!] Reached step limit ({MAX_AGENT_STEPS}). Forcing final report...")
        self.messages.append({
            "role": "user",
            "content": (
                "You have used all available investigation steps. "
                "You MUST call submit_report RIGHT NOW with your findings. "
                "Do NOT call any other tool. Summarise everything you have "
                "discovered and submit the report immediately."
            ),
        })
        try:
            response = self._call_api()
            msg = response.choices[0].message
            if msg.tool_calls:
                for tc in msg.tool_calls:
                    if tc.function.name == "submit_report":
                        args = json.loads(tc.function.arguments) if tc.function.arguments else {}
                        self.report = args.get("report", "")
                        self._save_report()
                        return self.report
            # If model returned text instead of tool call, use it as report
            if msg.content and len(msg.content) > 200:
                self.report = msg.content
                self._save_report()
                return self.report
        except Exception as e:
            print(f"  [error] Failed to get forced report: {e}")

        return self.report or "Agent did not produce a report within the step limit."

    # ── API call with retry ────────────────────────────────────────────────

    def _call_api(self):
        for attempt in range(3):
            try:
                return self.client.chat.completions.create(
                    model=self.deployment,
                    messages=self.messages,
                    tools=TOOLS,
                    tool_choice="auto",
                    temperature=0.1,
                )
            except Exception as e:
                if attempt < 2:
                    wait = 5 * (2 ** attempt)
                    print(f"\n  [retry] API error: {e} — waiting {wait}s")
                    time.sleep(wait)
                else:
                    raise

    # ── message serialisation ──────────────────────────────────────────────

    @staticmethod
    def _serialise_msg(msg) -> dict:
        """Convert a ChatCompletionMessage to a plain dict for the history."""
        d: dict = {"role": msg.role, "content": msg.content}
        if msg.tool_calls:
            d["tool_calls"] = [
                {
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in msg.tool_calls
            ]
        return d

    # ── tool dispatch ──────────────────────────────────────────────────────

    def _execute_tool(self, name: str, args: dict) -> str:
        try:
            match name:
                case "pcap_overview":
                    return self.tools.pcap_overview()
                case "protocol_hierarchy":
                    return self.tools.protocol_hierarchy()
                case "ip_conversations":
                    return self.tools.ip_conversations(args.get("top_n", 30))
                case "tcp_conversations":
                    return self.tools.tcp_conversations(
                        args.get("display_filter"), args.get("top_n", 30)
                    )
                case "packet_query":
                    return self.tools.packet_query(
                        args["display_filter"],
                        args.get("fields"),
                        args.get("count_only", False),
                        args.get("max_packets", 100),
                    )
                case "group_count":
                    return self.tools.group_count(
                        args["display_filter"],
                        args["group_by_field"],
                        args.get("top_n", 20),
                    )
                case _:
                    return f"[ERROR] Unknown tool: {name}"
        except Exception as e:
            return f"[ERROR] Tool '{name}' failed: {e}"

    # ── report output ──────────────────────────────────────────────────────

    def _save_report(self):
        if not self.report:
            return
        Path(self.output_path).write_text(self.report, encoding="utf-8")
        print(f"\n{'─' * 64}")
        print(f"  Report saved → {self.output_path}")
        print(f"  Length: {len(self.report):,} chars")
        print(f"{'─' * 64}")


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Utilities
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def find_tshark() -> str | None:
    """Auto-detect tshark binary location."""
    env = os.environ.get("TSHARK_PATH")
    if env and os.path.isfile(env):
        return env

    path = shutil.which("tshark")
    if path:
        return path

    for candidate in [
        "/opt/homebrew/opt/wireshark/bin/tshark",
        "/opt/homebrew/bin/tshark",
        "/usr/local/bin/tshark",
        "/usr/bin/tshark",
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
    ]:
        if os.path.isfile(candidate):
            return candidate

    return None


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CLI
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━


def main():
    parser = argparse.ArgumentParser(
        description="SC4063 Agentic Network Forensic — Initial Access Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Environment variables (or .env file):
              AZURE_OPENAI_ENDPOINT     https://<resource>.openai.azure.com/
              AZURE_OPENAI_API_KEY      <your-key>
              AZURE_OPENAI_DEPLOYMENT   deployment name (default: gpt-4o-mini)
              TSHARK_PATH               /path/to/tshark (auto-detected)

            Example:
              python agent.py capture.pcap -o initial_access_report.md
        """),
    )
    parser.add_argument("pcap", help="Path to the PCAP file to analyse")
    parser.add_argument(
        "-o", "--output",
        default="initial_access_report.md",
        help="Output report path (default: initial_access_report.md)",
    )
    parser.add_argument(
        "--deployment",
        default=None,
        help="Azure OpenAI deployment name (overrides env var)",
    )
    args = parser.parse_args()

    # ── validate PCAP ──
    pcap = os.path.abspath(args.pcap)
    if not os.path.isfile(pcap):
        print(f"Error: PCAP file not found: {pcap}", file=sys.stderr)
        sys.exit(1)

    # ── find tshark ──
    tshark = find_tshark()
    if not tshark:
        print(
            "Error: tshark not found. Install Wireshark or set TSHARK_PATH.",
            file=sys.stderr,
        )
        sys.exit(1)
    print(f"tshark : {tshark}")

    # ── Azure OpenAI config ──
    endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT")
    api_key = os.environ.get("AZURE_OPENAI_API_KEY")
    deployment = args.deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "gpt-4o-mini")

    if not endpoint or not api_key:
        print(
            "Error: Set AZURE_OPENAI_ENDPOINT and AZURE_OPENAI_API_KEY.\n"
            "       You can use a .env file or export them in your shell.",
            file=sys.stderr,
        )
        sys.exit(1)

    print(f"Azure  : {endpoint}")
    print(f"Deploy : {deployment}")

    azure_config = {
        "endpoint": endpoint,
        "api_key": api_key,
        "deployment": deployment,
    }

    # ── run agent ──
    agent = ForensicAgent(
        pcap_path=pcap,
        azure_config=azure_config,
        tshark_path=tshark,
        output_path=os.path.abspath(args.output),
    )

    t_start = time.time()
    agent.run()
    elapsed = time.time() - t_start

    print(f"\n{'=' * 64}")
    print(f"  Analysis complete in {elapsed:.0f}s")
    print(f"{'=' * 64}\n")


if __name__ == "__main__":
    main()
