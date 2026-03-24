"""
agent.py
=========
ForensicAgent — Initial Access Analysis Agent

Uses tshark to extract key network features from a PCAP, then calls Azure
OpenAI (via langchain-openai) to reason about the initial access vector and
produce a structured Markdown incident report.

Interface expected by agents/initial_access_adapter.py:
    agent = ForensicAgent(pcap_path, azure_config, tshark_path, output_path)
    report_markdown: str = agent.run()
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


class ForensicAgent:
    """
    Forensic agent for identifying the initial access vector in a PCAP.

    Steps
    -----
    1. Run several targeted tshark queries to extract evidence.
    2. Feed the combined evidence to Azure OpenAI GPT-4o-mini.
    3. Return a Markdown report string (and optionally save it to disk).
    """

    def __init__(
        self,
        pcap_path: str,
        azure_config: dict,
        tshark_path: str = "tshark",
        output_path: Optional[str] = None,
    ) -> None:
        self.pcap_path = pcap_path
        self.azure_config = azure_config
        self.tshark = tshark_path
        self.output_path = output_path

    # ── tshark helpers ────────────────────────────────────────────────────────

    def _run(self, args: list[str], timeout: int = 120) -> str:
        try:
            r = subprocess.run(
                [self.tshark, "-r", self.pcap_path] + args,
                capture_output=True, text=True, timeout=timeout,
            )
            return (r.stdout or "")[:20_000]
        except subprocess.TimeoutExpired:
            return "[tshark timeout]"
        except Exception as exc:
            return f"[tshark error: {exc}]"

    def _tcp_conversations(self) -> str:
        """Top TCP conversations by bytes — surfaces heavy sessions."""
        return self._run(["-q", "-z", "conv,tcp"])

    def _rdp_connections(self) -> str:
        """RDP (3389) connection events — primary initial-access channel."""
        return self._run([
            "-Y", "tcp.port == 3389",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "tcp.flags.syn", "-e", "tcp.flags.ack",
            "-e", "tcp.len",
            "-c", "1000",
        ])

    def _ntlm_events(self) -> str:
        """NTLM auth events — brute-force / pass-the-hash evidence."""
        return self._run([
            "-Y", "ntlmssp",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "ntlmssp.messagetype",
            "-e", "ntlmssp.auth.username",
            "-c", "2000",
        ])

    def _syn_scan(self) -> str:
        """High SYN-only count per source — brute-force / port-scan indicator."""
        return self._run([
            "-Y", "tcp.flags.syn == 1 && tcp.flags.ack == 0",
            "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst", "-e", "tcp.dstport",
            "-c", "3000",
        ])

    def _http_requests(self) -> str:
        """HTTP request summary — phishing drops / C2 beacon check-ins."""
        return self._run([
            "-Y", "http.request",
            "-T", "fields",
            "-e", "frame.time_relative",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "http.host", "-e", "http.request.uri",
            "-e", "http.request.method",
            "-c", "500",
        ])

    def _smb_activity(self) -> str:
        """SMB activity — lateral movement enabler / file drops after access."""
        return self._run([
            "-Y", "smb or smb2",
            "-T", "fields",
            "-e", "ip.src", "-e", "ip.dst",
            "-e", "smb.cmd", "-e", "smb2.cmd",
            "-c", "500",
        ])

    # ── Main entry point ──────────────────────────────────────────────────────

    def run(self) -> str:
        """
        Extract evidence from the PCAP, call Azure OpenAI, and return a
        Markdown incident report.
        """
        print(f"  [ForensicAgent] Extracting data from {Path(self.pcap_path).name}…")

        tcp_conv    = self._tcp_conversations()
        rdp         = self._rdp_connections()
        ntlm        = self._ntlm_events()
        syn_scan    = self._syn_scan()
        http        = self._http_requests()
        smb         = self._smb_activity()

        print("  [ForensicAgent] Calling Azure OpenAI for analysis…")

        system_prompt = (
            "You are a senior network forensics analyst performing an incident investigation.\n"
            "Analyse the provided tshark extracts and identify the initial access vector.\n\n"
            "Focus on:\n"
            "- Brute-force attacks (high SYN count / many failed NTLM auths from a single IP)\n"
            "- Successful authentication after repeated failures\n"
            "- RDP / SSH / SMB exploitation\n"
            "- The 'patient zero' — the first internal host accessed by the attacker\n"
            "- The attacker's external IP address\n"
            "- Attack timeline (start / success timestamps)\n\n"
            "Output ONLY a Markdown report with these sections:\n"
            "# Initial Access Analysis\n"
            "## Executive Summary\n"
            "## Attack Vector\n"
            "## Patient Zero\n"
            "## Attacker IP\n"
            "## Timeline\n"
            "## Indicators of Compromise\n"
            "## Recommendations\n"
        )

        user_content = (
            f"PCAP file: {self.pcap_path}\n\n"
            f"## TCP Conversations (top talkers / bytes)\n```\n{tcp_conv[:5000]}\n```\n\n"
            f"## RDP Connections (port 3389)\n```\n{rdp[:3000]}\n```\n\n"
            f"## NTLM Authentication Events\n```\n{ntlm[:3000]}\n```\n\n"
            f"## SYN-Only Packets (brute-force / scan indicator)\n```\n{syn_scan[:3000]}\n```\n\n"
            f"## HTTP Requests\n```\n{http[:2000]}\n```\n\n"
            f"## SMB Activity\n```\n{smb[:2000]}\n```\n\n"
            "Write the full incident report now."
        )

        report = self._call_azure(system_prompt, user_content)

        if self.output_path:
            p = Path(self.output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report, encoding="utf-8")
            print(f"  [ForensicAgent] Report saved → {self.output_path}")

        return report

    # ── LLM call ─────────────────────────────────────────────────────────────

    def _call_azure(self, system: str, user: str) -> str:
        """Call Azure OpenAI and return the response text."""
        try:
            from langchain_openai import AzureChatOpenAI
            from langchain_core.messages import HumanMessage, SystemMessage

            llm = AzureChatOpenAI(
                azure_endpoint=self.azure_config["endpoint"],
                api_key=self.azure_config["api_key"],
                azure_deployment=self.azure_config.get("deployment", "gpt-4o-mini"),
                api_version="2024-02-01",
                temperature=0.1,
                max_tokens=4000,
            )
            response = llm.invoke([
                SystemMessage(content=system),
                HumanMessage(content=user),
            ])
            return response.content or ""
        except Exception as exc:
            return (
                "# Initial Access Analysis\n\n"
                f"**Error calling Azure OpenAI:** {exc}\n\n"
                "Analysis could not be completed. Check AZURE_OPENAI_ENDPOINT and "
                "AZURE_OPENAI_API_KEY environment variables."
            )
