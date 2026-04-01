# SC4063 Agentic Network Forensic Analysis Pipeline

Autonomous network forensic analysis agent for the SC4063 Final Project. Analyses 9 days of PCAP and Zeek network capture data from the Apex Global Logistics Lynx ransomware incident and produces a structured incident response report.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Pipeline Stages](#pipeline-stages)
- [Tools Reference](#tools-reference)
- [Key Design Decisions](#key-design-decisions)
- [Troubleshooting](#troubleshooting)

## Architecture Overview

The pipeline uses a **two-pass architecture**:

**Pass 1 -- Zeek Sweep (all 9 days, no PCAPs):**
Downloads Zeek structured logs for each day and runs four agents (Initial Access triage, Lateral Movement, Exfiltration, Payload) using only parsed log data. Fast, lightweight, and provides full coverage. Determines which days need deeper investigation.

**Pass 2 -- PCAP Drill-Down (flagged days only):**
Downloads one PCAP per flagged day and runs Initial Access (tshark-based deep analysis) and Payload (file extraction + inspection) agents. Provides packet-level confirmation and artifact extraction.

Both passes feed into a combined MITRE ATT&CK enrichment step and a final LLM-generated incident report (Markdown + PDF).

### Data Flow

1. **Alerts** downloaded for all days, scored for suspect IPs
2. **Zeek logs** (11 datasets/day) downloaded per day, normalised from ECS/Filebeat format to standard Zeek field names via `shared/ecs_compat.py`
3. **Agents** consume normalised data, produce structured JSON findings
4. **Attack context** accumulates chronologically across days (patient zero, compromised hosts, attacker IPs)
5. **MITRE enrichment** maps findings to ATT&CK techniques and threat groups
6. **Report writer** synthesises all findings into a single incident report

### Disk Management

A sliding window keeps disk usage under control:
- Soft limit: 5 GB, hard limit: 8 GB
- At most 1 day's Zeek + 1 PCAP on disk at a time (~4.5 GB peak)
- Previous day's data released and evicted before next day downloads
- Checkpoint after every day -- crash-resilient, resume from last completed day

## Prerequisites

### Required Software

| Software | Version | Purpose |
|----------|---------|---------|
| Python | 3.10+ (3.12 recommended) | Pipeline runtime |
| tshark | 4.x (Wireshark CLI) | PCAP analysis in Pass 2 |
| pip | Latest | Package installation |

### Required Accounts / API Keys

| Service | Purpose | Required |
|---------|---------|----------|
| Azure OpenAI | LLM inference (GPT-4o-mini) | Yes |
| Google OAuth | Authenticated Drive API downloads (bypasses quota) | Yes |
| VirusTotal | Payload hash lookup | Optional |

### Hardware Requirements

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 2 cores | 4+ cores |
| RAM | 4 GB | 8 GB |
| Disk | 15 GB free | 30 GB free |
| GPU | Not required | N/A |
| Network | Broadband | 50+ MB/s |

The pipeline is CPU-light (~6% peak), RAM-light (~200 MB), and network-bound (80% of runtime is downloading data).

## Installation

```bash
# Clone or extract the project
cd SC4063_project

# Create virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Verify tshark is available
tshark --version
```

### Installing tshark

Ubuntu/Debian:
```bash
sudo apt install tshark
```

macOS:
```bash
brew install wireshark
```

Windows: Install Wireshark from https://www.wireshark.org/ -- tshark is included.

## Configuration

### Environment Variables

Copy the example and fill in your keys:

```bash
cp .env.example .env
```

Required variables in `.env`:

```
# Azure OpenAI (required)
AZURE_OPENAI_ENDPOINT=https://your-instance.openai.azure.com/
AZURE_OPENAI_API_KEY=your-api-key
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini

# VirusTotal (optional -- payload agent skips VT lookup if not set)
VIRUSTOTAL_API_KEY=your-vt-key

# tshark path (auto-detected if on PATH)
TSHARK_PATH=/usr/bin/tshark
```

### Google OAuth Setup

The pipeline uses authenticated Google Drive API to bypass public download quota limits. Required files:

- `oauth-client.json` -- OAuth 2.0 client credentials (from Google Cloud Console)
- `oauth-token.json` -- Refresh token (generated on first auth)

To generate the token:
```bash
python auth_drive.py
```
This opens a browser for Google OAuth consent. The token is saved to `oauth-token.json`.

## Usage

### Full Analysis (All 9 Days)

```bash
source venv/bin/activate
python master_pipeline.py --all-days --work-dir data
```

This runs the complete two-pass pipeline:
1. Downloads alerts for all 9 days
2. Scores alerts and ranks PCAPs
3. Pass 1: Zeek sweep of all days (no PCAPs)
4. Pass 2: PCAP drill-down on flagged days
5. Generates combined incident report

Output: `reports/<run_id>/combined_incident_report.md` and `.pdf`

### Single Day Analysis

```bash
python master_pipeline.py --day 2025-03-06 --work-dir data
```

Runs the full pipeline (ingest + all 4 agents + MITRE + report) for one day.

### Single Day with Local PCAP

```bash
python master_pipeline.py --day 2025-03-09 \
  --pcap data/2025-03-09/pcap/34936-sensor-250309-00002476_redacted.pcap \
  --work-dir data
```

Skips API ingestion and uses a local PCAP. Auto-discovers Zeek files in `data/<day>/zeek/`.

### Single Agent Debug Mode

```bash
python master_pipeline.py --day 2025-03-06 --only lateral_movement --work-dir data
```

Runs only one agent. Useful for debugging. Options: `initial_access`, `lateral_movement`, `exfiltration`, `payload`, `report`.

### CLI Options

| Flag | Description | Default |
|------|-------------|---------|
| `--day YYYY-MM-DD` | Single day to analyse | -- |
| `--all-days` | Analyse all available days | -- |
| `--work-dir PATH` | Directory for downloads and outputs | `./data` |
| `--pcap PATH` | Skip ingestion, use local PCAP | -- |
| `--only AGENT` | Run only one agent (debug mode) | -- |
| `--no-provenance` | Disable evidence provenance tracking | Enabled |
| `--disk-soft-gb N` | Soft disk budget in GB | 5.0 |
| `--disk-hard-gb N` | Hard disk budget in GB | 8.0 |

### Non-Interactive Mode

When run without a terminal (e.g., background process, CI/CD), the pipeline automatically:
- Selects the best PCAP per day by alert score (no HITL prompt)
- Uses generous drill-down thresholds (errs on the side of investigating)

### Resuming from Crash

The pipeline checkpoints after every day. If it crashes:
```bash
# Just re-run the same command -- it resumes automatically
python master_pipeline.py --all-days --work-dir data
```

To force a fresh run, delete the checkpoint:
```bash
rm data/.pipeline_checkpoint.json
```

## Project Structure

```
SC4063_project/
|-- master_pipeline.py              # Main orchestrator (two-pass architecture)
|-- initial_access_agent.py         # ForensicAgent: tshark ReAct loop + Zeek seeds
|-- payload_agent.py                # Payload detection: 4 Zeek + 4 PCAP tools
|-- .env                            # API keys (not committed)
|-- requirements.txt                # Python dependencies
|-- oauth-client.json               # Google OAuth client credentials
|-- oauth-token.json                # Google OAuth refresh token
|-- auth_drive.py                   # Google OAuth token generator
|-- copy_drive_files.py             # Drive folder copy utility (quota management)
|
|-- agents/                         # Agent adapters (PipelineState interface)
|   |-- initial_access_adapter.py   # Wraps ForensicAgent for pipeline
|   |-- lateral_movement_adapter.py # Wraps LM agent for pipeline
|   |-- exfiltration_agent.py       # Exfiltration agent + zeek_root adapter
|   |-- payload_agent_adapter.py    # Wraps payload agent for pipeline
|
|-- lateral_movement/               # Lateral movement detection
|   |-- lateral_movement.py         # 5 Zeek-based tools + LLM ReAct loop
|
|-- exfil/                          # Exfiltration detection module
|   |-- exfiltration_tool.py        # Volume spike + beaconing detection
|   |-- dns_exfiltration.py         # DNS tunneling detection
|   |-- http_exfiltration.py        # HTTP upload detection
|   |-- exfiltration_summarizer.py  # LLM narrative summariser
|   |-- exfiltration_pipeline_runner.py  # Orchestrates exfil sub-pipeline
|   |-- pcap_ingestor.py            # PCAP-to-Zeek converter (local zeek binary)
|   |-- shard_api_client.py         # Direct API client for exfil module
|
|-- shared/                         # Shared utilities
|   |-- data_contract.py            # PipelineState TypedDict + canonical accessors
|   |-- ecs_compat.py               # ECS/Filebeat to standard Zeek field normalisation
|   |-- pcap_api.py                 # SC4063 API client (alerts, Zeek, PCAPs)
|   |-- disk_manager.py             # Disk budget manager + provenance tracking
|   |-- api_config.py               # API endpoint pool with failover
|
|-- mitre_reference/
|   |-- enterprise-attack.json      # MITRE ATT&CK database (835 techniques)
|
|-- data/                           # Working directory (downloads, checkpoints)
|   |-- .pipeline_checkpoint.json   # Auto-saved pipeline state
|   |-- .disk_manifest.json         # Disk budget tracking
|   |-- 2025-03-XX/                 # Per-day data (alerts, zeek/, pcap/)
|
|-- reports/                        # Generated reports
    |-- <run_id>/
        |-- combined_incident_report.md
        |-- combined_incident_report.pdf
```

## Pipeline Stages

### Phase 0: Triage
- Downloads Suricata alerts for all 9 days
- Scores alerts across days to identify suspect IPs and high-activity periods
- Ranks all PCAPs globally by alert density

### Pass 1: Zeek Sweep

For each day (chronologically):

1. **Download Zeek logs** (11 datasets: connection, DNS, RDP, HTTP, SMB files, SMB mapping, DCE-RPC, Kerberos, SSL, notice, weird)
2. **IA Triage** -- Deterministic scan of Zeek RDP + connection logs. Counts brute-force attempts, identifies largest RDP session (likely successful login), extracts patient_zero and attacker_ip.
3. **Lateral Movement Agent** -- LLM ReAct loop calls 5 tools to detect SMB admin share access, internal RDP, Kerberos anomalies, DCE-RPC service creation/SAMR enumeration.
4. **Exfiltration Agent** -- Analyses connection, DNS, HTTP, SSL logs for volume spikes, DNS tunneling, HTTP uploads.
5. **Payload Agent** -- Detects SMB file drops (executables, archives), RDP from DC, WinRM/WMI/DCOM remote execution, suspicious HTTP downloads.
6. **MITRE Enrichment** -- Maps findings to ATT&CK techniques and identifies candidate threat groups.
7. **Drill-down decision** -- Flags day for PCAP analysis if any suspicious activity detected.

### Pass 2: PCAP Drill-Down

For each flagged day:

1. **Download 1 PCAP** (highest alert score for that day)
2. **Initial Access Agent** -- Full ForensicAgent with tshark: Zeek-based seed queries (fast) + LLM-driven ad-hoc tshark queries (up to 30 steps)
3. **Payload Agent** -- All Zeek tools + tshark file extraction (--export-objects http/smb), file inspection (SHA256, entropy, magic numbers), custom pattern search
4. **MITRE re-enrichment** with combined Pass 1 + Pass 2 findings

### Report Generation
- LLM synthesises all per-day findings into a single combined report
- Structured sections: Executive Summary, Detailed Findings (per attack phase), MITRE mapping, Threat Group Assessment, Timeline, Recommendations, Evidence Gaps
- Evidence Provenance appendix lists exactly which files each agent accessed

## Tools Reference

### Lateral Movement Agent (5 tools)
| Tool | Data Source | Detects |
|------|-----------|---------|
| `smb_lateral_movement` | zeek.smb_files + smb_mapping | Admin share access (IPC$, ADMIN$), PsExec artifacts, file share operations |
| `rdp_lateral_movement` | zeek.rdp | Internal RDP sessions (host-to-host) |
| `ntlm_auth_events` | tshark fallback | Pass-the-hash, credential relay, spray patterns |
| `kerberos_events` | zeek.kerberos | Kerberoasting, pass-the-ticket, AS-REP roasting |
| `dce_rpc_events` | zeek.dce_rpc | Service creation (SCM), WMI, DCOM, SAMR user/group manipulation |

### Payload Agent (8 tools)
| Tool | Pass | Data Source | Detects |
|------|------|-----------|---------|
| `smb_file_drops` | 1+2 | zeek.smb_files | Executable/archive writes via SMB |
| `rdp_from_dc` | 1+2 | zeek.rdp + connection | RDP from DC to targets (payload deployment) |
| `remote_execution_events` | 1+2 | zeek.dce_rpc + http | WinRM, WMI, DCOM, service creation |
| `http_payload_downloads` | 1+2 | zeek.http | Suspicious downloads from external IPs |
| `extract_http_objects` | 2 | PCAP | Extract files from HTTP streams |
| `extract_smb_objects` | 2 | PCAP | Extract files from SMB streams |
| `inspect_file` | 2 | Extracted file | SHA256, entropy, magic number analysis |
| `search_pcap_for_pattern` | 2 | PCAP | Custom tshark display filter queries |

### Initial Access Agent (6 tools, Pass 2 only)
| Tool | Detects |
|------|---------|
| `pcap_overview` | Capture metadata (duration, packet count, file size) |
| `tcp_conversations` | TCP sessions sorted by bytes (find successful logins) |
| `packet_query` | Custom display filter queries |
| `group_count` | Packet counts grouped by field (e.g., brute-force source IPs) |
| `protocol_hierarchy` | Protocol distribution |
| `ip_conversations` | IP-level conversation summary |

### Exfiltration Agent (3 modules)
| Module | Detects |
|--------|---------|
| `exfiltration_tool` | Outbound volume spikes, beaconing patterns |
| `dns_exfiltration` | DNS tunneling (high entropy, long queries, rare domains) |
| `http_exfiltration` | Large HTTP POST uploads, file-sharing service usage |

## Key Design Decisions

### ECS Normalisation Layer
The SC4063 API serves Zeek logs in Elastic Common Schema (ECS/Filebeat) format, not standard Zeek JSON. The `shared/ecs_compat.py` module auto-detects the format and translates 40+ fields across 12 log types. This is transparent to all agent tools -- they use standard field names like `rec.get("id.orig_h")` regardless of the underlying format.

### Two-Pass vs Single-Pass
A single-pass approach (download PCAPs + Zeek for every day) would require ~50 GB of disk and ~12+ hours. The two-pass approach downloads only Zeek in Pass 1 (~2 GB/day) and PCAPs only for flagged days in Pass 2. This reduces disk usage to ~4.5 GB peak and runtime to ~6.2 hours.

### Quota Latch
Google Drive public download links hit per-file quota limits quickly. The pipeline implements a "quota latch" -- on the first quota failure, all subsequent downloads permanently switch to the authenticated Drive API. This eliminates ~30 minutes of wasted retry attempts.

### Chronological Context
Attack context (patient_zero, attacker_ips, compromised_hosts) accumulates as days are processed in order. Day N+1's agents receive all findings from days 1 through N, enabling them to make more targeted analysis decisions.

### Checkpoint/Resume
Pipeline state is saved to `.pipeline_checkpoint.json` after every completed day. On crash or interruption, re-running the same command automatically resumes from the last checkpoint. The checkpoint includes all findings, drill-down decisions, and provenance data.

## Troubleshooting

### Common Issues

**Pipeline crashes with `AZURE_OPENAI_ENDPOINT not set`:**
Ensure `.env` file exists with valid Azure OpenAI credentials.

**tshark not found:**
Install Wireshark/tshark or set `TSHARK_PATH` in `.env`.

**Google Drive quota errors on every file:**
Ensure `oauth-token.json` exists and contains a valid refresh token. Run `python auth_drive.py` to regenerate.

**Pipeline stuck on download:**
Google Drive authenticated API throughput is ~10 MB/s. Large Zeek files (1-2 GB) take several minutes. Check progress by monitoring `data/<day>/zeek/` directory.

**Disk full during run:**
Increase disk budget: `--disk-soft-gb 8 --disk-hard-gb 12`. The sliding window should prevent this, but very large Zeek datasets can temporarily exceed the soft limit.

**Resuming a failed run:**
Just re-run the same command. The checkpoint system handles resume automatically.

**Forcing a fresh run:**
```bash
rm data/.pipeline_checkpoint.json
python master_pipeline.py --all-days --work-dir data
```

### Monitoring a Run

The pipeline prints progress to stdout. For background runs, use:
```bash
PYTHONUNBUFFERED=1 python master_pipeline.py --all-days --work-dir data 2>&1 | tee pipeline.log
```

Check checkpoint status:
```bash
python3 -c "import json; d=json.load(open('data/.pipeline_checkpoint.json')); print(f'days={len(d[\"completed_days\"])} sweep={d[\"sweep_done\"]} drill={len(d[\"drilldown_days\"])}')"
```
