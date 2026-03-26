# SC4063 Security Analysis Pipeline

Autonomous multi-agent PCAP forensics pipeline built on LangGraph. Analyses network captures across multiple days, maps findings to MITRE ATT&CK, identifies candidate threat groups, and produces a PDF incident report.

---

## Pipeline Flow

### All-Days Mode (Two-Phase Ingestion)

```
Phase 1: ingest_all_logs()           Download Zeek + Suricata alerts for all 9 days (~MBs)
              │
Phase 2: score_alerts()              Parse all Suricata alerts, rank IPs by severity score
         select_pcaps()              Map alert density per hour → PCAP index, pick top N
              │
Phase 3: download_selected_pcaps()   Download only the most suspicious PCAPs per day
              │
Phase 4: per-day agent pipeline      Run all 4 agents + MITRE enrichment per day
              │
Final:   write_combined_report()     LLM generates combined PDF incident report
```

### Per-Day Agent Pipeline

```
ingest → supervisor → agents (loop) → supervisor → mitre_enrichment → report_writing → END
```

```
┌─────────────────────────────────────┐
│          master_pipeline.py          │
│        (LangGraph orchestrator)      │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│            ingest_node               │
│  shared/pcap_api.py                  │
│  • Fetches alerts, Zeek logs, PCAP   │
│  • Returns ZeekContext               │
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│          supervisor_node             │
│  Deterministic routing:             │
│  initial_access → lateral_movement  │
│  → exfiltration → payload → FINISH  │
└──────────────┬──────────────────────┘
    ┌──────────┼──────────┬───────────┐
    ▼          ▼          ▼           ▼
┌────────┐┌────────┐┌────────┐┌──────────┐
│Initial ││Lateral ││ Exfil  ││ Payload  │
│Access  ││Movement││ Agent  ││ Agent    │
└───┬────┘└───┬────┘└───┬────┘└────┬─────┘
    └─────────┴─────────┴──────────┘
               │ (all loop back to supervisor)
               ▼
┌─────────────────────────────────────┐
│       mitre_enrichment_node          │
│  • Loads enterprise-attack.json      │
│  • Maps findings → ATT&CK techniques│
│  • Identifies candidate threat groups│
└──────────────┬──────────────────────┘
               ▼
┌─────────────────────────────────────┐
│        report_writing_node           │
│  Azure GPT-4o                        │
│  • MITRE-enriched system prompt      │
│  • Anti-hallucination constraints    │
│  • Outputs PDF to reports/           │
└─────────────────────────────────────┘
```

---

## Smart Ingestion

The pipeline uses Suricata alert scoring to select which PCAPs to download, instead of downloading all ~72 PCAPs (~25 GB).

### How it works

1. **Download lightweight logs first** — Suricata `alerts.ndjson` + Zeek NDJSON logs for all 9 days (small files, fast)
2. **Score alerts across all days** — parse every alert, weight by severity (severity 1 = 3 pts, severity 2 = 2 pts, severity 3 = 1 pt), rank source IPs globally
3. **Rank all PCAPs globally** — each day has 8 sequential PCAPs covering ~45 min each. Group suspect-IP alerts by hour, map to the corresponding PCAP index, score each PCAP, rank across all days
4. **Human-in-the-loop selection** — the pipeline presents a ranked table of all suspicious PCAPs with scores and sizes. The analyst chooses how many to ingest (e.g., "5" downloads the top 5 most suspicious PCAPs across all days)

This avoids downloading ~25 GB blindly and lets the analyst control the scope of analysis.

---

## Agent Details

### 1. Initial Access Agent

Identifies how the attacker first gained access to the network.

| Aspect | Detail |
|---|---|
| **Data sources** | PCAP file (via tshark) |
| **LLM** | Azure OpenAI GPT-4o-mini |
| **Agent type** | ReAct agent with function calling (up to 30 steps) |

**Detection methods:**
- **tshark protocol hierarchy** — identifies dominant protocols in the capture
- **IP conversation analysis** — ranks hosts by bytes transferred, identifies top talkers
- **RDP brute-force detection** — counts SYN packets to port 3389 grouped by source IP; flags IPs with high attempt counts
- **Successful session identification** — compares session byte counts; successful RDP logins are 10-100x larger than failed attempts (50-500 KB vs 2-5 KB)
- **Pre-existing compromise check** — searches for C2 beacon domains (RMM tools, TacticalRMM, MeshCentral) and external IP lookups active from capture start
- **DNS analysis** — queries for known malicious domain patterns

**Output:** Patient zero IP, attacker IP, attack vector, exposed service, brute-force count, session timeline, IOCs.

---

### 2. Lateral Movement Agent

Tracks how the attacker moved between internal hosts after initial compromise.

| Aspect | Detail |
|---|---|
| **Data sources** | Zeek logs (SMB, RDP, NTLM, Kerberos, DCE/RPC), PCAP fallback via tshark |
| **LLM** | Azure OpenAI |
| **Agent type** | ReAct agent with function calling (up to 12 steps) |

**Detection methods:**
- **SMB analysis** — parses `zeek.smb_files.ndjson` and `zeek.smb_mapping.ndjson` for admin share access (ADMIN$, IPC$, C$), PsExec artifacts, and file transfers between internal hosts
- **RDP lateral sessions** — identifies internal-to-internal RDP connections (port 3389) from `zeek.rdp.ndjson`, tracks authentication cookies
- **NTLM authentication** — detects pass-the-hash and credential relay from `zeek.ntlm.ndjson`; flags failed authentication attempts as spray indicators
- **Kerberos anomalies** — identifies AS-REP roasting (no pre-auth), kerberoasting (TGS-REQ for service accounts), and overpass-the-hash from `zeek.kerberos.ndjson`
- **DCE/RPC remote execution** — detects service creation (SCM), WMI calls, DCOM, and Task Scheduler operations from `zeek.dce_rpc.ndjson` (common PsExec/Impacket indicators)
- **Internal-only filtering** — only considers RFC1918 ↔ RFC1918 traffic
- **Host pair frequency** — groups operations by source/destination pair, ranks by frequency to identify movement chains

**Output:** Movement paths (IP pairs), compromised hosts, techniques used, TacticalRMM assessment, evidence highlights, IOCs.

---

### 3. Exfiltration Agent

Detects data theft and covert data channels.

| Aspect | Detail |
|---|---|
| **Data sources** | Zeek logs (connection, DNS, HTTP, SSL, files) |
| **LLM** | Azure OpenAI (for narrative summarisation) |
| **Agent type** | Analysis pipeline + LLM summariser |

**Detection methods:**
- **Volume anomaly detection** — identifies spikes in outbound bytes to external destinations relative to baseline traffic
- **Beaconing detection** — finds regular periodic connections to the same external IP/domain (C2 heartbeat pattern)
- **DNS tunneling** — flags DNS queries with unusually large payloads or high response sizes (covert data exfiltration via DNS)
- **HTTP upload detection** — identifies large HTTP POST/PUT transfers to non-standard external hosts
- **File-sharing service detection** — checks for uploads to known services (e.g., temp.sh)
- **Compression indicators** — looks for 7-Zip magic bytes in transferred data
- **Confidence scoring** — combined LOW/MEDIUM/HIGH assessment across all indicators

**Output:** Detected flag, data volume, destination IPs/domains, protocols used, timeframe, confidence level, IOCs.

---

### 4. Payload Agent

Analyses extracted files for malware indicators.

| Aspect | Detail |
|---|---|
| **Data sources** | PCAP file (HTTP object extraction via tshark) |
| **LLM** | Azure OpenAI GPT-4o |
| **Agent type** | Strict 3-step workflow agent |

**Detection methods:**
- **HTTP object extraction** — uses tshark to carve files from HTTP traffic in the PCAP
- **SHA256 + VirusTotal lookup** — hashes each extracted file and checks reputation via the VirusTotal API; flags files detected by any engine
- **File magic analysis** — reads hex headers to identify true file type (PE/EXE, ELF, Mach-O); detects extension mismatches (e.g., `.txt` file with MZ header)
- **Shannon entropy scoring** — calculates byte entropy; >7.0 indicates packed/encrypted/obfuscated content; small file (<1 KB) + high entropy = shellcode indicator
- **Combined verdict** — MALICIOUS (VT hits), SUSPICIOUS (high entropy or type mismatch), or CLEAN

**Output:** Files analysed, malicious/suspicious/clean file lists with SHA256 hashes, VirusTotal stats, entropy scores, IOCs.

---

### 5. MITRE ATT&CK Enrichment

Maps agent findings to the MITRE ATT&CK framework and identifies candidate threat groups.

| Aspect | Detail |
|---|---|
| **Data source** | `mitre_reference/enterprise-attack.json` (STIX 2.0, 835 techniques, 187 groups) |
| **Method** | Keyword extraction + graph lookup (no LLM) |

**How it works:**
- Extracts behavioural keywords from all agent findings (e.g., "rdp", "smb", "brute", "dns")
- Maps keywords to ATT&CK technique IDs via a lookup table (e.g., RDP → T1021.001, SMB → T1021.002)
- Queries the STIX relationship graph for threat groups that use >=2 of the matched techniques
- Ranks groups by overlap count and returns top 10 candidates

---

### 6. Report Writer

Generates the final incident report as PDF.

| Aspect | Detail |
|---|---|
| **LLM** | Azure OpenAI GPT-4o-mini |
| **Output** | Markdown + PDF (saved to `reports/`) |

**Report sections:** Title, Table of Contents, Executive Summary, Detailed Findings (with MITRE mappings), Conclusion & Recommendations (prioritised High/Medium/Low), Timeline Appendix, Technical Details Appendix, Evidence Gaps.

**Anti-hallucination rules:** Every claim must cite evidence (5-tuples, timestamps, log sources). Missing evidence must be stated as "Insufficient evidence". No fabricated IDs, hashes, or timestamps.

---

## Directory Structure

```
SC4063_project/
├── master_pipeline.py              # Orchestrator — run this
├── initial_access_agent.py         # InitialAccess ForensicAgent
├── payload_agent.py                # Payload agent
├── requirements.txt
├── .env                            # API keys (not committed)
│
├── shared/
│   ├── data_contract.py            # Canonical data types & state schema
│   └── pcap_api.py                 # SC4063 API client + ingestion + scoring
│
├── agents/
│   ├── initial_access_adapter.py   # Wraps agent.py → PipelineState
│   ├── lateral_movement_adapter.py # Wraps lateral_movement.py → PipelineState
│   ├── exfiltration_agent.py       # Zeek-aware exfiltration agent
│   └── payload_agent_adapter.py    # Wraps payload_agent.py → PipelineState
│
├── lateral_movement/
│   └── lateral_movement.py         # Lateral movement agent
│
├── mitre_reference/
│   └── enterprise-attack.json      # MITRE ATT&CK STIX bundle (used by enrichment)
│
└── reports/                        # Generated PDF reports (output)
```

---

## Setup

### 1. Install dependencies

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Set environment variables

Create a `.env` file in the project root:

```bash
AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com/
AZURE_OPENAI_API_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini
VIRUSTOTAL_API_KEY=<key>
TSHARK_PATH=/usr/bin/tshark   # optional — auto-detected
```

### 3. Run the pipeline

```bash
# All days with smart PCAP selection + human-in-the-loop (recommended)
python master_pipeline.py --all-days

# Single day
python master_pipeline.py --day 2025-03-06

# Custom work directory
python master_pipeline.py --all-days --work-dir ./data
```

### 4. Debug a single agent

```bash
python master_pipeline.py --day 2025-03-06 \
    --pcap /tmp/sc4063/2025-03-06/pcap/capture.pcap \
    --only exfiltration
```

### 5. Output

Reports are saved to `reports/` in the project root:

- All days: `reports/combined_incident_report.pdf`
- Single day: `reports/incident_report_YYYY-MM-DD.pdf`

Markdown copies are also saved to the work directory (`/tmp/sc4063/` by default).

---

## Data Contract

All agents read from and write to `PipelineState` (defined in `shared/data_contract.py`).

| Key | Type | Written by | Read by |
|---|---|---|---|
| `target_day` | `str` | caller | ingest |
| `pcap_file` | `str` | ingest | all agents |
| `pcap_files` | `list[str]` | ingest | agents |
| `zeek_context` | `ZeekContext` | ingest | all agents |
| `alert_scoring` | `dict` | ingest | report_writing |
| `attack_context` | `dict` | all agents | all agents |
| `initial_access_findings` | `dict` | initial_access | supervisor, report |
| `lateral_movement_findings` | `dict` | lateral_movement | supervisor, report |
| `exfiltration_findings` | `dict` | exfiltration | supervisor, report |
| `payload_findings` | `dict` | payload | supervisor, report |
| `mitre_enrichment` | `dict` | mitre_enrichment | report_writing |
| `final_report` | `str` | report_writing | caller |
| `completed_agents` | `list[str]` | each node | supervisor |
