# SC4063 Security Analysis Pipeline

Autonomous multi-agent PCAP forensics pipeline built on LangGraph. Analyses network captures across multiple days, maps findings to MITRE ATT&CK, identifies candidate threat groups, and produces a PDF incident report.

---

## Pipeline Flow

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
│        ││        ││        ││          │
│Azure   ││Azure   ││Zeek +  ││Ollama    │
│GPT-4o  ││LLM     ││tshark  ││          │
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

## Directory Structure

```
SC4063_project/
├── master_pipeline.py              # Orchestrator — run this
├── agent.py                        # InitialAccess ForensicAgent
├── payload_agent.py                # Payload agent
├── requirements.txt
├── .env                            # API keys (not committed)
│
├── shared/
│   ├── data_contract.py            # Canonical data types & state schema
│   └── pcap_api.py                 # SC4063 API client + Zeek helpers
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
# Single day
python master_pipeline.py --day 2025-03-06

# All available days (combined report)
python master_pipeline.py --all-days

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

Reports are saved to the `reports/` directory in the project root:

- Single day: `reports/incident_report_YYYY-MM-DD.pdf`
- All days: `reports/combined_incident_report.pdf`

Markdown copies are also saved to the work directory (`/tmp/sc4063/` by default).

---

## Data Contract

All agents read from and write to `PipelineState` (defined in `shared/data_contract.py`).

| Key | Type | Written by | Read by |
|---|---|---|---|
| `target_day` | `str` | caller | ingest |
| `pcap_file` | `str` | ingest | all agents |
| `zeek_context` | `ZeekContext` | ingest | all agents |
| `attack_context` | `dict` | all agents | all agents |
| `initial_access_findings` | `dict` | initial_access | supervisor, report |
| `lateral_movement_findings` | `dict` | lateral_movement | supervisor, report |
| `exfiltration_findings` | `dict` | exfiltration | supervisor, report |
| `payload_findings` | `dict` | payload | supervisor, report |
| `mitre_enrichment` | `dict` | mitre_enrichment | report_writing |
| `final_report` | `str` | report_writing | caller |
| `completed_agents` | `list[str]` | each node | supervisor |

---

## MITRE ATT&CK Enrichment

The `mitre_enrichment_node` loads `mitre_reference/enterprise-attack.json` (STIX 2.0 bundle) and:

1. Extracts behavioural keywords from all agent findings
2. Maps them to ATT&CK technique IDs (e.g. RDP -> T1021.001, SMB -> T1021.002)
3. Finds threat groups that use >=2 of the matched techniques
4. Passes enriched data (techniques + candidate groups) to the report writer

The report writer uses this to produce MITRE-mapped findings and threat group assessments.
