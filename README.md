# SC4063 Security Analysis Pipeline

Autonomous multi-agent PCAP forensics pipeline built on LangGraph.

---

## Architecture

```
                    ┌─────────────────────────────────┐
                    │          master_pipeline.py       │
                    │        (LangGraph orchestrator)   │
                    └─────────────────────────────────┘
                                     │
                                     ▼
                    ┌─────────────────────────────────┐
                    │           ingest_node             │
                    │  shared/pcap_api.py               │
                    │  • API: days / alerts / zeek_datasets / pcaps
                    │  • Downloads alerts.ndjson        │
                    │  • Downloads Zeek NDJSON logs     │
                    │  • Downloads PCAP                 │
                    │  • Returns ZeekContext            │
                    └────────────────┬────────────────┘
                                     │
                                     ▼
                    ┌─────────────────────────────────┐
                    │          supervisor_node           │
                    │  Routes to next unrun agent       │
                    │  Uses deterministic order:        │
                    │  initial_access → lateral_movement│
                    │  → exfiltration → payload → FINISH│
                    └────────────────┬────────────────┘
                         ┌───────────┼───────────┐───────────┐
                         ▼           ▼           ▼           ▼
              ┌──────────────┐ ┌──────────┐ ┌────────┐ ┌────────┐
              │ InitialAccess│ │ Lateral  │ │ Exfil  │ │Payload │
              │  adapter     │ │Movement  │ │ agent  │ │adapter │
              │  (agent.py)  │ │ adapter  │ │        │ │        │
              │  ForensicAgent│ │(lateral_ │ │(new,   │ │payload_│
              │  Azure GPT-4o│ │movement) │ │Zeek+   │ │agent.py│
              │  tshark tools│ │Azure LLM │ │tshark) │ │Ollama  │
              └──────┬───────┘ └────┬─────┘ └───┬────┘ └───┬────┘
                     │              │            │          │
                     └──────────────┴────────────┴──────────┘
                                     │ (all loop back to supervisor)
                                     ▼
                    ┌─────────────────────────────────┐
                    │        report_writing_node        │
                    │  Ollama llama3.2                  │
                    │  Synthesises all findings into    │
                    │  a Markdown incident report       │
                    └─────────────────────────────────┘
```

---

## Directory Structure

```
pipeline/
├── master_pipeline.py          # Orchestrator — run this
│
├── shared/
│   ├── data_contract.py        # ★ Canonical data types & state schema
│   └── pcap_api.py             # SC4063 API client + Zeek streaming helpers
│
└── agents/
    ├── initial_access_adapter.py    # Wraps agent.py → PipelineState
    ├── lateral_movement_adapter.py  # Wraps lateral_movement.py → PipelineState
    ├── exfiltration_agent.py        # New Zeek-aware exfiltration agent
    └── payload_agent_adapter.py     # Wraps payload_agent.py → PipelineState
```

Place your existing files alongside `pipeline/`:
```
project_root/
├── agent.py                    # InitialAccess ForensicAgent (unchanged)
├── lateral_movement/
│   └── lateral_movement.py     # LateralMovement agent (unchanged)
├── payload_agent.py            # Payload agent (unchanged)
├── exfiltration_agent.py       # Your exfiltration module (if exists)
│
└── pipeline/                   # ← this folder
    ├── master_pipeline.py
    ├── shared/
    └── agents/
```

---

## Data Contract (the key design decision)

Every agent reads from and writes to `PipelineState` — a single
`TypedDict` defined in `shared/data_contract.py`.  No agent invents
its own inter-agent dict keys.

### PipelineState keys

| Key | Type | Written by | Read by |
|---|---|---|---|
| `target_day` | `str` | caller | ingest |
| `pcap_file` | `str` | ingest | all agents |
| `zeek_context` | `ZeekContext` dict | ingest | all agents |
| `attack_context` | `dict` | all agents (accumulate) | all agents |
| `initial_access_findings` | `InitialAccessFindings` dict | initial_access | supervisor, report |
| `lateral_movement_findings` | `LateralMovementFindings` dict | lateral_movement | supervisor, report |
| `exfiltration_findings` | `ExfiltrationFindings` dict | exfiltration | supervisor, report |
| `payload_findings` | `PayloadFindings` dict | payload | supervisor, report |
| `final_report` | `str` | report_writing | caller |
| `completed_agents` | `list[str]` | each agent | supervisor |

### ZeekContext

```python
ZeekContext(
    day="2025-03-06",
    pcap_path="/tmp/sc4063/2025-03-06/pcap/capture.pcap",
    alerts_path="/tmp/sc4063/2025-03-06/alerts.ndjson",
    zeek_files={
        "zeek.dns.ndjson": "/tmp/sc4063/2025-03-06/zeek/zeek.dns.ndjson",
        "zeek.connection.ndjson": "...",
        ...
    }
)
```

Each agent accesses Zeek logs through `get_zeek_context(state).zeek_files["zeek.dns.ndjson"]`.

### Shared attack_context

All agents read and write `state["attack_context"]` to share running
facts about the incident.  Canonical keys:

```python
{
    "patient_zero": "10.0.0.50",
    "attacker_ips": ["1.2.3.4"],
    "compromised_hosts": ["10.0.0.50", "10.0.0.100"],
    "techniques": ["smb_file_transfer"],
    "exfil_destinations": ["5.6.7.8"],
    "malicious_hashes": ["abc123..."],
    "timeline_events": [...]
}
```

---

## IOC propagation

Each agent produces `IOC` objects attached to its findings:

```python
@dataclass
class IOC:
    ioc_type: Literal["ip", "domain", "hash", "port", "file", "url", "user"]
    value: str
    source_agent: str
    confidence: Literal["high", "medium", "low"]
    notes: str
```

`merge_all_iocs(state)` collects and deduplicates IOCs from all agents
for the final report.

---

## Quick Start

### 1. Install dependencies
```bash
pip install langchain langgraph langchain-ollama langchain-openai \
            langchain-core python-dotenv requests tqdm
# Ensure Ollama is running: ollama pull llama3.2
```

### 2. Set environment variables
```bash
# .env
AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com/
AZURE_OPENAI_API_KEY=<key>
AZURE_OPENAI_DEPLOYMENT=gpt-4o-mini
VIRUSTOTAL_API_KEY=<key>
TSHARK_PATH=/usr/bin/tshark   # optional — auto-detected
```

### 3. Run the pipeline
```bash
cd pipeline
python master_pipeline.py --day 2025-03-06
```

### 4. Debug a single agent
```bash
# Test just the exfiltration agent with an already-downloaded PCAP
python master_pipeline.py --day 2025-03-06 \
    --pcap /tmp/sc4063/2025-03-06/pcap/capture.pcap \
    --only exfiltration
```

---

## API Flow (from notebook)

```
days → alerts (optional) → zeek_datasets → zeek_file → pcaps → file/download
```

The `ingest_node` runs this automatically.  Downloaded artifacts are
cached — re-running the pipeline skips files already on disk.

---

## Adding a New Agent

1. Create `agents/my_agent.py` with a function:
   ```python
   def my_agent_node(state: PipelineState) -> dict[str, Any]:
       ...
       findings = MyFindings(...)
       return {**state, "my_findings": findings.to_dict(), ...}
   ```

2. Add a findings dataclass to `shared/data_contract.py`.

3. Register the node in `master_pipeline.py`:
   ```python
   workflow.add_node("my_agent", my_agent_node)
   workflow.add_edge("my_agent", "supervisor")
   ```

4. Add `"my_agent"` to `_AGENT_ORDER` in `master_pipeline.py`.
