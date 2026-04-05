# SC4063 Agentic Network Forensic Analysis Pipeline — Presentation Script

> **Presenter Notes:** This script accompanies the slide deck (`slides.html`). Each section maps to one or more slides. Timing annotations are approximate for a 20-minute presentation.

---

## Slide 1 — Title (30 seconds)

Good [morning/afternoon]. Today we're presenting our SC4063 final project: an autonomous network forensic analysis pipeline.

Our system ingests raw PCAP network captures and Zeek structured logs from a real-world ransomware incident — the Apex Global Logistics Lynx ransomware case — and produces a complete incident response report, all without manual step-by-step guidance.

The pipeline analyses 9 days of network data, identifies the initial access vector, tracks lateral movement, detects data exfiltration, locates payload deployment, maps everything to the MITRE ATT&CK framework, and generates a professional PDF report — autonomously.

---

## Slide 2 — Agenda (15 seconds)

Here's what we'll cover today:

1. **Agent Architecture** — how the system is built and how data flows
2. **Demo** — the actual generated outputs from our pipeline
3. **Key Challenges** — technical problems we encountered and how we handled them
4. **Guardrails and Safety Controls** — how we prevent hallucination and ensure accuracy
5. **Cost and Efficiency** — real numbers on compute, time, and trade-offs

---

## Slide 3 — Architecture Overview (2 minutes)

Let's start with the big picture. Our pipeline uses a **two-pass architecture** built on **LangGraph**, which is a state machine framework for LLM-driven workflows.

**Pass 1 is the Zeek Sweep.** For all 9 days, we download only the Zeek structured logs — these are pre-parsed network metadata. We run four analysis agents on this lightweight data: an Initial Access triage, Lateral Movement detection, Exfiltration analysis, and Payload detection. This pass is fast — mostly I/O-bound — and gives us full coverage across every day.

At the end of Pass 1, each day gets a verdict: does it need deeper investigation?

**Pass 2 is the PCAP Drill-Down.** Only for days flagged as suspicious, we download the actual packet capture file and run the full tshark-based deep analysis. This gives us packet-level confirmation and artifact extraction — things like extracting files transferred over SMB or HTTP.

Both passes feed into MITRE ATT&CK enrichment and then a final LLM-driven report writer that synthesises everything into a single incident report.

**Why two passes?** A single-pass approach downloading PCAPs for all 9 days would need over 50 GB of disk and 12+ hours of runtime. Our two-pass approach peaks at just 4.5 GB of disk usage and completes in about 6 hours.

---

## Slide 4 — Data Flow Diagram (1.5 minutes)

Let me walk through the data flow step by step.

**Step 1 — Ingestion.** The pipeline hits the SC4063 API to download Suricata alerts for all 9 days. These alerts are scored to identify suspect IP addresses and high-activity time periods.

**Step 2 — Zeek Log Download.** For each day, we download 11 Zeek log datasets: connection, DNS, RDP, HTTP, SMB files, SMB mapping, DCE-RPC, Kerberos, SSL, notice, and weird logs. These arrive in Elastic Common Schema format, so our ECS compatibility layer transparently normalises them to standard Zeek field names.

**Step 3 — Agent Analysis.** Each agent reads from and writes to a shared `PipelineState` — a typed dictionary that serves as our single source of truth. This state includes Zeek context, attack context that accumulates across days, and structured findings from each agent.

**Step 4 — MITRE Enrichment.** We map all findings to ATT&CK techniques using keyword matching against 835 technique definitions, and identify candidate threat groups based on technique overlap.

**Step 5 — Report Synthesis.** The report writer LLM receives all agent findings, MITRE enrichment data, and consolidated IOCs, and produces a structured Markdown report which is then rendered to PDF.

A critical detail: attack context **accumulates chronologically.** Day 2's agents receive all findings from Day 1. Day 3 receives findings from Days 1 and 2. This enables cross-day correlation.

---

## Slide 5 — Components: The Five Agents (2 minutes)

Let me introduce each agent.

**Agent 1: Initial Access.** This agent identifies how the attacker got into the network. In Pass 1, it's a fast deterministic scan — no LLM — just counting external RDP connections and finding the largest session. In Pass 2, it becomes a full LLM-driven ReAct agent with up to 30 tshark query steps. It has tools for PCAP overview, TCP conversations, custom packet queries, and protocol hierarchy analysis. Its key insight is that a successful RDP login is dramatically larger than failed attempts — 50 to 500 KB versus 2 to 5 KB for failures.

**Agent 2: Lateral Movement.** This agent tracks how the attacker spread through the network. It runs an LLM ReAct loop with 5 tools analysing Zeek logs: SMB lateral movement detects admin share access and PsExec artifacts; RDP lateral movement finds internal host-to-host RDP sessions; DCE-RPC events detect service creation and SAMR user enumeration; Kerberos events catch Kerberoasting; and NTLM auth events detect pass-the-hash patterns.

**Agent 3: Exfiltration.** This agent detects data theft. It has three sub-modules: volume spike detection for outbound traffic anomalies, DNS tunnelling detection using entropy analysis, and HTTP exfiltration detection for large POST uploads — especially to file-sharing services like temp.sh. It also has a unique LLM-based summariser with a post-generation **grounding check** that verifies every IP and domain the LLM mentions actually exists in the evidence.

**Agent 4: Payload.** This agent determines how ransomware was deployed. In Pass 1, it detects SMB file drops, RDP from domain controllers, and remote execution via WinRM or WMI. In Pass 2, it gains tshark tools to extract files from HTTP and SMB streams, inspect them for magic numbers, calculate entropy, and compute SHA256 hashes.

**Agent 5: Report Writer.** The synthesis agent. It receives all findings as JSON, the MITRE enrichment data, consolidated IOCs, and evidence provenance — then produces a structured incident report with 9 sections including an Executive Summary, Detailed Findings mapped to MITRE, a Timeline, Recommendations, and Evidence Gaps.

---

## Slide 6 — Tools Available to Each Agent (1 minute)

This table summarises every tool available in the pipeline. There are **25 unique tools** across the agents.

The Initial Access agent has 6 tshark-based tools plus automatic seed queries from Zeek logs. Lateral Movement has 5 Zeek-based tools. Exfiltration has 3 detection modules plus the LLM summariser. The Payload agent has 8 tools total — 4 Zeek-based that work in both passes, and 4 PCAP-based that only activate in Pass 2.

A key design choice: tools return **structured JSON or truncated text**, never raw multi-gigabyte data. Every tshark query output is capped at 12,000 to 15,000 characters to stay within LLM context windows.

---

## Slide 7 — Decision-Making Logic (1 minute)

The supervisor uses **deterministic routing**, not LLM-based decisions. Agents execute in a fixed forensic order: Initial Access, then Lateral Movement, then Exfiltration, then Payload. This is a deliberate choice for reliability and cost control.

After all four agents complete, the supervisor routes to MITRE enrichment, then to report writing.

The drill-down decision is also rule-based. A day gets flagged for PCAP analysis if ANY of these conditions are met: a successful RDP session larger than 10 KB, more than 1000 brute-force attempts, any lateral movement detected, any exfiltration detected, or more than 50 alerts on that day. We deliberately err on the side of investigation.

Within each agent, the LLM ReAct loop is bounded by step limits — 30 for Initial Access, 8 for Lateral Movement and Payload without PCAPs, 15 for Payload with PCAPs. If the limit is reached, the agent is forced to produce its best-effort report.

---

## Slide 8 — Demo: Generated Outputs (2 minutes)

Now let's look at what the pipeline actually produces.

*[Show the combined incident report PDF]*

The **combined incident report** covers all 9 days in a single document. It opens with a **Title Page** and **Table of Contents**, followed by an **Executive Summary** written for C-suite audience — covering root cause, business impact, and priority recommendations.

The **Detailed Findings** section is organised by attack phase — Initial Access, Lateral Movement, Exfiltration, Payload — with each observation mapped to specific MITRE ATT&CK technique IDs and names. For example, the RDP brute-force campaign maps to T1110.001 (Brute Force: Password Guessing) and T1021.001 (Remote Services: Remote Desktop Protocol).

The **Threat Group Assessment** identifies candidate threat groups based on technique overlap. Groups with 2 or more matching techniques from the MITRE database are ranked by overlap count.

The **Timeline Appendix** provides a chronological reconstruction of events across all 9 days.

The **Evidence Gaps** section explicitly states what the pipeline could and could not determine, including data limitations and scope boundaries.

Finally, the **Evidence Provenance Appendix** lists exactly which PCAP and Zeek files each agent accessed on each day — full audit trail.

The report is saved as both Markdown and PDF. The PDF is generated using ReportLab with professional styling: A4 pages, proper headings, bullet lists, code blocks, and horizontal rules.

---

## Slide 9 — Demo: Pipeline Console Output (1 minute)

*[Show terminal output or screenshot]*

Here's what a pipeline run looks like in the terminal. You can see:

- Phase 1 scoring alerts across all days, identifying top suspect IPs
- Pass 1 sweeping each day with Zeek data — the IA triage, lateral movement agent, exfiltration agent, and payload agent all running in sequence
- The drill-down decision for each day — "PCAP drill-down needed: successful RDP session (245,832 bytes)" or "No PCAP drill-down needed: no significant findings"
- Pass 2 downloading a PCAP and running the deep-dive agents
- MITRE enrichment matching techniques and threat groups
- The final report generation

The checkpoint system saves progress after every day. If the pipeline crashes mid-way through day 5, you just re-run the same command and it resumes from day 5 — no work is lost.

---

## Slide 10 — Key Challenges: Technical (1.5 minutes)

Let me discuss the main technical challenges we faced.

**Challenge 1: ECS Field Format Mismatch.** The SC4063 API returns Zeek logs in Elastic Common Schema format — nested JSON with fields like `source.ip` and `destination.port`. But every Zeek analysis tool expects flat fields like `id.orig_h` and `id.resp_p`. Our solution: the `ecs_compat.py` module auto-detects the format and translates over 40 fields across 12 log types. This translation is completely transparent to agents.

**Challenge 2: Google Drive Download Quota.** Public Google Drive links hit per-file quota limits fast. Our "quota latch" mechanism detects the first quota failure and permanently switches all subsequent downloads to the authenticated Drive API — eliminating about 30 minutes of wasted retry attempts.

**Challenge 3: PCAP Size vs. Analysis Time.** Some PCAPs are 1 to 5 GB. Running tshark queries on these takes significant time — up to 2 minutes per query. Our mitigation: pre-filter queries by source/destination port in display filters, limit packet counts, and only do PCAP analysis on flagged days.

**Challenge 4: Multi-Day Context Correlation.** The attack spans 9 days. Patient zero identified on Day 1 needs to influence the analysis on Day 5. Our rolling attack context propagates findings chronologically, so later days benefit from accumulated intelligence.

---

## Slide 11 — Key Challenges: False Positives and Detection Gaps (1 minute)

**DNS Tunnelling False Positives.** DNS C2 beaconing generates high query rates and entropy that mimic tunnelling. We use conservative thresholds — entropy above 3.5 bits per character, label length above 40 characters, query rate above 200 per 5 minutes — and require multiple indicators before flagging.

**Exfiltration Volume False Positives.** Legitimate backup and sync services generate large outbound volumes. We filter known CDN and service ports and apply beaconing coefficient-of-variation checks.

**Lateral Movement False Negatives.** Encrypted RDP and SMB traffic doesn't reveal operation details in Zeek logs. In Pass 2, we fall back to tshark packet inspection for confirmation.

**Missed Detections.** Some Zeek datasets are unavailable on certain days due to API rate-limiting or capture gaps. The pipeline degrades gracefully — agents continue with available data, and the provenance log records exactly what was missing.

---

## Slide 12 — Key Challenges: Tool Limitations and Scaling (1 minute)

**tshark Timeouts.** On large PCAPs, complex tshark queries can exceed our 120-to-300-second timeout. We handle this with error catching and simplified fallback queries.

**LLM Step Limits.** The Initial Access agent's 30-step ReAct loop occasionally exhausts its budget before completing a thorough investigation. In those cases, the agent is forced to submit its best-effort report. More complex incidents might benefit from higher step limits — at the cost of increased latency and API calls.

**Disk Constraints.** Our sliding window disk manager keeps usage under 5 GB, but very large Zeek datasets can temporarily exceed the soft limit. The hard limit at 8 GB triggers warnings.

**Scaling.** Processing 9 days takes approximately 6 hours, with 80% of that time spent on network downloads. The actual analysis is CPU-light at about 6% peak and RAM-light at about 200 MB. For larger incidents with more days, the runtime scales linearly with the number of days.

---

## Slide 13 — Guardrails: Anti-Hallucination (2 minutes)

Preventing LLM hallucination is critical in forensic analysis. A fabricated IP address or technique ID could derail an investigation. Here's our multi-layered approach.

**Layer 1: Evidence-Only System Prompts.** Every agent's system prompt contains explicit anti-hallucination instructions. The report writer's prompt states: "Never fabricate packet IDs, hashes, users, hosts, ATT&CK IDs, or timestamps." The exfiltration summariser says: "You may ONLY reference IP addresses, domain names, timestamps, and byte counts that appear verbatim in the evidence provided."

**Layer 2: Low Temperature.** All LLM calls use temperature 0.0 to 0.1. This makes outputs highly deterministic and factual, at the expense of creativity — which is exactly what forensic analysis requires.

**Layer 3: Post-Generation Grounding Check.** This is our most sophisticated guardrail. After the exfiltration summariser LLM produces its narrative, we:
1. Extract all IP addresses and domain names from the LLM's output using regex
2. Extract all IPs and domains from the source evidence
3. Verify every entity the LLM mentioned actually appears in the evidence
4. Calculate a grounding score from 0.0 to 1.0
5. Return any ungrounded claims and a hallucination risk level

This catches cases where the LLM invents plausible-sounding but non-existent IPs or domains.

**Layer 4: Structured Output Constraints.** Agents that produce JSON are constrained to specific schemas. The payload agent must return specific fields — `summary`, `deployment_method`, `payload_files`, `source_host`, `target_hosts`. There's no room for free-form hallucination.

**Layer 5: MITRE Mapping is Deterministic.** ATT&CK technique matching uses keyword lookup against a static database — not LLM inference. The LLM cannot fabricate technique IDs.

---

## Slide 14 — Guardrails: Agent Constraints and Validation (1.5 minutes)

Beyond anti-hallucination, we constrain agent behaviour in several ways.

**Step Limits.** Each agent has a hard cap on LLM iterations: 30 for Initial Access, 8 for Lateral Movement, 8 or 15 for Payload depending on whether PCAPs are available. This prevents runaway API costs and infinite tool-calling loops.

**Token Budgets.** Tool outputs are truncated to 12,000 to 15,000 characters. The report writer gets 16,000 output tokens. The exfiltration summariser gets 1,500. These limits prevent context window overflows and control costs.

**Deterministic Routing.** The supervisor uses fixed agent ordering, not LLM-based decisions. This eliminates the risk of the orchestrator hallucinating about which agent to run.

**Mandatory Checklists.** The Initial Access agent in Pass 2 has a mandatory 8-point checklist it must address before submitting its report: Patient Zero identity, exposed service, brute-force count, successful login IP, session details, comparison to failed attempts, pre-existing compromise evidence, and IOC list.

**Validation at Every Stage.** IOCs from all agents are deduplicated using `merge_all_iocs()`. Attack context is validated — compromised hosts must be RFC1918 internal IPs. MITRE threat group attribution requires a minimum of 2 overlapping techniques.

---

## Slide 15 — Guardrails: Human-in-the-Loop (45 seconds)

The pipeline supports human-in-the-loop at specific decision points.

**Interactive Mode:** When run with a terminal, the pipeline can prompt the user to select which PCAP to drill down on when multiple candidates exist for a day.

**Non-Interactive Mode:** For background or CI/CD runs, the pipeline auto-selects the best PCAP by alert score and uses generous drill-down thresholds — erring on the side of investigation rather than skipping.

**Debug Mode:** Operators can run a single agent with `--only lateral_movement` for targeted investigation. This is useful for iterating on findings without rerunning the full pipeline.

**Provenance Audit Trail:** The provenance appendix provides a complete record of which files each agent accessed, enabling post-hoc review of the pipeline's evidence basis.

---

## Slide 16 — Cost and Efficiency (2 minutes)

Let's talk numbers.

**Model:** We use Azure OpenAI GPT-4o-mini for all LLM calls. This is the most cost-effective GPT-4-class model while still providing strong reasoning for forensic analysis.

**Estimated LLM API Cost per Full Run (9 days):**
- Pass 1 agents make roughly 50 to 80 LLM calls across all days
- Pass 2 agents make roughly 30 to 50 calls per flagged day (typically 3 to 5 days flagged)
- Report writer: 1 large call per run
- At GPT-4o-mini pricing (~$0.15 per million input tokens, ~$0.60 per million output tokens), the total API cost is estimated at **$2 to $5 per full 9-day run**

**Time to Complete:**
| Phase | Duration | Bottleneck |
|-------|----------|------------|
| Alert download + scoring | ~5 minutes | Network |
| Pass 1: Zeek sweep (9 days) | ~30 minutes | Zeek log download |
| Pass 2: PCAP drill-down (3–5 days) | ~1–2 hours per day | PCAP download + tshark |
| Report generation | ~2 minutes | LLM inference |
| **Total** | **~4–6 hours** | **80% network** |

**Resource Usage:**
- CPU: ~6% peak — this is not a compute-intensive workload
- RAM: ~200 MB peak
- Disk: 4.5 GB peak with our sliding window manager
- Network: ~10 MB/s throughput via Google Drive API

**Trade-offs:**
- **Speed vs. Coverage:** Our two-pass architecture trades a small amount of Pass 2 depth for full coverage of all 9 days. A single-pass approach would take 12+ hours and 50+ GB.
- **Accuracy vs. Cost:** Higher step limits would allow more thorough agent investigation but increase API costs linearly. Our current limits (30 steps for IA, 8 for LM) balance thoroughness against cost.
- **Determinism vs. Flexibility:** Fixed agent ordering sacrifices the ability to dynamically prioritise agents but eliminates routing hallucination and reduces total cost.

---

## Slide 17 — Summary and Key Takeaways (1 minute)

To summarise:

Our pipeline demonstrates that an **autonomous LLM-driven agent can perform credible network forensic analysis** at scale — ingesting raw network data and producing structured incident response reports without manual step-by-step guidance.

The key design principles that make this work:
1. **Two-pass architecture** for efficiency — full Zeek sweep, targeted PCAP drill-down
2. **Deterministic orchestration** — fixed agent order for reliability, LLM ReAct loops within agents for flexibility
3. **Multi-layered guardrails** — evidence-only prompts, low temperature, grounding checks, step limits, structured schemas
4. **Chronological context accumulation** — findings from earlier days inform later analysis
5. **Full auditability** — provenance tracking, checkpoint/resume, evidence citations in every claim

The pipeline processed 9 days of the Apex Global Logistics Lynx ransomware incident, identified the initial RDP brute-force entry, traced lateral movement through the network, detected data exfiltration to external services, and mapped the full attack chain to MITRE ATT&CK — all autonomously.

---

## Slide 18 — Questions (open)

Thank you. We're happy to take questions.

*[Potential questions to prepare for:]*
- *"How do you handle cases where the LLM makes wrong tool calls?"* → Step limits force termination; best-effort report still captures partial findings.
- *"Could this work on non-ransomware incidents?"* → The architecture is general; agent prompts and tool definitions would need adaptation for different attack types.
- *"What's the biggest limitation?"* → Network download time dominates runtime; the analysis itself is fast. Also, encrypted traffic limits Zeek-level visibility.
- *"Why GPT-4o-mini instead of GPT-4o?"* → Cost efficiency. For this structured forensic task, mini provides sufficient reasoning quality at a fraction of the cost.
