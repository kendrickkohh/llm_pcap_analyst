# Initial Access Agent — Presentation Script

---

## Slide 1: INITIAL ACCESS AGENT *(Section Header)*

> "Now we'll be going into the Initial Access Agent — the first and arguably most critical agent in our pipeline.
>
> Its job is to answer the most fundamental question in any ransomware investigation: **how did the attacker get in?**
>
> Specifically, it needs to identify Patient Zero — the first host that was compromised — figure out what service was exploited, which IP the attacker used to get in, and whether there was already a pre-existing foothold before the capture even started.
>
> Everything downstream — lateral movement, exfiltration, payload — depends on what this agent finds first."

---

## Slide 2: TWO-PASS DESIGN

> "The Initial Access agent uses a two-pass design, and this was a deliberate architectural choice.
>
> **Pass 1** is a fast, deterministic scan of the Zeek RDP logs — no PCAP needed. It counts brute-force attempts and measures session bytes directly from the structured log files. This is cheap to run, so we do it across all 9 days.
>
> The output of Pass 1 feeds directly into the `needs_pcap_drilldown()` function you saw earlier in the scoring logic slides. If a day shows a large successful RDP session or thousands of brute-force attempts, it gets flagged.
>
> **Pass 2** only activates on those flagged days. This is where the LLM comes in — a ForensicAgent runs a full ReAct loop, issuing up to 30 custom tshark queries against the actual PCAP file. It reasons step-by-step, picks its own tools, and keeps investigating until it's confident enough to submit a report.
>
> The key insight here is efficiency: we don't download or analyse PCAPs for all 9 days. Pass 1 narrows it down to 1 or 2, and only then do we do the expensive packet-level work."

---

## Slide 3: SYSTEM PROMPT — REASONING PRINCIPLES

> "The system prompt is where we encode the actual forensic expertise into the agent. It's not just a task description — it contains critical analysis principles that a junior analyst might miss.
>
> The most important one: **the IPs doing the brute-force are not necessarily the ones that logged in successfully.** In real attacks, one group hammers the door down, and a separate operator quietly slips in using the stolen credentials. If the agent just looks at who sent the most SYNs, it'll identify the wrong attacker.
>
> The second principle is about **session size as a discriminator.** A failed RDP login is tiny — 2 to 5 kilobytes, maybe 20 frames, gone in under 10 seconds. A successful interactive session is orders of magnitude larger — easily 50 to 500 kilobytes, hundreds of frames, lasting minutes. So we tell the agent: sort TCP conversations by bytes, and the successful login will be a visible outlier.
>
> The third principle handles **pre-existing compromise.** If C2 traffic or RMM tool beacons are present right from the very first packets of the capture, the network was already owned before this recording started. The agent needs to flag that, because it completely changes the incident timeline.
>
> These principles are baked into the system prompt so the LLM cannot skip any of them."

---

## Slide 4: SEED QUERIES

> "Before the ReAct loop even starts, we automatically run four queries and inject the results into the agent's context as seed data.
>
> Why? Because we can't rely on the LLM to always start its investigation in the right order. By pre-loading the most critical evidence upfront, we guarantee it can't miss anything obvious.
>
> **Query 1** is a PCAP overview — time range, total packet count, file size. This orients the agent to what it's working with.
>
> **Query 2** counts all SYN packets to port 3389, grouped by source IP. This gives the agent the full brute-force landscape immediately — how many sources, how many attempts per IP.
>
> **Query 3** is the most important one: all TCP conversations on port 3389, sorted by total bytes. This is exactly where the successful session shows up as an outlier. We show the top 50 so the agent can see both the failed attempts and the one session that's dramatically larger.
>
> **Query 4** checks for RMM tool or C2 beacon domains in DNS — things like 'rmm', 'tactical', 'mesh' — in the first 60 seconds of the capture. This is the pre-existing compromise check.
>
> So by the time the agent starts reasoning, it already has the full picture in front of it."

---

## Slide 5: OUTPUT SCHEMA — InitialAccessFindings

> "Once the agent finishes its investigation, it writes its findings into a structured dataclass called `InitialAccessFindings`, which lives in our shared data contract.
>
> The key fields are exactly what you'd expect from a forensic report: Patient Zero IP, the attack vector, the attacker's IP, the exposed service and port, the brute-force count, and the size of the successful session in bytes.
>
> We also capture session timestamps in ISO-8601 format, a boolean for pre-existing compromise, and a list of IOCs — each tagged with a type, value, source agent, and confidence level.
>
> This structured output is what gets passed into `PipelineState`, and every agent that runs after this — Lateral Movement, Payload — can read from it. For example, Lateral Movement uses the `patient_zero` and `attacker_ips` fields to know where to start looking for internal spread.
>
> It also feeds back into the scoring logic: `successful_session_bytes` greater than 10,000 and `brute_force_count` greater than 1,000 are the thresholds that trigger a PCAP drill-down in the first place."

---

## Slide 6: ADAPTER — MARKDOWN TO STRUCTURED DATA

> "The last piece is the adapter — and this is an interesting design challenge we had to solve.
>
> The ForensicAgent uses the raw Azure OpenAI SDK, not LangChain. It calls a `submit_report` tool that accepts free-form Markdown. This was intentional — forcing the LLM to output structured JSON mid-investigation is brittle and makes the prompt much harder to write.
>
> But the rest of our pipeline needs structured data, not Markdown. So `initial_access_adapter.py` acts as the bridge.
>
> The `_parse_report()` function uses a set of regex patterns to extract each field from the Markdown report. Patient Zero is matched from lines like 'Patient Zero: 10.0.0.50'. The attacker IP is matched from phrases like 'successful login from' or 'logged in using'. Brute-force count is extracted from mentions of SYN counts or failed attempts. Session bytes from the first byte count mentioned. And pre-existing compromise is flagged if keywords like 'c2 beacon' or 'return visit' appear.
>
> This approach is intentionally pragmatic — the LLM's narrative language is actually quite consistent for these fields, so regex works reliably here. And it means we don't need to constrain how the agent reasons or writes its report.
>
> The extracted findings are then written back into `PipelineState` using the canonical `set_initial_access()` helper, and the pipeline moves on to Lateral Movement."

---
