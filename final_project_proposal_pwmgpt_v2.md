# Final Project Proposal (Revised): From Classical AEG to LLM-Agent Exploitation — Reproducing PwnGPT with a Deeper AEG/CRS Paper Review

**Team:** Zhaowen Deng, Bingyi Li  
**Date:** 2026-03-03

---

## 1. Summary Abstract

We propose a reproduction-style graduate group project that (1) implements and evaluates an LLM-agent pipeline for automated exploit generation (AEG) inspired by **PwnGPT (ACL 2025)**, and (2) grounds the work in a **more detailed literature review of classical AEG and cyber reasoning systems (CRS)** as suggested by the instructor.

Concretely, we will build a three-stage pipeline **Analysis → Generation → Verification (iterative repair)** that runs only on **local** binaries. The system extracts compact binary context, prompts the Gemini API to generate a structured exploit attempt, executes it locally to verify success/failure, and iteratively refines the exploit using execution feedback.

To address the “graduate group project” expectation, we will additionally produce a structured paper review covering: **AEG (NDSS 2011)** and its follow-on systems (e.g., **Mayhem**), the **DARPA Cyber Grand Challenge (CGC)** lineage, the **Automated Exploitation Grand Challenge (AEGC)** challenge set and retrospective, and the more recent **DARPA AI Cyber Challenge (AIxCC)** CRS ecosystem (e.g., Trail of Bits **Buttercup**).

---

## 2. Motivation and Why This Revision

Our original proposal already included a PwnGPT-style pipeline and evaluation plan (analysis JSON → exploit generation → verification loop) and a small toy benchmark suite. The instructor feedback asks for **(a) deeper AEG paper review** and **(b) connecting to challenge/competition lineages (AEGC, AIxCC) and CRS systems (Buttercup)**. Therefore this revision adds:

1. **A literature review deliverable** (annotated bibliography + comparison table + short report).  
2. **A benchmark plan** that mixes *our toy binaries* (for fast iteration) with *selected public challenges* (AEGC-style) where feasible.  
3. **Clear positioning**: PwnGPT is treated as one point in a longer research arc from classical AEG → CGC/CRS → AIxCC → LLM-agent pipelines.

---

## 3. Background and Paper Review Plan (What We Will Read and Summarize)

### 3.1 Classical AEG (baseline concepts)
- **AEG: Automatic Exploit Generation (NDSS 2011)** — end-to-end pipeline: bug finding → exploitability reasoning → exploit generation.
- Key ideas to extract: exploitability models, constraints, assumptions, and what types of exploits are produced.

### 3.2 Follow-on AEG systems / scaling up
- **Mayhem (IEEE S&P 2012)** — automatic bug discovery + exploit generation at the binary level; emphasis on scalable symbolic execution techniques.
- **Hybrid fuzzing + symbolic execution lines** (e.g., **Driller (NDSS 2016)**) — important because modern CRS often couples fuzzing and symbolic execution.

### 3.3 Challenge lineages: AEGC and CGC
- **AEGC (Automated Exploitation Grand Challenge)** materials and retrospective (Vanegue) — what the original challenges were, why they were structured that way, what lessons were learned after several years.
- **DARPA CGC (2016)** CRS framing — systems that automatically find, exploit, and patch vulnerabilities under a competition setting.

### 3.4 Modern CRS and AIxCC (context for where the field moved)
- **DARPA AIxCC (AI Cyber Challenge)** — what changed from CGC to AIxCC; what tasks are emphasized; how modern systems are architected.
- **Buttercup (Trail of Bits)** — open-source CRS aimed at finding and patching vulnerabilities; we will study its architecture as a reference CRS and use it to motivate our evaluation metrics and tooling choices.

### 3.5 LLM-based AEG and PwnGPT
- **PwnGPT (ACL 2025)** — explicit “task decomposition + structured output + verification feedback” pipeline.
- We will compare PwnGPT’s assumptions and failure modes to classical AEG/CRS approaches.

### 3.6 Paper Review Output (deliverable format)
We will produce:
1. **Annotated bibliography** (1–2 pages; bullets per paper: goal, setting, pipeline, assumptions, limitations).  
2. **Comparison matrix** (table): {system} × {bug discovery, exploit gen, patching, feedback loops, target type, success criteria}.  
3. **Short review write-up** (4–6 pages) synthesizing: “What changed from AEG→CGC→AIxCC and how LLMs fit in.”

---

## 4. Updated Objectives

1. **Implement** a PwnGPT-style pipeline:
   - Analysis: extract/prune binary context into structured JSON  
   - Generation: Gemini produces a strictly structured exploit attempt  
   - Verification loop: local execution + condensed failure feedback + repair iterations
2. **Literature review deliverable** on classical AEG + follow-ons + AEGC/CGC/AIxCC/CRS.
3. **Benchmark suite**:
   - A: 3–8 local toy binaries for rapid iteration  
   - B: 1–3 public challenge binaries in an “AEGC-style” spirit (selected for being runnable locally without exotic runtimes)
4. **Evaluation + Ablations**:
   - Pruning vs no pruning  
   - Verification loop vs single-shot  
   - Strict structured output vs relaxed output
5. **Deliver** a runnable repository + results artifacts + review report.

---

## 5. System Overview (Implementation Plan)

### 5.1 Pipeline Architecture

1. **Analysis Module**
   - Inputs: binary path  
   - Outputs: `AnalysisReport.json`  
   - Tools: `file`, `readelf`, `objdump` (Intel syntax), `strings`, optional `nm`  
   - Extract:
     - mitigations (PIE/NX/Canary/RELRO)
     - imports/exports, interesting strings, entry/main candidates
     - focused disassembly snippets (pruned)
     - vulnerability heuristics (e.g., unsafe sinks, suspicious parsing)

2. **Generation Module (Gemini)**
   - Inputs: `AnalysisReport.json` + prompt template  
   - Output: structured response with:
     - `SECTION 1: Strategy`
     - `SECTION 2: Code` (single fenced Python code block; typically pwntools)
     - `SECTION 3: Success Conditions`
   - Robust parsing:
     - reject malformed output
     - one automatic “format repair” re-prompt if needed

3. **Verification Module**
   - Runs exploit locally with timeout  
   - Captures: stdout/stderr tail, exit code/signal  
   - Success detection: markers like `WIN` / `FLAG{...}` or per-challenge regex  
   - Produces `VerificationResult.json` + a condensed `feedback_payload` for repair

4. **Orchestrator + Evaluation Harness**
   - `loop`: end-to-end solve with max iterations  
   - `eval`: batch run across all challenges and dump CSV/JSON metrics  
   - Ablation flags

### 5.2 Data Contracts (Schemas)

**AnalysisReport.json** (minimum)
- `binary_path`, `binary_name`, `timestamp`
- `protections`: `{ pie, nx, canary, relro }`
- `architecture`
- `imports`, `exports`
- `interesting_strings`
- `entry_points`: `{ main_candidates, input_functions }`
- `suspected_vulns`: list of `{ function, type, evidence }`
- `pruned_context`: disassembly snippets + notes

**VerificationResult.json**
- `attempt`, `status`, `stdout_tail`, `stderr_tail`, `exit_code`, `signal`, `timeout`
- `artifacts`: `{ exploit_path, run_log_path }`
- `success_reason`, `failure_reason`
- `feedback_payload`

---

## 6. Benchmark / Challenge Suite (Revised)

### 6.1 Local Toy Binaries (rapid iteration)
We will still build 3–8 small ELF binaries with benign win conditions:
- branch puzzle → prints `WIN`
- stack overwrite → redirect to `win()` → prints `FLAG{...}`
- format string toy → leak/overwrite to print secret
- integer edge cases → boundary triggers win path
- optional: minimal heap misuse (only if time permits)

Each includes:
- source under `challenges/src/`
- build script `challenges/build.sh`
- docs `challenges/README.md`

### 6.2 “AEGC-style” Public Challenges (added for realism)
If the AEGC/CGC challenge binaries can be executed locally with reasonable effort, we will select a small subset (1–3) that are:
- runnable in our environment
- clearly scoped
- represent at least one vulnerability class different from the toy set

If a challenge suite requires a non-standard runtime that would dominate project time, we will fall back to widely used CTF-style binaries that are open-source and runnable locally, while still keeping the evaluation fair and reproducible.

---

## 7. Evaluation Plan

### 7.1 Metrics
Per challenge and overall:
- success rate (solved/total)
- attempts-to-success (mean/median)
- time-to-success
- structured-output failures (format repair triggers)
- failure taxonomy (timeout, crash, wrong output, parse error, etc.)

### 7.2 Ablations
- context pruning vs no pruning
- verification loop vs single-shot
- strict structured format vs relaxed format

### 7.3 Qualitative Analysis (added)
For a subset of failures, we will manually tag root causes such as:
- missing prerequisite info leak
- incorrect calling convention / stack alignment
- bad ROP chain assumptions
- environment mismatch (PIE/ASLR handling)
- exploit script runtime errors

This connects directly to classical AEG/CRS discussions (where those issues are handled by symbolic reasoning, models, or environment constraints).

---

## 8. Timeline (2-person plan)

**Week 1**
- finalize paper list + start annotated bibliography
- implement analysis schema + basic binary feature extraction

**Week 2**
- implement generation prompt + strict parser + format-repair
- implement verification runner + feedback payload

**Week 3**
- integrate full loop + build toy suite + first end-to-end demos

**Week 4**
- add evaluation harness + run ablations
- attempt public “AEGC-style” challenges
- write review summary + results report

---

## 9. Expected Deliverables

1. Git repository (CLI + configs)
2. Challenge suite (toy sources + build)
3. Evaluation outputs (CSV/JSON) + short results report
4. AEG/CRS paper review (annotated bib + comparison table + write-up)
5. Demo: one solved challenge with visible iterative loop

---

## 10. References / Pointers (starter list)

- AEG (NDSS 2011)  
- Mayhem (IEEE S&P 2012)  
- Driller (NDSS 2016)  
- AEGC materials (Vanegue)  
- DARPA CGC (context)  
- DARPA AIxCC (context)  
- Buttercup CRS (Trail of Bits)  
- PwnGPT (ACL 2025)

