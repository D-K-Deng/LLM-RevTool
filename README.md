# PwnGPT-Style Local AEG Pipeline

This repository implements the coding part of the proposal:

- Analysis -> Generation -> Verification iterative loop
- Read-only local tool loop that the LLM can request between iterations
- Gemini or OpenAI-compatible exploit generation
- Strict structured output parsing + one format-repair retry
- Batch evaluation harness
- Local toy challenges
- Downloaded public ROP Emporium challenges

## 1. What You Need

For end-to-end runs on ELF binaries, use Linux or WSL.

Required:

- WSL with an Ubuntu distro, or a native Linux machine
- `python3`
- `python3-venv`
- `python3-pip`
- `gcc`
- `binutils` (`readelf`, `objdump`, `strings`)
- `file`
- LLM API key
- `gdb`
- `patchelf`
- `pwntools`

Windows Python alone is not enough for full runs, because the targets are Linux ELF binaries.

All commands below assume you first `cd` into the repository root in PowerShell.

## 2. Install WSL and Ubuntu

In an elevated PowerShell window:

```powershell
wsl --install -d Ubuntu
```

If WSL is already installed:

```powershell
wsl -l -v
```

Then open Ubuntu once and finish the first-time setup.

## 3. Install System Packages Inside WSL

Run this in PowerShell:

```powershell
wsl bash -lc "sudo apt update && sudo apt install -y python3 python3-venv python3-pip gcc binutils file gdb build-essential patchelf"
```

## 4. Install Python Dependencies Inside WSL

From the project root:

```powershell
$REPO_ROOT = (Get-Location).Path
$REPO_ROOT_WSL = (wsl wslpath -a "$REPO_ROOT").Trim()
```

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && python3 -m venv .venv && source .venv/bin/activate && python3 -m pip install --upgrade pip && python3 -m pip install -r requirements.txt"
```

`pwntools` is included in `requirements.txt` and is treated as a required dependency.

The CLI will automatically prefer the repository's `.venv` Python if it exists, even if you forget to activate it manually.

## 5. Configure LLM Provider

Copy the template:

```powershell
Copy-Item .env.example .env
```

Edit `.env`:

- `LLM_PROVIDER=gemini` or `LLM_PROVIDER=openai_compatible`
- `REFLECTION_LLM_PROVIDER=gemini` or `REFLECTION_LLM_PROVIDER=openai_compatible`
- `GEMINI_API_KEY=...`
- `GEMINI_MODEL=gemini-3.1-pro-preview`
- `REFLECTION_GEMINI_MODEL=gemini-2.5-flash`

Recommended primary models:

- `gemini-3.1-pro-preview`
- `anthropic.claude-opus-4-6`
- `gpt-5.4-2026-03-05`

Recommended setup:

- Use the stronger model for exploit generation
- Use a cheaper, faster model for reflection and format repair

Default split used by `.env.example`:

- primary Gemini: `gemini-3.1-pro-preview`
- reflection Gemini: `gemini-2.5-flash`

Recommended provider/model combinations:

- Gemini primary: `GEMINI_MODEL=gemini-3.1-pro-preview`
- OpenAI-compatible primary with Claude: `OPENAI_COMPAT_MODEL=anthropic.claude-opus-4-6`
- OpenAI-compatible primary with GPT: `OPENAI_COMPAT_MODEL=gpt-5.4-2026-03-05`

Example Dartmouth OpenAI-compatible config:

```env
LLM_PROVIDER=openai_compatible
REFLECTION_LLM_PROVIDER=openai_compatible
OPENAI_COMPAT_BASE_URL=https://llm-proxy.dartmouth.edu
OPENAI_COMPAT_API_KEY=YOUR_VIRTUAL_KEY_GOES_HERE
OPENAI_COMPAT_MODEL=gpt-5.4-2026-03-05
REFLECTION_OPENAI_COMPAT_MODEL=gpt-4.1-mini
PWNGPT_MAX_OUTPUT_TOKENS=8192
PWNGPT_REFLECTION_MAX_OUTPUT_TOKENS=2048
PWNGPT_REQUEST_TIMEOUT_S=180
PWNGPT_REFLECTION_REQUEST_TIMEOUT_S=60
PWNGPT_SCAFFOLD_TEMPERATURE=0.1
PWNGPT_FORMAT_REPAIR_TEMPERATURE=0.0
PWNGPT_REFLECTION_TEMPERATURE=0.1
PWNGPT_MAX_INNER_ROUNDS_PER_ATTEMPT=4
PWNGPT_MAX_GENERATION_ATTEMPTS_PER_ROUND=8
```

`PWNGPT_MAX_GENERATION_ATTEMPTS_PER_ROUND` caps how many invalid drafts the solver will tolerate before it gives up on producing one verified round. Only verification outcomes consume a round; pure format or generation failures stay within the same logical round.

The OpenAI-compatible client assumes the endpoint is:

```text
<OPENAI_COMPAT_BASE_URL>/v1/chat/completions
```

If Dartmouth exposes a different model name on your account, change `OPENAI_COMPAT_MODEL`.

How the pipeline uses the two models:

- Primary model: exploit generation
- Reflection model: failure diagnosis, revision hints, and format repair
- Each outer attempt can contain multiple inner reflection/generation/verification rounds
- The reflection/tool-planning loop can request local read-only analysis tools and feed results back into the next generation round

This keeps iterative loops cheaper and faster while reserving the expensive model for the main exploit-writing step.

Research context that informed this design:

- Original AEG reference: "Automatic Exploit Generation in the Shell" (Brumley et al., NDSS 2011)
- Julien Vanegue's AEGC material and retrospective:
  - https://openwall.info/wiki/_media/people/jvanegue/files/aegc_vanegue.pdf
  - https://spw18.langsec.org/slides/Vanegue-AEGC-5-year-perspective.pdf
- AI Cyber Challenge official site:
  - https://aicyberchallenge.com/
- Trail of Bits Buttercup CRS:
  - https://github.com/trailofbits/buttercup

The practical takeaway is that high-performing systems are not "one prompt, one exploit". They are staged systems that combine:

- binary analysis
- challenge-family classification
- targeted evidence gathering
- iterative exploit refinement
- runtime verification
- repair / retry loops

Token budgeting:

- `PWNGPT_MAX_OUTPUT_TOKENS`: main exploit-generation and format-repair output budget
- `PWNGPT_REFLECTION_MAX_OUTPUT_TOKENS`: reflection / tool-planning output budget
- `PWNGPT_REQUEST_TIMEOUT_S`: timeout for main exploit-generation / format-repair requests
- `PWNGPT_REFLECTION_REQUEST_TIMEOUT_S`: timeout for reflection / tool-planning requests
- `PWNGPT_SCAFFOLD_TEMPERATURE`: lower temperature used for scaffold-family body generation
- `PWNGPT_FORMAT_REPAIR_TEMPERATURE`: low temperature used for syntax / format repair
- `PWNGPT_REFLECTION_TEMPERATURE`: temperature used for reflection / tool planning

Recommended default:

- keep `PWNGPT_MAX_OUTPUT_TOKENS` high enough for full exploit scripts, for example `8192`
- keep `PWNGPT_REFLECTION_MAX_OUTPUT_TOKENS` lower, for example `2048`
- keep `PWNGPT_REQUEST_TIMEOUT_S` higher for Gemini main generations, for example `180`
- keep `PWNGPT_REFLECTION_REQUEST_TIMEOUT_S` lower, for example `60`
- keep `PWNGPT_SCAFFOLD_TEMPERATURE` low, for example `0.1`
- keep `PWNGPT_FORMAT_REPAIR_TEMPERATURE` near `0.0`
- keep `PWNGPT_REFLECTION_TEMPERATURE` low, for example `0.1`

Local tool layer:

- The model can request a small allowlisted set of read-only tools
- The model can also request a small allowlisted set of read-only local commands
- If `PWNGPT_ALLOW_UNSAFE_MODEL_COMMANDS=true`, the model can also request arbitrary local shell commands
- The pipeline executes them locally and stores the outputs in artifacts
- The next generation round receives those tool results as extra input

Current allowlisted tools:

- `symbol_disasm(symbol)`
- `gadget_search(needle)`
- `strings_search(pattern)`
- `readelf_symbols(pattern)`
- `readelf_sections()`
- `readelf_relocs()`

Current allowlisted commands:

- `file_info()`
- `ldd()`
- `objdump_disasm()`
- `ropgadget()`
- `nm_symbols()`
- `run_head(timeout=2)`
- `run_with_stdin(input_text='', input_hex='', timeout=2)`
- `nearby_files()`

Automatic bootstrap evidence:

- Before the first LLM round, the pipeline now auto-collects a base evidence bundle
- This always includes file metadata, runtime-directory file listings, dynamic-library information, startup output, section headers, relocations, and key symbols
- The exact bootstrap bundle is then extended based on the inferred challenge class
- The pipeline also derives a short `AutoFacts.txt` summary from that evidence so the LLM sees the most important constraints first

Challenge taxonomy used by the pipeline:

- `branch_input` -> direct input validation
  - main tools: `strings_search`, `run_head`, `run_with_stdin`
- `ret2win` -> simple control hijack
  - main tools: `readelf_symbols`, `gadget_search`, `run_head`
- `split` -> simple ROP argument call
  - main tools: `strings_search`, `readelf_symbols`, `gadget_search`
- `callme` -> multi-call ROP
  - main tools: `readelf_symbols`, `gadget_search`, `nearby_files`
- `write4` -> write-what-where ROP
  - main tools: `readelf_sections`, `gadget_search`, `readelf_symbols`
- `badchars` -> encoded-write then decode ROP
  - main tools: `readelf_sections`, `gadget_search`, `readelf_symbols`
- `fluff` -> constrained-gadget ROP
  - main tools: `readelf_sections`, `readelf_symbols`, `gadget_search`
- `pivot` -> stack pivot plus dynamic symbol resolution
  - main tools: `readelf_symbols`, `readelf_relocs`, `gadget_search`, `nearby_files`
- `ret2csu` -> CSU-dispatch ROP
  - main tools: `symbol_disasm(__libc_csu_init)`, `gadget_search`, `readelf_symbols`
- `format_string` -> format-string leak/write
  - main tools: `strings_search`, `readelf_symbols`, `run_head`
- `stack_overflow` -> generic memory corruption
  - main tools: `readelf_symbols`, `run_head`, `nearby_files`

Why the taxonomy matters:

- It reduces prompt ambiguity
- It tells the LLM which exploit primitives are even plausible
- It lets the pipeline collect better local evidence before the LLM writes code
- It avoids wasting rounds on obviously wrong strategies

Runtime-directory rule:

- The verifier exports `TARGET_BINARY`, `TARGET_BINARY_DIR`, `TARGET_RUNTIME_DIR`, and `TARGET_CHALLENGE_DIR`
- For challenges with sidecar files such as `.so`, `flag.txt`, `.dat`, or helper artifacts, generated exploits should prefer `TARGET_RUNTIME_DIR` or the current working directory over `dirname(binary_path)`
- This is important for challenges like `pivot` or shared-library-backed tasks, where helper files may live in the challenge runtime directory rather than beside the copied binary

Unsafe mode:

- Set `PWNGPT_ALLOW_UNSAFE_MODEL_COMMANDS=true` to let the model request arbitrary local shell commands
- CLI override: `--unsafe-model-commands`
- When enabled, tool planning may emit `shell_requests`
- Shell outputs are stored in `ToolResults.json` and fed back into the next round

## 6. Build Toy Challenges

From the project root:

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL/challenges' && bash build.sh"
```

This produces ELF binaries in `challenges/bin/`.

## 7. Public Challenges Already Included

Downloaded public binaries are already placed in `challenges/bin/`:

- `rop_ret2win`
- `rop_split`
- `rop_callme`
- `rop_write4`
- `rop_badchars`
- `rop_fluff`
- `rop_pivot`
- `rop_ret2csu`

Their manifest is:

- `challenges/manifest_rop.json`
- `challenges/manifest_rop_extra.json`
- `challenges/manifest_rop_all.json`

Source links are recorded in:

- `challenges/downloads/README.md`

Executable permission is handled automatically during `solve` and `eval`.

## 8. How To Test

All commands below should be run from the project root in PowerShell.

### 8.1 Sanity check

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --help"
```

For harder binaries, prefer a small number of outer attempts with deeper inner rounds, for example `--max-iterations 3 --max-inner-rounds 4`.

### 8.2 Analyze one binary

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli analyze --binary challenges/bin/branch_puzzle"
```

### 8.3 Solve the easiest toy binary

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --max-iterations 3 --max-inner-rounds 4 solve --binary challenges/bin/branch_puzzle"
```

### 8.4 Solve one public challenge

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --max-iterations 3 --max-inner-rounds 4 solve --binary challenges/bin/rop_ret2win --success-regex 'ROPE\\{[^}]+\\}'"
```

### 8.5 Batch eval on downloaded public set

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --max-iterations 3 --max-inner-rounds 4 eval --manifest challenges/manifest_rop.json"
```

### 8.6 Batch eval on harder downloaded public set

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --unsafe-model-commands --max-iterations 3 --max-inner-rounds 4 eval --manifest challenges/manifest_rop_extra.json"
```

### 8.7 Batch eval on all downloaded public ROP challenges

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --unsafe-model-commands --max-iterations 3 --max-inner-rounds 4 eval --manifest challenges/manifest_rop_all.json"
```

### 8.8 Batch eval on all listed challenges

```powershell
wsl bash -lc "cd '$REPO_ROOT_WSL' && source .venv/bin/activate && python3 -m pwngpt_pipeline.cli --max-iterations 3 --max-inner-rounds 4 eval --manifest challenges/manifest.json"
```

## 9. Add Your Own Challenge

Put your ELF binary under `challenges/bin/`.

Example:

```powershell
Copy-Item C:\path\to\my_chal.exe .\challenges\bin\my_chal
```

Then add it to `challenges/manifest.json`:

```json
{
  "name": "my_chal",
  "binary": "challenges/bin/my_chal",
  "success_regex": ["FLAG\\{[^}]+\\}", "WIN"]
}
```

If the binary depends on local files, place them next to the binary or update your run environment accordingly.

## 10. Where Results Go

Each run writes to `artifacts/<binary>_<timestamp>/`:

- `AnalysisReport.json`
- `BootstrapEvidence.txt`
- `AutoFacts.txt` when distilled facts are available
- `attempt_XX/GenerationResult.json`
- `attempt_XX/raw_model_output.txt`
- `attempt_XX/exploit.py`
- `attempt_XX/VerificationResult.json`
- `attempt_XX/round_YY/...` for deeper intra-attempt revisions
- `attempt_XX/ToolPlan.json`
- `attempt_XX/ToolResults.json`
- `attempt_XX/ToolResults.txt`
- `run_summary.json`

Read `run_summary.json` first. If a run fails, inspect `attempt_01/VerificationResult.json` and `attempt_01/exploit.py`.

## 11. Common Problems

### `unexpected model name format`

Your `.env` contains a display name instead of an API model ID.

Use an actual API model ID, for example:

- `gemini-2.5-pro`
- `gemini-2.5-flash`
- `gemini-3-flash-preview`

### OpenAI-compatible provider errors

Check these fields:

- `LLM_PROVIDER=openai_compatible`
- `REFLECTION_LLM_PROVIDER=openai_compatible` if you also want cheap reflections through the same proxy
- `OPENAI_COMPAT_BASE_URL`
- `OPENAI_COMPAT_API_KEY`
- `OPENAI_COMPAT_MODEL`
- `REFLECTION_OPENAI_COMPAT_MODEL`

If your OpenAI-compatible proxy routes to Anthropic or Claude models, some backends reject requests that specify both `temperature` and `top_p`.

The current client now handles this automatically:

- Anthropic/Claude via OpenAI-compatible: sends only `temperature`
- Gemini: unchanged, still sends both `temperature` and `top_p`

### `ModuleNotFoundError: No module named 'pwn'`

The generated exploit tried to use `pwntools`.

Fix options:

- install `pwntools` in WSL
- rerun with the current codebase, which now pushes the model toward standard-library-only scripts

### PowerShell can import the package, but solving fails

Use WSL `python3`, not Windows `python`, for ELF targets.

## 12. Retry Behavior

LLM retry logic is implemented in:

- `pwngpt_pipeline/llm_client.py`

Current behavior:

- `max_retries + 1` total attempts
- retries on `408`, `409`, `425`, `429`, `500`, `502`, `503`, `504`
- exponential backoff plus jitter
- retries on network exceptions, JSON parse failures, and empty text
