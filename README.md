# PwnGPT-Style Local AEG Pipeline

This repository implements the coding part of the proposal:

- Analysis -> Generation -> Verification iterative loop
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
- `GEMINI_MODEL=gemini-2.5-pro`
- `REFLECTION_GEMINI_MODEL=gemini-2.5-flash`

Recommended model values:

- `gemini-2.5-pro`
- `gemini-2.5-flash`
- `gemini-3-flash-preview`

Recommended setup:

- Use the stronger model for exploit generation
- Use a cheaper, faster model for reflection and format repair

Default split used by `.env.example`:

- primary Gemini: `gemini-2.5-pro`
- reflection Gemini: `gemini-2.5-flash`

Example Dartmouth OpenAI-compatible config:

```env
LLM_PROVIDER=openai_compatible
REFLECTION_LLM_PROVIDER=openai_compatible
OPENAI_COMPAT_BASE_URL=https://llm-proxy.dartmouth.edu
OPENAI_COMPAT_API_KEY=YOUR_VIRTUAL_KEY_GOES_HERE
OPENAI_COMPAT_MODEL=gpt-5.4-2026-03-05
REFLECTION_OPENAI_COMPAT_MODEL=gpt-4.1-mini
PWNGPT_MAX_INNER_ROUNDS_PER_ATTEMPT=4
```

The OpenAI-compatible client assumes the endpoint is:

```text
<OPENAI_COMPAT_BASE_URL>/v1/chat/completions
```

If Dartmouth exposes a different model name on your account, change `OPENAI_COMPAT_MODEL`.

How the pipeline uses the two models:

- Primary model: exploit generation
- Reflection model: failure diagnosis, revision hints, and format repair
- Each outer attempt can contain multiple inner reflection/generation/verification rounds

This keeps iterative loops cheaper and faster while reserving the expensive model for the main exploit-writing step.

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

Their manifest is:

- `challenges/manifest_rop.json`

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

### 8.6 Batch eval on all listed challenges

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
- `attempt_XX/GenerationResult.json`
- `attempt_XX/raw_model_output.txt`
- `attempt_XX/exploit.py`
- `attempt_XX/VerificationResult.json`
- `attempt_XX/round_YY/...` for deeper intra-attempt revisions
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

### `ModuleNotFoundError: No module named 'pwn'`

The generated exploit tried to use `pwntools`.

Fix options:

- install `pwntools` in WSL
- rerun with the current codebase, which now pushes the model toward standard-library-only scripts

### `wsl: Failed to mount Z:\`

This is usually non-blocking if your project drive still mounts and commands keep running.

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
