# PwnGPT-Style Local AEG Pipeline

This repository implements a binary-exploitation pipeline with:

- analysis -> generation -> verification loops
- local read-only tool use during solving
- Gemini or OpenAI-compatible model backends
- heuristic solvers for stable challenge families
- LLM fallback for harder or non-heuristic cases
- batch evaluation over local manifests

The project ships with local toy challenges and downloaded public ROP Emporium challenges.

For end-to-end ELF solving, the actual target execution environment must be Linux-compatible.

## Jump To Your Platform

- [Windows](#windows)
- [macos](#macos)
- [linux](#linux)

## Model Setup

Copy the template and edit your provider settings:

```powershell
Copy-Item .env.example .env
```

Recommended primary models:

- `gemini-3.1-pro-preview`
- `anthropic.claude-opus-4-6`
- `gpt-5.4-2026-03-05`

Recommended reflection model:

- a cheaper fast model such as `gemini-2.5-flash` or `gpt-4.1-mini`

If your `.env` already contains:

```env
PWNGPT_ALLOW_UNSAFE_MODEL_COMMANDS=true
```

then you do not need to add `--unsafe-model-commands` to every command.

## Command Semantics

This README uses the launcher command:

```powershell
llmrev 1 15 challenges/manifest.json
```

Meaning:

- heuristic runs first by default and is recorded as `attempt 1` when available
- `1`: allow `1` LLM outer attempt after the heuristic pass
- `15`: allow up to `15` verified inner rounds for that LLM attempt
- `challenges/manifest.json`: evaluate all challenges listed in that manifest

Install the launcher with editable mode from the repository root:

```powershell
python -m pip install -e .
```

## Windows

Use Windows for editing and launching, but let `llmrev` forward the actual solve into WSL.

### Requirements

- WSL with Ubuntu
- `python3`, `python3-venv`, `python3-pip`
- `gcc`, `binutils`, `file`, `gdb`, `patchelf`

### First-Time Setup

In an elevated PowerShell window:

```powershell
wsl --install -d Ubuntu
```

Then install Linux packages inside WSL:

```powershell
wsl bash -lc "sudo apt update && sudo apt install -y python3 python3-venv python3-pip gcc binutils file gdb build-essential patchelf"
```

Back in PowerShell at the repository root, install the launcher:

```powershell
python -m pip install -e .
```

### Run All Challenges

```powershell
llmrev 1 15 challenges/manifest.json
```

## macOS

The `llmrev` launcher works on macOS, but ELF solving still needs a Linux-compatible runtime.
Use a Linux VM, container, remote Linux machine, or similar environment for actual challenge execution.

### Recommended Setup

- install the repo on your Linux execution environment
- install Python and the system packages there
- install the launcher in editable mode there

```bash
python3 -m pip install -e .
```

### Run All Challenges

```bash
llmrev 1 15 challenges/manifest.json
```

## Linux

Native Linux is the simplest environment for end-to-end solving.

### System Packages

On Debian or Ubuntu:

```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip gcc binutils file gdb build-essential patchelf
```

### Python Setup

From the repository root:

```bash
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -r requirements.txt
python3 -m pip install -e .
```

### Run All Challenges

```bash
llmrev 1 15 challenges/manifest.json
```

## Challenge Sets

- `challenges/manifest.json`: local toy set plus stable ROP examples
- `challenges/manifest_rop_extra.json`: harder LLM-heavy ROP set
- `challenges/manifest_rop_all.json`: all downloaded public ROP challenges in this repo

## Artifacts

Each run writes logs and generated exploits under `artifacts/`.
A batch evaluation writes one `eval_*` directory plus one run directory per challenge.

## Notes

- Windows Python alone is not enough for direct ELF execution.
- If `.venv` exists, the launcher prefers it automatically.
- If you want to test the full local set, the default command is still:

```powershell
llmrev 1 15 challenges/manifest.json
```
