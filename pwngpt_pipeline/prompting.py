from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from typing import Any


def _default_generation_prompt() -> str:
    return dedent(
        """
        You are a binary exploitation assistant.
        Goal: generate a local exploit script for a single binary.

        Hard constraints:
        1) Output exactly 3 sections:
           SECTION 1: Strategy
           SECTION 2: Code
           SECTION 3: Success Conditions
        2) SECTION 2 must contain exactly one fenced Python code block.
        3) Code must run locally and should be deterministic.
        4) Use argparse and accept binary path from argv[1] or --binary.
        4a) The verifier will invoke the script with the binary path as argv[1]. You must use that path.
        4b) Do NOT hardcode paths like ./chall, ./branch_puzzle, /tmp/..., or remote host placeholders.
        5) Prefer Python standard library only (`subprocess`, `socket`, `struct`, `time`, `re`, `pathlib`).
        6) Do NOT use `pwntools` unless the feedback explicitly says it is installed and required.
        7) If the task is simple input/output, use `subprocess.Popen(..., stdin=PIPE, stdout=PIPE, stderr=PIPE, text=False)`.
        8) Do not include TODO placeholders like CORRECT_CODE_HERE; infer concrete values from the analysis JSON.
        9) Do not include markdown outside the required section text.
        10) Keep script self-contained with clear runtime checks.

        Tips:
        - Use mitigations and function hints from analysis context.
        - For simple branch/input puzzles, extract the exact required string from interesting_strings or disassembly and send it directly.
        - If exploit is uncertain, still produce your best executable attempt.
        - Print meaningful progress logs from the script.

        Input JSON:
        {analysis_json}

        Attempt number: {attempt}
        Previous feedback JSON:
        {feedback_json}
        """
    ).strip()


def load_generation_prompt_template(template_path: Path | None = None) -> str:
    if template_path and template_path.exists():
        return template_path.read_text(encoding="utf-8")
    return _default_generation_prompt()


def build_generation_prompt(
    analysis: dict[str, Any],
    attempt: int,
    feedback: dict[str, Any],
    strict_output: bool,
    template_path: Path | None = None,
) -> str:
    template = load_generation_prompt_template(template_path)
    prompt = template.format(
        analysis_json=json.dumps(analysis, indent=2, ensure_ascii=False),
        attempt=attempt,
        feedback_json=json.dumps(feedback, indent=2, ensure_ascii=False),
    )
    if not strict_output:
        prompt += (
            "\n\nRelaxed mode: you may provide concise reasoning, but you must still include a runnable python code block."
        )
    return prompt


def build_format_repair_prompt(raw_response: str) -> str:
    return dedent(
        f"""
        Reformat the following model output into STRICT format.

        Required format:
        SECTION 1: Strategy
        <text>
        SECTION 2: Code
        ```python
        <code>
        ```
        SECTION 3: Success Conditions
        <text>

        Constraints:
        - Keep the original exploit logic as much as possible.
        - Ensure exactly one python fenced code block.
        - No extra sections.

        Original output:
        {raw_response}
        """
    ).strip()
