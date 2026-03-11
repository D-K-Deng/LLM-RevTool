from __future__ import annotations

import json
from pathlib import Path
from textwrap import dedent
from typing import Any

from .local_tools import (
    build_command_catalog_text,
    build_tool_catalog_text,
    build_unsafe_command_catalog_text,
)


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
        5) For simple stdin/stdout tasks, prefer Python standard library (`subprocess`, `socket`, `struct`, `time`, `re`, `pathlib`).
        6) `pwntools` is installed in this environment. For nontrivial ROP tasks, prefer `pwntools` (`ELF`, `ROP`, `process`, `p64`, `u64`) over ad-hoc parsing.
        7) If the task is simple input/output, use `subprocess.Popen(..., stdin=PIPE, stdout=PIPE, stderr=PIPE, text=False)`.
        8) Do not include TODO placeholders like CORRECT_CODE_HERE; infer concrete values from the analysis JSON.
        9) Do not include markdown outside the required section text.
        10) Keep script self-contained with clear runtime checks.
        11) The exploit must actually execute the target and print the resulting process output. Do not just build or return a payload.
        12) If the binary fits a known family (branch/input, simple ROP, constrained write, stack pivot, ret2csu-style dispatcher), follow the playbook evidence instead of improvising.
        13) Use this exact runtime skeleton shape unless there is a strong reason not to:
            - parse argv / --binary with argparse
            - create a local process for the provided binary path
            - send payload / interact
            - collect output
            - print output
            - exit nonzero only on real failure

        Tips:
        - Use mitigations and function hints from analysis context.
        - For simple branch/input puzzles, extract the exact required string from interesting_strings or disassembly and send it directly.
        - Use the helper insights and playbook below; do not rediscover the challenge class from scratch.
        - Read the previous exploit and previous verifier output carefully before revising.
        - If exploit is uncertain, still produce your best executable attempt.
        - Print meaningful progress logs from the script.
        - If concrete addresses, gadgets, relocations, writable sections, or runtime prompts are missing, request local tools/commands early instead of guessing.

        Helper playbook:
        {playbook_text}

        Attempt history JSON:
        {attempt_history_json}

        Previous exploit code:
        {previous_code}

        Reflection summary:
        {reflection_text}

        Latest local tool results:
        {tool_results_text}

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
    attempt_history: list[dict[str, Any]] | None = None,
    previous_code: str = "",
    reflection_text: str = "",
    tool_results_text: str = "",
    template_path: Path | None = None,
) -> str:
    template = load_generation_prompt_template(template_path)
    playbook_text = build_playbook_text(analysis)
    prompt = template.format(
        analysis_json=json.dumps(analysis, indent=2, ensure_ascii=False),
        attempt=attempt,
        feedback_json=json.dumps(feedback, indent=2, ensure_ascii=False),
        playbook_text=playbook_text,
        attempt_history_json=json.dumps(attempt_history or [], indent=2, ensure_ascii=False),
        previous_code=previous_code or "<none>",
        reflection_text=reflection_text or "<none>",
        tool_results_text=tool_results_text or "<no local tool results>",
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


def build_reflection_prompt(
    analysis: dict[str, Any],
    attempt: int,
    feedback: dict[str, Any],
    previous_code: str,
    attempt_history: list[dict[str, Any]] | None = None,
    allow_unsafe_commands: bool = False,
) -> str:
    playbook_text = build_playbook_text(analysis)
    tool_catalog = build_tool_catalog_text()
    command_catalog = build_command_catalog_text()
    unsafe_catalog = build_unsafe_command_catalog_text() if allow_unsafe_commands else ""
    return dedent(
        f"""
        You are reflecting on a failed exploit attempt for a local binary challenge.

        Write a short, concrete reflection with exactly these sections:
        SECTION A: Failure Diagnosis
        SECTION B: Fix Plan
        SECTION C: Non-Negotiable Constraints

        Rules:
        - Be specific about why the previous attempt failed.
        - Refer to helper insights and the challenge playbook.
        - Mention exact runtime errors, wrong assumptions, and next-step fixes.
        - Keep it concise and actionable.

        Helper playbook:
        {playbook_text}

        Available local tools:
        {tool_catalog}

        Available local commands:
        {command_catalog}

        {unsafe_catalog}

        Attempt number:
        {attempt}

        Attempt history JSON:
        {json.dumps(attempt_history or [], indent=2, ensure_ascii=False)}

        Previous feedback JSON:
        {json.dumps(feedback, indent=2, ensure_ascii=False)}

        Previous exploit code:
        {previous_code or "<none>"}

        Analysis JSON:
        {json.dumps(analysis, indent=2, ensure_ascii=False)}
        """
    ).strip()


def build_tool_request_prompt(
    analysis: dict[str, Any],
    attempt: int,
    feedback: dict[str, Any],
    previous_code: str,
    reflection_text: str,
    attempt_history: list[dict[str, Any]] | None = None,
    previous_tool_results: str = "",
    allow_unsafe_commands: bool = False,
) -> str:
    tool_catalog = build_tool_catalog_text()
    command_catalog = build_command_catalog_text()
    unsafe_catalog = build_unsafe_command_catalog_text() if allow_unsafe_commands else ""
    playbook_text = build_playbook_text(analysis)
    schema_tail = (
        ',\n            "shell_requests": [\n              {"command": "echo test"}\n            ]'
        if allow_unsafe_commands
        else ""
    )
    shell_rule = (
        "- Request at most 2 shell_requests.\n"
        "- shell_requests execute arbitrary local shell commands.\n"
        "- Use shell_requests only when tools/allowlisted commands are insufficient."
        if allow_unsafe_commands
        else ""
    )
    no_request_return = (
        '{"tool_requests": [], "command_requests": [], "shell_requests": [], "why": "..."}'
        if allow_unsafe_commands
        else '{"tool_requests": [], "command_requests": [], "why": "..."}'
    )
    return dedent(
        f"""
        You are deciding whether to request local read-only analysis tools for a binary exploitation task.

        Available tools:
        {tool_catalog}

        Available commands:
        {command_catalog}

        {unsafe_catalog}

        Rules:
        - Return JSON only.
        - Use this exact schema:
          {{
            "tool_requests": [
              {{"tool": "symbol_disasm", "args": {{"symbol": "usefulGadgets"}}}}
            ],
            "command_requests": [
              {{"command": "file_info", "args": {{}}}}
            ]{schema_tail},
            "why": "short rationale"
          }}
        - Request at most 3 tools and at most 2 commands.
        - Only request tools/commands if they can unlock concrete missing facts.
        - Do not request arbitrary shell commands, writes, networking, or unrelated filesystem access.
        {shell_rule}
        - If no tools/commands are needed, return {no_request_return}.
        - For complex tasks, prefer requesting concrete gadget/symbol/disassembly evidence before proposing a chain.

        Helper playbook:
        {playbook_text}

        Attempt number:
        {attempt}

        Attempt history JSON:
        {json.dumps(attempt_history or [], indent=2, ensure_ascii=False)}

        Previous feedback JSON:
        {json.dumps(feedback, indent=2, ensure_ascii=False)}

        Previous exploit code:
        {previous_code or "<none>"}

        Reflection summary:
        {reflection_text or "<none>"}

        Previous local tool results:
        {previous_tool_results or "<none>"}

        Analysis JSON:
        {json.dumps(analysis, indent=2, ensure_ascii=False)}
        """
    ).strip()


def build_playbook_text(analysis: dict[str, Any]) -> str:
    helper = analysis.get("helper_insights", {})
    challenge_class = helper.get("challenge_class", "unknown")
    methods = helper.get("recommended_methods", [])
    warnings = helper.get("prompt_warnings", [])
    offsets = helper.get("candidate_offsets", [])
    symbols = helper.get("candidate_symbols", [])
    inputs = helper.get("candidate_inputs", [])

    lines = [f"challenge_class: {challenge_class}"]
    if methods:
        lines.append("recommended_methods:")
        lines.extend(f"- {item}" for item in methods)
    if warnings:
        lines.append("warnings:")
        lines.extend(f"- {item}" for item in warnings)
    if offsets:
        lines.append(f"candidate_offsets: {offsets}")
    if symbols:
        lines.append(f"candidate_symbols: {symbols}")
    if inputs:
        lines.append(f"candidate_inputs: {inputs[:8]}")
    return "\n".join(lines)
