from __future__ import annotations

import json
import re
import ast
import textwrap
from dataclasses import dataclass

from .llm_client import LLMClient, LLMError
from .prompting import (
    build_body_generation_prompt,
    build_exploit_plan_prompt,
    build_format_repair_prompt,
    build_generation_prompt,
    build_reflection_prompt,
    build_tool_request_prompt,
)
from .schemas import GenerationResult


class GenerationParseError(RuntimeError):
    pass


@dataclass
class ParsedSections:
    strategy: str
    code: str
    success_conditions: str


class ExploitGenerator:
    def __init__(self, client: LLMClient, prompt_template_path=None) -> None:
        self.client = client
        self.prompt_template_path = prompt_template_path

    def generate(
        self,
        analysis: dict,
        attempt: int,
        feedback: dict,
        strict_output: bool = True,
        attempt_history: list[dict] | None = None,
        previous_code: str = "",
        reflection_text: str = "",
        tool_results_text: str = "",
        exploit_plan_text: str = "",
    ) -> GenerationResult:
        prompt = build_generation_prompt(
            analysis=analysis,
            attempt=attempt,
            feedback=feedback,
            strict_output=strict_output,
            attempt_history=attempt_history,
            previous_code=previous_code,
            reflection_text=reflection_text,
            tool_results_text=tool_results_text,
            exploit_plan_text=exploit_plan_text,
            template_path=self.prompt_template_path,
        )
        raw = self.client.generate_text(prompt, purpose="scaffold").text

        code = _extract_python_from_any(raw)
        if code:
            return GenerationResult(
                strategy=_extract_strategy_summary(raw),
                code=code,
                success_conditions="Look for WIN / FLAG markers in target output.",
                raw_text=raw,
                used_format_repair=False,
                reflection_summary=reflection_text,
            )

        try:
            parsed = _parse_generation_response(raw, strict=strict_output)
            return GenerationResult(
                strategy=parsed.strategy,
                code=parsed.code,
                success_conditions=parsed.success_conditions,
                raw_text=raw,
                used_format_repair=False,
                reflection_summary=reflection_text,
            )
        except GenerationParseError:
            if not strict_output:
                raise

        repair_prompt = build_format_repair_prompt(raw)
        repaired = self.client.generate_text(repair_prompt, purpose="format_repair").text
        repaired_code = _extract_python_from_any(repaired)
        if repaired_code:
            return GenerationResult(
                strategy=_extract_strategy_summary(repaired),
                code=repaired_code,
                success_conditions="Look for WIN / FLAG markers in target output.",
                raw_text=repaired,
                used_format_repair=True,
                reflection_summary=reflection_text,
            )
        try:
            parsed = _parse_generation_response(repaired, strict=True)
            used_format_repair = True
            raw_text = repaired
        except GenerationParseError:
            # Preserve momentum when the model returns usable code but misses the exact section format.
            parsed = _parse_generation_response(repaired, strict=False)
            used_format_repair = True
            raw_text = repaired
        return GenerationResult(
            strategy=parsed.strategy,
            code=parsed.code,
            success_conditions=parsed.success_conditions,
            raw_text=raw_text,
            used_format_repair=used_format_repair,
            reflection_summary=reflection_text,
        )

    def generate_scaffolded(
        self,
        analysis: dict,
        attempt: int,
        feedback: dict,
        attempt_history: list[dict] | None = None,
        previous_code: str = "",
        reflection_text: str = "",
        tool_results_text: str = "",
        exploit_plan_text: str = "",
    ) -> GenerationResult:
        prompt = build_body_generation_prompt(
            analysis=analysis,
            attempt=attempt,
            feedback=feedback,
            attempt_history=attempt_history,
            previous_code=previous_code,
            reflection_text=reflection_text,
            tool_results_text=tool_results_text,
            exploit_plan_text=exploit_plan_text,
        )
        raw = self.client.generate_text(prompt, purpose="primary").text
        body = _extract_scaffold_body(raw)
        if not body:
            repair_prompt = (
                "Rewrite the following model output into exactly one JSON object and nothing else.\n"
                "Required format:\n"
                "{\n"
                '  "body_lines": ["stmt1", "stmt2"]\n'
                "}\n"
                "Each item must be one Python statement line for the body of run_exploit(binary_path, runtime_dir, elf).\n"
                "Each item must be a complete single-line statement.\n"
                "Do not split one statement across multiple items.\n"
                "Do not use comments.\n"
                "Do not return prose, markdown, or fenced code blocks.\n\n"
                f"Original output:\n{raw}"
            )
            repaired = self.client.generate_text(repair_prompt, purpose="format_repair").text
            body = _extract_scaffold_body(repaired)
            if not body:
                raise GenerationParseError("No scaffolded body found in model output.")
            raw = repaired

        wrapped = _wrap_scaffolded_body(body)
        return GenerationResult(
            strategy="Scaffolded body generation for complex exploit family.",
            code=wrapped,
            success_conditions="Look for WIN / FLAG markers in target output.",
            raw_text=raw,
            used_format_repair=False,
            reflection_summary=reflection_text,
        )

    def reflect(
        self,
        analysis: dict,
        attempt: int,
        feedback: dict,
        previous_code: str,
        attempt_history: list[dict] | None = None,
    ) -> str:
        prompt = build_reflection_prompt(
            analysis=analysis,
            attempt=attempt,
            feedback=feedback,
            previous_code=previous_code,
            attempt_history=attempt_history,
            allow_unsafe_commands=self.client.config.allow_unsafe_model_commands,
        )
        try:
            return self.client.generate_text(prompt, purpose="reflection").text
        except LLMError as exc:
            return f"<reflection unavailable: {exc}>"

    def repair_code_quality(
        self,
        code: str,
        issue: str,
        analysis: dict,
        attempt: int,
        feedback: dict,
        reflection_text: str = "",
        tool_results_text: str = "",
        scaffold_mode: bool = False,
    ) -> GenerationResult:
        if scaffold_mode:
            prompt = (
                "Fix the exploit BODY for a scaffolded exploit.\n"
                "Return exactly one JSON object and nothing else.\n"
                "Required format:\n"
                "{\n"
                '  "body_lines": ["stmt1", "stmt2"]\n'
                "}\n"
                "Each item in body_lines must be one valid Python statement line for the body of run_exploit(binary_path, runtime_dir, elf).\n"
                "Each item must be a complete single-line statement.\n"
                "Do not split one statement across multiple items.\n"
                "Do not use comments.\n"
                "Do not return imports, main(), argparse, __main__, prose, markdown, or fenced code blocks.\n"
                "Requirements:\n"
                "- valid Python 3 statements only\n"
                "- actually execute the target locally\n"
                "- use bytes for pwntools recv/send\n"
                "- prefer TARGET_RUNTIME_DIR / runtime_dir for sidecar files\n"
                "- avoid f-strings and multi-line string literals\n\n"
                f"Reported issue:\n{issue}\n\n"
                f"Reflection summary:\n{reflection_text or '<none>'}\n\n"
                f"Latest local tool results:\n{tool_results_text or '<none>'}\n\n"
                f"Feedback JSON:\n{json.dumps(feedback, indent=2, ensure_ascii=False)}\n\n"
                f"Analysis JSON:\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n\n"
                f"Previous code:\n```python\n{code}\n```"
            )
        else:
            prompt = (
                "Rewrite the exploit code and fix the reported issue.\n"
                "Return exactly one fenced Python code block and nothing else.\n"
                "Do not return section headers, explanations, bullets, markdown prose, or JSON.\n"
                "Requirements:\n"
                "- valid Python 3\n"
                "- accept binary path from argv / --binary\n"
                "- actually execute the provided binary locally\n"
                "- send payload or interact as needed\n"
                "- print resulting stdout/stderr\n"
                "- prefer os.environ['TARGET_RUNTIME_DIR'] or cwd for sidecar files instead of dirname(binary_path)\n"
                "- use pwntools for nontrivial ROP if helpful\n"
                "- avoid f-strings and multi-line string literals\n"
                "- keep the script short and concrete\n"
                "- exactly one python fenced code block\n\n"
                f"Reported issue:\n{issue}\n\n"
                f"Reflection summary:\n{reflection_text or '<none>'}\n\n"
                f"Latest local tool results:\n{tool_results_text or '<none>'}\n\n"
                f"Feedback JSON:\n{json.dumps(feedback, indent=2, ensure_ascii=False)}\n\n"
                f"Analysis JSON:\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n\n"
                f"Previous code:\n```python\n{code}\n```"
            )
        raw = self.client.generate_text(prompt, purpose="format_repair").text
        extracted = _extract_scaffold_body(raw) if scaffold_mode else _extract_python_from_any(raw)
        if not extracted:
            raise GenerationParseError("Code-quality repair did not return Python code.")
        code_out = _wrap_scaffolded_body(extracted) if scaffold_mode else extracted
        return GenerationResult(
            strategy="Repaired code after code-quality failure.",
            code=code_out,
            success_conditions="Look for WIN / FLAG markers in target output.",
            raw_text=raw,
            used_format_repair=True,
            reflection_summary=reflection_text,
        )

    def repair_runtime_issue(
        self,
        code: str,
        verification_feedback: dict,
        analysis: dict,
        attempt: int,
        reflection_text: str = "",
        tool_results_text: str = "",
        scaffold_mode: bool = False,
    ) -> GenerationResult:
        if scaffold_mode:
            prompt = (
                "Fix the BODY of a scaffolded exploit using the runtime failure details below.\n"
                "Return exactly one JSON object and nothing else.\n"
                "Required format:\n"
                "{\n"
                '  "body_lines": ["stmt1", "stmt2"]\n'
                "}\n"
                "Each item in body_lines must be one valid Python statement line for the body of run_exploit(binary_path, runtime_dir, elf).\n"
                "Each item must be a complete single-line statement.\n"
                "Do not split one statement across multiple items.\n"
                "Do not use comments.\n"
                "Do not return imports, main(), argparse, __main__, prose, markdown, or fenced code blocks.\n"
                "Preserve the exploit structure where possible and only fix the runtime bug.\n"
                "Use bytes for pwntools recv/send and avoid f-strings.\n\n"
                f"Attempt: {attempt}\n\n"
                f"Verification feedback JSON:\n{json.dumps(verification_feedback, indent=2, ensure_ascii=False)}\n\n"
                f"Reflection summary:\n{reflection_text or '<none>'}\n\n"
                f"Local tool results:\n{tool_results_text or '<none>'}\n\n"
                f"Analysis JSON:\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n\n"
                f"Current code:\n```python\n{code}\n```"
            )
        else:
            prompt = (
                "Fix the exploit code using the runtime failure details below.\n"
                "Return exactly one fenced Python code block and nothing else.\n"
                "Do not rewrite from scratch unless necessary; preserve the existing exploit structure.\n"
                "Requirements:\n"
                "- valid Python 3\n"
                "- keep argparse / TARGET_BINARY / TARGET_RUNTIME_DIR compatibility\n"
                "- keep executing the target locally\n"
                "- fix the specific runtime error shown in stderr/stdout\n"
                "- print final process output\n"
                "- avoid f-strings and multi-line string literals\n\n"
                f"Attempt: {attempt}\n\n"
                f"Verification feedback JSON:\n{json.dumps(verification_feedback, indent=2, ensure_ascii=False)}\n\n"
                f"Reflection summary:\n{reflection_text or '<none>'}\n\n"
                f"Local tool results:\n{tool_results_text or '<none>'}\n\n"
                f"Analysis JSON:\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n\n"
                f"Current code:\n```python\n{code}\n```"
            )
        raw = self.client.generate_text(prompt, purpose="format_repair").text
        extracted = _extract_scaffold_body(raw) if scaffold_mode else _extract_python_from_any(raw)
        if not extracted:
            raise GenerationParseError("Runtime repair did not return Python code.")
        code_out = _wrap_scaffolded_body(extracted) if scaffold_mode else extracted
        return GenerationResult(
            strategy="Repaired code after runtime verification failure.",
            code=code_out,
            success_conditions="Look for WIN / FLAG markers in target output.",
            raw_text=raw,
            used_format_repair=True,
            reflection_summary=reflection_text,
        )

    def plan_exploit(
        self,
        analysis: dict,
        attempt: int,
        feedback: dict,
        previous_code: str,
        reflection_text: str,
        tool_results_text: str = "",
        attempt_history: list[dict] | None = None,
    ) -> str:
        prompt = build_exploit_plan_prompt(
            analysis=analysis,
            attempt=attempt,
            feedback=feedback,
            previous_code=previous_code,
            reflection_text=reflection_text,
            tool_results_text=tool_results_text,
            attempt_history=attempt_history,
        )
        try:
            return self.client.generate_text(prompt, purpose="reflection").text
        except LLMError as exc:
            return f"<exploit plan unavailable: {exc}>"

    def plan_tools(
        self,
        analysis: dict,
        attempt: int,
        feedback: dict,
        previous_code: str,
        reflection_text: str,
        attempt_history: list[dict] | None = None,
        previous_tool_results: str = "",
    ) -> dict:
        prompt = build_tool_request_prompt(
            analysis=analysis,
            attempt=attempt,
            feedback=feedback,
            previous_code=previous_code,
            reflection_text=reflection_text,
            attempt_history=attempt_history,
            previous_tool_results=previous_tool_results,
            allow_unsafe_commands=self.client.config.allow_unsafe_model_commands,
        )
        try:
            raw = self.client.generate_text(prompt, purpose="reflection").text
        except LLMError as exc:
            return {
                "tool_requests": [],
                "command_requests": [],
                "shell_requests": [],
                "why": f"tool planning unavailable: {exc}",
                "raw_text": "",
            }

        try:
            return parse_tool_plan(raw)
        except GenerationParseError as exc:
            return {
                "tool_requests": [],
                "command_requests": [],
                "shell_requests": [],
                "why": f"tool planning parse failed: {exc}",
                "raw_text": raw,
            }


def parse_model_output(text: str, strict: bool = True) -> ParsedSections:
    if strict:
        return _parse_strict(text)
    try:
        return _parse_strict(text)
    except GenerationParseError:
        return _parse_relaxed(text)


def _parse_generation_response(text: str, strict: bool) -> ParsedSections:
    try:
        return parse_model_output(text, strict=strict)
    except GenerationParseError:
        code = _extract_python_from_any(text)
        if not code:
            raise
        return ParsedSections(
            strategy=_extract_strategy_summary(text),
            code=code,
            success_conditions="Look for WIN / FLAG markers in target output.",
        )


def _parse_strict(text: str) -> ParsedSections:
    sec1 = re.search(r"SECTION\s*1\s*:\s*Strategy", text, re.IGNORECASE)
    sec2 = re.search(r"SECTION\s*2\s*:\s*Code", text, re.IGNORECASE)
    sec3 = re.search(r"SECTION\s*3\s*:\s*Success Conditions", text, re.IGNORECASE)
    if not (sec1 and sec2 and sec3):
        raise GenerationParseError("Missing required sections.")
    if not (sec1.start() < sec2.start() < sec3.start()):
        raise GenerationParseError("Section order invalid.")

    strategy = text[sec1.end() : sec2.start()].strip()
    section2_body = text[sec2.end() : sec3.start()].strip()
    success_conditions = text[sec3.end() :].strip()

    code_blocks = re.findall(r"```(?:python)?\s*(.*?)```", section2_body, re.IGNORECASE | re.DOTALL)
    if len(code_blocks) != 1:
        raise GenerationParseError("SECTION 2 must contain exactly one python fenced block.")
    code = _normalize_python_candidate(code_blocks[0])
    if not code:
        raise GenerationParseError("Code block is empty.")

    return ParsedSections(
        strategy=strategy,
        code=code,
        success_conditions=success_conditions,
    )


def _parse_relaxed(text: str) -> ParsedSections:
    code = _extract_python_from_any(text)
    if "```" in text and code:
        match = re.search(r"```(?:python)?\s*.*?```", text, re.IGNORECASE | re.DOTALL)
        assert match is not None
        before = text[: match.start()].strip()
        after = text[match.end() :].strip()
    else:
        before = ""
        after = ""

    if not code:
        raise GenerationParseError("No python code block found.")

    strategy = before or "No explicit strategy provided."
    success_conditions = after or "Look for WIN / FLAG markers in target output."
    return ParsedSections(strategy=strategy, code=code, success_conditions=success_conditions)


def _extract_python_from_any(text: str) -> str:
    code_blocks = re.findall(r"```(?:python)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
    for block in code_blocks:
        candidate = _normalize_python_candidate(block)
        if candidate:
            return candidate
    return _extract_likely_python(text)


def _extract_strategy_summary(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return "Generated exploit code."
    code = _extract_python_from_any(text)
    if code:
        stripped = stripped.replace(code, "").strip()
    if not stripped:
        return "Generated exploit code."
    lines = [line.strip() for line in stripped.splitlines() if line.strip()]
    cleaned = []
    for line in lines:
        low = line.lower()
        if low.startswith("section ") or low in {"```python", "```", "python"}:
            continue
        cleaned.append(line)
        if len(cleaned) >= 3:
            break
    summary = " ".join(cleaned).strip()
    return summary[:300] or "Generated exploit code."


def _extract_likely_python(text: str) -> str:
    stripped = text.strip()
    if not stripped:
        return ""
    lines = stripped.splitlines()
    pythonish = []
    saw_code = False
    for line in lines:
        if not saw_code and not line.strip():
            continue
        if not saw_code and any(
            token in line
            for token in (
                "import ",
                "from ",
                "def ",
                "class ",
                "if __name__",
                "parser =",
                "process(",
                "subprocess.",
            )
        ):
            saw_code = True
        if saw_code:
            pythonish.append(line)
    candidate = _normalize_python_candidate("\n".join(pythonish))
    if candidate:
        return candidate

    fallback = _normalize_python_candidate(stripped)
    if any(token in fallback for token in ("import ", "from ", "def ", "process(", "subprocess.")):
        return fallback
    return ""


def _normalize_python_candidate(text: str) -> str:
    candidate = text.strip()
    if not candidate:
        return ""
    candidate = re.sub(r"^```(?:python)?", "", candidate, flags=re.IGNORECASE).strip()
    candidate = re.sub(r"```$", "", candidate).strip()
    if candidate.lower().startswith("python\n"):
        candidate = candidate.split("\n", 1)[1].strip()

    lines = candidate.splitlines()
    while lines:
        line = lines[0].strip()
        if not line:
            lines.pop(0)
            continue
        if line.lower() in {"python", "code", "section 2: code"}:
            lines.pop(0)
            continue
        if line.startswith(("SECTION ", "SECTION:", "Strategy:", "Success Conditions:")):
            lines.pop(0)
            continue
        if line.startswith(("```", "'''")):
            lines.pop(0)
            continue
        break

    while lines and not _looks_like_python_code_line(lines[0]):
        lines.pop(0)

    return "\n".join(lines).strip()


def _wrap_scaffolded_body(body: str) -> str:
    body = _normalize_scaffold_indentation(body)
    indented = "\n".join(
        ("    " + line) if line.strip() else ""
        for line in body.strip().splitlines()
    )
    return (
        "import argparse\n"
        "import os\n"
        "import re\n"
        "from pathlib import Path\n"
        "from pwn import *\n\n"
        "def run_exploit(binary_path, runtime_dir, elf):\n"
        f"{indented}\n\n"
        "def main():\n"
        "    parser = argparse.ArgumentParser()\n"
        "    parser.add_argument('binary', nargs='?', default=None)\n"
        "    parser.add_argument('--binary', dest='binary_flag', default=None)\n"
        "    args = parser.parse_args()\n"
        "    binary = args.binary_flag or args.binary or os.environ.get('TARGET_BINARY')\n"
        "    if not binary:\n"
        "        raise SystemExit('missing binary path')\n"
        "    binary_path = Path(binary).resolve()\n"
        "    runtime_dir = Path(os.environ.get('TARGET_RUNTIME_DIR', str(binary_path.parent))).resolve()\n"
        "    context.binary = str(binary_path)\n"
        "    context.arch = 'amd64'\n"
        "    context.bits = 64\n"
        "    context.log_level = 'info'\n"
        "    elf = ELF(str(binary_path), checksec=False)\n"
        "    run_exploit(binary_path, runtime_dir, elf)\n\n"
        "if __name__ == '__main__':\n"
        "    main()\n"
    )


def _extract_scaffold_body(text: str) -> str:
    json_body = _extract_scaffold_json_body(text)
    if json_body:
        return json_body
    code = _extract_python_from_any(text)
    if not code:
        return ""
    body = _extract_function_body(code, {"run_exploit", "exploit", "solve", "run"})
    if body:
        return _normalize_scaffold_indentation(body)
    lowered = code.lower()
    if any(token in lowered for token in ("import ", "if __name__", "argparse", "def main(")):
        return ""
    return _normalize_scaffold_indentation(code)


def _extract_scaffold_json_body(text: str) -> str:
    try:
        payload = json.loads(_extract_json_blob(text))
    except (GenerationParseError, json.JSONDecodeError):
        return ""

    if not isinstance(payload, dict):
        return ""

    body_lines = payload.get("body_lines", payload.get("lines"))
    if isinstance(body_lines, list):
        joined = "\n".join(str(line) for line in body_lines if str(line).strip())
        return _normalize_scaffold_indentation(joined)

    body = payload.get("body", payload.get("code"))
    if isinstance(body, str):
        return _normalize_scaffold_indentation(body)

    return ""


def _normalize_scaffold_indentation(body: str) -> str:
    body = textwrap.dedent(body).strip("\n")
    lines = body.splitlines()
    if not lines:
        return ""

    following_indents = []
    has_zero_indent_following = False
    for line in lines[1:]:
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip())
        if indent > 0:
            following_indents.append(indent)
        else:
            has_zero_indent_following = True

    if following_indents and not has_zero_indent_following:
        common_following_indent = min(following_indents)
        first_indent = len(lines[0]) - len(lines[0].lstrip()) if lines[0].strip() else 0
        if first_indent == 0 and common_following_indent > 0:
            normalized = [lines[0].lstrip()]
            for line in lines[1:]:
                if not line.strip():
                    normalized.append("")
                else:
                    normalized.append(
                        line[common_following_indent:]
                        if len(line) >= common_following_indent
                        else line.lstrip()
                    )
            lines = normalized

    return textwrap.dedent("\n".join(lines)).strip()


def _extract_function_body(code: str, candidate_names: set[str]) -> str:
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return ""
    lines = code.splitlines()
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name in candidate_names and node.body:
            start = node.body[0].lineno - 1
            end = node.body[-1].end_lineno or node.body[-1].lineno
            body_lines = lines[start:end]
            indents = [
                len(line) - len(line.lstrip())
                for line in body_lines
                if line.strip()
            ]
            indent = min(indents) if indents else 0
            return "\n".join(line[indent:] if len(line) >= indent else line for line in body_lines).strip()
    return ""


def _looks_like_python_code_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    starters = (
        "import ",
        "from ",
        "def ",
        "class ",
        "if ",
        "for ",
        "while ",
        "try:",
        "with ",
        "parser =",
        "args =",
        "binary =",
        "elf =",
        "rop =",
        "io =",
        "proc =",
        "context.",
        "target =",
        "payload =",
        "main(",
        "if __name__",
    )
    if any(stripped.startswith(prefix) for prefix in starters):
        return True
    return bool(re.match(r"^[A-Za-z_][A-Za-z0-9_]*\s*=", stripped))


def parse_tool_plan(text: str) -> dict:
    json_blob = _extract_json_blob(text)
    try:
        payload = json.loads(json_blob)
    except json.JSONDecodeError as exc:
        raise GenerationParseError(f"Tool plan is not valid JSON: {exc}") from exc

    tool_requests = payload.get("tool_requests", payload.get("requests", []))
    command_requests = payload.get("command_requests", [])
    if not isinstance(tool_requests, list):
        raise GenerationParseError("Tool plan tool_requests must be a list.")
    if not isinstance(command_requests, list):
        raise GenerationParseError("Tool plan command_requests must be a list.")
    sanitized_tools = []
    for item in tool_requests[:3]:
        if not isinstance(item, dict):
            continue
        tool = str(item.get("tool", "")).strip()
        args = item.get("args", {})
        if tool:
            sanitized_tools.append({"tool": tool, "args": args if isinstance(args, dict) else {}})
    sanitized_commands = []
    for item in command_requests[:2]:
        if not isinstance(item, dict):
            continue
        command = str(item.get("command", "")).strip()
        args = item.get("args", {})
        if command:
            sanitized_commands.append(
                {"command": command, "args": args if isinstance(args, dict) else {}}
            )
    sanitized_shells = []
    for item in payload.get("shell_requests", [])[:2] if isinstance(payload.get("shell_requests", []), list) else []:
        if isinstance(item, dict):
            command = str(item.get("command", "")).strip()
            if command:
                sanitized_shells.append({"command": command})
        elif isinstance(item, str) and item.strip():
            sanitized_shells.append({"command": item.strip()})

    return {
        "tool_requests": sanitized_tools,
        "command_requests": sanitized_commands,
        "shell_requests": sanitized_shells,
        "why": str(payload.get("why", "")).strip(),
        "raw_text": text,
    }


def _extract_json_blob(text: str) -> str:
    fenced = re.search(r"```(?:json)?\s*(\{.*\})\s*```", text, re.DOTALL)
    if fenced:
        return fenced.group(1)
    direct = re.search(r"(\{.*\})", text, re.DOTALL)
    if direct:
        return direct.group(1)
    raise GenerationParseError("No JSON object found in tool plan response.")
