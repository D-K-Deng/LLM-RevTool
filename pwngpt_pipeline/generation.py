from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .llm_client import LLMClient, LLMError
from .prompting import (
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
            template_path=self.prompt_template_path,
        )
        raw = self.client.generate_text(prompt, purpose="primary").text

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
    ) -> GenerationResult:
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
            "- use pwntools for nontrivial ROP if helpful\n"
            "- exactly one python fenced code block\n\n"
            f"Reported issue:\n{issue}\n\n"
            f"Reflection summary:\n{reflection_text or '<none>'}\n\n"
            f"Latest local tool results:\n{tool_results_text or '<none>'}\n\n"
            f"Feedback JSON:\n{json.dumps(feedback, indent=2, ensure_ascii=False)}\n\n"
            f"Analysis JSON:\n{json.dumps(analysis, indent=2, ensure_ascii=False)}\n\n"
            f"Previous code:\n```python\n{code}\n```"
        )
        raw = self.client.generate_text(prompt, purpose="format_repair").text
        extracted = _extract_python_from_any(raw)
        if not extracted:
            raise GenerationParseError("Code-quality repair did not return Python code.")
        return GenerationResult(
            strategy="Repaired code after code-quality failure.",
            code=extracted,
            success_conditions="Look for WIN / FLAG markers in target output.",
            raw_text=raw,
            used_format_repair=True,
            reflection_summary=reflection_text,
        )

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
            strategy="Recovered executable code from malformed model output.",
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
