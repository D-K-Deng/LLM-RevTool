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
            parsed = parse_model_output(raw, strict=strict_output)
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
            parsed = parse_model_output(repaired, strict=True)
            used_format_repair = True
            raw_text = repaired
        except GenerationParseError:
            # Preserve momentum when the model returns usable code but misses the exact section format.
            parsed = parse_model_output(repaired, strict=False)
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
    code = code_blocks[0].strip()
    if not code:
        raise GenerationParseError("Code block is empty.")

    return ParsedSections(
        strategy=strategy,
        code=code,
        success_conditions=success_conditions,
    )


def _parse_relaxed(text: str) -> ParsedSections:
    code_blocks = re.findall(r"```(?:python)?\s*(.*?)```", text, re.IGNORECASE | re.DOTALL)
    if not code_blocks:
        raise GenerationParseError("No python code block found.")
    code = code_blocks[0].strip()

    # Minimal fallback split around code block
    match = re.search(r"```(?:python)?\s*.*?```", text, re.IGNORECASE | re.DOTALL)
    assert match is not None
    before = text[: match.start()].strip()
    after = text[match.end() :].strip()

    strategy = before or "No explicit strategy provided."
    success_conditions = after or "Look for WIN / FLAG markers in target output."
    return ParsedSections(strategy=strategy, code=code, success_conditions=success_conditions)


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
