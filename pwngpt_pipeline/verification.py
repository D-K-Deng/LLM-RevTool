from __future__ import annotations

import os
import re
import signal
import subprocess
from pathlib import Path

from .config import PipelineConfig
from .schemas import VerificationResult
from .utils import ensure_text, tail_text


class ExploitVerifier:
    def __init__(self, config: PipelineConfig) -> None:
        self.config = config

    def verify(
        self,
        binary_path: Path,
        exploit_path: Path,
        attempt: int,
        success_regex: list[str] | None = None,
    ) -> VerificationResult:
        patterns = [re.compile(p) for p in (success_regex or self.config.success_regex)]
        env = os.environ.copy()
        env["TARGET_BINARY"] = str(binary_path.resolve())
        _augment_runtime_library_path(env, binary_path)

        cmd = [
            self.config.python_executable,
            str(exploit_path.resolve()),
            str(binary_path.resolve()),
        ]
        timed_out = False
        stdout = ""
        stderr = ""
        exit_code = None
        sig = None
        try:
            runtime_cwd = _runtime_workdir_for_binary(binary_path)
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.config.verification_timeout_s,
                env=env,
                cwd=str(runtime_cwd),
            )
            stdout = ensure_text(proc.stdout)
            stderr = ensure_text(proc.stderr)
            exit_code = proc.returncode
            if exit_code is not None and exit_code < 0:
                sig = -exit_code
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            stdout = ensure_text(exc.stdout)
            stderr = ensure_text(exc.stderr) + "\n[timeout]"

        combined = f"{stdout}\n{stderr}"
        matched = any(p.search(combined) for p in patterns)
        status = "success" if matched else ("timeout" if timed_out else "failed")
        success_reason = (
            "Matched success regex in process output."
            if matched
            else ""
        )

        failure_reason = ""
        if not matched:
            if timed_out:
                failure_reason = "Exploit timed out."
            elif "ModuleNotFoundError: No module named 'pwn'" in combined:
                failure_reason = (
                    "Exploit requires pwntools, but pwntools is not installed. "
                    "Rewrite using Python standard library only."
                )
            elif "does not exist" in combined:
                failure_reason = (
                    "Exploit used the wrong binary path. Use argv[1] or --binary instead of "
                    "hardcoded relative paths."
                )
            elif exit_code is not None and exit_code < 0:
                try:
                    sig_name = signal.Signals(-exit_code).name
                except ValueError:
                    sig_name = str(-exit_code)
                failure_reason = f"Exploit crashed by signal {sig_name}."
            elif exit_code is not None:
                failure_reason = f"Exploit exited with code {exit_code} without success markers."
            else:
                failure_reason = "Exploit failed without explicit return code."

        stdout_tail = tail_text(stdout, 2500)
        stderr_tail = tail_text(stderr, 2500)
        feedback_payload = {
            "status": status,
            "exit_code": exit_code,
            "signal": sig,
            "timeout": timed_out,
            "stdout_tail": stdout_tail,
            "stderr_tail": stderr_tail,
            "failure_reason": failure_reason,
            "success_reason": success_reason,
        }

        return VerificationResult(
            attempt=attempt,
            status=status,
            stdout_tail=stdout_tail,
            stderr_tail=stderr_tail,
            exit_code=exit_code,
            signal=sig,
            timeout=timed_out,
            artifacts={},
            success_reason=success_reason,
            failure_reason=failure_reason,
            feedback_payload=feedback_payload,
        )


def _augment_runtime_library_path(env: dict[str, str], binary_path: Path) -> None:
    binary_dir = binary_path.resolve().parent
    candidate_dirs = [binary_dir]

    project_root = binary_dir.parent.parent
    download_subdir = project_root / "challenges" / "downloads" / binary_path.name.removeprefix("rop_")
    if download_subdir.exists():
        candidate_dirs.append(download_subdir)

    existing = env.get("LD_LIBRARY_PATH", "")
    pieces = [str(path) for path in candidate_dirs if path.exists()]
    if existing:
        pieces.append(existing)
    env["LD_LIBRARY_PATH"] = ":".join(pieces)


def _runtime_workdir_for_binary(binary_path: Path) -> Path:
    binary_dir = binary_path.resolve().parent
    project_root = binary_dir.parent.parent
    download_subdir = project_root / "challenges" / "downloads" / binary_path.name.removeprefix("rop_")
    if download_subdir.exists():
        return download_subdir
    return binary_dir
