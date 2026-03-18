from __future__ import annotations

import os
import platform
import shlex
import subprocess
import sys
from pathlib import Path


PATH_FLAGS = {"--binary", "--manifest", "--artifact-root", "--prompt-template", "--out"}


def main() -> int:
    argv = _expand_shortcuts(sys.argv[1:])
    if platform.system().lower() != "windows":
        from .cli import main as cli_main

        sys.argv = ["llmrev", *argv]
        return cli_main()

    repo_root = Path(__file__).resolve().parents[1]
    repo_root_wsl = _to_wsl_path(str(repo_root))
    translated_args = _translate_args_for_wsl(argv)
    cmd = " ".join(shlex.quote(arg) for arg in translated_args)
    script = f"cd {shlex.quote(repo_root_wsl)} && python3 -m pwngpt_pipeline.cli {cmd}".strip()
    completed = subprocess.run(["wsl", "bash", "-lc", script], check=False)
    return completed.returncode


def _expand_shortcuts(argv: list[str]) -> list[str]:
    if len(argv) >= 3 and argv[0].isdigit() and argv[1].isdigit():
        max_iterations, max_inner_rounds, target = argv[0], argv[1], argv[2]
        tail = argv[3:]
        if target.lower().endswith(".json"):
            return [
                "--max-iterations",
                max_iterations,
                "--max-inner-rounds",
                max_inner_rounds,
                "eval",
                "--manifest",
                target,
                *tail,
            ]
        return [
            "--max-iterations",
            max_iterations,
            "--max-inner-rounds",
            max_inner_rounds,
            "solve",
            "--binary",
            target,
            *tail,
        ]
    return argv


def _translate_args_for_wsl(argv: list[str]) -> list[str]:
    translated: list[str] = []
    expect_path = False
    for arg in argv:
        if expect_path:
            translated.append(_translate_path_arg(arg))
            expect_path = False
            continue
        translated.append(arg)
        if arg in PATH_FLAGS:
            expect_path = True
    return translated


def _translate_path_arg(arg: str) -> str:
    path = Path(arg)
    if path.is_absolute():
        return _to_wsl_path(str(path))
    return arg.replace("\\", "/")


def _to_wsl_path(path: str) -> str:
    completed = subprocess.run(
        ["wsl", "wslpath", "-a", path],
        check=True,
        capture_output=True,
        text=True,
        env={**os.environ, "WSL_UTF8": "1"},
    )
    return completed.stdout.strip()


if __name__ == "__main__":
    raise SystemExit(main())
