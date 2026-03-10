from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str
    stderr: str


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


def command_exists(command: str) -> bool:
    return shutil.which(command) is not None


def run_command(
    cmd: Sequence[str],
    timeout_s: int = 30,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
) -> CommandResult:
    proc = subprocess.run(
        list(cmd),
        capture_output=True,
        text=True,
        timeout=timeout_s,
        cwd=str(cwd) if cwd else None,
        env=env if env is not None else os.environ.copy(),
    )
    return CommandResult(
        cmd=list(cmd),
        returncode=proc.returncode,
        stdout=proc.stdout,
        stderr=proc.stderr,
    )


def write_json(path: Path, payload: dict) -> None:
    ensure_dir(path.parent)
    path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False, default=_json_default),
        encoding="utf-8",
    )


def load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def tail_text(text: str | bytes, max_chars: int = 2000) -> str:
    text = ensure_text(text)
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def sanitize_filename(text: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in ("-", "_") else "_" for ch in text)
    return safe.strip("_") or "item"


def ensure_executable(path: Path) -> bool:
    """
    Ensure user-executable bit on POSIX systems.
    Returns True if mode was changed, else False.
    """
    if os.name == "nt":
        return False
    if not path.exists() or not path.is_file():
        return False
    mode = path.stat().st_mode
    if mode & stat.S_IXUSR:
        return False
    path.chmod(mode | stat.S_IXUSR)
    return True


def ensure_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def _json_default(obj):
    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")
    raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")
