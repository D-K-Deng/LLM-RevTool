from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .utils import ensure_text


ALLOWED_TOOLS = {
    "symbol_disasm",
    "gadget_search",
    "strings_search",
    "readelf_symbols",
    "readelf_sections",
    "readelf_relocs",
}

ALLOWED_COMMANDS = {
    "file_info",
    "ldd",
    "objdump_disasm",
    "ropgadget",
    "nm_symbols",
    "run_head",
    "run_with_stdin",
    "nearby_files",
}


def build_tool_catalog_text() -> str:
    return "\n".join(
        [
            "Available local read-only tools:",
            "- symbol_disasm(symbol): disassemble one named symbol/function from the binary",
            "- gadget_search(needle): search the full objdump disassembly for an instruction/gadget substring",
            "- strings_search(pattern): search extracted strings for a regex pattern",
            "- readelf_symbols(pattern): search symbol table / dynamic symbols for a regex pattern",
            "- readelf_sections(): dump ELF section headers",
            "- readelf_relocs(): dump ELF relocations / PLT-related relocation info",
            "Rules:",
            "- Request at most 3 tools per round",
            "- Use tools only when they can unlock missing concrete information",
            "- Do not request shell access, filesystem writes, networking, or arbitrary commands",
        ]
    )


def build_command_catalog_text() -> str:
    return "\n".join(
        [
            "Available local read-only commands:",
            "- file_info(): run `file <binary>`",
            "- ldd(): run `ldd <binary>`",
            "- objdump_disasm(): run `objdump -d -M intel <binary>`",
            "- ropgadget(binary_only=true): run `ROPgadget --binary <binary>` if installed",
            "- nm_symbols(): run `nm -C <binary>`",
            "- run_head(timeout=2): execute the binary briefly and capture initial stdout/stderr",
            "- run_with_stdin(input_text='', input_hex='', timeout=2): run once with provided stdin bytes",
            "- nearby_files(): list files near the binary and in the verifier runtime directory",
            "Rules:",
            "- Request at most 2 commands per round",
            "- Commands are allowlisted wrappers, not arbitrary shell",
            "- Use commands only when a higher-level tool is insufficient",
        ]
    )


def build_unsafe_command_catalog_text() -> str:
    return "\n".join(
        [
            "Unsafe shell mode is ENABLED.",
            "The model may request arbitrary local shell commands using:",
            '- shell(command): execute an arbitrary local shell command string',
            "Rules:",
            "- Prefer read-only inspection commands when possible",
            "- Use shell only when allowlisted tools/commands are insufficient",
            "- Returned output will be truncated and fed back into the next round",
        ]
    )


class LocalToolRunner:
    def __init__(self, max_requests_per_round: int = 3) -> None:
        self.max_requests_per_round = max_requests_per_round

    def run_requests(self, binary_path: Path, requests: list[dict] | None) -> list[dict]:
        results: list[dict] = []
        for request in (requests or [])[: self.max_requests_per_round]:
            tool_name = str(request.get("tool", "")).strip()
            args = request.get("args", {}) or {}
            if tool_name not in ALLOWED_TOOLS:
                results.append(
                    {
                        "tool": tool_name,
                        "status": "rejected",
                        "error": "tool is not in the allowlist",
                    }
                )
                continue
            try:
                output = self._dispatch(tool_name, binary_path, args)
                results.append(
                    {
                        "tool": tool_name,
                        "status": "ok",
                        "args": args,
                        "output": output,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "tool": tool_name,
                        "status": "error",
                        "args": args,
                        "error": str(exc),
                    }
                )
        return results

    def summarize_results(self, results: list[dict] | None) -> str:
        if not results:
            return "<no local tool results>"
        lines: list[str] = []
        for item in results:
            tool = item.get("tool", "<unknown>")
            status = item.get("status", "unknown")
            lines.append(f"TOOL {tool} [{status}]")
            if item.get("args"):
                lines.append(f"args: {item['args']}")
            if "output" in item:
                lines.append(str(item["output"]).strip() or "<empty output>")
            if "error" in item:
                lines.append(f"error: {item['error']}")
            lines.append("")
        return "\n".join(lines).strip()

    def _dispatch(self, tool_name: str, binary_path: Path, args: dict) -> str:
        if tool_name == "symbol_disasm":
            symbol = str(args.get("symbol", "")).strip()
            if not symbol:
                raise ValueError("symbol_disasm requires args.symbol")
            return self._symbol_disasm(binary_path, symbol)
        if tool_name == "gadget_search":
            needle = str(args.get("needle", "")).strip()
            if not needle:
                raise ValueError("gadget_search requires args.needle")
            return self._gadget_search(binary_path, needle)
        if tool_name == "strings_search":
            pattern = str(args.get("pattern", "")).strip()
            if not pattern:
                raise ValueError("strings_search requires args.pattern")
            return self._strings_search(binary_path, pattern)
        if tool_name == "readelf_symbols":
            pattern = str(args.get("pattern", "")).strip()
            if not pattern:
                raise ValueError("readelf_symbols requires args.pattern")
            return self._readelf_symbols(binary_path, pattern)
        if tool_name == "readelf_sections":
            return self._readelf_sections(binary_path)
        if tool_name == "readelf_relocs":
            return self._readelf_relocs(binary_path)
        raise ValueError(f"unsupported tool: {tool_name}")

    def _symbol_disasm(self, binary_path: Path, symbol: str) -> str:
        text = self._run_command(["objdump", "-d", "-M", "intel", str(binary_path)])
        pattern = rf"<{re.escape(symbol)}>:\n(?P<body>(?:.*\n){{0,80}})"
        match = re.search(pattern, text)
        if not match:
            raise RuntimeError(f"symbol not found in disassembly: {symbol}")
        body = match.group(0)
        return _truncate_text(body, 4000)

    def _gadget_search(self, binary_path: Path, needle: str) -> str:
        text = self._run_command(["objdump", "-d", "-M", "intel", str(binary_path)])
        lines = text.splitlines()
        normalized_needle = "".join(needle.lower().split())
        hits: list[str] = []
        for idx, line in enumerate(lines):
            normalized_line = "".join(line.lower().split())
            if normalized_needle in normalized_line:
                start = max(0, idx - 1)
                end = min(len(lines), idx + 2)
                hits.append("\n".join(lines[start:end]))
            if len(hits) >= 8:
                break
        if not hits:
            raise RuntimeError(f"gadget/instruction not found: {needle}")
        return _truncate_text("\n\n".join(hits), 4000)

    def _strings_search(self, binary_path: Path, pattern: str) -> str:
        text = self._run_command(["strings", "-a", str(binary_path)])
        regex = re.compile(pattern, re.IGNORECASE)
        hits = [line for line in text.splitlines() if regex.search(line)]
        if not hits:
            raise RuntimeError(f"no strings matched pattern: {pattern}")
        return _truncate_text("\n".join(hits[:80]), 4000)

    def _readelf_symbols(self, binary_path: Path, pattern: str) -> str:
        text = self._run_command(["readelf", "-Ws", str(binary_path)])
        regex = re.compile(pattern, re.IGNORECASE)
        hits = [line for line in text.splitlines() if regex.search(line)]
        if not hits:
            raise RuntimeError(f"no symbols matched pattern: {pattern}")
        return _truncate_text("\n".join(hits[:120]), 4000)

    def _readelf_sections(self, binary_path: Path) -> str:
        text = self._run_command(["readelf", "-S", str(binary_path)])
        return _truncate_text(text, 4000)

    def _readelf_relocs(self, binary_path: Path) -> str:
        text = self._run_command(["readelf", "-r", str(binary_path)])
        return _truncate_text(text, 4000)

    def _run_command(self, argv: list[str]) -> str:
        executable = argv[0]
        if shutil.which(executable) is None:
            raise RuntimeError(f"required tool is not installed: {executable}")
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            stderr = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(stderr or f"{executable} exited with code {proc.returncode}")
        return proc.stdout


def _truncate_text(text: str, limit: int) -> str:
    clean = text.strip()
    if len(clean) <= limit:
        return clean
    return clean[:limit] + "\n...[truncated]"


class LocalCommandRunner:
    def __init__(self, max_requests_per_round: int = 2, allow_unsafe: bool = False) -> None:
        self.max_requests_per_round = max_requests_per_round
        self.allow_unsafe = allow_unsafe

    def run_requests(self, binary_path: Path, requests: list[dict] | None) -> list[dict]:
        results: list[dict] = []
        for request in (requests or [])[: self.max_requests_per_round]:
            command_name = str(request.get("command", "")).strip()
            args = request.get("args", {}) or {}
            if command_name == "shell" and self.allow_unsafe:
                try:
                    output = self._shell_command(binary_path, args)
                    results.append(
                        {
                            "command": command_name,
                            "status": "ok",
                            "args": args,
                            "output": output,
                        }
                    )
                except Exception as exc:  # noqa: BLE001
                    results.append(
                        {
                            "command": command_name,
                            "status": "error",
                            "args": args,
                            "error": str(exc),
                        }
                    )
                continue
            if command_name not in ALLOWED_COMMANDS:
                results.append(
                    {
                        "command": command_name,
                        "status": "rejected",
                        "error": "command is not in the allowlist",
                    }
                )
                continue
            try:
                output = self._dispatch(command_name, binary_path, args)
                results.append(
                    {
                        "command": command_name,
                        "status": "ok",
                        "args": args,
                        "output": output,
                    }
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    {
                        "command": command_name,
                        "status": "error",
                        "args": args,
                        "error": str(exc),
                    }
                )
        return results

    def summarize_results(self, results: list[dict] | None) -> str:
        if not results:
            return "<no local command results>"
        lines: list[str] = []
        for item in results:
            command = item.get("command", "<unknown>")
            status = item.get("status", "unknown")
            lines.append(f"COMMAND {command} [{status}]")
            if item.get("args"):
                lines.append(f"args: {item['args']}")
            if "output" in item:
                lines.append(str(item["output"]).strip() or "<empty output>")
            if "error" in item:
                lines.append(f"error: {item['error']}")
            lines.append("")
        return "\n".join(lines).strip()

    def _dispatch(self, command_name: str, binary_path: Path, args: dict) -> str:
        if command_name == "file_info":
            return self._run_command(["file", str(binary_path)])
        if command_name == "ldd":
            return self._run_command(["ldd", str(binary_path)])
        if command_name == "objdump_disasm":
            return _truncate_text(self._run_command(["objdump", "-d", "-M", "intel", str(binary_path)]), 4000)
        if command_name == "ropgadget":
            return _truncate_text(self._run_command(["ROPgadget", "--binary", str(binary_path)]), 4000)
        if command_name == "nm_symbols":
            return _truncate_text(self._run_command(["nm", "-C", str(binary_path)]), 4000)
        if command_name == "run_head":
            timeout = int(args.get("timeout", 2) or 2)
            return self._run_head(binary_path, timeout)
        if command_name == "run_with_stdin":
            timeout = int(args.get("timeout", 2) or 2)
            input_text = str(args.get("input_text", ""))
            input_hex = str(args.get("input_hex", ""))
            return self._run_with_stdin(binary_path, timeout, input_text, input_hex)
        if command_name == "nearby_files":
            return self._nearby_files(binary_path)
        raise ValueError(f"unsupported command: {command_name}")

    def _run_head(self, binary_path: Path, timeout_s: int) -> str:
        runtime_cwd = _runtime_workdir_for_binary(binary_path)
        try:
            proc = subprocess.run(
                [str(binary_path)],
                capture_output=True,
                text=True,
                timeout=timeout_s,
                cwd=str(runtime_cwd),
                check=False,
            )
            combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
            return _truncate_text(combined.strip() or f"[exit_code={proc.returncode}]", 4000)
        except subprocess.TimeoutExpired as exc:
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            combined = ensure_text(stdout) + ("\n" + ensure_text(stderr) if stderr else "")
            combined = (combined.strip() + "\n[timeout]").strip()
            return _truncate_text(combined, 4000)

    def _run_with_stdin(
        self,
        binary_path: Path,
        timeout_s: int,
        input_text: str,
        input_hex: str,
    ) -> str:
        runtime_cwd = _runtime_workdir_for_binary(binary_path)
        if input_hex.strip():
            payload = bytes.fromhex(input_hex.strip())
        else:
            payload = input_text.encode()
        try:
            proc = subprocess.run(
                [str(binary_path)],
                input=payload,
                capture_output=True,
                timeout=timeout_s,
                cwd=str(runtime_cwd),
                check=False,
            )
            combined = ensure_text(proc.stdout) + ("\n" + ensure_text(proc.stderr) if proc.stderr else "")
            output = combined.strip() or f"[exit_code={proc.returncode}]"
            if proc.returncode != 0:
                output = f"[exit_code={proc.returncode}]\n{output}"
            return _truncate_text(output, 4000)
        except subprocess.TimeoutExpired as exc:
            stdout = ensure_text(exc.stdout)
            stderr = ensure_text(exc.stderr)
            combined = stdout + ("\n" + stderr if stderr else "")
            combined = (combined.strip() + "\n[timeout]").strip()
            return _truncate_text(combined, 4000)

    def _shell_command(self, binary_path: Path, args: dict) -> str:
        command = str(args.get("command", "")).strip()
        if not command:
            raise ValueError("shell command requires args.command")
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            shell=True,
            cwd=str(binary_path.parent),
        )
        combined = (proc.stdout or "") + ("\n" + proc.stderr if proc.stderr else "")
        if proc.returncode != 0:
            return _truncate_text(
                f"[exit_code={proc.returncode}]\n{combined.strip()}",
                4000,
            )
        return _truncate_text(combined.strip() or f"[exit_code={proc.returncode}]", 4000)

    def _nearby_files(self, binary_path: Path) -> str:
        binary_dir = binary_path.resolve().parent
        runtime_dir = _runtime_workdir_for_binary(binary_path)
        sections = [
            f"binary_dir: {binary_dir}",
            _list_dir(binary_dir),
        ]
        if runtime_dir != binary_dir:
            sections.extend(
                [
                    "",
                    f"runtime_dir: {runtime_dir}",
                    _list_dir(runtime_dir),
                ]
            )
        return _truncate_text("\n".join(sections), 4000)

    def _run_command(self, argv: list[str]) -> str:
        executable = argv[0]
        if shutil.which(executable) is None:
            raise RuntimeError(f"required command is not installed: {executable}")
        proc = subprocess.run(argv, capture_output=True, text=True, check=False)
        if proc.returncode != 0:
            stderr = (proc.stderr or proc.stdout or "").strip()
            raise RuntimeError(stderr or f"{executable} exited with code {proc.returncode}")
        return proc.stdout


def _runtime_workdir_for_binary(binary_path: Path) -> Path:
    binary_dir = binary_path.resolve().parent
    project_root = binary_dir.parent.parent
    download_subdir = project_root / "challenges" / "downloads" / binary_path.name.removeprefix("rop_")
    if download_subdir.exists():
        return download_subdir
    return binary_dir


def _list_dir(path: Path) -> str:
    if not path.exists():
        return "<missing>"
    entries = []
    for child in sorted(path.iterdir())[:80]:
        entries.append(child.name + ("/" if child.is_dir() else ""))
    return "\n".join(entries) if entries else "<empty>"
