from __future__ import annotations

import re
from pathlib import Path

from .helper_insights import build_helper_insights
from .schemas import AnalysisReport
from .utils import command_exists, run_command, utc_timestamp


SINK_KEYWORDS = [
    "gets",
    "strcpy",
    "strcat",
    "scanf",
    "fscanf",
    "read",
    "recv",
    "printf",
    "sprintf",
    "snprintf",
    "system",
    "%n",
]


class BinaryAnalyzer:
    def __init__(self, max_strings: int = 120, max_context_functions: int = 12) -> None:
        self.max_strings = max_strings
        self.max_context_functions = max_context_functions

    def analyze(self, binary_path: Path, prune: bool = True) -> AnalysisReport:
        binary_path = binary_path.resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        file_output = self._run_if_exists(["file", str(binary_path)])
        readelf_h = self._run_if_exists(["readelf", "-h", str(binary_path)])
        readelf_l = self._run_if_exists(["readelf", "-W", "-l", str(binary_path)])
        readelf_d = self._run_if_exists(["readelf", "-d", str(binary_path)])
        readelf_s = self._run_if_exists(["readelf", "-Ws", str(binary_path)])
        strings_output = self._run_if_exists(["strings", "-n", "4", str(binary_path)])
        objdump_output = self._run_if_exists(["objdump", "-d", "-M", "intel", str(binary_path)])
        nm_dyn = self._run_if_exists(["nm", "-D", "--defined-only", str(binary_path)])

        protections = {
            "pie": self._detect_pie(readelf_h.stdout, file_output.stdout),
            "nx": self._detect_nx(readelf_l.stdout),
            "canary": self._detect_canary(readelf_s.stdout, strings_output.stdout),
            "relro": self._detect_relro(readelf_l.stdout, readelf_d.stdout),
        }
        architecture = self._detect_arch(file_output.stdout, readelf_h.stdout)
        imports = self._extract_imports(readelf_s.stdout)
        exports = self._extract_exports(nm_dyn.stdout, readelf_s.stdout)
        interesting_strings = self._extract_strings(strings_output.stdout)
        entry_points = self._extract_entry_points(readelf_h.stdout, readelf_s.stdout)
        suspected_vulns = self._suspect_vulns(imports, interesting_strings, objdump_output.stdout)
        pruned_context = self._build_context(
            objdump_output.stdout, suspected_vulns, prune=prune
        )

        notes = []
        if objdump_output.returncode != 0:
            notes.append("objdump unavailable or failed; context may be incomplete.")
        if readelf_s.returncode != 0:
            notes.append("readelf symbol extraction failed; imports/exports may be incomplete.")
        helper_insights = build_helper_insights(
            binary_name=binary_path.name,
            architecture=architecture,
            imports=imports,
            exports=exports,
            interesting_strings=interesting_strings,
            pruned_context=pruned_context,
            protections=protections,
        )

        return AnalysisReport(
            binary_path=str(binary_path),
            binary_name=binary_path.name,
            timestamp=utc_timestamp(),
            architecture=architecture,
            protections=protections,
            imports=imports,
            exports=exports,
            interesting_strings=interesting_strings,
            entry_points=entry_points,
            suspected_vulns=suspected_vulns,
            pruned_context=pruned_context,
            helper_insights=helper_insights,
            notes=notes,
        )

    @staticmethod
    def _run_if_exists(cmd: list[str]):
        if not command_exists(cmd[0]):
            from .utils import CommandResult

            return CommandResult(cmd=cmd, returncode=127, stdout="", stderr="missing command")
        return run_command(cmd, timeout_s=60)

    @staticmethod
    def _detect_pie(readelf_h: str, file_output: str) -> bool | str:
        if "Type:                              DYN" in readelf_h:
            return True
        if "shared object" in file_output.lower():
            return True
        if "Type:                              EXEC" in readelf_h:
            return False
        return "unknown"

    @staticmethod
    def _detect_nx(readelf_l: str) -> bool | str:
        for line in readelf_l.splitlines():
            if "GNU_STACK" in line:
                if "RWE" in line:
                    return False
                return True
        return "unknown"

    @staticmethod
    def _detect_canary(readelf_s: str, strings_output: str) -> bool:
        return "__stack_chk_fail" in readelf_s or "__stack_chk_fail" in strings_output

    @staticmethod
    def _detect_relro(readelf_l: str, readelf_d: str) -> str:
        has_relro = "GNU_RELRO" in readelf_l
        bind_now = "BIND_NOW" in readelf_d
        if has_relro and bind_now:
            return "full"
        if has_relro:
            return "partial"
        return "none"

    @staticmethod
    def _detect_arch(file_output: str, readelf_h: str) -> str:
        if "x86-64" in file_output or "Advanced Micro Devices X86-64" in readelf_h:
            return "amd64"
        if "80386" in file_output or "Intel 80386" in readelf_h:
            return "i386"
        if "aarch64" in file_output.lower() or "AArch64" in readelf_h:
            return "aarch64"
        if "arm" in file_output.lower():
            return "arm"
        return "unknown"

    @staticmethod
    def _extract_imports(readelf_s: str) -> list[str]:
        imports: set[str] = set()
        for line in readelf_s.splitlines():
            if " UND " in line:
                parts = line.split()
                if parts:
                    imports.add(parts[-1].split("@")[0])
        return sorted(imports)

    @staticmethod
    def _extract_exports(nm_output: str, readelf_s: str) -> list[str]:
        exports: set[str] = set()
        for line in nm_output.splitlines():
            pieces = line.strip().split()
            if len(pieces) >= 3:
                exports.add(pieces[-1])
        if not exports:
            for line in readelf_s.splitlines():
                if " FUNC " in line and " UND " not in line:
                    parts = line.split()
                    if parts:
                        exports.add(parts[-1].split("@")[0])
        return sorted(exports)

    def _extract_strings(self, strings_output: str) -> list[str]:
        candidates = []
        for s in strings_output.splitlines():
            s = s.strip()
            if len(s) < 4:
                continue
            if any(k in s.lower() for k in ("flag", "win", "secret", "%", "input", "name")):
                candidates.append(s)
        if len(candidates) < self.max_strings:
            for s in strings_output.splitlines():
                s = s.strip()
                if len(s) >= 4 and s not in candidates:
                    candidates.append(s)
                if len(candidates) >= self.max_strings:
                    break
        return candidates[: self.max_strings]

    @staticmethod
    def _extract_entry_points(readelf_h: str, readelf_s: str) -> dict:
        entry = ""
        m = re.search(r"Entry point address:\s+([0-9a-fx]+)", readelf_h)
        if m:
            entry = m.group(1)
        mains = []
        input_funcs = []
        for line in readelf_s.splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[-1].split("@")[0]
            if name in {"main", "_start", "start"}:
                mains.append(name)
            if name in {"gets", "scanf", "fgets", "read", "recv"}:
                input_funcs.append(name)
        return {
            "entry_address": entry,
            "main_candidates": sorted(set(mains)),
            "input_functions": sorted(set(input_funcs)),
        }

    def _suspect_vulns(
        self, imports: list[str], interesting_strings: list[str], objdump_output: str
    ) -> list[dict[str, str]]:
        findings: list[dict[str, str]] = []
        for imp in imports:
            if imp in {"gets", "strcpy", "strcat", "sprintf"}:
                findings.append(
                    {
                        "function": imp,
                        "type": "unsafe_sink",
                        "evidence": f"imported function {imp} often leads to memory corruption.",
                    }
                )
            if imp in {"printf", "fprintf", "dprintf"}:
                findings.append(
                    {
                        "function": imp,
                        "type": "format_string_candidate",
                        "evidence": "printf-like sink imported; verify user-controlled format paths.",
                    }
                )

        for s in interesting_strings:
            lower = s.lower()
            if "flag{" in lower or "you win" in lower or lower == "win":
                findings.append(
                    {
                        "function": "unknown",
                        "type": "win_marker",
                        "evidence": f"binary string suggests success marker: {s[:80]}",
                    }
                )
            if "%n" in s:
                findings.append(
                    {
                        "function": "unknown",
                        "type": "format_write_hint",
                        "evidence": "found %n-like token in strings",
                    }
                )

        for fn in self._extract_function_names(objdump_output):
            low = fn.lower()
            if any(k in low for k in ("win", "flag", "secret", "shell")):
                findings.append(
                    {
                        "function": fn,
                        "type": "interesting_function",
                        "evidence": "function name suggests privileged path",
                    }
                )
        return findings

    @staticmethod
    def _extract_function_names(objdump_output: str) -> list[str]:
        names = []
        pat = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:$")
        for line in objdump_output.splitlines():
            m = pat.match(line.strip())
            if m:
                names.append(m.group(1))
        return names

    def _build_context(
        self, objdump_output: str, suspected_vulns: list[dict[str, str]], prune: bool
    ) -> list[dict[str, str]]:
        if not objdump_output.strip():
            return []
        functions = self._split_disassembly_by_function(objdump_output)
        if not prune:
            picked = list(functions.items())[: self.max_context_functions]
            return [
                {"function": name, "reason": "no_pruning", "snippet": "\n".join(lines[:120])}
                for name, lines in picked
            ]

        suspect_names = {f["function"] for f in suspected_vulns if f["function"] != "unknown"}
        selected: list[tuple[str, list[str], str]] = []

        for name, lines in functions.items():
            low = name.lower()
            reason = None
            if name in suspect_names:
                reason = "from_suspected_vulns"
            elif any(k in low for k in ("main", "win", "vuln", "input", "secret")):
                reason = "name_hint"
            elif any(k in "\n".join(lines).lower() for k in SINK_KEYWORDS):
                reason = "sink_pattern"
            if reason:
                selected.append((name, lines, reason))
            if len(selected) >= self.max_context_functions:
                break

        if not selected:
            fallback = list(functions.items())[: min(4, len(functions))]
            selected = [(name, lines, "fallback_head") for name, lines in fallback]

        context = []
        for name, lines, reason in selected:
            context.append(
                {
                    "function": name,
                    "reason": reason,
                    "snippet": "\n".join(lines[:120]),
                }
            )
        return context

    @staticmethod
    def _split_disassembly_by_function(objdump_output: str) -> dict[str, list[str]]:
        functions: dict[str, list[str]] = {}
        cur_name = None
        cur_lines: list[str] = []
        pat = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:$")
        for line in objdump_output.splitlines():
            m = pat.match(line.strip())
            if m:
                if cur_name is not None:
                    functions[cur_name] = cur_lines
                cur_name = m.group(1)
                cur_lines = [line]
                continue
            if cur_name is not None:
                cur_lines.append(line)
        if cur_name is not None:
            functions[cur_name] = cur_lines
        return functions
