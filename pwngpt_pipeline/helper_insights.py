from __future__ import annotations

import re
from typing import Any


def build_helper_insights(
    binary_name: str,
    architecture: str,
    imports: list[str],
    exports: list[str],
    interesting_strings: list[str],
    pruned_context: list[dict[str, str]],
    protections: dict[str, Any],
) -> dict[str, Any]:
    context_blob = "\n".join(item.get("snippet", "") for item in pruned_context)
    strings_blob = "\n".join(interesting_strings)
    challenge_class = classify_challenge(
        binary_name=binary_name,
        imports=imports,
        exports=exports,
        strings_blob=strings_blob,
        context_blob=context_blob,
    )

    return {
        "challenge_class": challenge_class,
        "challenge_family": challenge_family_for_class(challenge_class),
        "recommended_methods": recommended_methods_for_class(challenge_class),
        "prompt_warnings": prompt_warnings_for_class(challenge_class, protections),
        "recommended_local_tools": recommended_tools_for_class(challenge_class),
        "recommended_preruns": recommended_preruns_for_class(challenge_class),
        "runtime_hints": runtime_hints_for_class(challenge_class, interesting_strings, exports),
        "completion_requirements": completion_requirements_for_class(challenge_class),
        "bootstrap_bundle": bootstrap_bundle_for_class(challenge_class),
        "candidate_inputs": extract_candidate_inputs(interesting_strings),
        "candidate_offsets": candidate_offsets_for_class(challenge_class, architecture, strings_blob),
        "candidate_symbols": extract_candidate_symbols(exports, pruned_context),
        "success_markers": extract_success_markers(interesting_strings),
    }


def classify_challenge(
    binary_name: str,
    imports: list[str],
    exports: list[str],
    strings_blob: str,
    context_blob: str,
) -> str:
    lower_name = binary_name.lower()
    lower_strings = strings_blob.lower()
    lower_context = context_blob.lower()
    export_set = {e.lower() for e in exports}
    import_set = {i.lower() for i in imports}

    if lower_name == "rop_ret2win" or "ret2win" in export_set:
        return "ret2win"
    if lower_name == "rop_split" or ("/bin/cat flag.txt" in lower_strings and "system" in import_set):
        return "split"
    if lower_name == "rop_callme" or {"callme_one", "callme_two", "callme_three"} <= export_set:
        return "callme"
    if lower_name == "rop_write4" or ("print_file" in export_set and "mov qword ptr [r14],r15" in lower_context):
        return "write4"
    if lower_name == "rop_badchars" or ("print_file" in export_set and "xor    byte ptr [r15],r14b" in lower_context):
        return "badchars"
    if lower_name == "rop_fluff":
        return "fluff"
    if lower_name == "rop_pivot":
        return "pivot"
    if lower_name == "rop_ret2csu":
        return "ret2csu"
    if "say the course code:" in lower_strings or "strcmp@plt" in lower_context:
        return "branch_input"
    if "printf" in import_set and "%n" in lower_strings:
        return "format_string"
    if "gets" in import_set or ("stack buffer" in lower_strings and "read()" in lower_strings):
        return "stack_overflow"
    return "unknown"


def recommended_methods_for_class(challenge_class: str) -> list[str]:
    mapping = {
        "branch_input": [
            "extract concrete secret/input from strings or disassembly",
            "run target locally and send exact bytes including newline if needed",
        ],
        "ret2win": [
            "find win/ret2win symbol",
            "determine offset to saved RIP",
            "try payloads with and without a stack-alignment ret gadget",
        ],
        "split": [
            "locate /bin/cat flag.txt string in the binary",
            "call system with pop rdi; ret on amd64",
            "consider an extra ret for stack alignment",
        ],
        "callme": [
            "build a ROP chain that calls callme_one, callme_two, callme_three in order",
            "use the expected 64-bit constants exactly",
            "ensure any required shared library path is available at runtime",
        ],
        "write4": [
            "write flag.txt into writable memory using write-what-where gadgets",
            "then call print_file(pointer)",
            "fall back to objdump-derived gadget addresses if gadget auto-detection fails",
        ],
        "badchars": [
            "write an encoded string into writable memory",
            "decode it in place using xor gadgets byte-by-byte",
            "then call print_file(pointer)",
        ],
        "fluff": [
            "this is a constrained write-what-where ROP task; use pwntools and inspect useful gadgets/functions first",
            "recover how to load controlled values into registers from useful gadgets or helper functions",
            "write flag.txt into writable memory byte-by-byte using the constrained gadget sequence, then call print_file(pointer)",
        ],
        "pivot": [
            "this is a stack pivot challenge; use pwntools and inspect foothold_function, ret2win, and pivot gadgets",
            "build a small first-stage chain on the stack that pivots into attacker-controlled heap memory",
            "use the leaked pivot address from process output and resolve ret2win via foothold_function/GOT mechanics",
        ],
        "ret2csu": [
            "this is a ret2csu challenge; use pwntools and inspect __libc_csu_init gadgets",
            "find the two CSU gadgets that control rbx/rbp/r12/r13/r14/r15 and perform the indirect call",
            "use the CSU sequence to set up arguments and call the target function deterministically",
            "do not assume ret2win lives in the PLT; prefer the real main-binary symbol and the exact 64-bit constants expected by the challenge family",
        ],
        "format_string": [
            "identify whether you need a leak, write, or both",
            "prefer deterministic payloads over blind guessing",
        ],
        "stack_overflow": [
            "determine exact offset to saved return address",
            "check for PIE and canary before assuming a direct ret overwrite works",
        ],
    }
    return mapping.get(challenge_class, ["derive a concrete exploit from the analysis report and runtime feedback"])


def challenge_family_for_class(challenge_class: str) -> str:
    mapping = {
        "branch_input": "direct_input_validation",
        "ret2win": "simple_control_hijack",
        "split": "simple_rop_argument_call",
        "callme": "multi_call_rop",
        "write4": "write_what_where_rop",
        "badchars": "encoded_write_then_decode_rop",
        "fluff": "constrained_gadget_rop",
        "pivot": "stack_pivot_and_dynamic_resolution",
        "ret2csu": "csu_dispatch_rop",
        "format_string": "format_string",
        "stack_overflow": "generic_memory_corruption",
    }
    return mapping.get(challenge_class, "unknown")


def recommended_tools_for_class(challenge_class: str) -> list[str]:
    mapping = {
        "branch_input": [
            "strings_search",
            "run_head",
            "run_with_stdin",
        ],
        "ret2win": [
            "readelf_symbols",
            "gadget_search(pop rdi / ret / leave / ret as needed)",
            "run_head",
        ],
        "split": [
            "strings_search(/bin/cat|flag)",
            "readelf_symbols(print_file|system|main)",
            "gadget_search(pop rdi)",
        ],
        "callme": [
            "readelf_symbols(callme_one|callme_two|callme_three|useful)",
            "gadget_search(pop rdi|pop rsi|pop rdx)",
            "nearby_files",
        ],
        "write4": [
            "readelf_sections",
            "gadget_search(mov qword ptr [...], ...)",
            "readelf_symbols(print_file|useful)",
        ],
        "badchars": [
            "readelf_sections",
            "gadget_search(xor byte ptr [...])",
            "gadget_search(mov qword ptr [...], ...)",
        ],
        "fluff": [
            "readelf_sections",
            "readelf_symbols(useful|print_file)",
            "gadget_search(xlat|bextr|stos)",
        ],
        "pivot": [
            "readelf_symbols(foothold|ret2win|useful|main)",
            "readelf_relocs",
            "gadget_search(xchg rsp,rax|pop rax)",
            "nearby_files",
        ],
        "ret2csu": [
            "symbol_disasm(__libc_csu_init)",
            "gadget_search(call qword ptr [r12+rbx*8])",
            "readelf_symbols(ret2win|win|callme|system)",
        ],
        "format_string": [
            "strings_search(%p|%n|%s)",
            "readelf_symbols(printf|puts|system)",
            "run_head",
        ],
        "stack_overflow": [
            "readelf_symbols(main|win|system)",
            "run_head",
            "nearby_files",
        ],
    }
    return mapping.get(challenge_class, ["readelf_symbols", "readelf_sections", "run_head"])


def recommended_preruns_for_class(challenge_class: str) -> list[str]:
    mapping = {
        "direct_input_validation": [],
        "branch_input": [
            "capture initial prompt with run_head",
            "try exact candidate strings only after extracting them from strings/disassembly",
        ],
        "pivot": [
            "capture the leaked pivot address from initial output",
            "list runtime directory files before assuming helper libraries live next to the binary",
        ],
        "ret2csu": [
            "inspect __libc_csu_init before building the chain",
        ],
        "fluff": [
            "inspect useful gadgets before choosing a constrained-write strategy",
        ],
    }
    return mapping.get(challenge_class, ["capture startup output before guessing interaction"])


def runtime_hints_for_class(
    challenge_class: str,
    interesting_strings: list[str],
    exports: list[str],
) -> list[str]:
    hints = []
    export_set = {item.lower() for item in exports}
    strings_blob = "\n".join(interesting_strings).lower()
    if ".so" in strings_blob or "foothold" in export_set or challenge_class in {"pivot", "callme"}:
        hints.append("This challenge may depend on sidecar shared libraries or helper files in the runtime directory.")
    if "flag.txt" in strings_blob or "print_file" in export_set:
        hints.append("Look for flag.txt or print_file-related file access; the target may expect a runtime cwd with helper files.")
    if challenge_class in {"pivot", "ret2csu"}:
        hints.append("Do not guess gadgets from memory; inspect useful gadgets / __libc_csu_init / relocations first.")
    return hints


def bootstrap_bundle_for_class(challenge_class: str) -> dict[str, list[dict[str, object]]]:
    base_tools = [
        {"tool": "readelf_sections", "args": {}},
        {"tool": "readelf_relocs", "args": {}},
        {"tool": "readelf_symbols", "args": {"pattern": "main|win|ret|foothold|print_file|system|call|pivot|useful|csu"}},
    ]
    base_commands = [
        {"command": "file_info", "args": {}},
        {"command": "nearby_files", "args": {}},
        {"command": "ldd", "args": {}},
        {"command": "run_head", "args": {"timeout": 2}},
    ]
    extras: dict[str, list[dict[str, object]]] = {"tool_requests": [], "command_requests": []}

    if challenge_class == "pivot":
        extras["tool_requests"] = [
            {"tool": "gadget_search", "args": {"needle": "xchg rsp,rax"}},
            {"tool": "gadget_search", "args": {"needle": "pop rax"}},
            {"tool": "readelf_symbols", "args": {"pattern": "foothold|ret2win|useful|main"}},
        ]
    elif challenge_class == "ret2csu":
        extras["tool_requests"] = [
            {"tool": "symbol_disasm", "args": {"symbol": "__libc_csu_init"}},
            {"tool": "gadget_search", "args": {"needle": "call qword ptr [r12+rbx*8]"}},
            {"tool": "readelf_symbols", "args": {"pattern": "ret2win|win|system|call"}},
        ]
    elif challenge_class == "fluff":
        extras["tool_requests"] = [
            {"tool": "gadget_search", "args": {"needle": "xlat"}},
            {"tool": "gadget_search", "args": {"needle": "bextr"}},
            {"tool": "gadget_search", "args": {"needle": "stos"}},
        ]
    elif challenge_class in {"write4", "badchars"}:
        extras["tool_requests"] = [
            {"tool": "gadget_search", "args": {"needle": "mov qword ptr"}},
            {"tool": "gadget_search", "args": {"needle": "xor byte ptr"}},
            {"tool": "readelf_symbols", "args": {"pattern": "print_file|useful"}},
        ]

    return {
        "tool_requests": base_tools + extras["tool_requests"],
        "command_requests": base_commands + extras["command_requests"],
    }


def completion_requirements_for_class(challenge_class: str) -> list[str]:
    mapping = {
        "pivot": [
            "use the leaked pivot address from startup output",
            "send a first-stage chain that pivots execution into attacker-controlled memory",
            "resolve ret2win through foothold_function / libpivot rather than assuming ret2win is in the main binary",
            "send the later-stage payload(s) needed to actually call ret2win",
            "print final process output after the last stage",
        ],
        "ret2csu": [
            "identify and use the two __libc_csu_init gadgets",
            "set up the indirect call arguments through the CSU sequence",
            "use the exact 64-bit constants required by the challenge family and call the real ret2win symbol, not ret2win@plt",
            "print final process output after the target call",
        ],
        "fluff": [
            "build the constrained write primitive with xlat/bextr/stos or equivalent helper gadgets",
            "write flag.txt into writable memory",
            "call print_file(pointer_to_flag)",
            "print final process output",
        ],
    }
    return mapping.get(challenge_class, [])


def prompt_warnings_for_class(challenge_class: str, protections: dict[str, Any]) -> list[str]:
    warnings = []
    if protections.get("pie") is True:
        warnings.append("PIE is enabled; avoid hardcoding absolute code addresses unless you have a leak or non-PIE evidence.")
    if protections.get("canary") is True:
        warnings.append("Stack canary is enabled; simple stack smashing may fail unless the challenge design clearly bypasses it.")
    if challenge_class in {"ret2win", "split", "callme", "write4", "badchars", "fluff", "pivot", "ret2csu"}:
        warnings.append("This is a ROP-style challenge; a mere input string is not enough.")
    if challenge_class == "branch_input":
        warnings.append("This is likely not a memory-corruption exploit; send the exact expected input instead of crafting a payload.")
    return warnings


def extract_candidate_inputs(strings: list[str]) -> list[str]:
    candidates = []
    for item in strings:
        if re.fullmatch(r"[A-Za-z0-9_{}./-]{4,64}", item):
            if item.startswith("GLIBC_") or item.startswith("__"):
                continue
            if "/lib" in item or "/usr/" in item:
                continue
            candidates.append(item)
    return candidates[:20]


def candidate_offsets_for_class(challenge_class: str, architecture: str, strings_blob: str) -> list[int]:
    if architecture == "amd64" and challenge_class in {"ret2win", "split", "callme", "write4", "badchars", "fluff", "pivot", "ret2csu"}:
        return [40, 32, 44, 48, 56]
    if challenge_class == "stack_overflow":
        return [40, 64, 72, 80]
    if "56 bytes of user input into 32 bytes" in strings_blob:
        return [40]
    return []


def extract_candidate_symbols(exports: list[str], pruned_context: list[dict[str, str]]) -> list[str]:
    candidates = []
    for symbol in exports:
        low = symbol.lower()
        if any(token in low for token in ("win", "ret2win", "print_file", "callme", "system", "useful", "foothold", "csu")):
            candidates.append(symbol)
    if candidates:
        return sorted(set(candidates))

    context_blob = "\n".join(item.get("snippet", "") for item in pruned_context)
    for match in re.findall(r"<([^>]+)>:", context_blob):
        low = match.lower()
        if any(token in low for token in ("win", "ret2win", "print_file", "callme", "system", "useful", "foothold", "csu")):
            candidates.append(match)
    return sorted(set(candidates))


def extract_success_markers(strings: list[str]) -> list[str]:
    markers = []
    for item in strings:
        if any(token in item for token in ("WIN", "FLAG{", "ROPE{", "Well done!", "flag.txt")):
            markers.append(item)
    return markers[:10]
