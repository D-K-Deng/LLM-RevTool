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
        "recommended_methods": recommended_methods_for_class(challenge_class),
        "prompt_warnings": prompt_warnings_for_class(challenge_class, protections),
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
            "write flag.txt into writable memory, then call print_file(pointer)",
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
