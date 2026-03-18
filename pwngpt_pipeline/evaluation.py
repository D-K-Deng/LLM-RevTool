from __future__ import annotations

import csv
from pathlib import Path
from statistics import mean, median

from .config import PipelineConfig
from .orchestrator import SolveOrchestrator
from .utils import ensure_dir, ensure_executable, load_json, utc_timestamp, write_json


def run_evaluation(
    config: PipelineConfig,
    manifest_path: Path,
    max_iterations: int | None = None,
    strict_output: bool | None = None,
    enable_pruning: bool | None = None,
    prompt_template_path: Path | None = None,
) -> dict:
    manifest = load_json(manifest_path)
    challenges = manifest.get("challenges", [])
    if not challenges:
        raise ValueError(f"No challenges found in manifest: {manifest_path}")

    orchestrator = SolveOrchestrator(config, prompt_template_path=prompt_template_path)
    eval_dir = config.artifact_root / f"eval_{utc_timestamp().replace(':', '-')}"
    ensure_dir(eval_dir)

    rows = []
    for item in challenges:
        name = item["name"]
        binary = _resolve_manifest_binary_path(Path(item["binary"]), manifest_path)
        ensure_executable(binary)
        success_regex = item.get("success_regex")
        print(f"[eval] solving {name}", flush=True)

        summary = orchestrator.solve(
            binary_path=binary,
            success_regex=success_regex,
            max_iterations=max_iterations,
            strict_output=strict_output,
            enable_pruning=enable_pruning,
        )
        row = {
            "name": name,
            "binary": str(binary),
            "solved": summary["solved"],
            "success_attempt": summary["success_attempt"]
            if summary["success_attempt"] is not None
            else -1,
            "attempts_used": summary["attempts_used"],
            "elapsed_seconds": summary["elapsed_seconds"],
            "run_dir": summary["run_dir"],
            "last_error": summary["last_error"],
        }
        rows.append(row)
        status = "SOLVED" if row["solved"] else "FAILED"
        print(
            f"[eval] {name}: {status} "
            f"(attempts={row['attempts_used']}, success_attempt={row['success_attempt']})",
            flush=True,
        )

    solved_count = sum(1 for r in rows if r["solved"])
    attempts_for_success = [
        r["success_attempt"] for r in rows if r["solved"] and r["success_attempt"] >= 0
    ]
    summary_payload = {
        "manifest_path": str(manifest_path),
        "eval_dir": str(eval_dir.resolve()),
        "total": len(rows),
        "solved": solved_count,
        "success_rate": solved_count / len(rows) if rows else 0.0,
        "attempts_to_success_mean": round(mean(attempts_for_success), 3)
        if attempts_for_success
        else None,
        "attempts_to_success_median": median(attempts_for_success)
        if attempts_for_success
        else None,
        "rows": rows,
    }
    print(
        f"[eval] done: solved {solved_count}/{len(rows)} "
        f"(success_rate={summary_payload['success_rate']:.3f})",
        flush=True,
    )

    write_json(eval_dir / "evaluation_summary.json", summary_payload)
    _write_csv(eval_dir / "evaluation_results.csv", rows)
    return summary_payload


def _write_csv(path: Path, rows: list[dict]) -> None:
    ensure_dir(path.parent)
    fieldnames = [
        "name",
        "binary",
        "solved",
        "success_attempt",
        "attempts_used",
        "elapsed_seconds",
        "run_dir",
        "last_error",
    ]
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)


def _resolve_manifest_binary_path(binary: Path, manifest_path: Path) -> Path:
    if binary.is_absolute():
        return binary.resolve()

    cwd_candidate = (Path.cwd() / binary).resolve()
    if cwd_candidate.exists():
        return cwd_candidate

    manifest_candidate = (manifest_path.parent / binary).resolve()
    if manifest_candidate.exists():
        return manifest_candidate

    # Fall back to cwd-relative resolution so the eventual error message is easy to read.
    return cwd_candidate
