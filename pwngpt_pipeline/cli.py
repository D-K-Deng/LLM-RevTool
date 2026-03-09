from __future__ import annotations

import argparse
import json
from pathlib import Path

from .analysis import BinaryAnalyzer
from .config import PipelineConfig
from .evaluation import run_evaluation
from .orchestrator import SolveOrchestrator
from .utils import ensure_dir, write_json


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Local PwnGPT-style AEG pipeline")
    parser.add_argument("--provider", default=None, help="LLM provider override")
    parser.add_argument("--api-key", default=None, help="Gemini API key override")
    parser.add_argument("--model", default=None, help="Gemini model override")
    parser.add_argument("--base-url", default=None, help="OpenAI-compatible base URL override")
    parser.add_argument(
        "--openai-api-key",
        default=None,
        help="OpenAI-compatible API key override",
    )
    parser.add_argument(
        "--openai-model",
        default=None,
        help="OpenAI-compatible model override",
    )
    parser.add_argument("--artifact-root", default=None, help="Artifacts root directory")
    parser.add_argument("--max-retries", type=int, default=None, help="Gemini max retries")
    parser.add_argument(
        "--max-iterations", type=int, default=None, help="Max solve iterations per binary"
    )
    parser.add_argument(
        "--verification-timeout",
        type=int,
        default=None,
        help="Timeout seconds for each exploit attempt",
    )
    parser.add_argument(
        "--relaxed-output",
        action="store_true",
        help="Relax parser constraints (for ablation).",
    )
    parser.add_argument(
        "--no-pruning",
        action="store_true",
        help="Disable context pruning (for ablation).",
    )
    parser.add_argument(
        "--prompt-template",
        type=Path,
        default=Path("prompts/generation_prompt.txt"),
        help="Prompt template path.",
    )

    sub = parser.add_subparsers(dest="command", required=True)

    analyze = sub.add_parser("analyze", help="Analyze a binary and emit AnalysisReport.json")
    analyze.add_argument("--binary", required=True, type=Path, help="Path to ELF binary")
    analyze.add_argument("--out", type=Path, default=Path("artifacts/AnalysisReport.json"))

    solve = sub.add_parser("solve", help="Run full iterative solve loop")
    solve.add_argument("--binary", required=True, type=Path, help="Path to ELF binary")
    solve.add_argument(
        "--success-regex",
        action="append",
        default=None,
        help="Custom success regex. Repeatable.",
    )

    eval_parser = sub.add_parser("eval", help="Batch evaluate challenges from manifest")
    eval_parser.add_argument("--manifest", required=True, type=Path, help="Manifest JSON path")

    return parser


def build_config(args: argparse.Namespace) -> PipelineConfig:
    cfg = PipelineConfig.from_env()
    artifact_root = Path(args.artifact_root) if args.artifact_root else None
    cfg.with_overrides(
        llm_provider=args.provider,
        gemini_api_key=args.api_key,
        gemini_model=args.model,
        openai_compat_base_url=args.base_url,
        openai_compat_api_key=args.openai_api_key,
        openai_compat_model=args.openai_model,
        max_iterations=args.max_iterations,
        max_retries=args.max_retries,
        strict_output=not args.relaxed_output,
        enable_pruning=not args.no_pruning,
        artifact_root=artifact_root,
        verification_timeout_s=args.verification_timeout,
    )
    ensure_dir(cfg.artifact_root)
    return cfg


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    cfg = build_config(args)

    if args.command == "analyze":
        analyzer = BinaryAnalyzer()
        report = analyzer.analyze(args.binary, prune=cfg.enable_pruning)
        write_json(args.out, report.to_dict())
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False))
        return 0

    if args.command == "solve":
        orchestrator = SolveOrchestrator(cfg, prompt_template_path=args.prompt_template)
        result = orchestrator.solve(
            binary_path=args.binary,
            success_regex=args.success_regex,
            max_iterations=cfg.max_iterations,
            strict_output=cfg.strict_output,
            enable_pruning=cfg.enable_pruning,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    if args.command == "eval":
        result = run_evaluation(
            config=cfg,
            manifest_path=args.manifest,
            max_iterations=cfg.max_iterations,
            strict_output=cfg.strict_output,
            enable_pruning=cfg.enable_pruning,
            prompt_template_path=args.prompt_template,
        )
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
