from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class AnalysisReport:
    binary_path: str
    binary_name: str
    timestamp: str
    architecture: str
    protections: dict[str, Any]
    imports: list[str] = field(default_factory=list)
    exports: list[str] = field(default_factory=list)
    interesting_strings: list[str] = field(default_factory=list)
    entry_points: dict[str, Any] = field(default_factory=dict)
    suspected_vulns: list[dict[str, str]] = field(default_factory=list)
    pruned_context: list[dict[str, str]] = field(default_factory=list)
    helper_insights: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class GenerationResult:
    strategy: str
    code: str
    success_conditions: str
    raw_text: str
    used_format_repair: bool = False
    reflection_summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    attempt: int
    status: str
    stdout_tail: str
    stderr_tail: str
    exit_code: int | None
    signal: int | None
    timeout: bool
    artifacts: dict[str, str]
    success_reason: str
    failure_reason: str
    feedback_payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
