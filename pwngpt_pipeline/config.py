from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class PipelineConfig:
    llm_provider: str = "gemini"
    reflection_llm_provider: str = ""
    gemini_api_key: str = ""
    gemini_model: str = "gemini-3.1-pro"
    reflection_gemini_model: str = ""
    openai_compat_base_url: str = ""
    openai_compat_api_key: str = ""
    openai_compat_model: str = ""
    reflection_openai_compat_model: str = ""
    request_timeout_s: int = 60
    max_retries: int = 6
    retry_base_delay_s: float = 1.0
    retry_max_delay_s: float = 20.0
    temperature: float = 0.2
    top_p: float = 0.95
    max_output_tokens: int = 4096
    max_iterations: int = 6
    verification_timeout_s: int = 20
    python_executable: str = sys.executable
    artifact_root: Path = Path("artifacts")
    strict_output: bool = True
    enable_pruning: bool = True
    success_regex: list[str] = field(
        default_factory=lambda: [r"WIN\b", r"FLAG\{[^}]+\}"]
    )

    @classmethod
    def from_env(cls) -> "PipelineConfig":
        _load_dotenv_from_parents()
        artifact_root = os.getenv("PWNGPT_ARTIFACT_ROOT", "artifacts")
        python_executable = _detect_preferred_python()
        cfg = cls(
            llm_provider=os.getenv("LLM_PROVIDER", "gemini").strip().lower(),
            reflection_llm_provider=os.getenv("REFLECTION_LLM_PROVIDER", "").strip().lower(),
            gemini_api_key=os.getenv("GEMINI_API_KEY", "").strip(),
            gemini_model=os.getenv("GEMINI_MODEL", "gemini-3.1-pro").strip(),
            reflection_gemini_model=os.getenv("REFLECTION_GEMINI_MODEL", "").strip(),
            openai_compat_base_url=os.getenv("OPENAI_COMPAT_BASE_URL", "").strip(),
            openai_compat_api_key=os.getenv("OPENAI_COMPAT_API_KEY", "").strip(),
            openai_compat_model=os.getenv("OPENAI_COMPAT_MODEL", "").strip(),
            reflection_openai_compat_model=os.getenv("REFLECTION_OPENAI_COMPAT_MODEL", "").strip(),
            python_executable=python_executable,
            artifact_root=Path(artifact_root),
        )
        return cfg

    def with_overrides(
        self,
        llm_provider: Optional[str] = None,
        reflection_llm_provider: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        gemini_model: Optional[str] = None,
        reflection_gemini_model: Optional[str] = None,
        openai_compat_base_url: Optional[str] = None,
        openai_compat_api_key: Optional[str] = None,
        openai_compat_model: Optional[str] = None,
        reflection_openai_compat_model: Optional[str] = None,
        max_iterations: Optional[int] = None,
        max_retries: Optional[int] = None,
        strict_output: Optional[bool] = None,
        enable_pruning: Optional[bool] = None,
        artifact_root: Optional[Path] = None,
        verification_timeout_s: Optional[int] = None,
    ) -> "PipelineConfig":
        if llm_provider is not None:
            self.llm_provider = llm_provider.strip().lower()
        if reflection_llm_provider is not None:
            self.reflection_llm_provider = reflection_llm_provider.strip().lower()
        if gemini_api_key is not None:
            self.gemini_api_key = gemini_api_key
        if gemini_model is not None:
            self.gemini_model = gemini_model
        if reflection_gemini_model is not None:
            self.reflection_gemini_model = reflection_gemini_model
        if openai_compat_base_url is not None:
            self.openai_compat_base_url = openai_compat_base_url
        if openai_compat_api_key is not None:
            self.openai_compat_api_key = openai_compat_api_key
        if openai_compat_model is not None:
            self.openai_compat_model = openai_compat_model
        if reflection_openai_compat_model is not None:
            self.reflection_openai_compat_model = reflection_openai_compat_model
        if max_iterations is not None:
            self.max_iterations = max_iterations
        if max_retries is not None:
            self.max_retries = max_retries
        if strict_output is not None:
            self.strict_output = strict_output
        if enable_pruning is not None:
            self.enable_pruning = enable_pruning
        if artifact_root is not None:
            self.artifact_root = artifact_root
        if verification_timeout_s is not None:
            self.verification_timeout_s = verification_timeout_s
        return self


def _load_dotenv_from_parents() -> None:
    """
    Load the first .env found from cwd upward without overriding existing env vars.
    """
    current = Path.cwd().resolve()
    candidates = [current, *current.parents]
    for directory in candidates:
        env_path = directory / ".env"
        if env_path.exists():
            _load_dotenv_file(env_path)
            return


def _load_dotenv_file(env_path: Path) -> None:
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip("'").strip('"')
        if key and key not in os.environ:
            os.environ[key] = value


def _detect_preferred_python() -> str:
    current = Path.cwd().resolve()
    candidates = [current, *current.parents]

    for directory in candidates:
        posix_venv = directory / ".venv" / "bin" / "python3"
        if posix_venv.exists():
            return str(posix_venv)
        posix_venv_alt = directory / ".venv" / "bin" / "python"
        if posix_venv_alt.exists():
            return str(posix_venv_alt)
        windows_venv = directory / ".venv" / "Scripts" / "python.exe"
        if windows_venv.exists():
            return str(windows_venv)

    return sys.executable
