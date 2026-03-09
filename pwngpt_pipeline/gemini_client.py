from __future__ import annotations

import random
import time
from dataclasses import dataclass

import requests

from .config import PipelineConfig


RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class GeminiError(RuntimeError):
    pass


@dataclass
class GeminiResponse:
    text: str
    raw_json: dict


class GeminiClient:
    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        if not self.config.gemini_api_key:
            raise GeminiError(
                "Missing GEMINI_API_KEY. Set env GEMINI_API_KEY or pass --api-key."
            )

    def generate_text(self, prompt: str, system_instruction: str = "") -> GeminiResponse:
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{self.config.gemini_model}:generateContent"
        )
        params = {"key": self.config.gemini_api_key}
        payload = {
            "contents": [{"role": "user", "parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": self.config.temperature,
                "topP": self.config.top_p,
                "maxOutputTokens": self.config.max_output_tokens,
            },
        }
        if system_instruction.strip():
            payload["systemInstruction"] = {"parts": [{"text": system_instruction}]}

        last_err: Exception | None = None
        total_attempts = self.config.max_retries + 1
        for attempt in range(1, total_attempts + 1):
            try:
                resp = requests.post(
                    endpoint,
                    params=params,
                    json=payload,
                    timeout=self.config.request_timeout_s,
                )
            except requests.RequestException as exc:
                last_err = exc
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                raise GeminiError(f"Gemini request failed after retries: {exc}") from exc

            if resp.status_code >= 400:
                if resp.status_code in RETRYABLE_STATUS and attempt < total_attempts:
                    last_err = GeminiError(f"HTTP {resp.status_code}: {resp.text[:500]}")
                    self._sleep_before_retry(attempt)
                    continue
                raise GeminiError(f"Gemini API error HTTP {resp.status_code}: {resp.text[:800]}")

            try:
                data = resp.json()
            except ValueError as exc:
                last_err = exc
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                raise GeminiError("Gemini API returned non-JSON payload.") from exc

            text = self._extract_text(data)
            if text.strip():
                return GeminiResponse(text=text, raw_json=data)

            last_err = GeminiError("Gemini returned empty candidate text.")
            if attempt < total_attempts:
                self._sleep_before_retry(attempt)
                continue
            break

        raise GeminiError(f"Gemini call exhausted retries. Last error: {last_err}")

    def _sleep_before_retry(self, attempt: int) -> None:
        base = self.config.retry_base_delay_s
        max_delay = self.config.retry_max_delay_s
        delay = min(max_delay, base * (2 ** (attempt - 1)))
        delay += random.uniform(0.0, 0.5 * base)
        time.sleep(delay)

    @staticmethod
    def _extract_text(data: dict) -> str:
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [part.get("text", "") for part in parts if "text" in part]
        return "\n".join(texts).strip()
