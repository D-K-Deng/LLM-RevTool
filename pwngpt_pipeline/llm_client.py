from __future__ import annotations

import random
import time
from dataclasses import dataclass

import requests

from .config import PipelineConfig


RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


class LLMError(RuntimeError):
    pass


@dataclass
class LLMResponse:
    text: str
    raw_json: dict


class LLMClient:
    def __init__(self, config: PipelineConfig) -> None:
        self.config = config
        self._validate_profile(self._profile_for_purpose("primary"))
        reflection_profile = self._profile_for_purpose("reflection")
        if reflection_profile != self._profile_for_purpose("primary"):
            self._validate_profile(reflection_profile)

    def generate_text(
        self,
        prompt: str,
        system_instruction: str = "",
        purpose: str = "primary",
    ) -> LLMResponse:
        profile = self._profile_for_purpose(purpose)
        provider = profile["provider"]
        if provider == "gemini":
            return self._generate_gemini(prompt, system_instruction, profile["model"], profile["api_key"])
        if provider in {"openai_compatible", "openai-compat", "dartmouth"}:
            return self._generate_openai_compatible(
                prompt,
                system_instruction,
                profile["base_url"],
                profile["api_key"],
                profile["model"],
            )
        raise LLMError(f"Unsupported LLM provider: {provider}")

    def _generate_gemini(
        self,
        prompt: str,
        system_instruction: str,
        model: str,
        api_key: str,
    ) -> LLMResponse:
        endpoint = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:generateContent"
        )
        params = {"key": api_key}
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
        return self._post_with_retry(
            endpoint=endpoint,
            params=params,
            headers={},
            payload=payload,
            extractor=self._extract_gemini_text,
            provider_name="Gemini",
        )

    def _generate_openai_compatible(
        self,
        prompt: str,
        system_instruction: str,
        base_url: str,
        api_key: str,
        model: str,
    ) -> LLMResponse:
        endpoint = base_url.rstrip("/") + "/v1/chat/completions"
        messages = []
        if system_instruction.strip():
            messages.append({"role": "system", "content": system_instruction})
        messages.append({"role": "user", "content": prompt})
        payload = {
            "model": model,
            "messages": messages,
            "temperature": self.config.temperature,
            "top_p": self.config.top_p,
            "max_tokens": self.config.max_output_tokens,
        }
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        }
        return self._post_with_retry(
            endpoint=endpoint,
            params={},
            headers=headers,
            payload=payload,
            extractor=self._extract_openai_compatible_text,
            provider_name="OpenAI-compatible",
        )

    def _post_with_retry(
        self,
        endpoint: str,
        params: dict,
        headers: dict,
        payload: dict,
        extractor,
        provider_name: str,
    ) -> LLMResponse:
        last_err: Exception | None = None
        total_attempts = self.config.max_retries + 1
        for attempt in range(1, total_attempts + 1):
            try:
                resp = requests.post(
                    endpoint,
                    params=params,
                    headers=headers,
                    json=payload,
                    timeout=self.config.request_timeout_s,
                )
            except requests.RequestException as exc:
                last_err = exc
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                raise LLMError(f"{provider_name} request failed after retries: {exc}") from exc

            if resp.status_code >= 400:
                if resp.status_code in RETRYABLE_STATUS and attempt < total_attempts:
                    last_err = LLMError(f"HTTP {resp.status_code}: {resp.text[:500]}")
                    self._sleep_before_retry(attempt)
                    continue
                raise LLMError(
                    f"{provider_name} API error HTTP {resp.status_code}: {resp.text[:800]}"
                )

            try:
                data = resp.json()
            except ValueError as exc:
                last_err = exc
                if attempt < total_attempts:
                    self._sleep_before_retry(attempt)
                    continue
                raise LLMError(f"{provider_name} API returned non-JSON payload.") from exc

            text = extractor(data)
            if text.strip():
                return LLMResponse(text=text, raw_json=data)

            last_err = LLMError(f"{provider_name} returned empty candidate text.")
            if attempt < total_attempts:
                self._sleep_before_retry(attempt)
                continue
            break

        raise LLMError(f"{provider_name} call exhausted retries. Last error: {last_err}")

    def _sleep_before_retry(self, attempt: int) -> None:
        base = self.config.retry_base_delay_s
        max_delay = self.config.retry_max_delay_s
        delay = min(max_delay, base * (2 ** (attempt - 1)))
        delay += random.uniform(0.0, 0.5 * base)
        time.sleep(delay)

    @staticmethod
    def _extract_gemini_text(data: dict) -> str:
        candidates = data.get("candidates", [])
        if not candidates:
            return ""
        parts = candidates[0].get("content", {}).get("parts", [])
        texts = [part.get("text", "") for part in parts if "text" in part]
        return "\n".join(texts).strip()

    @staticmethod
    def _extract_openai_compatible_text(data: dict) -> str:
        choices = data.get("choices", [])
        if not choices:
            return ""
        message = choices[0].get("message", {})
        content = message.get("content", "")
        if isinstance(content, str):
            return content.strip()
        if isinstance(content, list):
            texts = []
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text":
                    texts.append(item.get("text", ""))
            return "\n".join(texts).strip()
        return ""

    def _profile_for_purpose(self, purpose: str) -> dict:
        if purpose in {"reflection", "format_repair"}:
            provider = self.config.reflection_llm_provider or self.config.llm_provider
            provider = provider.strip().lower()
            if provider == "gemini":
                return {
                    "provider": provider,
                    "model": self.config.reflection_gemini_model or self.config.gemini_model,
                    "api_key": self.config.gemini_api_key,
                }
            if provider in {"openai_compatible", "openai-compat", "dartmouth"}:
                return {
                    "provider": provider,
                    "base_url": self.config.openai_compat_base_url,
                    "api_key": self.config.openai_compat_api_key,
                    "model": self.config.reflection_openai_compat_model or self.config.openai_compat_model,
                }
        provider = self.config.llm_provider
        if provider == "gemini":
            return {
                "provider": provider,
                "model": self.config.gemini_model,
                "api_key": self.config.gemini_api_key,
            }
        if provider in {"openai_compatible", "openai-compat", "dartmouth"}:
            return {
                "provider": provider,
                "base_url": self.config.openai_compat_base_url,
                "api_key": self.config.openai_compat_api_key,
                "model": self.config.openai_compat_model,
            }
        return {"provider": provider}

    @staticmethod
    def _validate_profile(profile: dict) -> None:
        provider = profile["provider"]
        if provider == "gemini":
            if not profile.get("api_key"):
                raise LLMError("Missing GEMINI_API_KEY for gemini provider.")
            if not profile.get("model"):
                raise LLMError("Missing Gemini model for selected purpose.")
            return
        if provider in {"openai_compatible", "openai-compat", "dartmouth"}:
            if not profile.get("api_key"):
                raise LLMError("Missing OPENAI_COMPAT_API_KEY for openai-compatible provider.")
            if not profile.get("base_url"):
                raise LLMError("Missing OPENAI_COMPAT_BASE_URL for openai-compatible provider.")
            if not profile.get("model"):
                raise LLMError("Missing OpenAI-compatible model for selected purpose.")
            return
        raise LLMError(f"Unsupported LLM provider: {provider}")
