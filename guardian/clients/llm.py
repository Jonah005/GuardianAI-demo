from __future__ import annotations

import json
import logging
import time
from typing import Any, TypeVar

import httpx
from pydantic import BaseModel

from guardian.config import AppSettings

T = TypeVar("T", bound=BaseModel)
LOGGER = logging.getLogger(__name__)


class ModelClientError(RuntimeError):
    pass


def _json_object_candidates(text: str) -> list[dict[str, Any]]:
    """Return every decodable JSON object in a model response.

    Reasoning-capable models sometimes emit example objects, evidence records,
    or schema fragments before the requested final object. Returning all
    candidates lets chat_json select the object that actually matches the
    requested Pydantic schema instead of blindly using the first object.
    """

    stripped = text.strip()
    candidates: list[dict[str, Any]] = []
    fingerprints: set[str] = set()

    def add(value: Any) -> None:
        if not isinstance(value, dict):
            return
        fingerprint = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            default=str,
        )
        if fingerprint not in fingerprints:
            fingerprints.add(fingerprint)
            candidates.append(value)

    try:
        add(json.loads(stripped))
    except (json.JSONDecodeError, TypeError):
        pass

    decoder = json.JSONDecoder()
    for index, char in enumerate(stripped):
        if char != "{":
            continue
        try:
            parsed, _ = decoder.raw_decode(stripped[index:])
        except json.JSONDecodeError:
            continue
        add(parsed)

    return candidates


class GuardianModelClient:
    """Client for OpenAI-compatible or simple JSON HTTP model servers."""

    def __init__(self, settings: AppSettings) -> None:
        self.settings = settings
        self.client = httpx.Client(timeout=settings.model_timeout_seconds)

    @property
    def endpoint(self) -> str:
        return f"{self.settings.model_base_url}{self.settings.model_chat_path}"

    def _is_local_provider(self) -> bool:
        """The fine-tuned Colab model (Qwen) vs a generic hosted API (DeepSeek).

        Local: thinking must be disabled via chat_template_kwargs and a temperature
        floor guards the diversity bug. A hosted OpenAI-compatible provider needs
        neither -- and would reject the vLLM-only chat_template_kwargs field.
        """
        return (self.settings.model_provider or "local").strip().lower() in {
            "local", "finetuned", "fine-tuned", "guardian", "qwen", "colab", ""
        }

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        api_key = (self.settings.model_api_key or "").strip()
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        return headers

    def _payload(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        is_local = self._is_local_provider()
        configured = float(self.settings.model_temperature or 0.0)
        effective_temperature = max(configured, 0.9) if is_local else (configured or 0.7)
        if not getattr(self, "_temp_logged", False):
            import sys as _sys
            print(f"[guardian] provider={self.settings.model_provider} "
                  f"model={self.settings.model_name} "
                  f"sampling temperature={effective_temperature}",
                  file=_sys.stderr, flush=True)
            self._temp_logged = True
        payload: dict[str, Any] = {
            "model": self.settings.model_name,
            "messages": messages,
            "temperature": effective_temperature,
            "top_p": 0.95,
            "max_tokens": max_tokens or self.settings.model_max_tokens,
            "stream": False,
        }
        if is_local:
            payload["chat_template_kwargs"] = {"enable_thinking": False}
        if self.settings.model_json_mode:
            payload["response_format"] = {"type": "json_object"}
        return payload

    def chat(
        self,
        messages: list[dict[str, str]],
        max_tokens: int | None = None,
    ) -> str:
        last_error: Exception | None = None
        for attempt in range(3):
            try:
                response = self.client.post(
                    self.endpoint,
                    headers=self._headers(),
                    json=self._payload(messages, max_tokens=max_tokens),
                )
                response.raise_for_status()
                try:
                    data = response.json()
                except json.JSONDecodeError as exc:
                    raise ModelClientError(
                        f"Model endpoint returned non-JSON: {response.text[:1500]}"
                    ) from exc
                content = self._extract_content(data)
                if not content.strip():
                    raise ModelClientError(
                        "Could not find generated text in model response: "
                        f"{str(data)[:1500]}"
                    )
                return content
            except httpx.HTTPStatusError as exc:
                body = exc.response.text[:1500]
                last_error = ModelClientError(
                    f"Model endpoint returned HTTP {exc.response.status_code}: {body}"
                )
            except (httpx.HTTPError, ModelClientError) as exc:
                last_error = exc
            if attempt < 2:
                time.sleep(2**attempt)
        raise ModelClientError(
            f"Model request failed after 3 attempts: {last_error}"
        )

    def chat_json(
        self,
        messages: list[dict[str, str]],
        schema: type[T],
        max_tokens: int | None = None,
    ) -> T:
        original_messages = list(messages)
        working_messages = list(messages)
        last_error: Exception | None = None
        schema_document = schema.model_json_schema()
        required_fields = schema_document.get("required", [])

        for attempt in range(1, 4):
            text = self.chat(working_messages, max_tokens=max_tokens)
            candidates = _json_object_candidates(text)
            candidate_errors: list[Exception] = []

            for candidate in candidates:
                try:
                    return schema.model_validate(candidate)
                except Exception as exc:
                    candidate_errors.append(exc)

            if candidate_errors:
                last_error = candidate_errors[-1]
            else:
                last_error = ValueError(
                    "No decodable JSON object was found in the model response"
                )

            observed_keys = [
                sorted(str(key) for key in candidate.keys())[:20]
                for candidate in candidates[:8]
            ]
            LOGGER.warning(
                "Structured output attempt %s/3 for %s failed. "
                "Candidate top-level keys: %s. Validation: %s",
                attempt,
                schema.__name__,
                observed_keys,
                str(last_error)[:1200],
            )

            working_messages = original_messages + [
                {
                    "role": "user",
                    "content": (
                        "Your previous reply did not contain a JSON object that "
                        f"matches {schema.__name__}. Return exactly one corrected "
                        "JSON object and no reasoning, examples, markdown, database "
                        "field definitions, or commentary. "
                        f"Required top-level fields: {required_fields}. "
                        f"Previous candidate top-level keys: {observed_keys}. "
                        f"Validation error: {str(last_error)[:1600]}"
                    ),
                }
            ]

        raise ModelClientError(
            f"Model did not return valid structured output: {last_error}"
        )

    @staticmethod
    def _extract_content(data: Any) -> str:
        if isinstance(data, str):
            return data
        if not isinstance(data, dict):
            return ""

        choices = data.get("choices")
        if isinstance(choices, list) and choices:
            choice = choices[0]
            if isinstance(choice, dict):
                message = choice.get("message")
                if isinstance(message, dict):
                    content = message.get("content")
                    if isinstance(content, str):
                        return content
                    if isinstance(content, list):
                        parts = [
                            str(part.get("text", ""))
                            for part in content
                            if isinstance(part, dict)
                            and part.get("type") in {"text", "output_text"}
                        ]
                        return "".join(parts)
                if isinstance(choice.get("text"), str):
                    return choice["text"]

        for key in (
            "content",
            "text",
            "response",
            "generated_text",
            "output_text",
        ):
            if isinstance(data.get(key), str):
                return data[key]
        output = data.get("output")
        if isinstance(output, str):
            return output
        return ""

    def close(self) -> None:
        self.client.close()
