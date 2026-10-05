from __future__ import annotations

import time
from typing import Any

import httpx

from guardian.config import AppSettings, ExecutionConfig


class LangflowClientError(RuntimeError):
    pass


class LangflowClient:
    def __init__(self, settings: AppSettings, execution_config: ExecutionConfig | None = None) -> None:
        self.settings = settings
        self.execution_config = execution_config or ExecutionConfig()
        self.client = httpx.Client(timeout=self.execution_config.timeout_seconds)

    def _headers(self) -> dict[str, str]:
        headers = {"Accept": "application/json", "Content-Type": "application/json"}
        if self.settings.langflow_api_key:
            headers["x-api-key"] = self.settings.langflow_api_key
        return headers

    def get_flow(self, flow_id: str | None = None) -> dict[str, Any]:
        selected = flow_id or self.settings.langflow_flow_id
        response = self.client.get(
            f"{self.settings.langflow_url}/api/v1/flows/{selected}",
            headers=self._headers(),
        )
        self._raise(response, "read flow")
        data = response.json()
        if not isinstance(data, dict):
            raise LangflowClientError("Langflow flow response was not a JSON object")
        return data

    def list_flows(self) -> Any:
        response = self.client.get(
            f"{self.settings.langflow_url}/api/v1/flows/",
            params={
                "remove_example_flows": "false",
                "components_only": "false",
                "get_all": "true",
                "header_flows": "false",
                "page": 1,
                "size": 100,
            },
            headers=self._headers(),
        )
        self._raise(response, "list flows")
        return response.json()

    def run_flow(
        self,
        input_value: str,
        session_id: str,
        flow_id: str | None = None,
    ) -> tuple[Any, int]:
        selected = flow_id or self.settings.langflow_flow_id
        payload: dict[str, Any] = {
            "input_value": input_value,
            "session_id": session_id,
            "input_type": self.execution_config.input_type,
            "output_type": self.execution_config.output_type,
        }
        if self.execution_config.output_component:
            payload["output_component"] = self.execution_config.output_component
        if self.execution_config.tweaks:
            payload["tweaks"] = self.execution_config.tweaks

        start = time.perf_counter()
        response = self.client.post(
            f"{self.settings.langflow_url}/api/v1/run/{selected}",
            headers=self._headers(),
            json=payload,
        )
        duration_ms = int((time.perf_counter() - start) * 1000)
        self._raise(response, "run flow")
        try:
            return response.json(), duration_ms
        except ValueError:
            return response.text, duration_ms

    @staticmethod
    def extract_output_text(data: Any) -> str:
        try:
            outputs = data.get("outputs", []) if isinstance(data, dict) else []
            for outer in reversed(outputs):
                for inner in reversed(outer.get("outputs", [])):
                    results = inner.get("results", {})
                    message = results.get("message", {})
                    if isinstance(message, dict) and isinstance(message.get("text"), str):
                        if message["text"].strip():
                            return message["text"].strip()
                    if isinstance(results.get("text"), str) and results["text"].strip():
                        return results["text"].strip()
        except (AttributeError, TypeError):
            pass

        texts: list[str] = []

        def walk(value: Any, key_hint: str = "") -> None:
            if isinstance(value, dict):
                for key, item in value.items():
                    if key in {"text", "content", "message"} and isinstance(item, str):
                        texts.append(item)
                    else:
                        walk(item, key)
            elif isinstance(value, list):
                for item in value:
                    walk(item, key_hint)

        walk(data)
        deduped: list[str] = []
        seen: set[str] = set()
        for text in texts:
            clean = text.strip()
            if clean and clean not in seen:
                seen.add(clean)
                deduped.append(clean)
        return deduped[-1] if deduped else ""

    @staticmethod
    def _raise(response: httpx.Response, action: str) -> None:
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise LangflowClientError(
                f"Could not {action}; Langflow returned HTTP {response.status_code}: {response.text[:2000]}"
            ) from exc

    def close(self) -> None:
        self.client.close()
