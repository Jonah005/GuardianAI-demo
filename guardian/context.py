from __future__ import annotations

import json
from typing import Any

from guardian.config import AppSettings, RunConfig, resolve_project_path
from guardian.database import DatabaseContextError, inspect_database
from guardian.record_vocab import extract_record_vocabulary
from guardian.schemas import FlowInventory
from guardian.utils import load_data_file, redact_secrets, truncate_json


class SetupContextBuilder:
    def __init__(self, settings: AppSettings, run_config: RunConfig) -> None:
        self.settings = settings
        self.run_config = run_config

    @staticmethod
    def _rendered_length(value: Any) -> int:
        return len(json.dumps(value, ensure_ascii=False, default=str))

    def _fit_structured_context(self, context: dict[str, Any]) -> dict[str, Any]:
        """Keep the context structured instead of replacing it with one text preview."""

        max_chars = self.run_config.context.max_context_chars
        if self._rendered_length(context) <= max_chars:
            return context

        compact = redact_secrets(context)
        flow_inventory = compact.get("flow_inventory")
        if isinstance(flow_inventory, dict):
            agents = flow_inventory.get("agents")
            if isinstance(agents, list):
                for agent in agents:
                    if not isinstance(agent, dict):
                        continue
                    prompt = agent.get("system_prompt")
                    if isinstance(prompt, str) and len(prompt) > 2500:
                        agent["system_prompt"] = prompt[:2500] + "\n...[truncated]"

            tools = flow_inventory.get("tools")
            if isinstance(tools, list):
                for tool in tools:
                    if not isinstance(tool, dict):
                        continue
                    description = tool.get("description")
                    if isinstance(description, str) and len(description) > 1200:
                        tool["description"] = description[:1200] + "...[truncated]"

        if self._rendered_length(compact) <= max_chars:
            return compact

        supplements = compact.get("snapshots", {})
        if supplements:
            compact["snapshots"] = truncate_json(supplements, max(4000, max_chars // 4))

        if self._rendered_length(compact) <= max_chars:
            return compact

        vocab = compact.get("grounding_vocabulary")
        record_vocab = compact.get("record_vocabulary")
        truncated = truncate_json(compact, max_chars)
        if isinstance(truncated, dict):
            if vocab is not None:
                truncated["grounding_vocabulary"] = vocab
            if record_vocab is not None:
                truncated["record_vocabulary"] = record_vocab
        return truncated

    @staticmethod
    def _grounding_vocabulary(inventory: FlowInventory) -> dict[str, list[str]]:
        """The exact valid names, as flat lists, so the model can never miss them.

        This is the ground truth for the grounding check. It is placed at the
        very top of the context and is never truncated, so even if the rest of
        the context is trimmed the model always sees which tool and agent names
        actually exist -- preventing it from inventing plausible-but-wrong ones.
        """
        try:
            tools = sorted(set(inventory.known_tool_names()))
        except Exception:            tools = []
        try:
            agents = sorted(set(inventory.known_agent_names()))
        except Exception:            agents = []
        return {"valid_tool_names": tools, "valid_agent_names": agents}

    def build(self, inventory: FlowInventory, raw_flow: dict[str, Any]) -> dict[str, Any]:
        config_path = self.settings.config_path.resolve()
        context: dict[str, Any] = {
            "grounding_vocabulary": self._grounding_vocabulary(inventory),
            "source_of_truth": {
                "workflow_structure": "Langflow flow API",
                "agent_instructions": "Langflow agent system prompts",
                "tool_capabilities": "Langflow MCP tools_metadata",
                "external_state": "configured database or test snapshot",
            },
            "flow_inventory": inventory.compact(),
            "snapshots": {},
            "supplemental_process_graph": None,
            "database": {"enabled": False},
        }

        for value in self.run_config.context.snapshot_files:
            path = resolve_project_path(value, config_path)
            if not path.exists():
                context["snapshots"][str(path)] = {"error": "file not found"}
                continue
            context["snapshots"][path.name] = redact_secrets(load_data_file(path))

        graph_file = self.run_config.context.process_graph_file
        if graph_file:
            path = resolve_project_path(graph_file, config_path)
            context["supplemental_process_graph"] = (
                redact_secrets(load_data_file(path))
                if path.exists()
                else {"error": f"file not found: {path}"}
            )

        if self.run_config.database.enabled:
            try:
                context["database"] = inspect_database(
                    self.settings.database_url,
                    self.run_config.database,
                )
            except DatabaseContextError as exc:
                context["database"] = {
                    "enabled": True,
                    "connected": False,
                    "error": str(exc),
                }

        if self.run_config.context.include_raw_flow:
            context["raw_flow"] = redact_secrets(raw_flow)

        db_samples = context.get("database", {})
        record_sources = [context.get("snapshots", {}),
                          db_samples.get("samples") if isinstance(db_samples, dict) else None]
        context["record_vocabulary"] = extract_record_vocabulary(record_sources)

        return self._fit_structured_context(context)
