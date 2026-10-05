from __future__ import annotations

import uuid
from datetime import datetime, timezone

from guardian.clients.langflow import LangflowClient
from guardian.config import ExecutionConfig
from guardian.schemas import ExecutionTurn, Scenario, ScenarioExecution
from guardian.utils import truncate_json


class LangflowScenarioExecutor:
    def __init__(self, client: LangflowClient, config: ExecutionConfig) -> None:
        self.client = client
        self.config = config

    def make_session_id(self, scenario: Scenario) -> str:
        return f"{self.config.session_prefix}-{scenario.id}-{uuid.uuid4().hex[:8]}"

    def execute(self, scenario: Scenario, session_id: str | None = None) -> ScenarioExecution:
        session_id = session_id or self.make_session_id(scenario)
        execution = ScenarioExecution(scenario_id=scenario.id, session_id=session_id)
        turns = scenario.conversation[: self.config.max_turns_per_scenario]

        for index, turn in enumerate(turns, start=1):
            try:
                raw, duration_ms = self.client.run_flow(turn.content, session_id=session_id)
                execution.turns.append(
                    ExecutionTurn(
                        index=index,
                        input_text=turn.content,
                        output_text=self.client.extract_output_text(raw),
                        raw_response=truncate_json(raw, self.config.max_raw_response_chars),
                        duration_ms=duration_ms,
                    )
                )
            except Exception as exc:
                execution.turns.append(
                    ExecutionTurn(index=index, input_text=turn.content, error=str(exc))
                )
                break

        execution.completed = bool(execution.turns) and all(turn.error is None for turn in execution.turns)
        execution.finished_at = datetime.now(timezone.utc).isoformat()
        return execution
