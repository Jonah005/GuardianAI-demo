from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EdgeInfo(BaseModel):
    source: str
    target: str
    source_handle: str | None = None
    target_handle: str | None = None


class ToolActionInfo(BaseModel):
    """One concrete tool action exposed by a Langflow tool component."""

    component_id: str
    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    connected_agent_ids: list[str] = Field(default_factory=list)


class ComponentInfo(BaseModel):
    id: str
    name: str
    node_type: str
    description: str = ""
    base_classes: list[str] = Field(default_factory=list)
    template_fields: list[str] = Field(default_factory=list)
    is_agent: bool = False
    is_tool: bool = False

    system_prompt: str = ""
    tool_action_names: list[str] = Field(default_factory=list)
    upstream_agent_ids: list[str] = Field(default_factory=list)
    downstream_agent_ids: list[str] = Field(default_factory=list)

    connected_agent_ids: list[str] = Field(default_factory=list)


class FlowInventory(BaseModel):
    flow_id: str
    flow_name: str = ""
    flow_description: str = ""
    components: list[ComponentInfo] = Field(default_factory=list)
    tool_actions: list[ToolActionInfo] = Field(default_factory=list)
    edges: list[EdgeInfo] = Field(default_factory=list)
    agent_ids: list[str] = Field(default_factory=list)
    tool_ids: list[str] = Field(default_factory=list)
    entry_component_ids: list[str] = Field(default_factory=list)
    exit_component_ids: list[str] = Field(default_factory=list)

    def compact(self) -> dict[str, Any]:
        """Return a model-friendly, structured representation of the flow."""

        components_by_id = {item.id: item for item in self.components}

        agents = []
        for item in self.components:
            if not item.is_agent:
                continue
            agents.append(
                {
                    "id": item.id,
                    "name": item.name,
                    "type": item.node_type,
                    "description": item.description,
                    "system_prompt": item.system_prompt,
                    "enabled_tools": item.tool_action_names,
                    "upstream_agents": [
                        {
                            "id": agent_id,
                            "name": components_by_id.get(agent_id).name
                            if components_by_id.get(agent_id)
                            else agent_id,
                        }
                        for agent_id in item.upstream_agent_ids
                    ],
                    "downstream_agents": [
                        {
                            "id": agent_id,
                            "name": components_by_id.get(agent_id).name
                            if components_by_id.get(agent_id)
                            else agent_id,
                        }
                        for agent_id in item.downstream_agent_ids
                    ],
                }
            )

        tools_by_name: dict[str, dict[str, Any]] = {}
        for action in self.tool_actions:
            bucket = tools_by_name.setdefault(
                action.name,
                {
                    "name": action.name,
                    "description": action.description,
                    "parameters": action.parameters,
                    "tool_component_ids": [],
                    "connected_agents": [],
                },
            )
            if action.component_id not in bucket["tool_component_ids"]:
                bucket["tool_component_ids"].append(action.component_id)
            if not bucket["description"] and action.description:
                bucket["description"] = action.description
            if not bucket["parameters"] and action.parameters:
                bucket["parameters"] = action.parameters
            for agent_id in action.connected_agent_ids:
                agent = components_by_id.get(agent_id)
                agent_doc = {
                    "id": agent_id,
                    "name": agent.name if agent else agent_id,
                }
                if agent_doc not in bucket["connected_agents"]:
                    bucket["connected_agents"].append(agent_doc)

        workflow_edges = []
        for edge in self.edges:
            source = components_by_id.get(edge.source)
            target = components_by_id.get(edge.target)
            workflow_edges.append(
                {
                    "source_id": edge.source,
                    "source_name": source.name if source else edge.source,
                    "target_id": edge.target,
                    "target_name": target.name if target else edge.target,
                    "source_handle": edge.source_handle,
                    "target_handle": edge.target_handle,
                }
            )

        return {
            "flow_id": self.flow_id,
            "flow_name": self.flow_name,
            "flow_description": self.flow_description,
            "entry_components": self.entry_component_ids,
            "exit_components": self.exit_component_ids,
            "agents": agents,
            "tools": sorted(tools_by_name.values(), key=lambda item: item["name"]),
            "workflow_edges": workflow_edges,
        }

    def known_agent_names(self) -> set[str]:
        output: set[str] = set()
        for component in self.components:
            if component.is_agent:
                output.add(component.id)
                output.add(component.name)
        return output

    def known_tool_names(self) -> set[str]:
        return {action.name for action in self.tool_actions if action.enabled}


class ScenarioTurn(BaseModel):
    role: Literal["user"] = "user"
    content: str = Field(min_length=1)


class Scenario(BaseModel):
    id: str = ""
    category: str
    title: str = Field(min_length=3)
    objective: str = Field(min_length=3)
    preconditions: list[str] = Field(default_factory=list)
    conversation: list[ScenarioTurn] = Field(min_length=1)
    required_tools: list[str] = Field(default_factory=list)
    expected_safe_behavior: list[str] = Field(default_factory=list)
    prohibited_outcomes: list[str] = Field(default_factory=list)
    evidence_needed: list[str] = Field(default_factory=list)
    assumptions: list[str] = Field(default_factory=list)
    severity_if_successful: Literal["low", "medium", "high", "critical"] = "medium"

    @field_validator("conversation", mode="before")
    @classmethod
    def normalize_conversation(cls, value: Any) -> Any:
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return [{"role": "user", "content": item} for item in value]
        return value


class GroundingAssessment(BaseModel):
    valid: bool
    confidence: float = Field(ge=0, le=1)
    matched_agents: list[str] = Field(default_factory=list)
    matched_tools: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    unsupported_claims: list[str] = Field(default_factory=list)
    missing_prerequisites: list[str] = Field(default_factory=list)
    revision_instructions: list[str] = Field(default_factory=list)


class StaticAssessment(BaseModel):
    plausible_vulnerability: bool
    confidence: float = Field(ge=0, le=1)
    vulnerability_type: str = ""
    rationale: list[str] = Field(default_factory=list)
    likely_control_points: list[str] = Field(default_factory=list)
    expected_failure_mode: str = ""
    planner_feedback: list[str] = Field(default_factory=list)


class ExecutionTurn(BaseModel):
    index: int
    input_text: str
    output_text: str = ""
    raw_response: dict[str, Any] | list[Any] | str | None = None
    error: str | None = None
    duration_ms: int | None = None


class ScenarioExecution(BaseModel):
    scenario_id: str
    session_id: str
    started_at: str = Field(default_factory=utc_now_iso)
    finished_at: str | None = None
    turns: list[ExecutionTurn] = Field(default_factory=list)
    completed: bool = False


class RuntimeAssessment(BaseModel):
    tested: bool = True
    vulnerability_observed: bool
    confidence: float = Field(ge=0, le=1)
    severity: Literal["none", "low", "medium", "high", "critical"] = "none"
    observed_behavior: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    violated_invariants: list[str] = Field(default_factory=list)
    controls_that_worked: list[str] = Field(default_factory=list)
    recommended_fixes: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ScenarioResult(BaseModel):
    scenario: Scenario
    grounding: GroundingAssessment
    static_assessment: StaticAssessment
    execution: ScenarioExecution | None = None
    runtime_assessment: RuntimeAssessment | None = None


class CategoryRunSummary(BaseModel):
    category: str
    generation_calls: int = 0
    duplicate_generations: int = 0
    attempts: int = 0
    unique_scenarios: int = 0
    grounded_candidates: int = 0
    static_candidates: int = 0
    executed: int = 0
    vulnerabilities_observed: int = 0
    exhausted: bool = False
    errors: list[str] = Field(default_factory=list)


class RunManifest(BaseModel):
    run_id: str
    created_at: str = Field(default_factory=utc_now_iso)
    flow_id: str
    flow_name: str = ""
    execute_enabled: bool
    config_path: str
    model_base_url: str
    model_name: str
    category_summaries: list[CategoryRunSummary] = Field(default_factory=list)
    report_json: str | None = None
    report_markdown: str | None = None
