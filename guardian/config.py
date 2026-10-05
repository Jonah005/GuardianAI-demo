from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AppSettings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    langflow_url: str = Field(default="http://127.0.0.1:7860", validation_alias="LANGFLOW_URL")
    langflow_api_key: str = Field(default="", validation_alias="LANGFLOW_API_KEY")
    langflow_flow_id: str = Field(default="", validation_alias="LANGFLOW_FLOW_ID")

    model_base_url: str = Field(default="", validation_alias="GUARDIAN_MODEL_BASE_URL")
    model_chat_path: str = Field(default="/chat/completions", validation_alias="GUARDIAN_MODEL_CHAT_PATH")
    model_name: str = Field(default="", validation_alias="GUARDIAN_MODEL_NAME")
    model_json_mode: bool = Field(default=False, validation_alias="GUARDIAN_MODEL_JSON_MODE")
    model_timeout_seconds: float = Field(default=240, validation_alias="GUARDIAN_MODEL_TIMEOUT_SECONDS")
    model_max_tokens: int = Field(default=2500, validation_alias="GUARDIAN_MODEL_MAX_TOKENS")
    model_temperature: float = Field(default=0.7, validation_alias="GUARDIAN_MODEL_TEMPERATURE")
    model_api_key: str = Field(default="", validation_alias="GUARDIAN_MODEL_API_KEY")
    model_provider: str = Field(default="local", validation_alias="GUARDIAN_MODEL_PROVIDER")

    config_path: Path = Field(default=Path("config/guardian.yaml"), validation_alias="GUARDIAN_CONFIG")
    output_root: Path = Field(default=Path("runs"), validation_alias="GUARDIAN_OUTPUT_ROOT")
    allow_side_effects: bool = Field(default=False, validation_alias="GUARDIAN_ALLOW_SIDE_EFFECTS")
    database_url: str = Field(default="", validation_alias="GUARDIAN_DB_URL")

    @field_validator("langflow_url", "model_base_url")
    @classmethod
    def strip_trailing_slash(cls, value: str) -> str:
        return value.rstrip("/")

    def validate_required(self) -> list[str]:
        missing: list[str] = []
        if not self.langflow_flow_id:
            missing.append("LANGFLOW_FLOW_ID")
        if not self.model_base_url:
            missing.append("GUARDIAN_MODEL_BASE_URL")
        if not self.model_name:
            missing.append("GUARDIAN_MODEL_NAME")
        return missing


class ContextConfig(BaseModel):
    snapshot_files: list[str] = Field(default_factory=list)
    process_graph_file: str | None = None
    max_context_chars: int = 70000
    include_raw_flow: bool = False


class DatabaseConfig(BaseModel):
    enabled: bool = False
    include_schema: bool = True
    sample_tables: list[str] = Field(default_factory=list)
    sample_rows: int = Field(default=3, ge=0, le=20)
    include_views: bool = False


class PlannerConfig(BaseModel):
    target_candidates_per_category: int = Field(default=2, ge=1, le=20)
    max_attempts_per_category: int = Field(default=8, ge=1, le=100)
    max_prior_scenarios_in_prompt: int = Field(default=8, ge=0, le=50)
    max_feedback_items: int = Field(default=12, ge=0, le=100)


class ExecutionConfig(BaseModel):
    input_type: str = "chat"
    output_type: str = "chat"
    output_component: str = ""
    timeout_seconds: float = 180
    session_prefix: str = "guardian"
    max_turns_per_scenario: int = Field(default=8, ge=1, le=50)
    max_raw_response_chars: int = Field(default=30000, ge=1000, le=500000)
    tweaks: dict[str, Any] = Field(default_factory=dict)


class CategoryConfig(BaseModel):
    id: str
    name: str
    description: str
    guidance: list[str] = Field(default_factory=list)
    enabled: bool = True
    target_candidates: int | None = Field(default=None, ge=1, le=20)
    max_attempts: int | None = Field(default=None, ge=1, le=100)


class RunConfig(BaseModel):
    context: ContextConfig = Field(default_factory=ContextConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    planner: PlannerConfig = Field(default_factory=PlannerConfig)
    execution: ExecutionConfig = Field(default_factory=ExecutionConfig)
    categories: list[CategoryConfig]


def load_run_config(path: Path) -> RunConfig:
    if not path.exists():
        raise FileNotFoundError(f"Guardian config not found: {path}")
    with path.open("r", encoding="utf-8") as handle:
        raw = yaml.safe_load(handle) or {}
    return RunConfig.model_validate(raw)


def resolve_project_path(value: str | Path, config_path: Path) -> Path:
    path = Path(value)
    if path.is_absolute():
        return path
    project_root = config_path.parent.parent if config_path.parent.name == "config" else config_path.parent
    return (project_root / path).resolve()
