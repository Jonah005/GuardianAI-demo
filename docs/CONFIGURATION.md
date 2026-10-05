# Configuration Reference

Run settings live in [`config/guardian.yaml`](../config/guardian.yaml). Secrets and connection details live in `.env` (see [`.env.example`](../.env.example)). Relative paths in the YAML are resolved from the repository root. Use `--config <path>` or `GUARDIAN_CONFIG` to load a different file.

## Environment Variables

Model variables are listed in [Model Configuration](MODEL_CONFIGURATION.md). The rest:

| Variable | Default | Purpose |
|---|---|---|
| `LANGFLOW_URL` | `http://127.0.0.1:7860` | Langflow base URL |
| `LANGFLOW_API_KEY` | empty | Langflow API key |
| `LANGFLOW_FLOW_ID` | none (required) | ID of the flow to test |
| `GUARDIAN_CONFIG` | `config/guardian.yaml` | Path to the run config |
| `GUARDIAN_OUTPUT_ROOT` | `runs` | Where run artifacts are written |
| `GUARDIAN_ALLOW_SIDE_EFFECTS` | `false` | Allow `--execute` without `--confirm-side-effects` |
| `GUARDIAN_DB_URL` | empty | SQLAlchemy URL of the workflow database (see below) |
| `GUARDIAN_UI_PORT` | `5050` | Dashboard port (tries the next 9 ports if busy) |
| `GUARDIAN_UI_NO_BROWSER` | unset | Set to `1` to stop the dashboard opening a browser |

Demo workflow only (read by the files in `langflow_refund_database/`):

| Variable | Default | Purpose |
|---|---|---|
| `GUARDIAN_BUSINESS_DB` | `langflow_refund_database/langflow_refund_demo.db` | Path to the demo SQLite database |
| `GUARDIAN_ENFORCEMENT` | `off` | Set to `on` to enable the demo's optional runtime enforcement gate |

## `context`

What the model is told about the workflow.

```yaml
context:
  snapshot_files:
    - langflow_refund_database/database_snapshot.json
  process_graph_file: null
  max_context_chars: 40000
  include_raw_flow: false
```

| Key | Default | Meaning |
|---|---|---|
| `snapshot_files` | `[]` | Context files (JSON, JSONL, YAML, CSV, text or Markdown) |
| `process_graph_file` | `null` | Optional process description of the workflow |
| `max_context_chars` | `70000` | Size cap for the context sent to the model |
| `include_raw_flow` | `false` | Include the raw flow export in the context |

## `database`

Optional read-only inspection of a live database, added to the model's context.

```yaml
database:
  enabled: true
  include_schema: true
  sample_tables:
    - public.orders
    - public.refunds
  sample_rows: 3
  include_views: false
```

| Key | Default | Meaning |
|---|---|---|
| `enabled` | `false` | Turn live inspection on |
| `include_schema` | `true` | Include table schemas |
| `sample_tables` | `[]` | Tables to sample. Only these are read |
| `sample_rows` | `3` | Rows per table (0 to 20) |
| `include_views` | `false` | Include views |

Keep this disabled when a snapshot file already supplies enough information, as in the default config.

## GUARDIAN_DB_URL

`GUARDIAN_DB_URL` is a [SQLAlchemy URL](https://docs.sqlalchemy.org/en/20/core/engines.html#database-urls). When set, it is used for:

1. **Live inspection**, if `database.enabled` is `true`.
2. **Audit judging.** Guardian finds the workflow's tool-call log table and judges each scenario by whether a state-changing tool actually ran. Without it, Guardian falls back to the transcript-based judge.
3. **Session markers.** Guardian writes a small record to its own control table, `guardian_active_session`, to match tool calls to scenarios. Business tables are never written.

Examples:

```env
GUARDIAN_DB_URL=sqlite:///langflow_refund_database/langflow_refund_demo.db
GUARDIAN_DB_URL=postgresql+psycopg://user:password@host:5432/database
```

SQLite needs no extra driver. For PostgreSQL install one, for example `pip install "psycopg[binary]"`. Use placeholder credentials in documentation and never commit real ones.

## `planner`

```yaml
planner:
  target_candidates_per_category: 5
  max_attempts_per_category: 12
  max_prior_scenarios_in_prompt: 8
  max_feedback_items: 12
```

| Key | Code default | Allowed | Meaning |
|---|---|---|---|
| `target_candidates_per_category` | `2` | 1 to 20 | Minimum accepted (grounded) scenarios to aim for per category. Generation continues past this while the model still produces new scenarios |
| `max_attempts_per_category` | `8` | 1 to 100 | Generation attempts before a category is marked exhausted |
| `max_prior_scenarios_in_prompt` | `8` | 0 to 50 | Earlier scenarios shown to the model to avoid repeats |
| `max_feedback_items` | `12` | 0 to 100 | Failure explanations fed back to the planner |

The repository's `guardian.yaml` sets `target_candidates_per_category` to `5` and `max_attempts_per_category` to `12`.

## `execution`

How scenarios are sent to Langflow (`/api/v1/run/{flow_id}`).

```yaml
execution:
  input_type: chat
  output_type: chat
  output_component: ""
  timeout_seconds: 180
  session_prefix: guardian
  max_turns_per_scenario: 8
  max_raw_response_chars: 30000
  tweaks: {}
```

| Key | Default | Meaning |
|---|---|---|
| `input_type`, `output_type` | `chat` | Langflow input and output types |
| `output_component` | `""` | Specific output component to read, if any |
| `timeout_seconds` | `180` | Per-request timeout |
| `session_prefix` | `guardian` | Prefix for per-scenario Langflow session IDs |
| `max_turns_per_scenario` | `8` | Maximum conversation turns (1 to 50) |
| `max_raw_response_chars` | `30000` | Cap on stored raw response size |
| `tweaks` | `{}` | Langflow component tweaks, sent unchanged with every request |

Every scenario uses a fresh Langflow `session_id`; all turns within a scenario share it.

Example `tweaks`, copied from your flow's API panel:

```yaml
execution:
  tweaks:
    Agent-ABC123:
      some_parameter: some_value
```

## `categories`

The five categories are defined in the repository's config: `parameter_manipulation`, `workflow_order_violation`, `unsafe_tool_chaining`, `cross_agent_manipulation` and `indirect_prompt_injection`.

```yaml
categories:
  - id: parameter_manipulation
    name: Parameter manipulation
    description: >
      What this category tests.
    guidance:
      - Extra instruction for the model.
    enabled: true
    target_candidates: 4
    max_attempts: 15
```

| Key | Default | Meaning |
|---|---|---|
| `id`, `name`, `description` | required | Identity and description shown to the model |
| `guidance` | `[]` | Extra instructions for generating this category |
| `enabled` | `true` | Set `false` to skip the category |
| `target_candidates` | planner value | Per-category override (1 to 20) |
| `max_attempts` | planner value | Per-category override (1 to 100) |

A category is marked `exhausted: true` in its summary when it hits the attempt limit before reaching its target.

## Executing Scenarios

```bash
python -m guardian run --execute --confirm-side-effects
```

or set `GUARDIAN_ALLOW_SIDE_EFFECTS=true` in `.env` for repeated runs in a test environment. The dashboard always passes the confirmation flag itself.
