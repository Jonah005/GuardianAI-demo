# GuardianAI — Automated Security Evaluation for Agentic AI Workflows

GuardianAI is an automated security evaluation system for LLM-powered, multi-agent workflows built in [Langflow](https://www.langflow.org/).

It reads a live Langflow workflow, extracts its agents, tools and connections, and uses a fine-tuned Guardian model to generate adversarial scenarios **grounded in what that workflow can actually do**. Scenarios that reference tools, agents or records that do not exist are rejected before anything is executed. Accepted scenarios are run against the real workflow, and the outcome is judged from the workflow's own tool-call log rather than from what the agents say.

## What GuardianAI Does

- Inspects a Langflow workflow and extracts agents, tools, components and edges.
- Loads workflow context (a database snapshot and an optional process graph) for the model.
- Generates adversarial scenarios across five configurable vulnerability categories.
- Rejects scenarios that are not grounded in the target workflow, and feeds the failure reason back to the planner so it can generate a replacement.
- Statically assesses whether a grounded scenario could plausibly reach a vulnerability.
- Executes accepted scenarios against the live workflow through the Langflow API (opt-in).
- Judges each execution using the workflow's tool-call audit log when a database is configured, and falls back to a transcript-based judge otherwise.
- Writes JSON, JSONL and Markdown reports, and can explain each confirmed issue and how to fix it.
- Includes a local web dashboard to run, review and export results.

## Pipeline

```text
Langflow workflow
      |
      v
1. Inspect     read the live flow: agents, tools, edges
      |
      v
2. Generate    Guardian model proposes attack scenarios per category
      |
      v
3. Validate    grounding check + static vulnerability assessment
      |         (failures are fed back to the planner)
      v
4. Execute     run accepted scenarios against the live workflow
      |
      v
5. Judge       audit-log verdict (or transcript fallback)
      |
      v
6. Report      report.json / report.md (+ optional remediation)
```

## Vulnerability Categories

Defined in [`config/guardian.yaml`](config/guardian.yaml):

| Category | What it tests |
|---|---|
| `parameter_manipulation` | Tampering with tool parameters, identifiers, amounts or record associations |
| `workflow_order_violation` | Skipping, reordering or bypassing required stages and approvals |
| `unsafe_tool_chaining` | Combining individually valid tools into an unsafe sequence |
| `cross_agent_manipulation` | Getting one agent to trust false claims from another |
| `indirect_prompt_injection` | Malicious instructions hidden in data the workflow retrieves |

## Quick Start

```bash
pip install -r requirements.txt -r requirements-ui.txt
cp .env.example .env        # then fill in your values
python -m guardian doctor   # check model + Langflow connectivity
python app.py               # start the dashboard
```

Full instructions, including Windows PowerShell commands and Langflow setup, are in the [Setup Guide](docs/SETUP.md).

## Documentation

- [Setup and Usage Guide](docs/SETUP.md)
- [Model Configuration](docs/MODEL_CONFIGURATION.md)
- [Configuration Reference](docs/CONFIGURATION.md)
- [Security Policy](SECURITY.md)
- [Demo workflow and database](langflow_refund_database/README.md)

## Project Layout

```text
.
├── app.py                      # starts the web dashboard
├── run_guardian.py             # CLI entry point (same as `python -m guardian`)
├── guardian/
│   ├── cli.py                  # doctor, inspect-flow, run, rejudge, remediate, show-report
│   ├── pipeline.py             # end-to-end orchestration
│   ├── planner.py              # scenario generation per category
│   ├── validators.py           # grounding, static and transcript judging
│   ├── grounding_repair.py     # swaps invented record IDs for real ones
│   ├── executor.py             # multi-turn Langflow scenario execution
│   ├── audit_judge.py          # verdict from the workflow's tool-call log
│   ├── session_marker.py       # attributes tool calls to a scenario
│   ├── flow_inventory.py       # extracts agents/tools/edges from a flow
│   ├── attack_surface.py       # renders the workflow for the model
│   ├── context.py, database.py # workflow context and optional DB inspection
│   ├── reporter.py             # report.json / report.md
│   ├── rejudge.py              # re-score a stored run
│   ├── remediate.py            # explain confirmed issues and fixes
│   ├── pdf_export.py           # PDF report export
│   ├── webapp.py               # Flask dashboard
│   ├── static/, templates/     # dashboard front end
│   ├── clients/                # Langflow and model clients
│   └── config.py, schemas.py, prompts.py, store.py, utils.py, ...
├── config/guardian.yaml        # categories and run settings
├── data/                       # example context files
├── langflow_refund_database/   # demo refund workflow, MCP tools, optional enforcement gate
├── scripts/                    # list flows, smoke-test connections
├── tests/
├── .env.example
├── requirements.txt            # core dependencies
└── requirements-ui.txt         # dashboard dependency (Flask)
```

## Output Structure

Each run writes to `runs/<run-id>/`:

```text
runs/<run-id>/
├── manifest.json
├── flow_inventory.json
├── flow_snapshot.redacted.json
├── setup_context.json
├── planning/
│   ├── scenarios.jsonl
│   ├── grounding.jsonl
│   └── static_assessments.jsonl
├── execution/
│   └── transcripts.jsonl          # only when run with --execute
├── results/
│   └── scenario_results.jsonl     # only when run with --execute
├── categories/
│   └── <category>.json
├── report.json
├── report.md
└── remediation.md                 # only after `remediate` / "Explain & fix"
```

## Safety

- Keys whose names look like credentials (api key, secret, token, password, authorization, private key) are redacted before workflow data is stored or sent to the model.
- From the CLI, live execution is blocked unless you pass `--confirm-side-effects` or set `GUARDIAN_ALLOW_SIDE_EFFECTS=true`.
- **The dashboard's "Run full evaluation" button executes scenarios with side effects confirmed automatically.** Only point it at a test environment.
- Live database inspection is read-only and limited to the tables you list. If `GUARDIAN_DB_URL` is set, Guardian also records a small session marker in a dedicated control table (`guardian_active_session`) to match tool calls to scenarios. It does not write to business tables.
- GuardianAI is intended for authorised testing of workflows you own or are permitted to test. See [SECURITY.md](SECURITY.md).

## Model Endpoint

GuardianAI talks to the Guardian model over an OpenAI-compatible chat-completions API. The model can run remotely (for example on Colab or Kaggle, reached over Tailscale) while Langflow stays on your machine. See [Model Configuration](docs/MODEL_CONFIGURATION.md). Model training code is not part of this repository.
