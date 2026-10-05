# Setup and Usage Guide

## Requirements

- Python 3.10 or newer
- A running [Langflow](https://www.langflow.org/) instance containing the workflow to test
- A Guardian model served over an OpenAI-compatible chat-completions API (see [Model Configuration](MODEL_CONFIGURATION.md))

## 1. Install

From the repository root.

Windows (PowerShell):

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-ui.txt
Copy-Item .env.example .env
```

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt -r requirements-ui.txt
cp .env.example .env
```

`requirements-ui.txt` (Flask) is only needed for the dashboard. Optionally install the `guardian` command:

```bash
pip install -e .
guardian --help
```

## 2. Configure `.env`

Open `.env` and set the Langflow and model values:

```env
LANGFLOW_URL=http://127.0.0.1:7860
LANGFLOW_API_KEY=your-langflow-api-key
LANGFLOW_FLOW_ID=your-flow-id

GUARDIAN_MODEL_BASE_URL=http://your-model-host:8000/v1
GUARDIAN_MODEL_NAME=your-model-name
GUARDIAN_MODEL_API_KEY=your-model-api-key
```

`LANGFLOW_FLOW_ID`, `GUARDIAN_MODEL_BASE_URL` and `GUARDIAN_MODEL_NAME` are required. If you do not know your flow ID, run `python scripts/list_langflow_flows.py` once Langflow is running.

For judging results from the workflow's own tool-call log, also set `GUARDIAN_DB_URL` to the workflow's database. See [Configuration](CONFIGURATION.md#guardian_db_url).

All model options are in [Model Configuration](MODEL_CONFIGURATION.md).

## 3. Set up the demo workflow (optional)

The repository includes a demo refund workflow with a SQLite database and an MCP tool server. To use it:

1. Generate the database. It is not committed, because `*.db` is git-ignored:
   ```bash
   cd langflow_refund_database
   python build_langflow_refund_database.py "New Flow (4).json" --output-dir .
   ```
2. Install the MCP dependency and register the MCP server in Langflow as described in [`langflow_refund_database/README.md`](../langflow_refund_database/README.md).
3. Point `config/guardian.yaml` at its snapshot (this is the repository default):
   ```yaml
   context:
     snapshot_files:
       - langflow_refund_database/database_snapshot.json
   ```

To test your own workflow instead, replace `snapshot_files` with your own context files and, if useful, set `process_graph_file`. Supported formats are JSON, JSONL, YAML, CSV, plain text and Markdown. Paths are relative to the repository root. The files in `data/` are generic examples.

## 4. Check connections

```bash
python -m guardian doctor
```

This sends a short test message to the model and reads the flow from Langflow. It does not run the workflow.

## 5. Inspect the workflow

```bash
python -m guardian inspect-flow --output flow_inventory.json
```

This saves the extracted agents, tools and components so you can confirm they were detected correctly.

## 6. Generate and validate scenarios (no execution)

```bash
python -m guardian run
```

This runs planning, grounding checks, static assessment and revision loops, then writes a report. It does not call the Langflow run endpoint.

## 7. Execute scenarios against the workflow

Use a test database and test integrations. Execution may write data, send notifications or call external services.

```bash
python -m guardian run --execute --confirm-side-effects
```

To skip the flag on repeated runs in a test environment, set `GUARDIAN_ALLOW_SIDE_EFFECTS=true` in `.env`.

## 8. Use the dashboard

```bash
python app.py
```

This starts a local web UI (default `http://127.0.0.1:5050`, opening in your browser) where you can pick the model, run a full evaluation, view past runs, and use **Re-judge** and **Explain & fix**. Results can be exported as a PDF.

Dashboard runs always execute with side effects confirmed, so use it only against a test environment. Set `GUARDIAN_UI_PORT` to change the port and `GUARDIAN_UI_NO_BROWSER=1` to stop it opening a browser.

## 9. Review and re-process a run

Artifacts are written to `runs/<run-id>/`. The main outputs are `report.json` and `report.md`.

```bash
python -m guardian show-report runs/<run-id>/report.json
python -m guardian rejudge --run latest
python -m guardian remediate --run latest
```

- `rejudge` re-scores a stored run with the current judge logic. It does not generate scenarios or call Langflow.
- `remediate` asks the Guardian model to explain each confirmed vulnerability and how to fix it. It writes `remediation.md` and updates the report.
- `--run` accepts a run ID or `latest`.

## 10. Run the tests

```bash
pytest
```
