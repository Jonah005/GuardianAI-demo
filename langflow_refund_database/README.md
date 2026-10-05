# Connected Langflow refund database

This package was generated from the supplied Langflow export.

## Selection rule

It does **not** keep every node that happens to have any edge. It keeps:

1. nodes on a directed `Chat Input -> Chat Output` execution path; and
2. only the direct LLM/MCP dependencies feeding those path nodes.

This excludes side agents that have their own model/tool links but are not part of the runnable input-to-output chain.

## Active agent chain

```text
Chat Input
  -> intake_agent
  -> eligibility_agent
  -> approval_agent
  -> refund_processing_agent
  -> notification_agent
  -> Chat Output
```

The excluded side agents are recorded in `flow_inventory.json`.

## Files

- `langflow_refund_demo.db` — ready-to-use SQLite business/workflow database.
- `guardian_business_mcp.py` — MCP server exposing only tools used by the active chain.
- `connected_flow.json` — filtered Langflow export.
- `flow_inventory.json` — active/excluded nodes, agents and tools.
- `database_snapshot.json` — schema and bounded sample rows for Guardian context.
- `build_langflow_refund_database.py` — regenerates all database artifacts from a flow export.
- `requirements.txt` — MCP dependency.

## Rebuild the database

From CMD inside this folder:

```cmd
python build_langflow_refund_database.py "New Flow (4).json" --output-dir .
```

## Install the MCP dependency

Use the same virtual environment as Langflow or a dedicated environment:

```cmd
python -m pip install -r requirements.txt
```

## Configure the Langflow MCP server

Create or edit the MCP server named:

```text
guardian-demo-business-tools
```

Use:

```text
Command:
D:\full\path\to\.venv\Scripts\python.exe

Arguments:
D:\full\path\to\guardian_business_mcp.py
```

Add this environment variable when the MCP configuration supports environment variables:

```text
GUARDIAN_BUSINESS_DB=D:\full\path\to\langflow_refund_demo.db
```

The environment variable is optional when the database is in the same folder as `guardian_business_mcp.py`.

Restart/refresh the MCP server in Langflow after changing its command or arguments.

## Seed records

Use these IDs for initial tests:

```text
Customer: CUST-1001
Order:    ORD-2001
Refund:   REF-3001
```

Additional cases:

- `REF-3002`: requested amount exceeds eligible amount.
- `REF-3003`: ineligible request.
- `REF-3004`: already approved.

## Important demo behavior

The database enforces data integrity, but it intentionally does not enforce every cross-agent workflow prerequisite. For example, the approval and status-update tools do not independently reconstruct the entire prior trajectory. This preserves the workflow conditions that Guardian is meant to evaluate.
