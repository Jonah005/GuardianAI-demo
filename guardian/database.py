from __future__ import annotations

from typing import Any

from sqlalchemy import MetaData, Table, create_engine, inspect, select
from sqlalchemy.engine import Engine

from guardian.config import DatabaseConfig
from guardian.utils import redact_secrets


class DatabaseContextError(RuntimeError):
    pass


def _split_table_name(name: str) -> tuple[str | None, str]:
    if "." in name:
        schema, table = name.split(".", 1)
        return schema, table
    return None, name


def inspect_database(url: str, config: DatabaseConfig) -> dict[str, Any]:
    if not url:
        return {"enabled": True, "connected": False, "error": "GUARDIAN_DB_URL is empty"}

    engine: Engine = create_engine(url, pool_pre_ping=True)
    try:
        inspector = inspect(engine)
        default_schema = inspector.default_schema_name
        schema_names = [default_schema] if default_schema else [None]
        output: dict[str, Any] = {
            "enabled": True,
            "connected": True,
            "dialect": engine.dialect.name,
            "default_schema": default_schema,
            "schemas": {},
            "samples": {},
        }

        if config.include_schema:
            for schema in schema_names:
                tables = inspector.get_table_names(schema=schema)
                views = inspector.get_view_names(schema=schema) if config.include_views else []
                schema_key = schema or "default"
                schema_doc: dict[str, Any] = {"tables": {}, "views": views}
                for table_name in tables:
                    columns = inspector.get_columns(table_name, schema=schema)
                    schema_doc["tables"][table_name] = [
                        {
                            "name": column.get("name"),
                            "type": str(column.get("type")),
                            "nullable": column.get("nullable"),
                            "default": str(column.get("default")) if column.get("default") is not None else None,
                        }
                        for column in columns
                    ]
                output["schemas"][schema_key] = schema_doc

        if config.sample_rows > 0:
            metadata = MetaData()
            for requested in config.sample_tables:
                schema, table_name = _split_table_name(requested)
                table = Table(table_name, metadata, schema=schema, autoload_with=engine)
                statement = select(table).limit(config.sample_rows)
                with engine.connect() as connection:
                    rows = [dict(row._mapping) for row in connection.execute(statement)]
                output["samples"][requested] = redact_secrets(rows)
        return redact_secrets(output)
    except Exception as exc:
        raise DatabaseContextError(f"Database inspection failed: {exc}") from exc
    finally:
        engine.dispose()
