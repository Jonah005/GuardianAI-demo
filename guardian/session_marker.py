"""
Scenario session bracket.

The runner opens a bracket in the workflow database immediately before it calls
the flow for a scenario, and closes it right after the flow returns. While the
bracket is open, the workflow's `audit()` stamps that session_id onto every
tool-call row it writes -- letting the audit judge attribute calls to a scenario
EXACTLY, instead of by wall-clock time.

Generic and optional: it uses the same GUARDIAN_DB_URL the runner already reads.
If no DB is configured it is a no-op, so the pipeline is unaffected when running
without a database. It writes only to a generic control table
(`guardian_active_session`) and never touches business tables.
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Iterator

from sqlalchemy import create_engine, text

LOGGER = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def session_bracket(database_url: str, session_id: str) -> Iterator[None]:
    """Open a session bracket for the duration of the block.

    On any error (including no DB configured) this quietly does nothing so a
    correlation aid never breaks execution.
    """
    url = (database_url or "").strip()
    if not url:
        yield
        return

    engine = None
    opened = False
    run_tag = f"pid{os.getpid()}"
    try:
        engine = create_engine(url, pool_pre_ping=True)
        with engine.begin() as conn:
            conn.execute(text(
                "CREATE TABLE IF NOT EXISTS guardian_active_session ("
                "session_id TEXT NOT NULL, run_tag TEXT, "
                "started_at TEXT NOT NULL, ended_at TEXT)"
            ))
            conn.execute(
                text("INSERT INTO guardian_active_session "
                     "(session_id, run_tag, started_at, ended_at) "
                     "VALUES (:s, :r, :t, NULL)"),
                {"s": session_id, "r": run_tag, "t": _now()},
            )
        opened = True
    except Exception as exc:        LOGGER.warning("session bracket could not open (%s); "
                       "audit judge will use time-window correlation", exc)

    try:
        yield
    finally:
        if opened and engine is not None:
            try:
                with engine.begin() as conn:
                    conn.execute(
                        text("UPDATE guardian_active_session SET ended_at = :t "
                             "WHERE session_id = :s AND ended_at IS NULL"),
                        {"t": _now(), "s": session_id},
                    )
            except Exception as exc:                LOGGER.warning("session bracket could not close (%s)", exc)
        if engine is not None:
            engine.dispose()
