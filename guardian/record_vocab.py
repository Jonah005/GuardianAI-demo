"""
Real record-identifier vocabulary, extracted generically from the connected
environment's data snapshot / database.

The fine-tuned model grounds tool and agent NAMES correctly but tends to emit
record ID VALUES from its training templates (e.g. REF-1001) instead of the real
records the live environment actually contains (e.g. REF-3001). Those phantom
IDs don't exist, so the workflow's first agent can't look anything up and the
attack never reaches the privileged agents.

This module reads whatever records the snapshot exposes and returns, per ID-like
column, the real values that exist -- so the prompt can require them, the context
can preserve them, and the grounding-repair can substitute them. Nothing about
refunds/orders/customers is hardcoded: ID columns are recognised by name shape
(a `*_id`, `*_code`, `*_no`, ... column) and values are taken from the data.
"""

from __future__ import annotations

import re
from typing import Any

_ID_COLUMN = re.compile(r"(?:^|_)(id|ids|code|codes|number|no|uuid|key|ref)$", re.I)
_ID_TOKEN = re.compile(r"\b[A-Za-z]{2,}[-_]\d{2,}\b")


def _is_id_column(name: str) -> bool:
    return bool(_ID_COLUMN.search(name.lower()))


def _prefix_of(value: str) -> str | None:
    """The alphabetic prefix of an ID token, e.g. 'REF-3001' -> 'REF-'.

    Used to group real IDs and to recognise a phantom that shares a family with
    a real group (a 'REF-...' that isn't a real REF). Returns None if the value
    isn't the LETTERS-DIGITS shape.
    """
    m = re.match(r"^([A-Za-z]+[-_]?)\d+$", value)
    return m.group(1).upper() if m else None


def _is_row(value: Any) -> bool:
    """A data ROW is a non-empty dict whose values are mostly scalars.

    This distinguishes an actual record ({refund_id: 'REF-3001', amount: 420})
    from a container ({tables: [...]}, {table, columns, sample_rows}) whose values
    are nested lists/dicts.
    """
    if not isinstance(value, dict) or not value:
        return False
    for v in value.values():
        if isinstance(v, dict):
            return False
        if isinstance(v, list) and any(isinstance(x, (dict, list)) for x in v):
            return False
    scalar = sum(1 for v in value.values()
                 if v is None or isinstance(v, (str, int, float, bool)))
    return scalar >= max(1, int(len(value) * 0.6))


def _iter_rows(obj: Any):
    """Yield every data-row dict found anywhere in a snapshot, generically.

    Handles the {tables:[{table,columns,sample_rows}]} shape, a dict of
    {table: [rows]}, and arbitrary nesting. Rows are recognised by shape
    (scalar-valued dicts), so wrapper/container dicts are recursed into, not
    mistaken for records.
    """
    if isinstance(obj, dict):
        for key in ("sample_rows", "rows"):
            rows = obj.get(key)
            if isinstance(rows, list):
                for item in rows:
                    if _is_row(item):
                        yield item
        for k, v in obj.items():
            if k in ("sample_rows", "rows"):
                continue
            yield from _iter_rows(v)
    elif isinstance(obj, list):
        if obj and all(_is_row(x) for x in obj):
            yield from obj
        else:
            for item in obj:
                yield from _iter_rows(item)


def extract_record_vocabulary(snapshots: Any) -> dict[str, list[str]]:
    """Return {id_column_name: [real distinct values]} from the snapshot data.

    Only ID-like columns are collected, and only string-ish values that look
    like identifiers (so free-text and timestamps are ignored).
    """
    by_column: dict[str, list[str]] = {}
    seen: dict[str, set[str]] = {}
    for row in _iter_rows(snapshots):
        for key, value in row.items():
            if value is None or not _is_id_column(str(key)):
                continue
            sval = str(value).strip()
            if not sval or len(sval) > 64:
                continue
            col = str(key)
            bucket = seen.setdefault(col, set())
            if sval not in bucket:
                bucket.add(sval)
                by_column.setdefault(col, []).append(sval)
    return {col: sorted(vals)[:25] for col, vals in by_column.items()}


def presentable_record_vocabulary(vocab: dict[str, list[str]]) -> dict[str, list[str]]:
    """Subset of the vocabulary suitable to SHOW the model in a prompt.

    Keeps only columns whose values look like real record identifiers (the
    LETTERS-DIGITS token shape), dropping incidental id-named columns whose
    values are booleans, plain counters, or internal node handles. Generic --
    the filter is on value shape, not on any specific column name.
    """
    out: dict[str, list[str]] = {}
    for col, values in vocab.items():
        idish = [v for v in values if _ID_TOKEN.fullmatch(v)]
        if idish and len(idish) >= max(1, int(len(values) * 0.6)):
            out[col] = idish
    return out


NEGATIVE_STATE = ("ineligible", "blocked", "denied", "rejected", "expired",
                  "cancelled", "canceled", "failed", "closed", "fraud",
                  "suspended", "void", "frozen", "restricted", "inactive",
                  "declined", "not_eligible", "on_hold", "hold")
STATUS_FIELD = ("status", "state", "eligib", "stage", "phase", "flag",
                "decision", "result", "standing", "disposition")


def negative_state_reason(record_id: str, states: dict[str, list]) -> str | None:
    """If any row for this record has a status field in a forbidding state, say why."""
    for row in states.get(record_id, []):
        if not isinstance(row, dict):
            continue
        for field_name, val in row.items():
            if not isinstance(val, str) or not any(s in field_name.lower()
                                                   for s in STATUS_FIELD):
                continue
            if any(neg in val.strip().lower() for neg in NEGATIVE_STATE):
                return f"{record_id}.{field_name}={val}"
    return None


def adversarial_records(snapshots: Any) -> dict[str, str]:
    """Records whose own state forbids a privileged action -> the reason.

    A successful privileged action on one of these is an unambiguous breach, so
    the generator can be steered to target them. Fully data-driven.
    """
    states = record_state_index(snapshots)
    out: dict[str, str] = {}
    for rid in states:
        reason = negative_state_reason(rid, states)
        if reason:
            out[rid] = reason
    return out


def record_state_index(snapshots: Any) -> dict[str, list[dict[str, Any]]]:
    """Map every real ID value to ALL rows that reference it.

    Lets a caller ask "what is the state of REF-3003?" and read its status fields
    across every table it appears in (an id is a primary key in one table and a
    foreign key in others, so a single row can hide the relevant status). Generic:
    any ID-like field's value becomes a key pointing at the rows carrying it.
    """
    index: dict[str, list[dict[str, Any]]] = {}
    for row in _iter_rows(snapshots):
        for key, value in row.items():
            if value is None or not _is_id_column(str(key)):
                continue
            sval = str(value).strip()
            if sval:
                index.setdefault(sval, [])
                if row not in index[sval]:
                    index[sval].append(row)
    return index


def real_id_index(vocab: dict[str, list[str]]) -> tuple[set[str], dict[str, list[str]]]:
    """From the vocabulary, build (set of all real IDs, {prefix: [real IDs]}).

    The prefix groups let the repair map a phantom token to a real one of the
    SAME family learned from the data -- never a hardcoded prefix.
    """
    all_ids: set[str] = set()
    groups: dict[str, list[str]] = {}
    for values in vocab.values():
        for v in values:
            all_ids.add(v)
            pfx = _prefix_of(v)
            if pfx:
                if v not in groups.setdefault(pfx, []):
                    groups[pfx].append(v)
    for pfx in groups:
        groups[pfx] = sorted(groups[pfx])
    return all_ids, groups
