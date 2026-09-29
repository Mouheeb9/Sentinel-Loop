"""Run one Sigma rule over events: the contract between the route node (Mouheb) and the
validation stack (Mouadh, docs/validation-setup.md).

Owner: Mouadh (Day 11). Change the signature only by a PR both of us review, like `schemas.py`.

How: the same engine Zircolite runs on. pySigma converts the rule to SQL (sqlite backend + the
Sysmon pipeline, which adds the EventID filter for each logsource category), the events' `raw`
dicts are loaded into an in-memory SQLite table, and the query runs there. In-process, so one rule
over one alert takes milliseconds, and nothing is written to disk.

Sigma semantics kept: values match case-insensitively (columns are COLLATE NOCASE, LIKE is
case-insensitive), a field an event doesn't have is NULL, `|re` uses Python regex.
"""

from __future__ import annotations

import json
import re
import sqlite3
from typing import Any

from sigma.backends.sqlite import sqlite as sigma_sqlite
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError
from sigma.pipelines.sysmon import sysmon_pipeline

from sentinel.schemas import Event

_ID_COLUMN = "sentinel_event_id"  # not a Sysmon field name, so it can't collide
_TABLE = "logs"  # the table name the sqlite backend queries


def match(rule_yaml: str, events: list[Event]) -> list[str]:
    """The `event_id`s of the events the rule fires on ([] when it fires on none).

    Raises ValueError when the rule can't be compiled, so a broken rule is never mistaken for
    "does not fire".
    """
    queries, fields = _compile(rule_yaml)
    if not events:
        return []
    db = _load(events, fields)
    try:
        fired: set[str] = set()
        for sql in queries:
            cursor = db.execute(sql)
            index = [d[0] for d in cursor.description].index(_ID_COLUMN)
            fired.update(row[index] for row in cursor)
    finally:
        db.close()
    return [e.event_id for e in events if e.event_id in fired]  # input order, no duplicates


def _compile(rule_yaml: str) -> tuple[list[str], set[str]]:
    """SQL queries for the rule, and every field it reads (so missing ones become NULL columns)."""
    try:
        collection = SigmaCollection.from_yaml(rule_yaml)
        backend = sigma_sqlite.sqliteBackend(sysmon_pipeline())
        converted = backend.convert(collection, "zircolite")
    except SigmaError as e:
        raise ValueError(f"rule does not compile: {e}") from e
    except Exception as e:  # yaml and pySigma internals raise a wide mix: all mean "broken rule"
        raise ValueError(f"rule does not compile: {type(e).__name__}: {e}") from e
    rules = json.loads(converted) if isinstance(converted, str) else converted
    queries = [q for r in rules for q in r.get("rule", [])]
    if not queries:
        raise ValueError("rule does not compile: no query produced")
    fields = {f for r in rules for f in r.get("required_fields", [])}
    return queries, fields


def _load(events: list[Event], rule_fields: set[str]) -> sqlite3.Connection:
    columns = sorted({k for e in events for k in e.raw} | rule_fields | {"EventID"})
    columns = [c for c in columns if c != _ID_COLUMN]
    db = sqlite3.connect(":memory:")
    db.create_function("regexp", 2, _regexp, deterministic=True)
    defs = ", ".join(f"{_quote(c)} TEXT COLLATE NOCASE" for c in [_ID_COLUMN, *columns])
    db.execute(f"CREATE TABLE {_TABLE} ({defs})")
    placeholders = ", ".join("?" for _ in range(len(columns) + 1))
    db.executemany(
        f"INSERT INTO {_TABLE} VALUES ({placeholders})",
        [[e.event_id, *(_text(e.raw.get(c)) for c in columns)] for e in events],
    )
    return db


def _quote(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _text(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def _regexp(pattern: str, value: str | None) -> bool:
    """SQLite calls `value REGEXP pattern` as regexp(pattern, value)."""
    return value is not None and re.search(pattern, value) is not None
