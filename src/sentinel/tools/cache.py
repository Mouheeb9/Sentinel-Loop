"""Postgres cache for enrichment tool responses.

NVD allows 50 requests per 30 s with a key and answers slowly; an eval run over 150 alerts would
spend most of its time waiting on it. So every successful answer (including "not found") is
stored under (tool, key) and reused until it is older than the tool's TTL. Transport errors are
never cached.

SENTINEL_TOOL_CACHE=frozen ignores the TTL: a cached answer is reused forever. Use it for eval
runs, so a ThreatFox entry appearing between two runs can't move the score.
"""

from __future__ import annotations

import os
from datetime import timedelta
from typing import Protocol

import psycopg
from psycopg.types.json import Jsonb

from sentinel.retrieval.store import database_url

_SCHEMA = """
CREATE TABLE IF NOT EXISTS tool_cache (
    tool       text NOT NULL,
    key        text NOT NULL,
    response   jsonb NOT NULL,
    fetched_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tool, key)
);
"""


def frozen() -> bool:
    return os.environ.get("SENTINEL_TOOL_CACHE", "").lower() == "frozen"


class ToolCache(Protocol):
    def get(self, tool: str, key: str, ttl: timedelta) -> dict | None: ...
    def put(self, tool: str, key: str, response: dict) -> None: ...


class PgToolCache:
    def __init__(self, url: str | None = None) -> None:
        self._url = url or database_url()
        self._ready = False

    def _connect(self) -> psycopg.Connection:
        conn = psycopg.connect(self._url, autocommit=True)
        if not self._ready:
            conn.execute(_SCHEMA)
            self._ready = True
        return conn

    def get(self, tool: str, key: str, ttl: timedelta) -> dict | None:
        sql = "SELECT response FROM tool_cache WHERE tool = %s AND key = %s"
        params: tuple = (tool, key)
        if not frozen():
            sql += " AND fetched_at > now() - %s"
            params += (ttl,)
        with self._connect() as conn:
            row = conn.execute(sql, params).fetchone()
        return row[0] if row else None

    def put(self, tool: str, key: str, response: dict) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO tool_cache (tool, key, response) VALUES (%s, %s, %s)
                ON CONFLICT (tool, key) DO UPDATE
                SET response = EXCLUDED.response, fetched_at = now()
                """,
                (tool, key, Jsonb(response)),
            )


class MemoryToolCache:
    """Same interface, no TTL, for tests."""

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict] = {}

    def get(self, tool: str, key: str, ttl: timedelta) -> dict | None:
        return self.rows.get((tool, key))

    def put(self, tool: str, key: str, response: dict) -> None:
        self.rows[(tool, key)] = response


_default: ToolCache | None = None


def default_cache() -> ToolCache:
    global _default
    if _default is None:
        _default = PgToolCache()
    return _default


def set_default_cache(cache: ToolCache | None) -> None:
    global _default
    _default = cache
