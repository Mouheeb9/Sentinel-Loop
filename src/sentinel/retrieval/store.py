"""pgvector storage for retrieval chunks."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence

import numpy as np
import psycopg
from pgvector.psycopg import register_vector

from sentinel.retrieval.chunks import Chunk
from sentinel.retrieval.embed import DIM, MODEL_NAME

# Matches docker-compose.yml (host port 5433: native Postgres already owns 5432).
DEFAULT_DATABASE_URL = "postgresql://sentinel:sentinel@localhost:5433/sentinel"

_SCHEMA = f"""
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS chunks (
    id            text PRIMARY KEY,
    kind          text NOT NULL CHECK (kind IN ('technique', 'sigma_rule')),
    title         text NOT NULL,
    text          text NOT NULL,
    platforms     text[] NOT NULL DEFAULT '{{}}',
    logsource     text,
    technique_ids text[] NOT NULL DEFAULT '{{}}',
    content_hash  text NOT NULL,
    embedding     vector({DIM}) NOT NULL,
    -- 'simple' = no stemming or stop words, so identifiers like T1003.001 or lsass.exe survive
    tsv           tsvector GENERATED ALWAYS AS (to_tsvector('simple', title || ' ' || text)) STORED
);

CREATE INDEX IF NOT EXISTS chunks_embedding_hnsw
    ON chunks USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS chunks_tsv_gin ON chunks USING gin (tsv);
CREATE INDEX IF NOT EXISTS chunks_platforms_gin ON chunks USING gin (platforms);
CREATE INDEX IF NOT EXISTS chunks_technique_ids_gin ON chunks USING gin (technique_ids);
"""

_UPSERT = """
INSERT INTO chunks (id, kind, title, text, platforms, logsource, technique_ids,
                    content_hash, embedding)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (id) DO UPDATE SET
    kind = EXCLUDED.kind, title = EXCLUDED.title, text = EXCLUDED.text,
    platforms = EXCLUDED.platforms, logsource = EXCLUDED.logsource,
    technique_ids = EXCLUDED.technique_ids, content_hash = EXCLUDED.content_hash,
    embedding = EXCLUDED.embedding
"""


def database_url() -> str:
    return os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)


def content_hash(chunk: Chunk) -> str:
    """Changes when the text or the embedding model changes -> triggers a re-embed."""
    return hashlib.sha256(f"{MODEL_NAME}\n{chunk.text}".encode()).hexdigest()


def connect(url: str | None = None) -> psycopg.Connection:
    """Open a connection and make sure the schema exists. Extension first, then register."""
    conn = psycopg.connect(url or database_url(), autocommit=True)
    conn.execute("CREATE EXTENSION IF NOT EXISTS vector")
    register_vector(conn)
    ensure_schema(conn)
    return conn


def ensure_schema(conn: psycopg.Connection) -> None:
    conn.execute(_SCHEMA)


def stored_hashes(conn: psycopg.Connection) -> dict[str, str]:
    return dict(conn.execute("SELECT id, content_hash FROM chunks").fetchall())


def upsert_chunks(
    conn: psycopg.Connection, chunks: Sequence[Chunk], embeddings: Sequence[np.ndarray]
) -> None:
    rows = [
        (
            c.id,
            c.kind,
            c.title,
            c.text,
            c.platforms,
            c.logsource,
            c.technique_ids,
            content_hash(c),
            np.asarray(e, dtype=np.float32),
        )
        for c, e in zip(chunks, embeddings, strict=True)
    ]
    with conn.transaction(), conn.cursor() as cur:
        cur.executemany(_UPSERT, rows)


def delete_stale(conn: psycopg.Connection, keep_ids: Sequence[str]) -> int:
    """Remove rows for chunks that left the corpus (e.g. a technique revoked upstream)."""
    return conn.execute("DELETE FROM chunks WHERE id <> ALL(%s)", (list(keep_ids),)).rowcount
