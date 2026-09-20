import hashlib
import uuid

import numpy as np
import psycopg
import pytest
from pgvector.psycopg import register_vector

from sentinel.retrieval import store
from sentinel.retrieval.chunks import Chunk
from sentinel.retrieval.embed import DIM
from sentinel.retrieval.index import build_index


def fake_embed(texts: list[str]) -> list[np.ndarray]:
    """Deterministic stand-in for the model: same text -> same vector."""
    out = []
    for t in texts:
        seed = int.from_bytes(hashlib.sha256(t.encode()).digest()[:4], "little")
        out.append(np.random.default_rng(seed).random(DIM, dtype=np.float32))
    return out


def chunk(cid: str, text: str, **kw) -> Chunk:
    return Chunk(id=cid, kind="technique", title=f"title {cid}", text=text, **kw)


@pytest.fixture
def conn():
    """A connection whose tables live in a throwaway schema, never in the real `chunks`."""
    try:
        c = psycopg.connect(store.database_url(), autocommit=True, connect_timeout=3)
    except psycopg.OperationalError:
        pytest.skip("Postgres not reachable (docker compose up -d postgres)")
    schema = f"test_{uuid.uuid4().hex[:8]}"
    c.execute("CREATE EXTENSION IF NOT EXISTS vector")
    c.execute(f"CREATE SCHEMA {schema}")
    c.execute(f"SET search_path TO {schema}, public")
    register_vector(c)
    store.ensure_schema(c)
    yield c
    c.execute(f"DROP SCHEMA {schema} CASCADE")
    c.close()


def test_content_hash_changes_with_text():
    assert store.content_hash(chunk("A", "one")) != store.content_hash(chunk("A", "two"))
    assert store.content_hash(chunk("A", "one")) == store.content_hash(chunk("B", "one"))


def test_indexes_everything_then_second_run_skips_all(conn):
    chunks = [chunk("T1", "alpha", platforms=["windows"]), chunk("T2", "beta")]
    first = build_index(conn, chunks, embed=fake_embed, log=lambda _: None)
    assert first == {"total": 2, "embedded": 2, "skipped": 0, "removed": 0}

    calls: list[list[str]] = []
    second = build_index(
        conn, chunks, embed=lambda t: calls.append(t) or fake_embed(t), log=lambda _: None
    )
    assert second["embedded"] == 0 and second["skipped"] == 2
    assert calls == []  # no model call at all when nothing changed


def test_only_changed_chunk_is_re_embedded_and_row_is_updated(conn):
    build_index(conn, [chunk("T1", "alpha"), chunk("T2", "beta")], embed=fake_embed, log=print)
    stats = build_index(
        conn, [chunk("T1", "alpha"), chunk("T2", "beta CHANGED")], embed=fake_embed, log=print
    )
    assert stats["embedded"] == 1 and stats["skipped"] == 1
    assert conn.execute("SELECT text FROM chunks WHERE id='T2'").fetchone() == ("beta CHANGED",)


def test_chunks_that_left_the_corpus_are_removed(conn):
    build_index(conn, [chunk("T1", "a"), chunk("T2", "b")], embed=fake_embed, log=print)
    stats = build_index(conn, [chunk("T1", "a")], embed=fake_embed, log=print)
    assert stats["removed"] == 1
    assert conn.execute("SELECT id FROM chunks").fetchall() == [("T1",)]


def test_duplicate_ids_are_rejected(conn):
    with pytest.raises(ValueError, match="duplicate"):
        build_index(conn, [chunk("T1", "a"), chunk("T1", "b")], embed=fake_embed)


def test_row_roundtrip_keeps_metadata_vector_and_search_column(conn):
    c = chunk(
        "T1003.001",
        "dump lsass.exe memory",
        platforms=["windows"],
        technique_ids=["T1003.001"],
    )
    build_index(conn, [c], embed=fake_embed, log=print)
    platforms, tids, dims = conn.execute(
        "SELECT platforms, technique_ids, vector_dims(embedding) FROM chunks"
    ).fetchone()
    assert (platforms, tids, dims) == (["windows"], ["T1003.001"], DIM)
    # the generated tsvector column is what step 4's exact-identifier matching will use
    hit = conn.execute(
        "SELECT count(*) FROM chunks WHERE tsv @@ plainto_tsquery('simple', 'lsass.exe')"
    ).fetchone()
    assert hit == (1,)


def test_hnsw_index_exists(conn):
    indexes = {
        r[0] for r in conn.execute("SELECT indexname FROM pg_indexes WHERE tablename='chunks'")
    }
    assert "chunks_embedding_hnsw" in indexes
