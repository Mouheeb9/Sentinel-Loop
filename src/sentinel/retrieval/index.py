"""Build / refresh the pgvector index from the ATT&CK and Sigma corpora.

    uv run python -m sentinel.retrieval.index

Resumable: chunks whose text and model are unchanged are skipped, and every batch is
committed, so an interrupted run picks up where it stopped.
"""

from __future__ import annotations

import time
from collections.abc import Callable

import numpy as np
import psycopg

from sentinel.retrieval import store
from sentinel.retrieval.attack import load_attack_chunks
from sentinel.retrieval.chunks import Chunk
from sentinel.retrieval.embed import embed_texts
from sentinel.retrieval.sigma import load_sigma_chunks

Embedder = Callable[[list[str]], list[np.ndarray]]


def build_index(
    conn: psycopg.Connection,
    chunks: list[Chunk],
    embed: Embedder = embed_texts,
    batch_size: int = 16,
    log: Callable[[str], None] = print,
) -> dict[str, int]:
    duplicates = len(chunks) - len({c.id for c in chunks})
    if duplicates:
        raise ValueError(f"{duplicates} duplicate chunk ids — ids must be unique across corpora")

    have = store.stored_hashes(conn)
    pending = [c for c in chunks if have.get(c.id) != store.content_hash(c)]
    # Similar lengths in a batch means less padding, which is most of the CPU cost.
    pending.sort(key=lambda c: len(c.text))

    started = time.time()
    for i in range(0, len(pending), batch_size):
        batch = pending[i : i + batch_size]
        store.upsert_chunks(conn, batch, embed([c.text for c in batch]))
        done = i + len(batch)
        log(f"embedded {done}/{len(pending)}  ({time.time() - started:.0f}s)")

    removed = store.delete_stale(conn, [c.id for c in chunks])
    return {
        "total": len(chunks),
        "embedded": len(pending),
        "skipped": len(chunks) - len(pending),
        "removed": removed,
    }


def main() -> None:
    chunks = load_attack_chunks() + load_sigma_chunks()
    with store.connect() as conn:
        print(build_index(conn, chunks))


if __name__ == "__main__":
    main()
