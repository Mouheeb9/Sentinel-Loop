"""Hybrid retrieval over the chunk index: exact IDs + vector similarity + lexical, with filters.

Pure semantic search over security text is mediocre because half the signal is exact
identifiers (`T1003.001`, `lsass.exe`, `vssadmin`). So results come from three sources:

1. exact ATT&CK IDs found in the query (pinned first),
2. vector similarity over the embeddings,
3. full-text match on the query's *rare* words, weighted by rarity (IDF). This leg exists to
   catch exact identifiers the embedding blurs, so it only fires on words present in at most
   LEXICAL_MAX_DF of the chunks being searched, plus identifier-shaped tokens (`lsass.exe`,
   `rundll32`, `445`) at any frequency. Ordinary words ("started", "windows") stay out: they add
   noise that pushes right answers the vector search had already found down the list.

Vector and lexical rankings are merged with reciprocal rank fusion (RRF), which needs no
score calibration between the two very different scales.

The lexical leg is OFF by default (`use_lexical=False`). Measured on 40 hand-written probes
(evals/results/v1_after.json, v2_after.json), vector-only beat hybrid on both sets — 0.90 vs
0.75 and 0.95 vs 0.90 recall@5 — because under RRF a chunk found by both lists outranks the
right chunk found by only the vector search. Exact ATT&CK IDs are pinned regardless. Re-test
with `use_lexical=True` on real alert-derived queries before turning it on.
"""

from __future__ import annotations

import math
import re
from typing import Literal

import psycopg
from pydantic import BaseModel

from sentinel.retrieval import store
from sentinel.retrieval.embed import embed_texts

POOL = 50  # candidates taken from each ranked list before fusion
RRF_K = 60  # standard RRF damping constant
LEXICAL_MAX_DF = 0.02  # a plain word is "rare" if it is in at most 2% of the searched chunks

_TECHNIQUE_ID = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_IDENTIFIER_SHAPED = re.compile(r"[\d._\\]")  # digit, dot, underscore or backslash
_WORD = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\\-]*")
_STOPWORDS = frozenset(
    "the and for with that this from into onto over under then than when where which while "
    "are was were has have had not but its their there they them can could would should will "
    "run runs ran use used uses using via per each any all one two new".split()
)

# ATT&CK and Sigma name platforms differently (ATT&CK: "iaas"; Sigma: "aws", "azure", "gcp").
# A group name expands to every raw value either corpus uses for it.
_PLATFORM_GROUPS: dict[str, frozenset[str]] = {
    "windows": frozenset({"windows"}),
    "linux": frozenset({"linux"}),
    "macos": frozenset({"macos"}),
    "esxi": frozenset({"esxi"}),
    "containers": frozenset({"containers", "kubernetes"}),
    "iaas": frozenset({"iaas", "aws", "azure", "gcp"}),
    "saas": frozenset({"saas", "m365", "github", "bitbucket"}),
    "office suite": frozenset({"office suite", "m365"}),
    "identity provider": frozenset({"identity provider", "okta", "onelogin"}),
    "network devices": frozenset({"network devices", "cisco", "juniper", "fortigate", "huawei"}),
}
_PLATFORM_ALIASES = {"cloud": "iaas", "mac": "macos", "osx": "macos", "network": "network devices"}


def expand_platform(platform: str) -> list[str]:
    """Raw platform values to match for a user-supplied platform name."""
    p = _PLATFORM_ALIASES.get(platform.strip().lower(), platform.strip().lower())
    if p in _PLATFORM_GROUPS:
        return sorted(_PLATFORM_GROUPS[p])
    # A raw product like "aws" matches itself plus the group(s) that contain it ("iaas").
    groups = [g for g, members in _PLATFORM_GROUPS.items() if p in members]
    return sorted({p, *groups})


class Hit(BaseModel):
    id: str
    kind: Literal["technique", "sigma_rule"]
    title: str
    text: str
    platforms: list[str]
    logsource: str | None
    technique_ids: list[str]
    score: float
    matched_by: list[str]  # any of "id", "vector", "lexical"


def _filters(
    kind: str | None, platform: str | None, logsource: str | None
) -> tuple[str, list[object]]:
    clauses, params = [], []
    if kind:
        clauses.append("kind = %s")
        params.append(kind)
    if platform:
        clauses.append("platforms && %s::text[]")
        params.append(expand_platform(platform))
    if logsource:
        # Technique chunks are not tied to a logsource, so they pass through this filter.
        clauses.append("(kind = 'technique' OR %s = ANY(string_to_array(logsource, '/')))")
        params.append(logsource.strip().lower())
    return (" AND ".join(clauses) or "TRUE"), params


def _lexical_terms(
    conn: psycopg.Connection, query: str, where: str = "TRUE", params: list[object] | None = None
) -> list[tuple[str, float]]:
    """Query words worth a lexical match, as (word, idf). Rarity is measured inside the filtered
    population, so a word that is common overall can still be rare among, say, techniques."""
    params = params or []
    total = conn.execute(f"SELECT count(*) FROM chunks WHERE {where}", params).fetchone()[0]
    if not total:
        return []
    terms: list[tuple[str, float]] = []
    for word in _WORD.findall(query.lower()):
        word = word.strip(".-\\")
        if len(word) < 3 or word in _STOPWORDS or any(word == t for t, _ in terms):
            continue
        df = conn.execute(
            f"SELECT count(*) FROM chunks WHERE ({where}) AND tsv @@ plainto_tsquery('simple', %s)",
            [*params, word],
        ).fetchone()[0]
        if df and (df <= LEXICAL_MAX_DF * total or _IDENTIFIER_SHAPED.search(word)):
            terms.append((word, math.log(total / df)))
    return terms


def _lexical_ranking(
    conn: psycopg.Connection, terms: list[tuple[str, float]], where: str, params: list[object]
) -> list[str]:
    """Chunk ids ranked by the summed IDF of the rare query words each one contains."""
    matched = " + ".join(
        ["(CASE WHEN tsv @@ plainto_tsquery('simple', %s) THEN %s::float8 ELSE 0 END)"] * len(terms)
    )
    weights = [x for term, idf in terms for x in (term, idf)]
    rows = conn.execute(
        f"SELECT id FROM (SELECT id, {matched} AS s FROM chunks WHERE {where}) t "
        "WHERE s > 0 ORDER BY s DESC, id LIMIT %s",
        [*weights, *params, POOL],
    )
    return [r[0] for r in rows]


def retrieve(
    query: str,
    k: int = 5,
    logsource: str | None = None,
    platform: str | None = None,
    *,
    kind: Literal["technique", "sigma_rule"] | None = None,
    conn: psycopg.Connection | None = None,
    use_lexical: bool = False,
) -> list[Hit]:
    owns_conn = conn is None
    conn = conn or store.connect()
    try:
        return _retrieve(conn, query, k, logsource, platform, kind, use_lexical)
    finally:
        if owns_conn:
            conn.close()


def _retrieve(
    conn: psycopg.Connection,
    query: str,
    k: int,
    logsource: str | None,
    platform: str | None,
    kind: str | None,
    use_lexical: bool,
) -> list[Hit]:
    where, params = _filters(kind, platform, logsource)

    # 1. exact ATT&CK IDs in the query: the technique chunk first, then rules mapped to it
    ids = sorted({m.upper() for m in _TECHNIQUE_ID.findall(query)})
    exact: list[str] = []
    if ids:
        exact = [
            r[0]
            for r in conn.execute(
                f"SELECT id FROM chunks WHERE ({where}) AND (id = ANY(%s) OR technique_ids && %s) "
                "ORDER BY (kind = 'technique') DESC, id",
                [*params, ids, ids],
            )
        ]

    # 2. vector similarity (iterative scan keeps filtered HNSW queries from returning too few)
    conn.execute("SET hnsw.iterative_scan = strict_order")
    qvec = embed_texts([query])[0]
    vector = [
        r[0]
        for r in conn.execute(
            f"SELECT id FROM chunks WHERE {where} ORDER BY embedding <=> %s LIMIT %s",
            [*params, qvec, POOL],
        )
    ]

    # 3. lexical match on discriminating words
    lexical: list[str] = []
    terms = _lexical_terms(conn, query, where, params) if use_lexical else []
    if terms:
        lexical = _lexical_ranking(conn, terms, where, params)

    scores: dict[str, float] = {}
    for ranking in (vector, lexical):
        for rank, cid in enumerate(ranking):
            scores[cid] = scores.get(cid, 0.0) + 1.0 / (RRF_K + rank + 1)
    fused = sorted(scores, key=lambda cid: (-scores[cid], cid))
    ordered = exact + [cid for cid in fused if cid not in set(exact)]
    top = ordered[:k]
    if not top:
        return []

    rows = {
        r[0]: r
        for r in conn.execute(
            "SELECT id, kind, title, text, platforms, logsource, technique_ids "
            "FROM chunks WHERE id = ANY(%s)",
            (top,),
        )
    }
    sources = {"id": set(exact), "vector": set(vector), "lexical": set(lexical)}
    hits = []
    for cid in top:
        r = rows[cid]
        hits.append(
            Hit(
                id=r[0],
                kind=r[1],
                title=r[2],
                text=r[3],
                platforms=r[4],
                logsource=r[5],
                technique_ids=r[6],
                score=scores.get(cid, 0.0) + (1.0 if cid in sources["id"] else 0.0),
                matched_by=[name for name, s in sources.items() if cid in s],
            )
        )
    return hits
