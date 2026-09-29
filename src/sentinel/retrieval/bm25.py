"""BM25 keyword search over the chunk index, in memory.

BM25 scores a chunk higher when it contains the query's words often, and when those words are
rare across all chunks ("lsass.exe" counts far more than "process"). Standard Okapi BM25:
k1 = 1.5 (how fast repeated words stop adding), b = 0.75 (how much long chunks are held back).

Security text needs its own word splitting: a path or file name is kept whole AND split into
its parts, so `C:\\Windows\\System32\\rundll32.exe` gives `rundll32.exe`, `rundll32`, `exe`,
`system32`, ... and both an exact file name and a partial one can match.

The index is built from the database once per process and kind (a few seconds), for the active
embedding model's schema; filters (platform, logsource) are applied by the caller's SQL.
"""

from __future__ import annotations

import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass

import psycopg

K1 = 1.5
B = 0.75

_TOKEN = re.compile(r"[a-z0-9_$%.\-]+")
_SPLIT = re.compile(r"[._\-$%]+")
_STOPWORDS = frozenset(
    "a an the and or of to in on for with by from as at is are was were be been it its this "
    "that these those can may use used using via into onto than then when which who".split()
)


def tokenize(text: str) -> list[str]:
    """Whole tokens (paths cut at slashes/spaces) plus their dot/dash/underscore parts."""
    out: list[str] = []
    for tok in _TOKEN.findall(text.lower().replace("\\", " ").replace("/", " ")):
        tok = tok.strip(".-")
        if not tok or tok in _STOPWORDS:
            continue
        out.append(tok)
        parts = [p for p in _SPLIT.split(tok) if p and p != tok]
        out += [p for p in parts if len(p) > 1 and p not in _STOPWORDS]
    return out


@dataclass
class BM25Index:
    ids: list[str]
    postings: dict[str, list[tuple[int, int]]]  # term -> [(doc index, term count)]
    doc_len: list[int]
    avg_len: float

    @classmethod
    def build(cls, docs: list[tuple[str, str]]) -> BM25Index:
        ids, lengths = [], []
        postings: dict[str, list[tuple[int, int]]] = defaultdict(list)
        for i, (doc_id, text) in enumerate(docs):
            counts = Counter(tokenize(text))
            ids.append(doc_id)
            lengths.append(sum(counts.values()))
            for term, n in counts.items():
                postings[term].append((i, n))
        avg = sum(lengths) / len(lengths) if lengths else 0.0
        return cls(ids, dict(postings), lengths, avg)

    def search(self, query: str, allowed: set[str] | None = None, limit: int = 50) -> list[str]:
        """Doc ids by BM25 score, best first; only ids in `allowed` when given."""
        n = len(self.ids)
        scores: dict[int, float] = defaultdict(float)
        for term in set(tokenize(query)):
            posting = self.postings.get(term)
            if not posting:
                continue
            idf = math.log(1 + (n - len(posting) + 0.5) / (len(posting) + 0.5))
            for i, tf in posting:
                norm = K1 * (1 - B + B * self.doc_len[i] / self.avg_len)
                scores[i] += idf * tf * (K1 + 1) / (tf + norm)
        ranked = sorted(scores, key=lambda i: (-scores[i], self.ids[i]))
        out = [self.ids[i] for i in ranked if allowed is None or self.ids[i] in allowed]
        return out[:limit]


_CACHE: dict[tuple[str, str], BM25Index] = {}


def index_for(conn: psycopg.Connection, kind: str) -> BM25Index:
    """The BM25 index of one chunk kind, built once per process (and per model schema)."""
    schema = conn.execute("SELECT current_schema()").fetchone()[0]
    key = (schema, kind)
    if key not in _CACHE:
        rows = conn.execute(
            "SELECT id, title || ' ' || text FROM chunks WHERE kind = %s ORDER BY id", (kind,)
        ).fetchall()
        _CACHE[key] = BM25Index.build(rows)
    return _CACHE[key]
