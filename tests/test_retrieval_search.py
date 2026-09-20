"""retrieve() behaviour on a tiny invented corpus (never the real probe queries)."""

import hashlib
import uuid

import numpy as np
import psycopg
import pytest
from pgvector.psycopg import register_vector

from sentinel.retrieval import search, store
from sentinel.retrieval.chunks import Chunk
from sentinel.retrieval.embed import DIM
from sentinel.retrieval.index import build_index
from sentinel.retrieval.search import expand_platform, retrieve


def fake_embed(texts: list[str]) -> list[np.ndarray]:
    out = []
    for t in texts:
        seed = int.from_bytes(hashlib.sha256(t.encode()).digest()[:4], "little")
        out.append(np.random.default_rng(seed).random(DIM, dtype=np.float32))
    return out


CORPUS = [
    Chunk(
        id="T9001",
        kind="technique",
        title="Credential Dumping X",
        text="T9001 Credential Dumping X. Attackers read zzqlsass.exe memory.",
        platforms=["windows"],
        technique_ids=["T9001"],
    ),
    Chunk(
        id="T9002",
        kind="technique",
        title="Cloud Key Theft",
        text="T9002 Cloud Key Theft. Steal keys from the metadata service.",
        platforms=["iaas"],
        technique_ids=["T9002"],
    ),
    Chunk(
        id="rule-1",
        kind="sigma_rule",
        title="Zzqlsass Dump Rule",
        text="Zzqlsass Dump Rule\nLogsource: process_access/windows\nzzqlsass.exe access",
        platforms=["windows"],
        logsource="process_access/windows",
        technique_ids=["T9001"],
    ),
    Chunk(
        id="rule-2",
        kind="sigma_rule",
        title="AWS Key Rule",
        text="AWS Key Rule\nLogsource: cloudtrail/aws\nGetSecretValue by unusual principal",
        platforms=["aws"],
        logsource="cloudtrail/aws",
        technique_ids=["T9002"],
    ),
]

# Filler so word frequencies look like a real corpus (the lexical leg drops words that appear
# in more than 10% of chunks; in a 4-chunk corpus every word would be "common").
CORPUS += [
    Chunk(
        id=f"filler-{i}",
        kind="sigma_rule",
        title=f"Filler {i}",
        # the first 10 also share one identifier-shaped token and one plain word, both at ~10%
        text=f"Filler {i} logsource unrelated linux content"
        + (" abc123def commonword" if i < 10 else ""),
        platforms=["linux"],
        logsource="x/linux",
    )
    for i in range(100)
]


@pytest.fixture
def conn(monkeypatch):
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
    build_index(c, CORPUS, embed=fake_embed, log=lambda _: None)
    monkeypatch.setattr(search, "embed_texts", fake_embed)
    yield c
    c.execute(f"DROP SCHEMA {schema} CASCADE")
    c.close()


def test_platform_names_are_normalised_across_the_two_corpora():
    assert expand_platform("iaas") == ["aws", "azure", "gcp", "iaas"]
    assert expand_platform("cloud") == expand_platform("iaas")
    assert expand_platform("aws") == ["aws", "iaas"]  # a raw product also reaches its group
    assert expand_platform("Windows") == ["windows"]
    assert expand_platform("brandnewproduct") == ["brandnewproduct"]  # unknown: literal match


def test_exact_technique_id_pins_its_chunk_then_its_rules_first(conn):
    hits = retrieve("look at T9001 please", k=3, conn=conn)
    assert [h.id for h in hits[:2]] == ["T9001", "rule-1"]
    assert "id" in hits[0].matched_by


def test_exact_id_is_case_insensitive(conn):
    assert retrieve("t9002", k=1, conn=conn)[0].id == "T9002"


def test_lexical_match_finds_a_rare_identifier(conn):
    hits = {
        h.id: h for h in retrieve("process touching zzqlsass.exe", k=5, conn=conn, use_lexical=True)
    }
    assert {"T9001", "rule-1"} <= set(hits)
    assert "lexical" in hits["T9001"].matched_by and "lexical" in hits["rule-1"].matched_by


def test_kind_filter(conn):
    hits = retrieve("zzqlsass.exe", k=10, kind="technique", conn=conn)
    assert hits and all(h.kind == "technique" for h in hits)


def test_platform_filter_reaches_both_corpora_vocabularies(conn):
    hits = retrieve("stolen keys", k=10, platform="iaas", conn=conn)
    assert {h.id for h in hits} == {"T9002", "rule-2"}  # ATT&CK "iaas" + Sigma "aws"


def test_logsource_filter_narrows_rules_but_lets_techniques_through(conn):
    hits = retrieve("dump", k=10, logsource="process_access", conn=conn)
    ids = {h.id for h in hits}
    assert "rule-1" in ids and "rule-2" not in ids
    assert {"T9001", "T9002"} <= ids  # technique chunks have no logsource


def test_empty_result_when_filters_match_nothing(conn):
    assert retrieve("anything", platform="macos", conn=conn) == []


def _words(terms):
    return [w for w, _ in terms]


def test_common_words_are_not_used_as_lexical_terms(conn):
    # "logsource" is in ~95% of chunks: no discriminating power. The rare identifier is kept.
    assert _words(search._lexical_terms(conn, "logsource zzqlsass.exe")) == ["zzqlsass.exe"]


def test_plain_word_needs_to_be_rare_but_identifier_shaped_token_does_not(conn):
    # "commonword" and "abc123def" both sit in ~10% of chunks (above the 2% cutoff); only the
    # identifier-shaped one survives. "attackers" is in 1 chunk, so a plain rare word is kept.
    kept = _words(search._lexical_terms(conn, "commonword abc123def attackers unrelated"))
    assert kept == ["abc123def", "attackers"]


def test_rarer_words_get_a_higher_idf_weight(conn):
    weights = dict(search._lexical_terms(conn, "attackers zzqlsass.exe abc123def"))
    assert weights["attackers"] > weights["zzqlsass.exe"] > weights["abc123def"] > 0


def test_rarity_is_measured_inside_the_filtered_population(conn):
    # Unfiltered, "zzqlsass.exe" is in 2 of 104 chunks; among technique chunks only, 1 of 2.
    everywhere = dict(search._lexical_terms(conn, "zzqlsass.exe"))
    where, params = search._filters("technique", None, None)
    among_techniques = dict(search._lexical_terms(conn, "zzqlsass.exe", where, params))
    assert among_techniques["zzqlsass.exe"] < everywhere["zzqlsass.exe"]


def test_lexical_ranking_puts_the_rarest_matching_word_first(conn):
    terms = search._lexical_terms(conn, "attackers abc123def")
    ranking = search._lexical_ranking(conn, terms, "TRUE", [])
    # "attackers" is in 1 chunk, "abc123def" in 10: the chunk holding the rarer word leads.
    assert ranking[0] == "T9001"
    assert set(ranking[1:]) == {f"filler-{i}" for i in range(10)}


def test_lexical_leg_is_off_by_default(conn):
    hits = retrieve("process touching zzqlsass.exe", k=5, conn=conn)
    assert all("lexical" not in h.matched_by for h in hits)


def test_no_lexical_terms_means_no_lexical_list(conn):
    hits = retrieve("logsource unrelated", k=3, conn=conn, use_lexical=True)  # only common words
    assert all("lexical" not in h.matched_by for h in hits)
