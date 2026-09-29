"""BM25 keyword search: security-aware word splitting and ranking. No database."""

from sentinel.retrieval.bm25 import BM25Index, tokenize


def test_paths_and_file_names_are_kept_whole_and_split():
    toks = tokenize(r"C:\Windows\System32\rundll32.exe comsvcs.dll MiniDump")
    assert {"rundll32.exe", "rundll32", "exe", "system32", "comsvcs.dll", "comsvcs"} <= set(toks)
    assert "minidump" in toks


def test_stopwords_dropped():
    assert tokenize("the use of a tool") == ["tool"]


def test_rare_word_outranks_common_word():
    docs = [("a", "process started lsass.exe dump")] + [
        (f"f{i}", "process started normally") for i in range(20)
    ]
    idx = BM25Index.build(docs)
    assert idx.search("process lsass.exe")[0] == "a"


def test_allowed_filter_and_limit():
    idx = BM25Index.build([("a", "lsass dump"), ("b", "lsass access"), ("c", "other")])
    assert idx.search("lsass", allowed={"b"}) == ["b"]
    assert len(idx.search("lsass", limit=1)) == 1
    assert idx.search("nothing-matches") == []
