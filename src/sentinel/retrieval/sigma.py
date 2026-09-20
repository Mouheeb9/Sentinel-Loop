"""SigmaHQ rules directory -> one Chunk per rule.

Title, logsource and tags stay in the chunk text: the tags carry ATT&CK IDs
(`attack.t1003.001`) and are strong retrieval signal. The detection block is
kept too — it holds the exact identifiers (`lsass.exe`, `comsvcs.dll`) that a
purely semantic search would blur.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from sentinel.retrieval.chunks import Chunk

DEFAULT_RULES_DIR = (
    Path(__file__).resolve().parents[3] / "data" / "raw" / "sigma" / "repo" / "rules"
)

_TECHNIQUE_TAG = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)
_SKIPPED_STATUSES = {"deprecated", "unsupported"}
# A few rules embed thousands of hashes or emoji (one is 240k chars). Those add no retrieval
# signal and would blow past the embedding model's input limit, so cap the detection block.
_MAX_DETECTION_CHARS = 2000


def _detection_text(detection: Any) -> str:
    text = yaml.safe_dump(detection, sort_keys=False, allow_unicode=True).strip()
    if len(text) > _MAX_DETECTION_CHARS:
        text = text[:_MAX_DETECTION_CHARS] + "\n... (truncated)"
    return text


def _logsource_label(logsource: dict[str, Any]) -> str | None:
    parts = [logsource.get(k) for k in ("category", "product", "service")]
    label = "/".join(str(p) for p in parts if p)
    return label or None


def _rule_to_chunk(rule: dict[str, Any]) -> Chunk | None:
    if not isinstance(rule, dict) or not rule.get("id") or not rule.get("title"):
        return None
    if rule.get("status") in _SKIPPED_STATUSES:
        return None

    tags = [str(t) for t in rule.get("tags") or []]
    technique_ids = [m.group(1).upper() for t in tags if (m := _TECHNIQUE_TAG.match(t))]
    logsource = rule.get("logsource") or {}
    product = logsource.get("product")

    parts = [
        f"{rule['title']}",
        f"Logsource: {_logsource_label(logsource)}" if _logsource_label(logsource) else "",
        f"Tags: {', '.join(tags)}" if tags else "",
        f"Level: {rule['level']}" if rule.get("level") else "",
        f"Description: {str(rule['description']).strip()}" if rule.get("description") else "",
        "Detection:\n" + _detection_text(rule["detection"]) if rule.get("detection") else "",
        "False positives: " + "; ".join(str(f) for f in rule["falsepositives"])
        if rule.get("falsepositives")
        else "",
    ]
    return Chunk(
        id=str(rule["id"]),
        kind="sigma_rule",
        title=str(rule["title"]),
        text="\n".join(p for p in parts if p),
        platforms=[str(product).lower()] if product else [],
        logsource=_logsource_label(logsource),
        technique_ids=technique_ids,
    )


def load_sigma_chunks(rules_dir: Path = DEFAULT_RULES_DIR) -> list[Chunk]:
    chunks = []
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (yaml.YAMLError, UnicodeDecodeError):
            continue  # one broken file must not take the whole corpus down
        chunk = _rule_to_chunk(rule)
        if chunk:
            chunks.append(chunk)
    return chunks
