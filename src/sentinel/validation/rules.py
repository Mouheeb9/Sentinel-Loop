"""Sigma rule ID -> the rule's YAML text, from the local SigmaHQ checkout.

Retrieval hits carry a rule's ID and a chunk of its text, not the rule itself; the matcher needs
the real YAML. The index (ID -> file) is built once per process by reading each file's top-level
`id:` line, which is much faster than parsing 3,000+ YAML files.
"""

from __future__ import annotations

import re
from functools import cache
from pathlib import Path

from sentinel.retrieval.sigma import DEFAULT_RULES_DIR

# A trailing YAML comment is allowed: some SigmaHQ rules have `id: <uuid>  # Exec`.
_ID_LINE = re.compile(r"^id:\s*['\"]?([0-9a-fA-F-]{36})['\"]?\s*(?:#.*)?$", re.MULTILINE)


@cache
def _index(rules_dir: Path) -> dict[str, Path]:
    index: dict[str, Path] = {}
    for path in sorted(rules_dir.rglob("*.yml")):
        try:
            m = _ID_LINE.search(path.read_text(encoding="utf-8"))
        except UnicodeDecodeError:
            continue
        if m:
            index.setdefault(m.group(1).lower(), path)
    return index


def rule_yaml(rule_id: str, rules_dir: Path = DEFAULT_RULES_DIR) -> str | None:
    """None when the rule isn't in the checkout (not downloaded, or removed upstream)."""
    path = _index(rules_dir).get(rule_id.lower())
    return path.read_text(encoding="utf-8") if path else None
