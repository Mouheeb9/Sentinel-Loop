"""ATT&CK Enterprise STIX bundle -> one Chunk per technique.

One chunk per technique (sub-techniques included) keeps ID, name, description,
detection guidance, data sources and platforms together — chunking by page or
by token count would split that structure.

Detection guidance is not a field on the technique any more. ATT&CK v18+ models
it as x-mitre-detection-strategy objects that `detect` a technique and point at
x-mitre-analytic objects, whose log-source references name data components.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from sentinel.retrieval.chunks import Chunk

DEFAULT_BUNDLE = (
    Path(__file__).resolve().parents[3] / "data" / "raw" / "attack" / "enterprise-attack.json"
)


_CITATION = re.compile(r"\(Citation: [^)]*\)")
_MD_LINK = re.compile(r"\[([^\]]+)\]\(https?://[^)]*\)")
# Only the formatting tags ATT&CK uses. Placeholders like <PID> or <script> are real content
# inside example commands and must survive.
_FORMAT_TAG = re.compile(r"</?(?:code|b)>", re.IGNORECASE)
_LINE_BREAK_TAG = re.compile(r"<br\s*/?>", re.IGNORECASE)


def _clean(text: str) -> str:
    """Drop citation markers, HTML formatting tags and link URLs (keeping the link label)."""
    text = _LINE_BREAK_TAG.sub("\n", _FORMAT_TAG.sub("", _CITATION.sub("", text)))
    return _MD_LINK.sub(r"\1", text).strip()


def _is_live(obj: dict[str, Any]) -> bool:
    return not obj.get("revoked", False) and not obj.get("x_mitre_deprecated", False)


def _technique_id(obj: dict[str, Any]) -> str | None:
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def load_attack_chunks(bundle_path: Path = DEFAULT_BUNDLE) -> list[Chunk]:
    objects = json.loads(bundle_path.read_text(encoding="utf-8"))["objects"]
    by_id = {o["id"]: o for o in objects}

    techniques = [o for o in objects if o["type"] == "attack-pattern" and _is_live(o)]

    strategies_by_technique: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for rel in objects:
        if rel["type"] != "relationship" or rel["relationship_type"] != "detects":
            continue
        strategy = by_id.get(rel["source_ref"])
        if strategy and strategy["type"] == "x-mitre-detection-strategy" and _is_live(strategy):
            strategies_by_technique[rel["target_ref"]].append(strategy)

    chunks = []
    for tech in techniques:
        tid = _technique_id(tech)
        if tid is None:
            continue
        tactics = [p["phase_name"] for p in tech.get("kill_chain_phases", [])]
        platforms = tech.get("x_mitre_platforms", [])

        detection_lines: list[str] = []
        data_components: list[str] = []
        for strategy in strategies_by_technique.get(tech["id"], []):
            for analytic_id in strategy.get("x_mitre_analytic_refs", []):
                analytic = by_id.get(analytic_id)
                if not analytic:
                    continue
                if analytic.get("description"):
                    detection_lines.append(_clean(analytic["description"]))
                for src in analytic.get("x_mitre_log_source_references", []):
                    name = src.get("name") or by_id.get(
                        src.get("x_mitre_data_component_ref"), {}
                    ).get("name")
                    if name and name not in data_components:
                        data_components.append(name)

        parts = [
            f"{tid} {tech['name']}",
            f"Tactics: {', '.join(tactics)}" if tactics else "",
            f"Platforms: {', '.join(platforms)}" if platforms else "",
            f"Description: {_clean(tech.get('description', ''))}",
            f"Data sources: {', '.join(data_components)}" if data_components else "",
            "Detection guidance:\n" + "\n".join(f"- {d}" for d in detection_lines)
            if detection_lines
            else "",
        ]
        chunks.append(
            Chunk(
                id=tid,
                kind="technique",
                title=tech["name"],
                text="\n".join(p for p in parts if p),
                platforms=[p.lower() for p in platforms],
                technique_ids=[tid],
            )
        )
    return sorted(chunks, key=lambda c: c.id)
