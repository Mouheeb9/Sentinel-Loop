"""The form the rule-generation model fills in, and the code that turns it into Sigma YAML.

A generated rule is code built from attacker-written values (command lines, paths, registry
keys), so the model never writes the rule text itself (OWASP LLM05, improper output handling).
It fills a strict form; this module checks the form and renders the YAML:

- fields come from a fixed allow-list per log source (the Sysmon field names our matcher maps);
- match types are equals / contains / startswith / endswith only: no `re`, no `base64`, no
  other modifier, so a value can never become a pattern;
- every value is matched literally: Sigma wildcards (`*`, `?`) and the escape character in it
  are escaped, so a planted `*` can't widen the rule into "match everything";
- values are single-line, bounded in length and count, and never empty;
- the condition is built by code from the selections and filters, never written by the model;
- the YAML is produced with yaml.safe_dump, so no value can inject keys or structure.

The rule's `id` is a UUID derived from its content, so the same form always gives the same rule.
"""

from __future__ import annotations

import re
import uuid
from datetime import date
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

Category = Literal["process_creation", "registry_set", "network_connection"]
MatchType = Literal["equals", "contains", "startswith", "endswith"]

# Sysmon field names per Sigma log source category (the fields the matcher's Sysmon pipeline
# understands for EID 1 / 13 / 3).
ALLOWED_FIELDS: dict[str, frozenset[str]] = {
    "process_creation": frozenset(
        {
            "Image",
            "OriginalFileName",
            "CommandLine",
            "ParentImage",
            "ParentCommandLine",
            "CurrentDirectory",
            "User",
            "IntegrityLevel",
        }
    ),
    "registry_set": frozenset({"Image", "TargetObject", "Details", "EventType"}),
    "network_connection": frozenset(
        {
            "Image",
            "DestinationIp",
            "DestinationPort",
            "DestinationHostname",
            "SourceIp",
            "Initiated",
            "Protocol",
        }
    ),
}
# Windows path fields: the model writes their separators as "/" and code turns them into "\".
# Free models lose backslashes when they write JSON (seen on Day 12: "HKLMSystemCurrent..."), and
# these fields never contain a real "/", so the conversion is lossless.
PATH_FIELDS = frozenset({"Image", "ParentImage", "TargetObject", "CurrentDirectory"})
MAX_VALUE_CHARS = 300
TECHNIQUE_ID_PATTERN = re.compile(r"T\d{4}(\.\d{3})?")  # same format as schemas.TriageVerdict
RULE_NAMESPACE = uuid.UUID("5b1c4f0e-0c1e-4c55-9e57-5e7f1e0b0a11")  # for content-derived ids


class FieldMatch(BaseModel):
    """One field test. Several values = any of them (OR)."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(description="Sysmon field name, from the allowed list for the category")
    match: MatchType = Field(description="equals, contains, startswith or endswith")
    values: list[str] = Field(
        min_length=1,
        max_length=10,
        description="matched literally; in path fields write the separator as / (code turns it "
        "into a backslash)",
    )

    @field_validator("values")
    @classmethod
    def _values(cls, values: list[str]) -> list[str]:
        out = []
        for v in values:
            v = v.strip()
            if not v:
                raise ValueError("empty value")
            if len(v) > MAX_VALUE_CHARS:
                raise ValueError(f"value longer than {MAX_VALUE_CHARS} characters")
            if any(ord(c) < 32 for c in v):
                raise ValueError("values must be one line, without control characters")
            out.append(v)
        return out


class Selection(BaseModel):
    """Field tests that must ALL be true (AND)."""

    model_config = ConfigDict(extra="forbid")

    items: list[FieldMatch] = Field(min_length=1, max_length=6)


class RuleDraft(BaseModel):
    """A detection for the behavior in the alert, as a form. The YAML is built by code."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=5, max_length=120)
    description: str = Field(min_length=10, max_length=500)
    category: Category = Field(description="Sigma logsource category (product is windows)")
    selections: list[Selection] = Field(
        min_length=1, max_length=3, description="the rule fires when ANY selection matches"
    )
    filters: list[Selection] = Field(
        default_factory=list,
        max_length=2,
        description="known-benign cases: the rule does NOT fire when any filter matches",
    )
    technique_ids: list[str] = Field(min_length=1, max_length=3)
    level: Literal["low", "medium", "high", "critical"]
    falsepositives: list[str] = Field(default_factory=list, max_length=3)

    @field_validator("title", "description")
    @classmethod
    def _one_line(cls, v: str) -> str:
        if any(ord(c) < 32 for c in v):
            raise ValueError("must be one line, without control characters")
        return v.strip()

    @field_validator("technique_ids")
    @classmethod
    def _techniques(cls, ids: list[str]) -> list[str]:
        bad = [t for t in ids if not TECHNIQUE_ID_PATTERN.fullmatch(t)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique id(s): {bad}")
        return ids

    @model_validator(mode="after")
    def _fields_allowed(self) -> RuleDraft:
        allowed = ALLOWED_FIELDS[self.category]
        used = {m.field for s in [*self.selections, *self.filters] for m in s.items}
        if bad := sorted(used - allowed):
            raise ValueError(
                f"field(s) {bad} not allowed for {self.category}; use: {sorted(allowed)}"
            )
        for sel in [*self.selections, *self.filters]:
            for m in sel.items:
                if m.field in PATH_FIELDS:
                    m.values = [v.replace("/", "\\") for v in m.values]
        return self


def escape_value(value: str) -> str:
    """A Sigma string that matches `value` literally: `*` and `?` are wildcards in Sigma and `\\`
    is its escape character, so they are escaped. A backslash only needs escaping before a
    special character (or at the very end), which keeps Windows paths readable."""
    out = []
    for i, c in enumerate(value):
        if c in "*?":
            out.append("\\" + c)
        elif c == "\\":
            nxt = value[i + 1] if i + 1 < len(value) else ""
            out.append("\\\\" if nxt in ("*", "?", "\\", "") else "\\")
        else:
            out.append(c)
    return "".join(out)


def _selection_yaml(sel: Selection) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for m in sel.items:
        key = m.field if m.match == "equals" else f"{m.field}|{m.match}"
        out.setdefault(key, [])
        out[key] += [escape_value(v) for v in m.values]
    return out


def render(draft: RuleDraft, today: date | None = None) -> str:
    """The Sigma rule YAML for a draft. Deterministic for a given draft and date."""
    detection: dict[str, object] = {}
    for i, sel in enumerate(draft.selections, start=1):
        detection[f"selection{i}"] = _selection_yaml(sel)
    for i, flt in enumerate(draft.filters, start=1):
        detection[f"filter{i}"] = _selection_yaml(flt)
    condition = "1 of selection*"
    if draft.filters:
        condition += " and not 1 of filter*"
    detection["condition"] = condition

    body: dict[str, object] = {
        "title": draft.title,
        "id": "",  # filled below from the rest of the content
        "status": "experimental",
        "description": draft.description,
        "author": "Sentinel Loop rule_gen v0",
        "date": (today or date.today()).isoformat(),
        "tags": [f"attack.{t.lower()}" for t in draft.technique_ids],
        "logsource": {"category": draft.category, "product": "windows"},
        "detection": detection,
        "falsepositives": draft.falsepositives or ["Unknown"],
        "level": draft.level,
    }
    body["id"] = str(uuid.uuid5(RULE_NAMESPACE, yaml.safe_dump(body, sort_keys=False)))
    return yaml.safe_dump(body, sort_keys=False, allow_unicode=True)
