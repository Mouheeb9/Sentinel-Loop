"""The contracts. Changed only by a PR both of you approve."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProcessInfo(StrictModel):
    pid: int | None = None
    image: str | None = None
    command_line: str | None = None
    parent: ProcessInfo | None = None


class NetworkInfo(StrictModel):
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None


class RegistryInfo(StrictModel):
    target_object: str | None = None
    details: str | None = None


class Event(StrictModel):
    """One normalized log event. Every source flattens into this."""

    event_id: str
    timestamp: datetime
    source: Literal["windows_sysmon", "linux_auditd", "aws_cloudtrail", "guardduty"]
    host: str
    user: str | None = None
    process: ProcessInfo | None = None
    network: NetworkInfo | None = None
    registry: RegistryInfo | None = None
    raw: dict[str, Any]
    # Dot-paths into THIS model (e.g. "process.command_line"), not into `raw`.
    # Set by the ingest normalizer from config/untrusted_fields.yaml so the prompt
    # layer can spotlight/delimit these without knowing per-source raw formats.
    untrusted_fields: list[str]

    @field_validator("timestamp")
    @classmethod
    def _require_tz(cls, v: datetime) -> datetime:
        if v.tzinfo is None:
            raise ValueError("timestamp must be timezone-aware")
        return v.astimezone(UTC)


class Alert(StrictModel):
    alert_id: str
    detection_name: str
    severity: Literal["low", "medium", "high", "critical"]
    events: list[Event]


class TriageVerdict(StrictModel):
    verdict: Literal["true_positive", "benign_noisy", "needs_review"]
    confidence: float = Field(ge=0, le=1)
    technique_ids: list[str]
    reasoning: str
    # Dot-paths into the Alert/Event that support the verdict. Paths, not prose.
    evidence_refs: list[str]
    # Literal IOC values (IP, hash, domain, ...) the model extracted. Scored by
    # matching against leaf VALUES/tokens of the input event, not a raw JSON
    # substring search — a token absent from every leaf is a hallucination.
    ioc_refs: list[str]

    @field_validator("technique_ids")
    @classmethod
    def _validate_technique_ids(cls, v: list[str]) -> list[str]:
        bad = [t for t in v if not _TECHNIQUE_ID_RE.fullmatch(t)]
        if bad:
            raise ValueError(f"invalid ATT&CK technique id(s): {bad}")
        return v


class FailedSample(StrictModel):
    sample_id: str
    should_fire: bool
    did_fire: bool
    event_ref: str
    note: str | None = None


class ValidationResult(StrictModel):
    rule_id: str
    compiled: bool
    compile_errors: list[str] = Field(default_factory=list)
    true_positives: int
    false_positives: int
    fp_rate: float = Field(ge=0, le=1)
    failed_samples: list[FailedSample] = Field(default_factory=list)
    feedback: str  # structured text the repair loop reads


class InjectionCase(StrictModel):
    case_id: str
    payload: str
    target_field: str  # dot-path where it gets embedded
    category: Literal[
        "direct_override",
        "fake_system_msg",
        "encoded",
        "context_stuffing",
        "tool_hijack",
    ]
    expected_safe_behavior: str
    success_signal: str  # how you decide the attack worked
