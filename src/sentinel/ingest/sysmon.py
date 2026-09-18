"""Raw Sysmon (winlogbeat-shaped) JSON -> normalized Event.

Only three Sysmon EventIDs are handled today: 1 (process creation), 3
(network connection), 13 (registry value set). A raw corpus of full
winlogbeat output contains far more channels and EventIDs (Security,
PowerShell/Operational, WMI-Activity, FileCreate, ...) than this ingests
this week — sysmon_to_event returns None for anything else, on purpose,
rather than guessing at a shape.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from sentinel.schemas import Event, NetworkInfo, ProcessInfo, RegistryInfo

_SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
_CONFIG_PATH = Path(__file__).resolve().parents[3] / "config" / "untrusted_fields.yaml"


def _load_untrusted_fields_by_event_id() -> dict[int, list[str]]:
    config = yaml.safe_load(_CONFIG_PATH.read_text())
    by_event_id: dict[int, list[str]] = {}
    for entry in config.get("windows_sysmon") or []:
        path = entry.get("normalized_path")
        if not path:
            continue  # documented attack surface for an event type we don't ingest yet
        for event_id in entry["event_ids"]:
            by_event_id.setdefault(event_id, []).append(path)
    return by_event_id


_UNTRUSTED_FIELDS_BY_EVENT_ID = _load_untrusted_fields_by_event_id()
_SUPPORTED_EVENT_IDS = {1, 3, 13}


def _parse_utc_time(value: str) -> datetime:
    # Sysmon's UtcTime looks like "2020-10-18 23:50:05.910" — naive, but it IS UTC.
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f").replace(tzinfo=UTC)


def _resolve_user(raw: dict[str, Any]) -> str | None:
    if raw.get("User"):
        return raw["User"]
    domain, account = raw.get("Domain"), raw.get("AccountName")
    return f"{domain}\\{account}" if domain and account else None


def _synthetic_event_id(raw: dict[str, Any]) -> str:
    # Only some pipelines/eras of this corpus carry RecordNumber. When it's
    # missing, hash stable raw fields so the same raw event always yields the
    # same event_id (normalization must be deterministic).
    if raw.get("RecordNumber"):
        return f"sysmon-{raw['RecordNumber']}"
    basis = "|".join(str(raw.get(k, "")) for k in ("Hostname", "EventID", "UtcTime", "ProcessGuid"))
    return f"sysmon-{hashlib.sha256(basis.encode()).hexdigest()[:16]}"


def _int_or_none(value: Any) -> int | None:
    return int(value) if value not in (None, "") else None


def _process_info(raw: dict[str, Any]) -> ProcessInfo | None:
    if not (raw.get("Image") or raw.get("CommandLine")):
        return None
    parent = None
    if raw.get("ParentImage") or raw.get("ParentCommandLine"):
        parent = ProcessInfo(
            image=raw.get("ParentImage"),
            command_line=raw.get("ParentCommandLine"),
        )
    return ProcessInfo(
        pid=_int_or_none(raw.get("ProcessId")),
        image=raw.get("Image"),
        command_line=raw.get("CommandLine"),
        parent=parent,
    )


def _network_info(raw: dict[str, Any]) -> NetworkInfo:
    return NetworkInfo(
        src_ip=raw.get("SourceIp"),
        dst_ip=raw.get("DestinationIp"),
        dst_port=_int_or_none(raw.get("DestinationPort")),
        protocol=raw.get("Protocol"),
    )


def _registry_info(raw: dict[str, Any]) -> RegistryInfo:
    return RegistryInfo(target_object=raw.get("TargetObject"), details=raw.get("Details"))


def sysmon_to_event(raw: dict[str, Any]) -> Event | None:
    """Normalize one raw Sysmon JSON record into an Event, or None to skip it."""
    if raw.get("Channel") != _SYSMON_CHANNEL:
        return None

    event_id = raw.get("EventID")
    if event_id not in _SUPPORTED_EVENT_IDS:
        return None

    return Event(
        event_id=_synthetic_event_id(raw),
        timestamp=_parse_utc_time(raw["UtcTime"]),
        source="windows_sysmon",
        host=raw["Hostname"],
        user=_resolve_user(raw),
        process=_process_info(raw),
        network=_network_info(raw) if event_id == 3 else None,
        registry=_registry_info(raw) if event_id == 13 else None,
        raw=raw,
        untrusted_fields=_UNTRUSTED_FIELDS_BY_EVENT_ID.get(event_id, []),
    )
