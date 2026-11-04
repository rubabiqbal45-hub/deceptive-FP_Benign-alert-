"""Normalise heterogeneous Windows telemetry into one canonical event shape.

Inputs
------
* Mordor / OTRF ``Security-Datasets`` NDJSON (one JSON object per line).
* EVTX exported to NDJSON by ``sysmon/collect_windows.ps1``.

Design rule: **never drop a field.** Every original key is preserved verbatim so
a Sigma rule that references something the normaliser never anticipated still has
a chance to match. On top of that we add canonical Sigma field names (populated
from unambiguous aliases only) and a few ``_``-prefixed derived fields used by the
engine, never by rules.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

# Sigma canonical name -> plausible source names, in priority order.
# Only unambiguous mappings belong here. In particular ``ObjectName`` is NOT
# mapped to ``TargetFilename``: on Security-channel object-access events it can
# be a file, a registry key or a kernel object, and guessing would create silent
# false negatives. Those events keep their raw fields instead.
FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "Image": ("Image", "NewProcessName", "ProcessName", "SourceImage"),
    "ParentImage": ("ParentImage", "ParentProcessName", "CreatorProcessName"),
    "CommandLine": ("CommandLine", "ProcessCommandLine"),
    "User": ("User", "SubjectUserName", "TargetUserName"),
    "TargetFilename": ("TargetFilename", "FileName"),
    "TargetObject": ("TargetObject", "RegistryKey"),
    "QueryName": ("QueryName", "DnsQuery"),
    "DestinationIp": ("DestinationIp", "DestAddress", "RemoteAddress"),
    "DestinationPort": ("DestinationPort", "DestPort", "RemotePort"),
    "SourceIp": ("SourceIp", "SourceAddress"),
    "SourcePort": ("SourcePort", "SourcePortNumber"),
    "Hashes": ("Hashes", "Hash"),
    "IntegrityLevel": ("IntegrityLevel", "MandatoryLabel"),
    "ParentCommandLine": ("ParentCommandLine", "ParentProcessCommandLine"),
    "TargetImage": ("TargetImage",),
}

TIME_FIELDS: tuple[str, ...] = (
    "@timestamp",
    "TimeCreated",
    "UtcTime",
    "SystemTime",
    "timestamp",
)

NUMERIC_FIELDS: tuple[str, ...] = (
    "EventID",
    "ProcessId",
    "SourceProcessId",
    "TargetProcessId",
    "DestinationPort",
    "SourcePort",
)

_EMPTY = (None, "", "-")


def parse_ts(value: Any) -> float | None:
    """Return a UTC epoch timestamp, or ``None`` when unparseable.

    Naive timestamps are treated as UTC. That is the correct assumption for
    Windows event logs (which record local time only in the rendered message)
    and for Mordor exports (UTC by construction).
    """
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return None

    iso = text[:-1] + "+00:00" if text.endswith("Z") else text
    try:
        dt = datetime.fromisoformat(iso)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            dt = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            continue
    return None


def channel_class(channel: Any) -> str:
    """Collapse a channel name to the small set the engine reasons about."""
    text = str(channel or "").lower()
    if "sysmon" in text:
        return "sysmon"
    if "security-auditing" in text or text in ("security", "microsoft-windows-security"):
        return "security"
    if "powershell" in text:
        return "powershell"
    return "other"


def to_int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def normalise_record(raw: dict[str, Any]) -> dict[str, Any]:
    """Return a copy of ``raw`` with canonical fields and derived ``_`` fields."""
    event: dict[str, Any] = dict(raw)

    for canonical, aliases in FIELD_ALIASES.items():
        if event.get(canonical) not in _EMPTY:
            continue
        for alias in aliases:
            if alias == canonical:
                continue
            value = raw.get(alias)
            if value not in _EMPTY:
                event[canonical] = value
                break

    event_id = to_int(event.get("EventID"))
    if event_id is not None:
        event["EventID"] = event_id
    for field in NUMERIC_FIELDS:
        if field == "EventID":
            continue
        if field in event:
            numeric = to_int(event[field])
            if numeric is not None:
                event[field] = numeric

    ts = None
    for field in TIME_FIELDS:
        ts = parse_ts(raw.get(field))
        if ts is not None:
            break

    event["_ts"] = ts
    event["_event_id"] = event_id
    event["_channel_class"] = channel_class(event.get("Channel") or event.get("SourceName"))
    event["_host"] = event.get("Hostname") or event.get("Computer")
    return event


def iter_ndjson(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield JSON objects from a newline-delimited JSON file.

    Malformed lines are skipped rather than aborting the load: a partially
    written export should not cost you the whole corpus. The count of skipped
    lines is available via :func:`count_bad_lines`.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def count_bad_lines(path: str | Path) -> int:
    """Lines that are neither blank nor parseable JSON."""
    bad = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                json.loads(line)
            except json.JSONDecodeError:
                bad += 1
    return bad


def iter_records(path: str | Path) -> Iterator[dict[str, Any]]:
    """Yield records from either NDJSON or a single JSON array.

    Format is sniffed from the first non-whitespace byte. Real exports are not
    consistent about this and a loader that rejects the "wrong" one wastes an
    afternoon.
    """
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        first = ""
        while True:
            char = handle.read(1)
            if not char:
                break
            if not char.isspace():
                first = char
                break
        handle.seek(0)

        if first == "[":
            payload = json.load(handle)
            if isinstance(payload, list):
                for item in payload:
                    if isinstance(item, dict):
                        yield item
            return

        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(record, dict):
                yield record


def load_events(path: str | Path) -> list[dict[str, Any]]:
    """Load and normalise one telemetry file (NDJSON or JSON array)."""
    return [normalise_record(record) for record in iter_records(path)]


def load_corpus(paths: Iterable[str | Path]) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for path in paths:
        events.extend(load_events(path))
    return events


def summarise(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Small descriptive summary, used by ``de-lab inspect`` and the report."""
    by_channel: dict[str, int] = {}
    by_event_id: dict[int, int] = {}
    hosts: set[str] = set()
    stamps = []
    for event in events:
        by_channel[event["_channel_class"]] = by_channel.get(event["_channel_class"], 0) + 1
        event_id = event.get("_event_id")
        if event_id is not None:
            by_event_id[event_id] = by_event_id.get(event_id, 0) + 1
        if event.get("_host"):
            hosts.add(str(event["_host"]))
        if event.get("_ts"):
            stamps.append(event["_ts"])

    return {
        "events": len(events),
        "channels": dict(sorted(by_channel.items(), key=lambda kv: -kv[1])),
        "event_ids": dict(sorted(by_event_id.items())),
        "hosts": sorted(hosts),
        "first_ts": min(stamps) if stamps else None,
        "last_ts": max(stamps) if stamps else None,
    }
