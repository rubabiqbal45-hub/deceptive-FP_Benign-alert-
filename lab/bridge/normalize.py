"""Normalise Wazuh alert JSON into a flat event table.

Input
-----
``/var/ossec/logs/alerts/alerts.json`` (one JSON object per line) or any
NDJSON export with the same shape.

The output columns are deliberately *raw* — no scoring, no derived context.
``detect.py`` applies the detection pack and ``context.py`` computes the
behavioural features.

Both the Wazuh JSON layout and a raw Sysmon XML ``full_log`` blob are handled,
because which one you get depends on the decoder version and on
``<logall_json>``/``<logall>`` settings.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import numpy as np
import pandas as pd

_XML_DATA = re.compile(r'<Data\s+Name="([^"]+)"\s*>(.*?)</Data>', re.IGNORECASE | re.DOTALL)


def _ci(d, key: str):
    """Case-insensitive dict lookup (Wazuh mixes camelCase and lowercase)."""
    if not isinstance(d, dict):
        return None
    if key in d:
        return d[key]
    low = key.lower()
    for k, v in d.items():
        if str(k).lower() == low:
            return v
    return None


def _dig(obj, *keys):
    cur = obj
    for k in keys:
        cur = _ci(cur, k)
        if cur is None:
            return None
    return cur


def _xml_eventdata(blob: str) -> dict:
    if not blob or "<Data" not in blob:
        return {}
    return {k.lower(): v for k, v in _XML_DATA.findall(blob)}


def _event_dict(alert: dict) -> dict:
    """Pull the Sysmon/Security eventdata map out of one alert."""
    data = _ci(alert, "data")
    win = _ci(data, "win") if isinstance(data, dict) else None

    merged: dict = {}
    # some decoders put the fields directly under data.win.eventdata,
    # others under data.win, others under data
    for container in (
        _dig(win, "eventdata"),
        _dig(data, "eventdata"),
        win,
        data,
    ):
        if isinstance(container, dict):
            for k, v in container.items():
                merged.setdefault(str(k).lower(), v)

    for k, v in _xml_eventdata(_ci(alert, "full_log") or "").items():
        merged.setdefault(k, v)
    return merged


def _system_dict(alert: dict) -> dict:
    data = _ci(alert, "data")
    win = _ci(data, "win") if isinstance(data, dict) else None
    sysd = _dig(win, "system")
    return sysd if isinstance(sysd, dict) else {}


def _as_int(x, default: int = 0) -> int:
    try:
        return int(str(x).strip())
    except (TypeError, ValueError):
        return default


def _as_bool_flag(x) -> float:
    if x is None:
        return float("nan")
    s = str(x).strip().lower()
    if s in ("true", "1", "yes"):
        return 1.0
    if s in ("false", "0", "no"):
        return 0.0
    return float("nan")


def _basename(path) -> str:
    if not path:
        return ""
    return re.split(r"[\\/]", str(path))[-1].lower()


def load_alerts(path: str | Path) -> list[dict]:
    """Read an NDJSON alert file, skipping malformed lines."""
    path = Path(path)
    out: list[dict] = []
    bad = 0
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                bad += 1
    if bad:
        print(f"  [warn] skipped {bad} malformed JSON lines")
    return out


def normalize(alerts: list[dict]) -> pd.DataFrame:
    """Return one row per raw telemetry event."""
    rows: list[dict] = []
    for a in alerts:
        ev = _event_dict(a)
        sysd = _system_dict(a)

        ts = _ci(a, "timestamp") or _ci(sysd, "utcTime")
        host = (
            _dig(a, "agent", "name")
            or _ci(sysd, "computer")
            or "unknown"
        )
        image = ev.get("image") or ""
        parent_image = ev.get("parentimage") or ""
        user = (
            ev.get("user")
            or ev.get("targetusername")
            or ev.get("subjectusername")
            or ""
        )

        rows.append({
            "ts": ts,
            "host_raw": str(host),
            "event_id": _as_int(_ci(sysd, "eventID") or sysd.get("eventid")),
            "image": str(image),
            "image_name": _basename(image),
            "parent_image": str(parent_image),
            "parent_name": _basename(parent_image),
            "command_line": str(ev.get("commandline") or ""),
            "parent_command_line": str(ev.get("parentcommandline") or ""),
            "user_raw": str(user),
            "process_guid": str(ev.get("processguid") or ""),
            "parent_guid": str(ev.get("parentprocessguid") or ""),
            "integrity_level": str(ev.get("integritylevel") or ""),
            "signed": _as_bool_flag(ev.get("signed")),
            "signature": str(ev.get("signature") or ""),
            "dst_ip": str(ev.get("destinationip") or ""),
            "dst_port": _as_int(ev.get("destinationport")),
            "target_image": str(ev.get("targetimage") or ""),
            "target_image_name": _basename(ev.get("targetimage")),
            "granted_access": str(ev.get("grantedaccess") or ""),
            "query_name": str(ev.get("queryname") or ""),
            "src_ip": str(ev.get("sourceip") or ""),
            "logon_type": _as_int(ev.get("logontype")),
            "wazuh_rule_id": str(_dig(a, "rule", "id") or ""),
            "wazuh_rule_desc": str(_dig(a, "rule", "description") or ""),
        })

    df = pd.DataFrame(rows)
    if df.empty:
        raise ValueError("no alerts parsed from the input file")

    df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df = df[df["ts"].notna()].copy()
    df["ts"] = df["ts"].dt.tz_convert(None)
    df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)
    df["event_uid"] = [f"EV-{i:07d}" for i in range(len(df))]
    return df


def deduplicate(df: pd.DataFrame) -> pd.DataFrame:
    """Collapse duplicated Sysmon events.

    Wazuh often emits the same event through more than one decoder (Sysmon
    channel + a custom rule).  Keeping the first occurrence prevents one
    process creation from being counted five times.
    """
    key = ["host_raw", "process_guid", "event_id"]
    has_guid = df["process_guid"].str.len() > 0
    a = df[has_guid].drop_duplicates(subset=key, keep="first")
    b = df[~has_guid].drop_duplicates(
        subset=["host_raw", "ts", "image", "command_line"], keep="first"
    )
    out = pd.concat([a, b]).sort_values("ts", kind="mergesort").reset_index(drop=True)
    return out


def summary(df: pd.DataFrame) -> dict:
    return {
        "events": int(len(df)),
        "hosts": int(df["host_raw"].nunique()),
        "users": int(df["user_raw"].nunique()),
        "event_ids": {int(k): int(v) for k, v in
                      df["event_id"].value_counts().head(10).items()},
        "first": str(df["ts"].min()),
        "last": str(df["ts"].max()),
    }


def process_depth(df: pd.DataFrame, cap: int = 8) -> np.ndarray:
    """Depth of each process in its parent chain, from Sysmon process GUIDs."""
    guid_depth: dict[str, int] = {}
    out = np.zeros(len(df), dtype=float)
    for i, (guid, pguid) in enumerate(
        zip(df["process_guid"].to_numpy(), df["parent_guid"].to_numpy())
    ):
        if not guid:
            out[i] = 0.0
            continue
        depth = guid_depth.get(pguid, 0) + 1 if pguid else 1
        depth = min(depth, cap)
        guid_depth[guid] = depth
        out[i] = float(depth)
    return out
