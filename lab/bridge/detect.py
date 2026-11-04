"""A minimal Sigma-style detection pack.

Why re-implement detections instead of reading Wazuh rule IDs?

Wazuh rule IDs differ between ruleset versions, and many installs disable the
Sysmon ruleset entirely. The lab would then "work" on one machine and silently
produce zero alerts on another. Detecting on the *Sysmon fields and command
line* is stable, auditable, and maps one-to-one onto the rule catalog the
thesis evaluates.

These are not production-grade Sigma rules — they are deliberately transparent
so a reviewer can check exactly why an alert fired.
"""

from __future__ import annotations

import pandas as pd

from soc_triage.schema import RULE_CATALOG

OFFICE = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe"}
DOWNLOADERS = {"curl.exe", "certutil.exe", "bitsadmin.exe", "wget.exe", "certreq.exe"}
REMOTE_TOOLS = {
    "winvnc.exe", "vncserver.exe", "tvnserver.exe", "tv_w32.exe",
    "teamviewer.exe", "anydesk.exe", "rutserv.exe", "screenconnect.clientservice.exe",
}
CHILD_SUSPECT = {
    "powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "wscript.exe",
    "cscript.exe", "mshta.exe", "regsvr32.exe", "certutil.exe",
}
LSASS_ACCESS = {"0x1010", "0x1410", "0x1fffff", "0x143a", "0x40"}

DETECTION_COLUMNS = [
    "event_uid", "ts", "host_raw", "user_raw",
    "rule_id", "rule_name", "technique", "severity",
    "process_name", "parent_process", "command_line",
    "signed", "signature", "dst_ip", "dst_port",
    "process_guid", "parent_guid", "target_image_name",
    "integrity_level", "src_ip", "source_event_id",
]


def _has(s: pd.Series, *needles: str) -> pd.Series:
    low = s.fillna("").astype(str).str.lower()
    mask = pd.Series(False, index=s.index)
    for n in needles:
        mask |= low.str.contains(n, regex=False)
    return mask


def detect(df: pd.DataFrame) -> pd.DataFrame:
    """Apply the rule pack; one row per (event, rule) pair."""
    img = df["image_name"].fillna("").str.lower()
    par = df["parent_name"].fillna("").str.lower()
    cmd = df["command_line"].fillna("").astype(str)
    eid = df["event_id"].fillna(0).astype(int)

    # --- correlation: office document that spawned a scripting child --------
    spawned = set(
        df.loc[img.isin(CHILD_SUSPECT), "parent_guid"].dropna().astype(str)
    )
    office_with_child = img.isin(OFFICE) & df["process_guid"].astype(str).isin(spawned)

    masks: dict[str, pd.Series] = {
        # Remote service execution
        "R-1021-002": img.isin({"psexec.exe", "psexesvc.exe"}),
        # Encoded / obfuscated PowerShell
        "R-1059-001": (
            img.isin({"powershell.exe", "pwsh.exe"})
            & _has(cmd, "-enc", "-encodedcommand", "frombase64string")
            & _has(cmd, "-nop", "-noprofile", "hidden", "bypass", "-w ")
        ),
        # Rundll32 proxy execution with a DLL argument
        "R-1218-011": (
            (img == "rundll32.exe")
            & _has(cmd, ".dll", ".cpl", ".ocx")
            & (par.isin(OFFICE) | ~_has(cmd, "c:\\windows\\system32"))
        ),
        # Ingress tool transfer
        "R-1105": (
            img.isin(DOWNLOADERS)
            & _has(cmd, "http://", "https://", "ftp://")
            & _has(cmd, "-o ", "-out", "-urlcache", "-transfer", "/transfer", "download")
        ),
        # Remote access tooling
        "R-1219": img.isin(REMOTE_TOOLS),
        # LSASS credential access
        "R-1003-001": (
            ((eid == 10) & (df["target_image_name"].str.lower() == "lsass.exe")
             & df["granted_access"].astype(str).str.lower().isin(LSASS_ACCESS))
            | ((img == "procdump.exe") & _has(cmd, "lsass"))
        ),
        # Scheduled task creation
        "R-1053-005": (img == "schtasks.exe") & _has(cmd, "/create", "-create"),
        # Application-layer beaconing (approximate: system binary talking out)
        "R-1071-001": (
            (eid == 3)
            & img.isin({"rundll32.exe", "regsvr32.exe", "mshta.exe"})
            & (df["dst_ip"].fillna("").astype(str).str.len() > 0)
            & ~df["dst_port"].fillna(0).astype(int).isin({53, 123, 137, 138, 139, 445})
        ),
        # Office macro execution
        "R-1204-002": office_with_child,
        # External remote service login
        "R-1133": (
            ((eid == 3) & (df["dst_port"].fillna(0).astype(int) == 3389))
            | (img == "mstsc.exe")
            | ((eid == 4624) & df["logon_type"].fillna(0).astype(int).isin({3, 10}))
        ),
    }

    frames = []
    for rule_id, mask in masks.items():
        mask = mask.fillna(False)
        if not mask.any():
            continue
        sub = df.loc[mask].copy()
        meta = RULE_CATALOG[rule_id]
        sub["rule_id"] = rule_id
        sub["rule_name"] = meta.name
        sub["technique"] = meta.technique
        sub["severity"] = meta.severity
        sub["process_name"] = sub["image_name"]
        sub["parent_process"] = sub["parent_name"]
        sub["source_event_id"] = sub["event_id"]
        frames.append(sub[DETECTION_COLUMNS])

    if not frames:
        return pd.DataFrame(columns=DETECTION_COLUMNS)

    out = pd.concat(frames, ignore_index=True)
    return out.sort_values(["ts", "rule_id"], kind="mergesort").reset_index(drop=True)


def coverage(det: pd.DataFrame) -> pd.DataFrame:
    """Per-rule counts, for a quick sanity check after a capture."""
    if det.empty:
        return pd.DataFrame(columns=["rule_id", "rule_name", "alerts", "hosts"])
    return (
        det.groupby(["rule_id", "rule_name"])
        .agg(alerts=("event_uid", "size"),
             hosts=("host_raw", "nunique"))
        .reset_index()
        .sort_values("alerts", ascending=False)
    )
