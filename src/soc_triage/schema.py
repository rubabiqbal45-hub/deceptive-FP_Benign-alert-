"""Canonical alert schema, shared by the synthetic generator and the lab bridge.

Both halves of the study have to agree on one table shape:

* ``synth.generator`` produces it directly;
* ``lab/bridge`` produces it from real Wazuh/Sysmon telemetry.

Having the contract in one place is what makes "swap the simulator for a live
export" a configuration change instead of a rewrite.
"""

from __future__ import annotations

from dataclasses import dataclass

import pandas as pd


@dataclass(frozen=True)
class Rule:
    """A deployed detection rule — the unit an analyst would whitelist."""

    rule_id: str
    name: str
    technique: str
    severity: int
    tactic: str


_CATALOG = (
    Rule("R-1133", "External Remote Service Login", "T1133", 2, "Initial Access"),
    Rule("R-1204-002", "Office Macro Execution", "T1204.002", 2, "Execution"),
    Rule("R-1105", "Ingress Tool Transfer over HTTP", "T1105", 2, "Command and Control"),
    Rule("R-1219", "Remote Access Tool Execution", "T1219", 3, "Command and Control"),
    Rule("R-1218-011", "Rundll32 Proxy Execution", "T1218.011", 3, "Defense Evasion"),
    Rule("R-1053-005", "Scheduled Task Creation", "T1053.005", 3, "Persistence"),
    Rule("R-1059-001", "Suspicious PowerShell Encoded Command", "T1059.001", 4, "Execution"),
    Rule("R-1021-002", "Remote Service Execution via PsExec", "T1021.002", 4, "Lateral Movement"),
    Rule("R-1071-001", "Application Layer C2 Beacon", "T1071.001", 4, "Command and Control"),
    Rule("R-1003-001", "LSASS Memory Access", "T1003.001", 5, "Credential Access"),
)

RULE_CATALOG: dict[str, Rule] = {r.rule_id: r for r in _CATALOG}

#: Severity is a property of the *rule*, never of the alert. If it tracked the
#: ground-truth label the classifier would learn a trivial shortcut.
RULE_SEVERITY: dict[str, int] = {r.rule_id: r.severity for r in _CATALOG}


REQUIRED_COLUMNS: tuple[str, ...] = (
    # identity / timing
    "alert_id", "ts", "week", "dow",
    # asset
    "host_id", "asset_type", "asset_criticality",
    # identity
    "user_id", "user_role",
    # detection
    "rule_id", "rule_name", "technique", "severity",
    "process_name", "parent_process", "command_line",
    # behavioural context
    "event_count", "burst_size", "lineage_depth",
    "host_novelty", "peer_rarity", "cmdline_distance",
    "dst_reputation", "signed_ratio", "role_asset_mismatch",
    # labels (ground truth)
    "label", "is_deceptive_fp", "is_deceptive_attack",
)

OPTIONAL_COLUMNS: tuple[str, ...] = (
    "scenario_id", "playbook", "dst_ip", "src_ip", "adversarial", "source",
)


def assert_schema(df: pd.DataFrame, strict: bool = True) -> None:
    """Fail loudly if a dataset cannot be fed to the pipeline."""
    missing = [c for c in REQUIRED_COLUMNS if c not in df.columns]
    if missing:
        raise ValueError(
            "dataset is missing required columns: " + ", ".join(missing)
        )
    if len(df) == 0:
        raise ValueError("dataset is empty")
    if strict:
        for c in ("label", "is_deceptive_fp", "is_deceptive_attack"):
            bad = set(pd.unique(df[c])) - {0, 1}
            if bad:
                raise ValueError(f"{c} must be binary, found {sorted(bad)}")
        if df["ts"].isna().any():
            raise ValueError("ts contains NaT values")
        if not df["ts"].is_monotonic_increasing:
            raise ValueError(
                "ts must be sorted ascending (causal feature construction "
                "depends on it)"
            )
