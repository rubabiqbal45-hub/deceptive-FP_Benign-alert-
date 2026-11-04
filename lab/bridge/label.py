"""Ground-truth attachment and deceptive-FP derivation.

Two labels are needed, and only one of them is free.

``label``
    Did this alert correspond to a real attack?  Comes from the test schedule
    written by ``run-atomics.ps1``: an alert is a true positive if it fired on
    the attack host while the technique was executing.

``is_deceptive_fp`` / ``is_deceptive_attack``
    Derived, exactly as in the synthetic study: a *behavioural signature*
    (rule + process + parent) is deceptive when it appears in both classes.
    A benign alert carrying such a signature is a deceptive false positive,
    because suppressing it would also suppress the attack that shares the
    signature.

That derivation is the point of the whole exercise: it is computed from real
telemetry, not asserted.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def signature(det: pd.DataFrame) -> pd.Series:
    return (
        det["rule_id"].astype(str) + "|"
        + det["process_name"].astype(str).str.lower() + "|"
        + det["parent_process"].astype(str).str.lower()
    )


def attach_labels(det: pd.DataFrame, truth: pd.DataFrame,
                  match: str = "time+rule",
                  slack_seconds: int = 90) -> pd.DataFrame:
    """Mark alerts that fall inside a scheduled technique execution."""
    d = det.copy()
    d["label"] = 0

    if truth is None or len(truth) == 0:
        raise ValueError(
            "ground truth is empty — run-atomics.ps1 must write ground_truth.csv"
        )

    required = {"host_id", "rule_id", "start_utc", "end_utc"}
    missing = required - set(truth.columns)
    if missing:
        raise ValueError(f"ground truth missing columns: {sorted(missing)}")

    truth = truth.copy()
    truth["start_utc"] = pd.to_datetime(truth["start_utc"], utc=True).dt.tz_convert(None)
    truth["end_utc"] = pd.to_datetime(truth["end_utc"], utc=True).dt.tz_convert(None)
    slack = pd.Timedelta(seconds=slack_seconds)

    for row in truth.itertuples(index=False):
        mask = (
            (d["host_id"].astype(str) == str(row.host_id))
            & (d["ts"] >= row.start_utc - slack)
            & (d["ts"] <= row.end_utc + slack)
        )
        if match == "time+rule":
            mask &= d["rule_id"].astype(str) == str(row.rule_id)
        d.loc[mask, "label"] = 1

    return d


def derive_deceptive(det: pd.DataFrame) -> pd.DataFrame:
    """Flag signatures that occur in both the benign and the malicious class."""
    d = det.copy()
    sig = signature(d)
    d["signature"] = sig

    attack_sigs = set(sig[d["label"] == 1])
    benign_sigs = set(sig[d["label"] == 0])

    d["is_deceptive_fp"] = (
        (d["label"] == 0) & sig.isin(attack_sigs)
    ).astype(int)
    d["is_deceptive_attack"] = (
        (d["label"] == 1) & sig.isin(benign_sigs)
    ).astype(int)
    return d


def assign_scenarios(det: pd.DataFrame, gap_minutes: int = 15) -> pd.Series:
    """Group alerts into bursts, the way an incident actually arrives."""
    d = det.sort_values("ts", kind="mergesort")
    gap = pd.Timedelta(minutes=gap_minutes)
    out = np.zeros(len(d), dtype=int)
    cur, prev_host, prev_ts = 0, None, None
    for i, (host, ts) in enumerate(zip(d["host_id"], d["ts"])):
        if prev_ts is None or host != prev_host or (ts - prev_ts) > gap:
            cur += 1
        out[i] = cur
        prev_host, prev_ts = host, ts
    return pd.Series(out, index=d.index).reindex(det.index)


def truth_template() -> pd.DataFrame:
    """Empty ground-truth frame with the expected columns, for reference."""
    return pd.DataFrame(columns=[
        "run_id", "rule_id", "technique", "action", "host", "host_id",
        "start_utc", "end_utc", "executor",
    ])
