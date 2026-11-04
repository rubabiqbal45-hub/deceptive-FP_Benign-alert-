"""Causal feature engineering.

Every historical feature is computed with an *expanding* window over time so
that an alert only ever sees information that existed before it arrived.  This
is the single most common source of inflated results in alert-triage papers and
is treated explicitly here.
"""

from __future__ import annotations

from collections import Counter

import numpy as np
import pandas as pd

NUM_FEATURES: list[str] = [
    # --- static context -------------------------------------------------
    "severity",
    "asset_criticality",
    "event_count",
    "burst_size",
    "lineage_depth",
    "host_novelty",
    "peer_rarity",
    "cmdline_distance",
    "dst_reputation",
    "signed_ratio",
    "role_asset_mismatch",
    # --- temporal context -----------------------------------------------
    "hour",
    "dow",
    "is_weekend",
    "user_hour_z",
    # --- causal history (expanding, no leakage) -------------------------
    "hist_user_rule",
    "hist_host_rule",
    "hist_user",
    "host_burst_10m",
    "days_since_rule_host",
    # --- command-line shape ---------------------------------------------
    "cmd_token_count",
    "cmd_suspicious_tokens",
    "cmd_entropy",
]

CAT_FEATURES: list[str] = [
    "user_role",
    "asset_type",
    "rule_id",
    "technique",
    "process_name",
]

_SUSPICIOUS_TOKENS = (
    "-enc", "-nop", "hidden", "bypass", "psexec", "rundll32", "lsass",
    "schtasks", "certutil", "urlcache", "iex", "downloadstring", "/create",
    "-ma", "procdump", "winvnc", "\\temp\\",
)


def _trailing_count(ts_ns: np.ndarray, groups: np.ndarray, window_ns: int) -> np.ndarray:
    """Count prior events in the same group within a trailing time window."""
    out = np.zeros(len(ts_ns), dtype=np.int64)
    for g in np.unique(groups):
        idx = np.flatnonzero(groups == g)
        arr = ts_ns[idx]
        left = np.searchsorted(arr, arr - window_ns, side="left")
        out[idx] = np.arange(len(arr)) - left
    return out


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = np.array(list(Counter(text).values()), dtype=float)
    p = counts / counts.sum()
    return float(-(p * np.log2(p)).sum())


def build_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str], list[str]]:
    """Return (dataframe with engineered columns, numeric features, categorical)."""
    d = df.sort_values("ts", kind="mergesort").reset_index(drop=True).copy()

    # ------------------------------------------------------------ temporal
    d["hour"] = d["ts"].dt.hour + d["ts"].dt.minute / 60.0
    d["is_weekend"] = (d["dow"] >= 5).astype(int)

    # ------------------------------------- causal counts over prior events
    d["hist_user_rule"] = d.groupby(["user_id", "rule_id"], sort=False).cumcount()
    d["hist_host_rule"] = d.groupby(["host_id", "rule_id"], sort=False).cumcount()
    d["hist_user"] = d.groupby("user_id", sort=False).cumcount()

    ts_ns = d["ts"].to_numpy(dtype="datetime64[ns]").astype("int64")
    host_codes = pd.factorize(d["host_id"], sort=False)[0]
    d["host_burst_10m"] = _trailing_count(ts_ns, host_codes, 10 * 60 * 1_000_000_000)

    # time since this rule last fired on this host
    prev = d.groupby(["host_id", "rule_id"], sort=False)["ts"].shift()
    delta_days = (d["ts"] - prev).dt.total_seconds() / 86400.0
    d["days_since_rule_host"] = delta_days.fillna(90.0).clip(0, 90)

    # user's personal baseline for time-of-day
    grp = d.groupby("user_id", sort=False)["hour"]
    mu = grp.transform(lambda s: s.expanding().mean().shift())
    sd = grp.transform(lambda s: s.expanding().std().shift())
    d["user_hour_z"] = ((d["hour"] - mu) / sd.replace(0.0, np.nan)).fillna(0.0).clip(-6, 6)

    # ------------------------------------------------------ command line
    cmd = d["command_line"].fillna("").astype(str)
    d["cmd_token_count"] = cmd.map(lambda s: len(s.split())).astype(float)
    lower = cmd.str.lower()
    d["cmd_suspicious_tokens"] = lower.map(
        lambda s: float(sum(s.count(tok) for tok in _SUSPICIOUS_TOKENS))
    )
    d["cmd_entropy"] = cmd.map(_entropy)

    for col in NUM_FEATURES:
        if col not in d.columns:
            d[col] = 0.0
        d[col] = pd.to_numeric(d[col], errors="coerce").astype(float).fillna(0.0)
    for col in CAT_FEATURES:
        d[col] = d[col].astype(str).fillna("__na__")

    return d, list(NUM_FEATURES), list(CAT_FEATURES)
