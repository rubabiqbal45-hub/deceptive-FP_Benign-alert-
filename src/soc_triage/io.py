"""Dataset loading: the seam between simulated and real telemetry.

``run_experiments.py --source csv --path lab/out/lab_dataset.csv`` reads a
dataset produced by ``lab/bridge/build_dataset.py`` and runs the identical
pipeline.  Nothing downstream knows or cares where the alerts came from.
"""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd

from soc_triage.schema import assert_schema


def _derive_time_columns(df: pd.DataFrame, start: pd.Timestamp) -> pd.DataFrame:
    df = df.copy()
    if "dow" not in df.columns or df["dow"].isna().any():
        df["dow"] = df["ts"].dt.day_of_week.astype(int)
    if "week" not in df.columns or df["week"].isna().any():
        df["week"] = ((df["ts"] - start).dt.days // 7 + 1).astype(int)
    return df


def load_dataset(path: str | Path, trim_weeks: int | None = None) -> pd.DataFrame:
    """Read a CSV dataset, coerce dtypes, validate the schema, sort by time."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"dataset not found: {path.resolve()}")

    df = pd.read_csv(path)
    if df.empty:
        raise ValueError(f"dataset is empty: {path}")

    df["ts"] = pd.to_datetime(df["ts"], errors="coerce", utc=True)
    df = df[df["ts"].notna()].copy()
    df["ts"] = df["ts"].dt.tz_convert(None)
    df = df.sort_values("ts", kind="mergesort").reset_index(drop=True)

    start = df["ts"].min().normalize()
    df = _derive_time_columns(df, start)

    if trim_weeks is not None and trim_weeks > 0:
        df = df[df["week"] <= trim_weeks].reset_index(drop=True)

    # numeric columns the pipeline expects to be floats
    numeric = (
        "severity", "asset_criticality", "event_count", "burst_size",
        "lineage_depth", "host_novelty", "peer_rarity", "cmdline_distance",
        "dst_reputation", "signed_ratio", "role_asset_mismatch",
        "label", "is_deceptive_fp", "is_deceptive_attack",
    )
    for c in numeric:
        if c in df.columns:
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0.0).astype(float)

    for c in ("label", "is_deceptive_fp", "is_deceptive_attack"):
        if c in df.columns:
            df[c] = (df[c] > 0.5).astype(int)

    if "alert_id" not in df.columns:
        df["alert_id"] = [f"AL-{i:06d}" for i in range(len(df))]

    # columns that exist but were parsed as strings need a sane default
    for c in ("rule_name", "technique", "process_name", "parent_process",
              "asset_type", "user_role"):
        if c in df.columns:
            df[c] = df[c].astype(str).replace({"nan": "unknown"})
    if "command_line" in df.columns:
        df["command_line"] = df["command_line"].fillna("").astype(str)

    assert_schema(df)
    return df


def dataset_summary(df: pd.DataFrame) -> dict:
    """Numbers quoted in the report's dataset table."""
    days = max((df["ts"].max() - df["ts"].min()).days, 1)
    return {
        "alerts": int(len(df)),
        "days": int(days),
        "weeks_observed": int(df["week"].max()),
        "attack_rate": float(df["label"].mean()),
        "deceptive_fp_rate": float(df["is_deceptive_fp"].mean()),
        "attacks": int(df["label"].sum()),
        "deceptive_attacks": int(df["is_deceptive_attack"].sum()),
        "unique_rules": int(df["rule_id"].nunique()),
        "unique_hosts": int(df["host_id"].nunique()),
        "unique_users": int(df["user_id"].nunique()),
    }


def write_scored_sample(df: pd.DataFrame, path: str | Path, n: int = 3000,
                        seed: int = 42) -> None:
    path = Path(path)
    sample = df.sample(min(n, len(df)), random_state=seed) if len(df) > n else df
    sample.to_csv(path, index=False)


def finite_or_nan(x: float) -> float:
    return float(x) if np.isfinite(x) else float("nan")
