"""Temporal splitting that also works on short lab captures.

The study uses a week-based split (train w1-6 / calibrate w7-8 / test w9-12).
A lab capture may only be a few days long, where every alert falls in "week 1"
and the week-based split would silently produce an empty test set.

``temporal_split`` keeps the week-based behaviour whenever the data really does
span enough weeks, and otherwise falls back to contiguous time fractions.  The
fallback is still strictly temporal: no alert ever trains on data from later
than the cutoff.
"""

from __future__ import annotations

import numpy as np
import pandas as pd


def temporal_split(
    df: pd.DataFrame,
    cfg,
    train_frac: float = 0.60,
    calib_frac: float = 0.20,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    """Return (train, calibrate, test) as contiguous slices of time."""
    n_weeks = int(df["week"].max()) if len(df) else 0
    week_based = n_weeks >= max(cfg.test_weeks[1], 4)

    if week_based:
        def cut(lo: int, hi: int) -> pd.DataFrame:
            return df[(df["week"] >= lo) & (df["week"] <= hi)]

        return cut(*cfg.train_weeks), cut(*cfg.calib_weeks), cut(*cfg.test_weeks)

    order = df.sort_values("ts", kind="mergesort")
    n = len(order)
    if n < 3:
        raise ValueError(
            f"need at least 3 alerts for a three-way split, got {n}"
        )
    # Keep all three slices non-empty even for a very short capture.
    i1 = min(max(1, int(round(train_frac * n))), n - 2)
    i2 = min(max(i1 + 1, int(round((train_frac + calib_frac) * n))), n - 1)

    train = order.iloc[:i1]
    calib = order.iloc[i1:i2]
    test = order.iloc[i2:]
    return train.copy(), calib.copy(), test.copy()


def split_info(df: pd.DataFrame, cfg) -> dict:
    """Describe which split rule was applied, for the report."""
    n_weeks = int(df["week"].max()) if len(df) else 0
    week_based = n_weeks >= max(cfg.test_weeks[1], 4)
    return {
        "mode": "week" if week_based else "time-fraction",
        "weeks_observed": n_weeks,
        "note": (
            "contiguous 60/20/20 split; capture is shorter than the "
            "configured 12-week window"
            if not week_based
            else "configured week ranges"
        ),
    }


def weeks_covered(df: pd.DataFrame) -> np.ndarray:
    """Week indices present, as a sorted int array."""
    if "week" not in df:
        return np.array([], dtype=int)
    return np.sort(df["week"].unique().astype(int))
