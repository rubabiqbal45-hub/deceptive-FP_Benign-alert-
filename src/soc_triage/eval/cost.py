"""Cost-aware operating-point analysis.

An SOC does not optimise F1.  It trades analyst hours against expected loss
from attacks that never reached a human::

    cost(threshold) = reviewed_alerts x cost_per_review
                    + missed_attacks x P(exploit | miss) x breach_cost

Because breach costs are large, the cost-optimal policy is frequently "review
almost everything" — which is *why* alert fatigue exists.  The sensitivity grid
shows the break-even point at which suppression becomes economically rational,
which is far more informative than a single optimum.
"""

from __future__ import annotations

from dataclasses import replace

import numpy as np
import pandas as pd


def cost_per_review(cfg) -> float:
    return cfg.analyst_hourly_cost / cfg.analyst_alerts_per_hour


def sweep_costs(df_test, scores: np.ndarray, cfg,
                n_points: int = 60, p_exploit: float | None = None,
                breach_cost: float | None = None) -> pd.DataFrame:
    """Annualised cost over a threshold sweep."""
    y = df_test["label"].to_numpy(int)
    n = len(y)
    days = max((df_test["ts"].max() - df_test["ts"].min()).days, 1)
    alerts_per_day = n / days
    neg_per_day = alerts_per_day * (1 - y.mean())
    pos_per_day = alerts_per_day * y.mean()

    p = cfg.p_exploit_given_miss if p_exploit is None else p_exploit
    breach = cfg.breach_cost if breach_cost is None else breach_cost
    cpr = cost_per_review(cfg)
    review_all_cost = 365.0 * alerts_per_day * cpr

    thresholds = np.unique(np.quantile(scores, np.linspace(0.0, 0.999, n_points)))
    rows = []
    for t in thresholds:
        pred = scores >= t
        fn = int(((~pred) & (y == 1)).sum())
        fn_rate = fn / max(int((y == 1).sum()), 1)
        kept_day = float(alerts_per_day * pred.mean())
        fn_day = fn_rate * pos_per_day
        review_cost = 365.0 * kept_day * cpr
        miss_cost = 365.0 * fn_day * p * breach
        rows.append({
            "threshold": float(t),
            "kept_per_day": kept_day,
            "keep_fraction": float(pred.mean()),
            "fn_per_day": float(fn_day),
            "review_cost_annual": float(review_cost),
            "miss_cost_annual": float(miss_cost),
            "total_cost_annual": float(review_cost + miss_cost),
            "recall": float(1 - fn_rate),
            "savings_vs_review_all": float(review_all_cost - (review_cost + miss_cost)),
        })

    out = pd.DataFrame(rows).sort_values("threshold").reset_index(drop=True)
    out.attrs["review_all_cost_annual"] = review_all_cost
    return out


def optimal_operating_point(df_test, scores: np.ndarray, cfg) -> dict:
    curve = sweep_costs(df_test, scores, cfg)
    best = curve.loc[curve["total_cost_annual"].idxmin()]
    review_all_cost = float(curve.attrs["review_all_cost_annual"])
    return {
        "threshold": float(best["threshold"]),
        "recall": float(best["recall"]),
        "kept_per_day": float(best["kept_per_day"]),
        "keep_fraction": float(best["keep_fraction"]),
        "total_cost_annual": float(best["total_cost_annual"]),
        "review_cost_annual": float(best["review_cost_annual"]),
        "miss_cost_annual": float(best["miss_cost_annual"]),
        "review_all_cost_annual": review_all_cost,
        "savings_annual": float(review_all_cost - best["total_cost_annual"]),
        "savings_pct": float(
            100.0 * (review_all_cost - best["total_cost_annual"])
            / max(review_all_cost, 1e-9)
        ),
        "curve": curve,
    }


def sensitivity_grid(df_test, scores: np.ndarray, cfg,
                     p_values: tuple[float, ...] = (1e-4, 1e-3, 1e-2, 5e-2)
                     ) -> pd.DataFrame:
    """Where does suppression start to pay for itself?

    For each assumed P(exploit | miss) we report the cost-optimal keep
    fraction.  A SOC that suppresses heavily is implicitly betting that this
    probability is small — often without ever writing the number down.
    """
    rows = []
    for p in p_values:
        opt = optimal_operating_point(df_test, scores, replace(cfg, p_exploit_given_miss=p))
        rows.append({
            "p_exploit_given_miss": p,
            "implicit_cost_per_miss": p * cfg.breach_cost,
            "optimal_keep_fraction": opt["keep_fraction"],
            "optimal_recall": opt["recall"],
            "savings_vs_review_all": opt["savings_annual"],
            "suppression_is_optimal": opt["keep_fraction"] < 0.80,
        })
    return pd.DataFrame(rows)
