"""Robustness experiments: concept drift and adversarial imitation.

Two failure modes that the literature routinely ignores and that an SOC will
hit within weeks:

* **Drift** — new benign automation makes a rule fire everywhere; the model's
  learned base rate is now wrong.
* **Adversarial imitation** — the attacker copies the admin's context
  (role, hours, destination, command line) so the triage score is high-benign.

Both are simulated by `synth.generator.inject_drift` / `inject_adversarial`.
"""

from __future__ import annotations

import numpy as np
import pandas as pd

from soc_triage.eval.metrics import pr_auc, roc_auc


def weekly_metrics(df: pd.DataFrame, scores: np.ndarray,
                   threshold: float) -> pd.DataFrame:
    """Per-week detection quality, to make drift visible."""
    rows = []
    for week, g in df.assign(score=scores).groupby("week"):
        y = g["label"].to_numpy(int)
        s = g["score"].to_numpy(float)
        if len(np.unique(y)) < 2:
            continue
        kept = s >= threshold
        tp = int((kept & (y == 1)).sum())
        rows.append({
            "week": int(week),
            "alerts": len(g),
            "attacks": int(y.sum()),
            "attack_rate": float(y.mean()),
            "roc_auc": roc_auc(y, s),
            "pr_auc": pr_auc(y, s),
            "recall_at_threshold": tp / max(int(y.sum()), 1),
            "alerts_kept": int(kept.sum()),
            "suppressed_frac": float(1 - kept.mean()),
        })
    return pd.DataFrame(rows)


def adversarial_report(df: pd.DataFrame, scores: np.ndarray,
                       threshold: float) -> pd.DataFrame:
    """Recall on attacks that imitate benign context vs. ordinary attacks."""
    y = df["label"].to_numpy(int)
    adv = df.get("adversarial", pd.Series(np.zeros(len(df)))).to_numpy(int)
    kept = scores >= threshold
    rows = []
    for label, m in (("ordinary attacks", (y == 1) & (adv == 0)),
                     ("adversarial attacks", (y == 1) & (adv == 1))):
        n = int(m.sum())
        rows.append({
            "group": label,
            "n": n,
            "recall": float((kept & m).sum() / n) if n else float("nan"),
        })
    return pd.DataFrame(rows)


def recalibration_gain(df_cal: pd.DataFrame, y_cal: np.ndarray,
                       df_test: pd.DataFrame, y_test: np.ndarray,
                       make_selector, alpha: float,
                       delta: float = 0.05,
                       min_suppress: int = 100) -> dict:
    """Compare a stale threshold with one recalibrated on the drifted period."""
    from soc_triage.models.selective import RiskControlledSelector

    stale = make_selector(alpha).fit(df_cal["score"].to_numpy(), y_cal)
    fresh = RiskControlledSelector(
        alpha=alpha, delta=delta, min_suppress=min_suppress
    ).fit(df_test["score"].to_numpy(), y_test)

    def realised(sel):
        m = sel.suppress_mask(df_test["score"].to_numpy())
        if m.sum() == 0:
            return {"coverage": 0.0, "fn_rate": float("nan")}
        return {
            "coverage": float(m.mean()),
            "fn_rate": float(y_test[m].mean()),
        }

    return {"stale": realised(stale), "recalibrated": realised(fresh)}
