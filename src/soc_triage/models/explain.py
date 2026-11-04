"""Explanation layer.

Two things an analyst actually needs:

1. Global feature importance, so the SOC can audit *why* the model suppresses.
2. A per-alert counterfactual: "which field made this look malicious?"

We implement ablation attribution rather than SHAP so the framework stays
dependency-light and deterministic on the SIEM node.  For a tree model the
ranking is close to SHAP for the top few features.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.inspection import permutation_importance

from soc_triage.features.build import NUM_FEATURES


def global_importance(model, df: pd.DataFrame, y: np.ndarray,
                      sample: int = 6000, n_repeats: int = 5) -> pd.DataFrame:
    """Permutation importance on a stratified subsample."""
    if len(df) > sample:
        rng = np.random.default_rng(0)
        idx = rng.choice(len(df), size=sample, replace=False)
        sub = df.iloc[idx]
        yy = y[idx]
    else:
        sub, yy = df, y

    X = model.enc.transform(sub)
    res = permutation_importance(
        model.estimator, X, yy, n_repeats=n_repeats,
        random_state=0, scoring="roc_auc", n_jobs=1,
    )
    names = list(model.enc.num) + list(model.enc.cat)
    return (
        pd.DataFrame({"feature": names,
                      "importance": res.importances_mean,
                      "std": res.importances_std})
        .sort_values("importance", ascending=False)
        .reset_index(drop=True)
    )


class AblationExplainer:
    """Per-alert attribution by replacing one field with its benign baseline."""

    def __init__(self, model, background: pd.DataFrame):
        self.model = model
        self.num_base = {c: float(background[c].median()) for c in NUM_FEATURES}
        self.cat_base = {
            c: str(background[c].mode().iloc[0])
            for c in model.enc.cat
        }

    def explain(self, alert: pd.DataFrame, top_k: int = 4) -> list[dict]:
        base_score = float(self.model.score(alert)[0])
        rows = []
        for c in NUM_FEATURES:
            probe = alert.copy()
            probe[c] = self.num_base[c]
            delta = base_score - float(self.model.score(probe)[0])
            rows.append({"feature": c, "value": float(alert[c].iloc[0]), "delta": delta})
        for c in self.model.enc.cat:
            probe = alert.copy()
            probe[c] = self.cat_base[c]
            delta = base_score - float(self.model.score(probe)[0])
            rows.append({"feature": c, "value": str(alert[c].iloc[0]), "delta": delta})

        rows.sort(key=lambda r: abs(r["delta"]), reverse=True)
        out = rows[:top_k]
        for r in out:
            r["direction"] = "toward attack" if r["delta"] > 0 else "toward benign"
        return out
