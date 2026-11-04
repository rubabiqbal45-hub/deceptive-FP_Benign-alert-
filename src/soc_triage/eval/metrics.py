"""Detection-quality metrics, including the ones that matter to a SOC.

F1 is reported for completeness but is not the headline.  The headline numbers
are (a) alert reduction at a fixed false-negative budget and (b) precision at a
fixed analyst review capacity.
"""

from __future__ import annotations

import numpy as np
from sklearn.metrics import (
    average_precision_score,
    brier_score_loss,
    precision_recall_fscore_support,
    roc_auc_score,
)


def pr_auc(y: np.ndarray, s: np.ndarray) -> float:
    return float(average_precision_score(y, s))


def roc_auc(y: np.ndarray, s: np.ndarray) -> float:
    if len(np.unique(y)) < 2:
        return float("nan")
    return float(roc_auc_score(y, s))


def ece(y: np.ndarray, p: np.ndarray, bins: int = 15) -> float:
    """Expected calibration error — critical if analysts use the probability."""
    edges = np.linspace(0.0, 1.0, bins + 1)
    idx = np.clip(np.digitize(p, edges[1:-1]), 0, bins - 1)
    total = 0.0
    for b in range(bins):
        m = idx == b
        if not m.any():
            continue
        total += (m.sum() / len(p)) * abs(p[m].mean() - y[m].mean())
    return float(total)


def confusion_at(y: np.ndarray, s: np.ndarray, threshold: float) -> dict:
    pred = s >= threshold
    tp = int(((pred == 1) & (y == 1)).sum())
    fp = int(((pred == 1) & (y == 0)).sum())
    fn = int(((pred == 0) & (y == 1)).sum())
    tn = int(((pred == 0) & (y == 0)).sum())
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn}


def alert_reduction(y: np.ndarray, s: np.ndarray, threshold: float) -> float:
    """Fraction of the alert stream that no longer reaches an analyst."""
    pred = s >= threshold
    return float(1.0 - pred.mean())


def precision_at_volume(y: np.ndarray, s: np.ndarray, k: int) -> dict:
    """Quality of the analyst queue when only k alerts can be reviewed."""
    k = min(k, len(s))
    order = np.argsort(-s, kind="mergesort")[:k]
    hits = int(y[order].sum())
    return {
        "reviewed": int(k),
        "true_positives": hits,
        "precision": hits / k if k else 0.0,
        "recall": hits / max(int(y.sum()), 1),
    }


def summary(y: np.ndarray, s: np.ndarray, threshold: float) -> dict:
    y = np.asarray(y, int)
    s = np.asarray(s, float)
    p, r, f1, _ = precision_recall_fscore_support(
        y, (s >= threshold).astype(int), average="binary", zero_division=0
    )
    c = confusion_at(y, s, threshold)
    return {
        "roc_auc": roc_auc(y, s),
        "pr_auc": pr_auc(y, s),
        "brier": float(brier_score_loss(y, s)),
        "ece": ece(y, s),
        "precision": float(p),
        "recall": float(r),
        "f1": float(f1),
        "threshold": float(threshold),
        "alerts_kept": int((s >= threshold).sum()),
        "alert_reduction": alert_reduction(y, s, threshold),
        **c,
    }


def fn_budget_curve(y: np.ndarray, s: np.ndarray,
                    grid: tuple[float, ...] = (0.005, 0.01, 0.02, 0.05, 0.10)) -> list[dict]:
    """Alert reduction achievable at several tolerated FN rates."""
    order = np.argsort(s, kind="mergesort")
    s_s, y_s = s[order], y[order]
    n = len(s_s)
    cum_att = np.cumsum(y_s)
    total_att = max(int(y_s.sum()), 1)
    out = []
    for b in grid:
        # largest prefix whose realised FN fraction of all attacks <= b
        limit = b * total_att
        ok = np.flatnonzero(cum_att <= limit)
        if len(ok) == 0:
            out.append({"fn_budget": b, "alert_reduction": 0.0, "kept": n, "missed": 0})
            continue
        i = int(ok[-1])
        out.append({
            "fn_budget": b,
            "alert_reduction": (i + 1) / n,
            "kept": n - (i + 1),
            "missed": int(cum_att[i]),
            "fn_realised": float(cum_att[i] / total_att),
        })
    return out


def stratified_report(df, scores: np.ndarray, mask: np.ndarray, name: str) -> dict:
    """Recall on the *deceptive* attack subset, which is the hard part."""
    y = df["label"].to_numpy(int)
    dec = df["is_deceptive_attack"].to_numpy(int) == 1
    sel = mask
    if dec.sum() == 0:
        return {"subset": name, "n": int(sel.sum()), "recall": float("nan")}
    caught = int((sel & dec).sum())
    return {
        "subset": name,
        "n_attacks": int(dec.sum()),
        "kept_deceptive": caught,
        "recall_deceptive": caught / int(dec.sum()),
        "recall_overall": float((sel & (y == 1)).sum() / max(y.sum(), 1)),
    }
