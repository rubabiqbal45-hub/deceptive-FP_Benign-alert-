"""Risk-controlled suppression.

The research question is *not* "can a classifier rank alerts".  It is:

    can we suppress a large fraction of alerts while bounding, with
    statistical confidence, the number of real attacks we throw away?

That is a selective-classification / conformal-risk-control problem.  We use a
Clopper-Pearson upper bound on the false-negative rate inside the suppressed
set and pick the largest suppression region whose bound stays under alpha.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from scipy.stats import beta as beta_dist

ACTION_SUPPRESS = 0
ACTION_RANK = 1
ACTION_ESCALATE = 2
ACTION_NAMES = {ACTION_SUPPRESS: "suppress", ACTION_RANK: "rank", ACTION_ESCALATE: "escalate"}


@dataclass
class RiskControlledSelector:
    """Choose a suppression threshold with a distribution-free FN guarantee."""

    alpha: float = 0.02
    delta: float = 0.05
    min_suppress: int = 100
    threshold: float = 0.0
    cal_fn_upper: float = float("nan")
    cal_coverage: float = 0.0

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> "RiskControlledSelector":
        s = np.asarray(scores, dtype=float)
        y = np.asarray(labels, dtype=int)
        order = np.argsort(s, kind="mergesort")
        s_s, y_s = s[order], y[order]

        n = np.arange(1, len(s_s) + 1)
        k = np.cumsum(y_s)                      # attacks inside the prefix
        safe = (n - k) > 0
        upper = np.full(len(s_s), np.inf)
        upper[safe] = beta_dist.ppf(1.0 - self.delta, k[safe] + 1, (n - k)[safe])

        ok = (upper <= self.alpha) & (n >= self.min_suppress) & (n < len(s_s))
        if not ok.any():
            self.threshold = 0.0
            self.cal_fn_upper = 0.0
            self.cal_coverage = 0.0
            return self

        idx = int(np.flatnonzero(ok)[-1])
        # suppress strictly below the next representable value so ties are exact
        self.threshold = float(np.nextafter(s_s[idx], np.inf))
        self.cal_fn_upper = float(upper[idx])
        self.cal_coverage = float(idx + 1) / len(s_s)
        return self

    def suppress_mask(self, scores: np.ndarray) -> np.ndarray:
        return np.asarray(scores, dtype=float) < self.threshold


def choose_escalation_threshold(scores: np.ndarray, labels: np.ndarray,
                                target_precision: float = 0.85,
                                floor_frac: float = 0.01) -> float:
    """Lowest score such that the top-k set reaches the target precision."""
    s = np.asarray(scores, dtype=float)
    y = np.asarray(labels, dtype=int)
    order = np.argsort(-s, kind="mergesort")
    y_s = y[order]
    s_s = s[order]
    cum_tp = np.cumsum(y_s)
    k = np.arange(1, len(y_s) + 1)
    prec = cum_tp / k

    # Largest top-k prefix whose precision still meets the target.
    below = np.flatnonzero(prec < target_precision)
    k_star = int(below[0]) if len(below) else len(prec)
    if k_star < 1:
        k_star = 1
    min_k = max(1, int(np.ceil(floor_frac * len(y_s))))
    k_star = max(k_star, min_k)
    return float(s_s[min(k_star, len(s_s)) - 1])


def assign_actions(scores: np.ndarray, t_suppress: float, t_escalate: float) -> np.ndarray:
    s = np.asarray(scores, dtype=float)
    actions = np.full(len(s), ACTION_RANK, dtype=int)
    actions[s < t_suppress] = ACTION_SUPPRESS
    actions[s >= t_escalate] = ACTION_ESCALATE
    return actions


@dataclass
class RecallControlledSelector:
    """Suppress alerts while bounding the fraction of *all* attacks lost.

    ``RiskControlledSelector`` bounds the FN rate *inside the suppressed set*.
    That guarantee is weak when the base rate is low: discarding 98% of a 3%
    alert stream can obey the bound and still throw away a third of all real
    attacks.  This selector instead bounds the share of the total attack
    population that is suppressed, which is what an SOC actually cares about.
    """

    beta: float = 0.05
    delta: float = 0.05
    min_suppress: int = 100
    threshold: float = 0.0
    cal_miss_upper: float = float("nan")
    cal_coverage: float = 0.0
    feasible: bool = True

    def fit(self, scores: np.ndarray, labels: np.ndarray) -> "RecallControlledSelector":
        s = np.asarray(scores, dtype=float)
        y = np.asarray(labels, dtype=int)
        order = np.argsort(s, kind="mergesort")
        s_s, y_s = s[order], y[order]
        total = int(y_s.sum())
        if total == 0:
            self.feasible = False
            return self

        n = np.arange(1, len(s_s) + 1)
        missed = np.cumsum(y_s)
        safe = missed < total
        upper = np.full(len(s_s), np.inf)
        upper[safe] = beta_dist.ppf(
            1.0 - self.delta, missed[safe] + 1, total - missed[safe]
        )
        ok = (upper <= self.beta) & (n >= self.min_suppress) & (n < len(s_s))
        if not ok.any():
            # The bound is infeasible for this many calibration attacks: no
            # threshold can certify beta at the requested confidence.
            self.feasible = False
            self.cal_miss_upper = float(upper[safe].min()) if safe.any() else float("nan")
            return self

        idx = int(np.flatnonzero(ok)[-1])
        self.threshold = float(np.nextafter(s_s[idx], np.inf))
        self.cal_miss_upper = float(upper[idx])
        self.cal_coverage = float(idx + 1) / len(s_s)
        self.feasible = True
        return self

    def suppress_mask(self, scores: np.ndarray) -> np.ndarray:
        return np.asarray(scores, dtype=float) < self.threshold


def evaluate_selector(scores: np.ndarray, labels: np.ndarray, sel: RiskControlledSelector) -> dict:
    """Measure what the guarantee actually bought on a held-out split."""
    mask = sel.suppress_mask(scores)
    n_sup = int(mask.sum())
    if n_sup == 0:
        return {"suppressed": 0, "suppressed_frac": 0.0, "fn_in_suppressed": 0,
                "realised_fn_rate": 0.0, "alerts_removed": 0}
    fn = int(labels[mask].sum())
    return {
        "suppressed": n_sup,
        "suppressed_frac": n_sup / len(scores),
        "fn_in_suppressed": fn,
        "realised_fn_rate": fn / n_sup,
        "alerts_removed": n_sup,
        "cal_bound": sel.cal_fn_upper,
        "threshold": sel.threshold,
    }
