"""Probability calibration.

A triage score is only useful if an analyst can read it as a probability.
Gradient-boosted trees saturate at 0 and 1 on easy data, which makes both the
risk-control threshold and the cost model degenerate.  Platt scaling on a
dedicated slice of the calibration window fixes that without touching the
risk-control sample (no double-dipping).
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from sklearn.linear_model import LogisticRegression


def _logit(x: np.ndarray) -> np.ndarray:
    p = np.clip(np.asarray(x, dtype=float), 1e-6, 1 - 1e-6)
    return np.log(p / (1 - p)).reshape(-1, 1)


@dataclass
class PlattCalibrator:
    def __post_init__(self) -> None:
        self.model = LogisticRegression(C=1.0, max_iter=1000)

    def fit(self, scores: np.ndarray, y: np.ndarray) -> "PlattCalibrator":
        y = np.asarray(y, dtype=int)
        if len(np.unique(y)) < 2:
            self.model = None
            return self
        self.model.fit(_logit(scores), y)
        return self

    def transform(self, scores: np.ndarray) -> np.ndarray:
        if self.model is None:
            return np.asarray(scores, dtype=float)
        return self.model.predict_proba(_logit(scores))[:, 1]
