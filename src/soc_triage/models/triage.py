"""Triage models: baselines and the proposed gradient-boosted triage engine.

The comparison set is deliberately conservative.  A thesis lives or dies on
whether it beats something an actual SOC already deploys, so we include the
two "free" strategies (static rule severity and historical rule FP rate) before
any ML.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from soc_triage.features.build import CAT_FEATURES, NUM_FEATURES


class FeatureEncoder:
    """Ordinal encoder with an explicit out-of-vocabulary bucket.

    Keeping the bucket is important: in a live SOC new users, hosts and rules
    appear constantly, and silently mapping them to -1 would break the
    gradient-boosted trees.
    """

    def __init__(self, num: list[str], cat: list[str]):
        self.num = num
        self.cat = cat
        self.categories_: dict[str, pd.Index] = {}

    def fit(self, df: pd.DataFrame) -> "FeatureEncoder":
        for c in self.cat:
            self.categories_[c] = pd.Index(sorted(df[c].astype(str).unique()))
        return self

    @property
    def cat_indices(self) -> list[int]:
        return list(range(len(self.num), len(self.num) + len(self.cat)))

    def transform(self, df: pd.DataFrame) -> np.ndarray:
        blocks = [df[self.num].to_numpy(dtype=float)]
        for c in self.cat:
            cats = self.categories_[c]
            codes = pd.Categorical(df[c].astype(str), categories=cats).codes.astype(float)
            codes[codes < 0] = len(cats)          # OOV bucket
            blocks.append(codes.reshape(-1, 1))
        return np.hstack(blocks)

    def one_hot(self, df: pd.DataFrame) -> np.ndarray:
        blocks = [df[self.num].to_numpy(dtype=float)]
        for c in self.cat:
            cats = self.categories_[c]
            codes = pd.Categorical(df[c].astype(str), categories=cats).codes
            block = np.zeros((len(df), len(cats) + 1))
            codes = codes.copy()
            codes[codes < 0] = len(cats)
            block[np.arange(len(df)), codes] = 1.0
            blocks.append(block)
        return np.hstack(blocks)


# --------------------------------------------------------------------------
# Baselines
# --------------------------------------------------------------------------


class SeverityBaseline:
    """What most SIEMs do by default: rank by static rule severity."""

    name = "B0 rule severity"

    def fit(self, df: pd.DataFrame, y: np.ndarray) -> "SeverityBaseline":
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        s = df["severity"].to_numpy(dtype=float)
        return (s - s.min()) / max(s.max() - s.min(), 1e-9)


class RulePriorBaseline:
    """Rank by the historical attack rate observed for the rule.

    This is the strongest *non-contextual* baseline: it learns that a rule is
    noisy but knows nothing about the host, user or command line.
    """

    name = "B1 rule base-rate"

    def fit(self, df: pd.DataFrame, y: np.ndarray) -> "RulePriorBaseline":
        self.global_ = float(np.mean(y))
        stats = pd.DataFrame({"rule_id": df["rule_id"].to_numpy(), "y": y})
        self.table_ = stats.groupby("rule_id")["y"].mean().to_dict()
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return df["rule_id"].map(self.table_).fillna(self.global_).to_numpy(dtype=float)


class SklearnModel:
    """Thin wrapper so every model shares fit(df, y) / score(df)."""

    def __init__(self, estimator, name: str, encoder: FeatureEncoder):
        self.estimator = estimator
        self.name = name
        self.enc = encoder

    def fit(self, df: pd.DataFrame, y: np.ndarray) -> "SklearnModel":
        self.enc.fit(df)
        self.estimator.fit(self.enc.transform(df), y)
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return self.estimator.predict_proba(self.enc.transform(df))[:, 1]


class LogisticModel(SklearnModel):
    """Logistic regression on scaled numerics + one-hot categoricals."""

    def fit(self, df: pd.DataFrame, y: np.ndarray) -> "LogisticModel":
        self.enc.fit(df)
        X = self.enc.one_hot(df)
        self.scaler = StandardScaler().fit(X)
        self.estimator.fit(self.scaler.transform(X), y)
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        X = self.scaler.transform(self.enc.one_hot(df))
        return self.estimator.predict_proba(X)[:, 1]


# --------------------------------------------------------------------------
# Proposed model
# --------------------------------------------------------------------------


@dataclass
class TriageModel:
    """Gradient-boosted triage engine (native, CPU-only, offline).

    Deliberately not an LLM: the "native" claim in the thesis requires
    deterministic, sub-50 ms, dependency-light inference on the SIEM node.
    """

    seed: int = 42
    name: str = "M1 native GBM triage"
    enc: FeatureEncoder = field(init=False)

    def __post_init__(self) -> None:
        self.enc = FeatureEncoder(NUM_FEATURES, CAT_FEATURES)
        self.estimator = HistGradientBoostingClassifier(
            learning_rate=0.04,
            max_iter=800,
            max_leaf_nodes=63,
            min_samples_leaf=15,
            l2_regularization=0.5,
            early_stopping=False,
            class_weight=None,
            random_state=self.seed,
        )

    def fit(self, df: pd.DataFrame, y: np.ndarray) -> "TriageModel":
        X = self.enc.fit(df).transform(df)
        self.estimator.set_params(categorical_features=self.enc.cat_indices)
        self.estimator.fit(X, y)
        return self

    def score(self, df: pd.DataFrame) -> np.ndarray:
        return self.estimator.predict_proba(self.enc.transform(df))[:, 1]


def build_models(seed: int) -> dict[str, object]:
    """Instantiate the full comparison set."""
    return {
        "B0 rule severity": SeverityBaseline(),
        "B1 rule base-rate": RulePriorBaseline(),
        "B2 logistic regression": LogisticModel(
            LogisticRegression(max_iter=3000, class_weight="balanced"), "B2 logistic regression",
            FeatureEncoder(NUM_FEATURES, CAT_FEATURES),
        ),
        "B3 random forest": SklearnModel(
            RandomForestClassifier(
                n_estimators=400, min_samples_leaf=5, max_features="sqrt",
                class_weight="balanced_subsample", n_jobs=-1, random_state=seed,
            ),
            "B3 random forest", FeatureEncoder(NUM_FEATURES, CAT_FEATURES),
        ),
        "M1 native GBM triage": TriageModel(seed=seed),
    }
