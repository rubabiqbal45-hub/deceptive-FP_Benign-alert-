"""Behavioural-cluster suppression.

Per-alert suppression is fragile.  What analysts actually do when drowning is
*whitelist a rule* — and an attacker who reuses that activity then walks
straight through.  That is the "masking false positive" failure mode this
module is built to study.

Two clustering modes are supported:

``signature``
    Group alerts by detection signature (rule, process, parent process).  This
    reproduces rule-level whitelisting and shows exactly which rules are safe
    to suppress and which hide lookalike attacks.

``context``
    KMeans over the behavioural context vector.  Finer-grained, but it pays a
    Bonferroni price for testing many clusters.

A cluster is suppressed only when its *entire* attack rate can be bounded below
alpha with statistical confidence.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import numpy as np
import pandas as pd
from scipy.stats import beta as beta_dist
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler

CONTEXT_COLS = [
    "host_novelty",
    "peer_rarity",
    "cmdline_distance",
    "dst_reputation",
    "signed_ratio",
    "role_asset_mismatch",
    "lineage_depth",
    "hour",
]


def signature_keys(df: pd.DataFrame) -> np.ndarray:
    """Coarse detection signature: the thing an analyst would whitelist."""
    return (
        df["rule_id"].astype(str) + "|"
        + df["process_name"].astype(str) + "|"
        + df["parent_process"].astype(str)
    ).to_numpy()


@dataclass
class ClusterSuppressor:
    k: int = 36
    alpha: float = 0.02
    delta: float = 0.05
    min_size: int = 20
    bonferroni: bool = True
    mode: str = "signature"

    scaler: StandardScaler = field(init=False)
    km: KMeans = field(init=False)
    key_map_: dict[str, int] = field(init=False, default_factory=dict)
    k_eff: int = field(init=False, default=0)
    suppress_cluster_: np.ndarray = field(init=False)
    cluster_table_: pd.DataFrame = field(init=False)

    def __post_init__(self) -> None:
        self.scaler = StandardScaler()
        self.km = None
        self.key_map_ = {}
        self.k_eff = 0
    def _matrix(self, df: pd.DataFrame) -> np.ndarray:
        cols = [c for c in CONTEXT_COLS if c in df.columns]
        return df[cols].to_numpy(dtype=float)

    def _fit_labels(self, df: pd.DataFrame) -> np.ndarray:
        if self.mode == "signature":
            keys = signature_keys(df)
            self.key_map_ = {k: i for i, k in enumerate(sorted(set(keys.tolist())))}
            self.k_eff = len(self.key_map_)
            return np.array([self.key_map_[k] for k in keys], dtype=int)
        X = self.scaler.fit_transform(self._matrix(df))
        self.km = KMeans(n_clusters=self.k, n_init=10, random_state=0).fit(X)
        self.k_eff = self.k
        return self.km.labels_.astype(int)

    def labels_for(self, df: pd.DataFrame) -> np.ndarray:
        if self.mode == "signature":
            keys = signature_keys(df)
            return np.array([self.key_map_.get(k, -1) for k in keys], dtype=int)
        return self.km.predict(self.scaler.transform(self._matrix(df))).astype(int)

    def fit(self, df_cal: pd.DataFrame, y_cal: np.ndarray,
            rule_ids: pd.Series | None = None) -> "ClusterSuppressor":
        labels = self._fit_labels(df_cal)
        y = np.asarray(y_cal, dtype=int)
        # Simultaneous control needs a Bonferroni correction over clusters; the
        # marginal variant controls each cluster independently and is what a
        # team would actually deploy.  Both are reported.
        delta_eff = self.delta / max(self.k_eff, 1) if self.bonferroni else self.delta

        rows = []
        for c in range(self.k_eff):
            m = labels == c
            n = int(m.sum())
            n_att = int(y[m].sum())
            if n == 0:
                rows.append({"cluster": c, "n": 0, "attack_rate": np.nan,
                             "upper_bound": np.nan, "suppress": False})
                continue
            upper = beta_dist.ppf(1.0 - delta_eff, n_att + 1, max(n - n_att, 1))
            rows.append({
                "cluster": c,
                "n": n,
                "attacks": n_att,
                "attack_rate": n_att / n,
                "upper_bound": float(upper),
                "suppress": bool(n >= self.min_size and upper <= self.alpha),
            })
        self.cluster_table_ = pd.DataFrame(rows)
        self.suppress_cluster_ = self.cluster_table_["suppress"].to_numpy()

        if rule_ids is not None:
            self.cluster_table_["dominant_rule"] = [
                _dominant(rule_ids[labels == c]) if (labels == c).any() else ""
                for c in range(self.k_eff)
            ]
        return self

    # -------------------------------------------------------------- predict
    def suppress_mask(self, df: pd.DataFrame) -> np.ndarray:
        labels = self.labels_for(df)
        out = np.zeros(len(labels), dtype=bool)
        valid = labels >= 0
        out[valid] = self.suppress_cluster_[labels[valid]]
        return out

    def report(self) -> pd.DataFrame:
        return self.cluster_table_.copy()


def _dominant(values: pd.Series) -> str:
    if len(values) == 0:
        return ""
    return str(values.value_counts().index[0])


def deceptive_cluster_audit(sup: ClusterSuppressor, df_cal: pd.DataFrame,
                            y_cal: np.ndarray) -> pd.DataFrame:
    """Which clusters contain lookalike false positives, and were they refused?

    Clusters that mix benign lookalikes with real attacks must *not* be
    suppressed; counting how often that happens is the core evidence for the
    "deceptive FP" argument.
    """
    labels = sup.labels_for(df_cal)
    out = pd.DataFrame({"cluster": labels,
                        "y": np.asarray(y_cal, int),
                        "deceptive": df_cal["is_deceptive_fp"].to_numpy(int)})
    g = out.groupby("cluster").agg(
        n=("y", "size"),
        attacks=("y", "sum"),
        deceptive_fps=("deceptive", "sum"),
    )
    g["suppressed"] = [bool(sup.suppress_cluster_[c]) if 0 <= c < len(sup.suppress_cluster_) else False
                       for c in g.index]
    g["refused_despite_fps"] = (~g["suppressed"]) & (g["deceptive_fps"] > 0)
    return g.reset_index()
