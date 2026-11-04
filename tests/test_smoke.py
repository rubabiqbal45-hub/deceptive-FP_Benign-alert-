"""Smoke tests for the SOC triage framework.

Run with either::

    python -m unittest discover -s tests -v
    pytest tests/
"""

from __future__ import annotations

import sys
import unittest
from dataclasses import replace
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from soc_triage.config import DEFAULT  # noqa: E402
from soc_triage.eval import metrics as met  # noqa: E402
from soc_triage.eval.queue_sim import business_seconds, simulate_queue  # noqa: E402
from soc_triage.features.build import build_features  # noqa: E402
from soc_triage.models.selective import (  # noqa: E402
    RecallControlledSelector,
    RiskControlledSelector,
)
from soc_triage.synth.generator import generate_alerts, inject_adversarial  # noqa: E402


class TestGenerator(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cfg = replace(DEFAULT, n_alerts=4_000, seed=7)
        cls.raw = generate_alerts(cls.cfg)
        cls.df, cls.num, cls.cat = build_features(cls.raw)

    def test_schema(self):
        required = {"alert_id", "ts", "rule_id", "label", "is_deceptive_fp",
                    "is_deceptive_attack", "host_id", "user_id"}
        self.assertTrue(required.issubset(self.raw.columns))

    def test_labels_are_binary(self):
        self.assertTrue(set(self.raw["label"].unique()) <= {0, 1})

    def test_no_rule_is_attack_only(self):
        """If a rule fired only on attacks, rule_id would be a trivial shortcut."""
        g = self.raw.groupby("rule_id")["label"].agg(["min", "max", "size"])
        g = g[g["size"] > 50]
        self.assertTrue((g["min"] == 0).all(),
                        f"attack-only rules: {g[g['min'] == 1].index.tolist()}")

    def test_some_rules_are_benign_only(self):
        """Cluster suppression needs genuinely suppressible (pure-benign) rules."""
        g = self.raw.groupby("rule_id")["label"].max()
        self.assertGreater(int((g == 0).sum()), 0)

    def test_features_are_finite(self):
        X = self.df[self.num].to_numpy(float)
        self.assertTrue(np.isfinite(X).all())

    def test_history_features_are_causal(self):
        """A user's first alert can never report prior history."""
        d = self.df.sort_values("ts", kind="mergesort")
        first = d.groupby("user_id").head(1)
        self.assertTrue((first["hist_user"] == 0).all())

    def test_timestamps_sorted(self):
        self.assertTrue(self.raw["ts"].is_monotonic_increasing)


class TestSelectors(unittest.TestCase):
    def setUp(self):
        rng = np.random.default_rng(0)
        n = 5_000
        self.y = (rng.random(n) < 0.05).astype(int)
        # informative score with overlap
        self.s = np.clip(0.25 * self.y + rng.normal(0.45, 0.25, n), 0, 1)

    def test_risk_selector_respects_bound(self):
        sel = RiskControlledSelector(alpha=0.02, delta=0.05, min_suppress=50)
        sel.fit(self.s, self.y)
        if sel.threshold > 0:
            mask = sel.suppress_mask(self.s)
            self.assertLessEqual(self.y[mask].mean(), 0.10)  # loose sanity bound

    def test_recall_selector_respects_beta(self):
        sel = RecallControlledSelector(beta=0.10, delta=0.05, min_suppress=50)
        sel.fit(self.s, self.y)
        self.assertTrue(sel.feasible)
        mask = sel.suppress_mask(self.s)
        missed = self.y[mask].sum() / max(self.y.sum(), 1)
        self.assertLessEqual(missed, 0.20)

    def test_infeasible_beta_is_reported(self):
        sel = RecallControlledSelector(beta=1e-6, delta=0.05, min_suppress=50)
        sel.fit(self.s, self.y)
        self.assertFalse(sel.feasible)
        self.assertEqual(int(sel.suppress_mask(self.s).sum()), 0)


class TestQueue(unittest.TestCase):
    def test_business_time_is_monotone_and_bounded(self):
        import pandas as pd

        ts = pd.Series(pd.date_range("2026-01-05", periods=500, freq="37min"))
        bt = business_seconds(ts)
        self.assertTrue(np.all(np.diff(bt) >= 0))
        self.assertLess(bt.max(), 60 * 8 * 3600)

    def test_queue_overload_creates_backlog(self):
        rng = np.random.default_rng(1)
        arrivals = np.sort(rng.uniform(0, 3600, 400))
        service = np.full(400, 120.0)
        r = simulate_queue(arrivals, service, n_analysts=2, sla_seconds=300,
                           horizon=3600)
        self.assertGreater(r["mean_wait"], 0)
        self.assertGreater(r["sla_breach_rate"], 0.1)

    def test_empty_queue(self):
        r = simulate_queue(np.array([]), np.array([]), 3)
        self.assertEqual(r["arrivals"], 0)


class TestMetrics(unittest.TestCase):
    def test_perfect_ranking(self):
        y = np.array([0, 0, 0, 1, 1])
        s = np.array([0.1, 0.2, 0.3, 0.8, 0.9])
        self.assertEqual(met.roc_auc(y, s), 1.0)
        self.assertAlmostEqual(met.precision_at_volume(y, s, 2)["precision"], 1.0)

    def test_ece_zero_when_calibrated(self):
        y = np.array([0] * 50 + [1] * 50)
        p = np.array([0.0] * 50 + [1.0] * 50)
        self.assertLess(met.ece(y, p), 1e-9)


class TestEndToEnd(unittest.TestCase):
    def test_tiny_pipeline_runs(self):
        from soc_triage.pipeline import run

        cfg = replace(
            DEFAULT, n_alerts=3_000, cluster_k=8, min_suppress=30,
            cluster_min_size=10, outdir=str(ROOT / "results_test"),
            n_analysts=2,
        )
        res = run(cfg)
        self.assertIn("suppression", res)
        self.assertIn("queue", res)
        self.assertGreater(res["dataset"]["alerts"], 0)
        self.assertTrue((ROOT / "results_test" / "report.md").exists())


class TestInjection(unittest.TestCase):
    def test_adversarial_copies_benign_context(self):
        cfg = replace(DEFAULT, n_alerts=3_000, seed=3)
        raw = generate_alerts(cfg)
        df, _, _ = build_features(raw)
        adv = inject_adversarial(df, cfg)
        adv_atk = adv[(adv.label == 1) & (adv.adversarial == 1)]
        if len(adv_atk):
            self.assertEqual(float(adv_atk["role_asset_mismatch"].mean()), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
