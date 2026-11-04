"""Single source of truth for experiment configuration.

Everything that a reviewer would want to vary lives here so that the whole
study is reproducible from one dataclass instance.
"""

from __future__ import annotations

from dataclasses import dataclass, fields


@dataclass(frozen=True)
class Config:
    # ---------------------------------------------------------------- data
    seed: int = 42
    n_alerts: int = 48_000
    start_date: str = "2026-01-05"
    weeks: int = 12
    attack_rate: float = 0.03

    # ------------------------------------------------- temporal splitting
    train_weeks: tuple[int, int] = (1, 6)
    calib_weeks: tuple[int, int] = (7, 8)
    test_weeks: tuple[int, int] = (9, 12)
    drift_week: int = 10

    # --------------------------------------------------- risk control (ML)
    alpha_suppress: float = 0.02   # tolerated FN rate *among suppressed alerts*
    alpha_safety: float = 0.75     # safety margin applied to alpha (temporal drift)
    alpha_delta: float = 0.05      # 1-delta = statistical confidence of the bound
    beta_recall: float = 0.02      # tolerated share of ALL attacks that are suppressed
    escalation_fraction: float = 0.30  # share of kept alerts escalated immediately
    target_escalation_precision: float = 0.85
    min_suppress: int = 100

    # ------------------------------------------- behavioural clustering
    cluster_k: int = 36
    cluster_min_size: int = 20

    # --------------------------------------------- SOC operations model
    n_analysts: int = 8
    analyst_alerts_per_hour: float = 10.0
    analyst_hourly_cost: float = 45.0
    sla_minutes: float = 15.0
    workday_hours: float = 8.0

    # ------------------------------------------------------ cost model
    breach_cost: float = 1_200_000.0
    p_exploit_given_miss: float = 0.05

    # -------------------------------------------- robustness experiments
    adversarial_fraction: float = 0.30
    drift_shift: float = 0.35

    outdir: str = "results"

    def as_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}


DEFAULT = Config()
