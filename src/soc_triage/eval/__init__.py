from __future__ import annotations

from soc_triage.eval.cost import optimal_operating_point, sensitivity_grid, sweep_costs
from soc_triage.eval.metrics import (
    alert_reduction,
    confusion_at,
    ece,
    fn_budget_curve,
    pr_auc,
    precision_at_volume,
    roc_auc,
    stratified_report,
    summary,
)
from soc_triage.eval.queue_sim import compare_queues, simulate_queue
from soc_triage.eval.robustness import (
    adversarial_report,
    recalibration_gain,
    weekly_metrics,
)

__all__ = [
    "sweep_costs", "optimal_operating_point", "sensitivity_grid",
    "pr_auc", "roc_auc", "ece", "confusion_at", "alert_reduction",
    "precision_at_volume", "summary", "fn_budget_curve", "stratified_report",
    "compare_queues", "simulate_queue",
    "weekly_metrics", "adversarial_report", "recalibration_gain",
]
