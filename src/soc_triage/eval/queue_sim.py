"""Discrete-event analyst-queue simulation.

Detection metrics cannot show alert fatigue.  Queue metrics can: mean wait,
95th-percentile wait, SLA breaches and the fraction of alerts never reviewed.

Alerts are mapped onto **business-time** coordinates (an 8-hour working day)
so that a 3-analyst team really does have 3 x 10 x 8 = 240 alerts/day of
capacity, rather than an unrealistic 24/7 pipeline.  The queue itself is a
small M/G/c system implemented with a heap; no external simulation library is
needed.
"""

from __future__ import annotations

import heapq

import numpy as np
import pandas as pd


def business_seconds(ts: pd.Series, workday_hours: float = 8.0,
                     day_start_hour: float = 8.0) -> np.ndarray:
    """Map wall-clock timestamps onto compressed working-hour coordinates.

    The full 24-hour day is linearly compressed into the working window.  A
    naive clip would pile every after-hours alert onto 16:00 and manufacture a
    fake arrival spike, which silently invalidates the queue results.
    """
    idx = pd.DatetimeIndex(pd.to_datetime(ts))
    day0 = idx.normalize().min()
    day_index = np.asarray((idx.normalize() - day0).days, dtype=float)
    tod = (idx.hour + idx.minute / 60.0 + idx.second / 3600.0).to_numpy(dtype=float)
    tod_c = day_start_hour + (tod / 24.0) * workday_hours
    return day_index * workday_hours * 3600.0 + (tod_c - day_start_hour) * 3600.0


def service_times(n: int, mean_seconds: float, sigma: float,
                  rng: np.random.Generator) -> np.ndarray:
    """Lognormal handling time with the requested mean."""
    if n <= 0:
        return np.array([])
    mu = np.log(mean_seconds) - 0.5 * sigma ** 2
    return rng.lognormal(mu, sigma, n)


def simulate_queue(arrivals: np.ndarray, service: np.ndarray,
                   n_analysts: int = 3, sla_seconds: float = 900.0,
                   horizon: float | None = None) -> dict:
    """Run a multi-server FIFO queue over one arrival-sorted stream."""
    arrivals = np.sort(np.asarray(arrivals, dtype=float))
    service = np.asarray(service, dtype=float)
    n = len(arrivals)
    if n == 0:
        return {"arrivals": 0, "served": 0, "mean_wait": 0.0, "p95_wait": 0.0,
                "max_wait": 0.0, "sla_breach_rate": 0.0, "unserved": 0,
                "unserved_frac": 0.0, "utilisation": 0.0}

    free = [0.0] * max(1, n_analysts)
    heapq.heapify(free)
    waits = np.zeros(n)
    starts = np.zeros(n)
    for i in range(n):
        f = heapq.heappop(free)
        start = max(arrivals[i], f)
        waits[i] = start - arrivals[i]
        starts[i] = start
        heapq.heappush(free, start + service[i])

    if horizon is None:
        horizon = float(starts.max() + service.max()) if n else 0.0
    unserved = int((starts > horizon).sum())
    busy = float(service.sum())
    span = float(horizon - arrivals[0]) if n and horizon > arrivals[0] else 1.0

    return {
        "arrivals": int(n),
        "served": int(n - unserved),
        "mean_wait": float(waits.mean()),
        "p95_wait": float(np.quantile(waits, 0.95)),
        "max_wait": float(waits.max()),
        "sla_breach_rate": float((waits > sla_seconds).mean()),
        "unserved": unserved,
        "unserved_frac": unserved / n,
        "utilisation": min(1.0, busy / (max(1, n_analysts) * span)),
    }


def compare_queues(df_test, scores: np.ndarray, t_suppress: float,
                   cfg, rng: np.random.Generator | None = None) -> dict:
    """Baseline (review everything) vs triaged (suppress, then review)."""
    rng = rng or np.random.default_rng(0)
    arrivals = business_seconds(df_test["ts"], cfg.workday_hours)
    horizon = float(arrivals.max())

    mean_service = 3600.0 / cfg.analyst_alerts_per_hour
    svc_all = service_times(len(arrivals), mean_service, 0.6, rng)

    keep = np.asarray(scores) >= t_suppress
    svc_kept = service_times(int(keep.sum()), mean_service, 0.6, rng)

    base = simulate_queue(arrivals, svc_all, cfg.n_analysts,
                          cfg.sla_minutes * 60, horizon)
    triaged = simulate_queue(arrivals[keep], svc_kept, cfg.n_analysts,
                             cfg.sla_minutes * 60, horizon)
    return {"baseline": base, "triaged": triaged,
            "business_hours": float(horizon / 3600.0)}


def capacity_to_meet_sla(df_test, scores: np.ndarray, cfg,
                         t_suppress: float = 0.0,
                         sla_target: float = 0.05,
                         rng: np.random.Generator | None = None) -> dict:
    """How many analysts are needed so <=5% of alerts breach the SLA?"""
    rng = rng or np.random.default_rng(1)
    arrivals = business_seconds(df_test["ts"], cfg.workday_hours)
    horizon = float(arrivals.max())
    mean_service = 3600.0 / cfg.analyst_alerts_per_hour
    keep = np.asarray(scores) >= t_suppress

    out = {}
    for label, sel in (("baseline", np.ones(len(arrivals), bool)),
                       ("triaged", keep)):
        arr = arrivals[sel]
        if len(arr) == 0:
            out[label] = 0
            continue
        svc = service_times(len(arr), mean_service, 0.6, rng)
        needed = None
        for c in range(1, 41):
            r = simulate_queue(arr, svc, c, cfg.sla_minutes * 60, horizon)
            if r["sla_breach_rate"] <= sla_target:
                needed = c
                break
        out[label] = needed
    return out
