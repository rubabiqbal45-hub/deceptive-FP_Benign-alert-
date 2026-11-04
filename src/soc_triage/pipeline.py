"""End-to-end experiment runner.

Run with::

    python run_experiments.py

Every number quoted in the thesis report is produced here, from a single seeded
configuration, so the study is reproducible.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pandas as pd

from soc_triage.config import Config, DEFAULT
from soc_triage.eval import cost as cost_mod
from soc_triage.eval import metrics as met
from soc_triage.eval import queue_sim as qsim
from soc_triage.eval import robustness as rob
from soc_triage.features.build import build_features
from soc_triage.io import dataset_summary, load_dataset
from soc_triage.models.calibration import PlattCalibrator
from soc_triage.models.cluster import ClusterSuppressor, deceptive_cluster_audit
from soc_triage.models.explain import AblationExplainer, global_importance
from soc_triage.models.selective import (
    ACTION_NAMES,
    RecallControlledSelector,
    RiskControlledSelector,
    assign_actions,
)
from soc_triage.models.triage import build_models
from soc_triage.splits import split_info, temporal_split
from soc_triage.synth.generator import (
    generate_alerts,
    inject_adversarial,
    inject_drift,
)


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------


def _jsonable(o):
    if isinstance(o, dict):
        return {str(k): _jsonable(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_jsonable(v) for v in o]
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    if isinstance(o, (pd.Timestamp,)):
        return o.isoformat()
    return o


def _mode_stats(scores, y, mask, label: str, bound: float) -> dict:
    """Summarise one suppression policy on the test stream."""
    y = np.asarray(y, dtype=int)
    n = len(scores)
    sup = int(mask.sum())
    fn = int(y[mask].sum())
    total_att = max(int(y.sum()), 1)
    return {
        "mode": label,
        "cal_bound": float(bound),
        "threshold": float(scores[mask].max()) if sup else 0.0,
        "suppression_rate": sup / n,
        "suppressed": sup,
        "fn_in_suppressed": fn,
        "realised_fn_rate": fn / sup if sup else 0.0,
        "missed_share_of_attacks": fn / total_att,
        "recall": 1.0 - fn / total_att,
    }


def _banner(text: str) -> None:
    print(f"\n{'=' * 74}\n{text}\n{'=' * 74}", flush=True)


# --------------------------------------------------------------------------
# main
# --------------------------------------------------------------------------


def run(cfg: Config = DEFAULT, source: str = "synth",
        path: str | None = None) -> dict:
    """Run the full study.

    ``source="synth"`` generates the mini-SOC stream; ``source="csv"`` loads a
    dataset produced by the lab bridge.  Everything downstream is identical.
    """
    outdir = Path(cfg.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # ---------------------------------------------------------- 1. data
    if source == "csv":
        if not path:
            raise ValueError("source='csv' requires a --path")
        _banner(f"1/7  Loading alert dataset from {path}")
        raw = load_dataset(path)
    elif source == "synth":
        _banner("1/7  Generating synthetic SOC alert stream")
        raw = generate_alerts(cfg)
    else:
        raise ValueError(f"unknown source: {source!r} (use 'synth' or 'csv')")

    df, num_features, cat_features = build_features(raw)
    summary = dataset_summary(df)
    print(f"alerts={summary['alerts']:,}  days={summary['days']}  "
          f"attack_rate={summary['attack_rate']:.4f}  "
          f"deceptive_fp={summary['deceptive_fp_rate']:.4f}  "
          f"source={source}")

    train, calib, test = temporal_split(df, cfg)
    sp = split_info(df, cfg)
    print(f"split={sp['mode']} ({sp['note']})")
    if len(train) == 0 or len(calib) == 0 or len(test) == 0:
        raise ValueError(
            f"one split is empty (train={len(train)}, calib={len(calib)}, "
            f"test={len(test)}); provide a longer capture"
        )
    print(f"train={len(train):,}  calib={len(calib):,}  test={len(test):,}")
    print(f"test attacks={int(test.label.sum()):,}  "
          f"deceptive attacks={int(test.is_deceptive_attack.sum()):,}")

    y_train = train["label"].to_numpy(int)
    y_cal = calib["label"].to_numpy(int)
    y_test = test["label"].to_numpy(int)

    # -------------------------------------------------- 2. model comparison
    _banner("2/7  Training baselines and proposed triage model")
    models = build_models(cfg.seed)
    raw: dict[str, np.ndarray] = {}
    for name, model in models.items():
        model.fit(train, y_train)
        raw[name] = np.asarray(model.score(test), dtype=float)

    # Platt calibration uses one half of the calibration window; the risk
    # control uses the other half, so the two guarantees stay independent.
    main_name = "M1 native GBM triage"
    main_model = models[main_name]
    raw_cal = np.asarray(main_model.score(calib), dtype=float)
    perm = np.random.default_rng(cfg.seed + 1).permutation(len(calib))
    # 30% of the calibration window fits the calibrator, 70% carries the
    # risk-control bound (more data = tighter Clopper-Pearson interval).
    n_fit = max(1, int(0.30 * len(calib)))
    fit_idx, risk_idx = perm[:n_fit], perm[n_fit:]

    calibrator = PlattCalibrator().fit(raw_cal[fit_idx], y_cal[fit_idx])
    raw[main_name] = calibrator.transform(raw[main_name])

    calib_risk = calib.iloc[risk_idx].reset_index(drop=True)
    y_cal_risk = y_cal[risk_idx]
    s_cal = calibrator.transform(raw_cal[risk_idx])
    s_test = raw[main_name]

    rows, scores = [], {}
    for name, s in raw.items():
        scores[name] = s
        rows.append({
            "model": name,
            "roc_auc": met.roc_auc(y_test, s),
            "pr_auc": met.pr_auc(y_test, s),
            "ece": met.ece(y_test, s),
        })
        print(f"  {name:<24} AUC={rows[-1]['roc_auc']:.4f}  "
              f"PR-AUC={rows[-1]['pr_auc']:.4f}  ECE={rows[-1]['ece']:.4f}")
    comparison = pd.DataFrame(rows).sort_values("pr_auc", ascending=False)

    # ------------------------------------- 3. risk-controlled suppression
    _banner("3/7  Risk-controlled suppression")
    # Mode A: bound the FN rate *among suppressed* alerts.
    sel_a = RiskControlledSelector(
        alpha=cfg.alpha_suppress * cfg.alpha_safety,
        delta=cfg.alpha_delta,
        min_suppress=cfg.min_suppress,
    ).fit(s_cal, y_cal_risk)

    # Mode B (operationally recommended): bound the share of ALL attacks lost.
    sel_b = RecallControlledSelector(
        beta=cfg.beta_recall,
        delta=cfg.alpha_delta,
        min_suppress=cfg.min_suppress,
    ).fit(s_cal, y_cal_risk)
    if not sel_b.feasible:
        print(f"  [warn] beta={cfg.beta_recall:.2%} is infeasible with "
              f"{int(y_cal_risk.sum())} calibration attacks; "
              f"smallest achievable bound = {sel_b.cal_miss_upper:.2%}")

    mode_a = _mode_stats(s_test, y_test, sel_a.suppress_mask(s_test),
                         "A: alpha among suppressed", sel_a.cal_fn_upper)
    mode_b = _mode_stats(s_test, y_test, sel_b.suppress_mask(s_test),
                         "B: beta of all attacks", sel_b.cal_miss_upper)
    mode_a["feasible"] = True
    mode_b["feasible"] = bool(sel_b.feasible)
    for name, m in (("A (alpha-based)", mode_a), ("B (recall-based)", mode_b)):
        print(f"  {name:<16} bound={m['cal_bound']:.4f}  "
              f"suppressed={m['suppression_rate']:.2%}  "
              f"FN-in-suppressed={m['realised_fn_rate']:.4f}  "
              f"attacks missed={m['missed_share_of_attacks']:.2%}  "
              f"recall={m['recall']:.2%}")

    # The recall-controlled mode is the one we take into the operations study.
    selector = sel_b
    mask_sup = selector.suppress_mask(s_test)
    keep = ~mask_sup
    n_sup = int(mask_sup.sum())
    fn_sup = int(y_test[mask_sup].sum())

    kept_cal = s_cal[s_cal >= selector.threshold]
    if len(kept_cal) > 0:
        t_esc = float(np.quantile(kept_cal, 1.0 - cfg.escalation_fraction))
    else:
        t_esc = float(selector.threshold)
    t_esc = max(t_esc, float(np.nextafter(selector.threshold, np.inf)))
    actions = assign_actions(s_test, selector.threshold, t_esc)

    action_counts = {ACTION_NAMES[a]: int((actions == a).sum())
                     for a in ACTION_NAMES}
    print(f"  escalation band : top {cfg.escalation_fraction:.0%} of kept alerts")
    print(f"  action mix      : {action_counts}")

    # FN-budget curve and capacity-limited precision
    budget = met.fn_budget_curve(y_test, s_test)
    days = max((test.ts.max() - test.ts.min()).days, 1)
    k_capacity = max(1, int(0.05 * len(test)))
    pav = met.precision_at_volume(y_test, s_test, k_capacity)
    strat = met.stratified_report(test, s_test, keep, "kept")

    # --------------------------------------- 4. behavioural clustering
    _banner("4/7  Behavioural-cluster suppression with FN bound")
    clus_variants: dict[str, dict] = {}
    clus = None
    variant_specs = (
        ("signature (Bonferroni)", "signature", True),
        ("signature (marginal)", "signature", False),
        ("context (marginal)", "context", False),
    )
    for label, mode, bonf in variant_specs:
        c = ClusterSuppressor(
            k=cfg.cluster_k, alpha=cfg.alpha_suppress * cfg.alpha_safety,
            delta=cfg.alpha_delta, min_size=cfg.cluster_min_size,
            bonferroni=bonf, mode=mode,
        ).fit(calib_risk, y_cal_risk, rule_ids=calib_risk["rule_id"])
        m = c.suppress_mask(test)
        n_sup_c = int(m.sum())
        n_fn_c = int(y_test[m].sum())
        audit_c = deceptive_cluster_audit(c, calib_risk, y_cal_risk)
        clus_variants[label] = {
            "mode": mode,
            "clusters": int(c.k_eff),
            "clusters_suppressed": int(c.suppress_cluster_.sum()),
            "coverage": n_sup_c / len(test),
            "fn_in_suppressed": n_fn_c,
            "fn_rate": (n_fn_c / n_sup_c if n_sup_c else 0.0),
            "refused_despite_deceptive_fps": int(audit_c["refused_despite_fps"].sum()),
        }
        print(f"  [{label}] clusters={int(c.suppress_cluster_.sum())}/{c.k_eff}  "
              f"coverage={n_sup_c / len(test):.2%}  FN={n_fn_c}")
        if label == "signature (Bonferroni)":
            clus, cmask, c_audit, c_report = c, m, audit_c, c.report()
            c_sup, c_fn = n_sup_c, n_fn_c

    print(f"  clusters refused despite containing deceptive FPs: "
          f"{int(c_audit['refused_despite_fps'].sum())}")

    # overwrite keep/mask with combined strategy: per-alert OR cluster
    keep2 = ~(mask_sup | cmask)

    # --------------------------------------------- 5. SOC operations
    _banner("5/7  Analyst queue simulation and cost model")
    rng = np.random.default_rng(cfg.seed)
    queues = qsim.compare_queues(test, s_test, selector.threshold, cfg, rng)
    b, t = queues["baseline"], queues["triaged"]
    print(f"  baseline  mean wait={b['mean_wait'] / 60:8.1f} min  "
          f"p95={b['p95_wait'] / 60:8.1f} min  "
          f"SLA breach={b['sla_breach_rate']:.1%}  "
          f"never reviewed={b['unserved_frac']:.1%}")
    print(f"  triaged   mean wait={t['mean_wait'] / 60:8.1f} min  "
          f"p95={t['p95_wait'] / 60:8.1f} min  "
          f"SLA breach={t['sla_breach_rate']:.1%}  "
          f"never reviewed={t['unserved_frac']:.1%}")

    cap = qsim.capacity_to_meet_sla(
        test, s_test, cfg, t_suppress=selector.threshold,
        rng=np.random.default_rng(cfg.seed + 3),
    )
    print(f"  analysts needed for 5% SLA: baseline={cap['baseline']}  "
          f"triaged={cap['triaged']}")

    opt = cost_mod.optimal_operating_point(test, s_test, cfg)
    print(f"  cost-optimal threshold={opt['threshold']:.3f}  "
          f"recall={opt['recall']:.1%}  kept/day={opt['kept_per_day']:.0f}")
    print(f"  annual savings vs review-all = ${opt['savings_annual']:,.0f} "
          f"({opt['savings_pct']:.1f}%)")

    sens = cost_mod.sensitivity_grid(test, s_test, cfg)
    print("  break-even analysis (cost-optimal keep fraction):")
    print(sens.to_string(index=False))

    # ----------------------------------- 6. drift and adversarial tests
    _banner("6/7  Robustness: concept drift and adversarial imitation")
    weekly_clean = rob.weekly_metrics(test, s_test, selector.threshold)
    auc_clean = met.roc_auc(y_test, s_test)

    robustness_available = source == "synth"
    if robustness_available:
        df_drift = inject_drift(test, cfg)
        s_drift = np.asarray(main_model.score(df_drift), dtype=float)
        weekly_drift = rob.weekly_metrics(df_drift, s_drift, selector.threshold)

        df_adv = inject_adversarial(test, cfg)
        s_adv = np.asarray(main_model.score(df_adv), dtype=float)
        adv_tbl = rob.adversarial_report(df_adv, s_adv, selector.threshold)
        print(adv_tbl.to_string(index=False))
        auc_adv = met.roc_auc(y_test, s_adv)
        print(f"  ROC-AUC clean={auc_clean:.4f}  adversarial={auc_adv:.4f} "
              f"(delta={auc_adv - auc_clean:+.4f})")

        rec = rob.recalibration_gain(
            calib_risk.assign(score=s_cal), y_cal_risk,
            df_drift.assign(score=s_drift), y_test,
            lambda a: RiskControlledSelector(alpha=a, delta=cfg.alpha_delta,
                                             min_suppress=cfg.min_suppress),
            cfg.alpha_suppress,
            delta=cfg.alpha_delta,
            min_suppress=cfg.min_suppress,
        )
    else:
        # This dataset is real telemetry. Injecting simulated drift or attacker
        # imitation into it would be fabricating evidence, so these analyses
        # are reported as unavailable instead of estimated.
        df_drift = test
        weekly_drift = weekly_clean
        adv_tbl = pd.DataFrame([{"group": "not available (real telemetry)",
                                 "n": 0, "recall": float("nan")}])
        auc_adv = float("nan")
        rec = {"stale": {"coverage": float("nan"), "fn_rate": float("nan")},
               "recalibrated": {"coverage": float("nan"),
                                "fn_rate": float("nan")}}
        print("  skipped: drift/adversarial injection is only defined on "
              "synthetic data")

    # ------------------------------------------------ 7. explanations
    _banner("7/7  Explainability")
    imp = global_importance(main_model, train, y_train)
    print(imp.head(8).to_string(index=False))

    background = train[train.label == 0].sample(
        min(2000, int((train.label == 0).sum())), random_state=cfg.seed
    )

    class _CalibratedView:
        """Model view that exposes calibrated scores to the explainer."""

        def __init__(self, model, cal):
            self.model, self.cal = model, cal
            self.enc = model.enc
            self.estimator = model.estimator

        def score(self, df):
            return self.cal.transform(self.model.score(df))

    explainer = AblationExplainer(_CalibratedView(main_model, calibrator), background)
    test_scored = test.assign(score=s_test)

    picks: list[tuple[str, pd.DataFrame]] = []
    dec_fp = test_scored[test_scored.is_deceptive_fp == 1]
    if len(dec_fp):
        picks.append(("deceptive false positive (highest-scoring)",
                      dec_fp.nlargest(1, "score")))
    dec_atk = test_scored[test_scored.is_deceptive_attack == 1]
    if len(dec_atk):
        picks.append(("deceptive attack (lowest-scoring)",
                      dec_atk.nsmallest(1, "score")))
    ordinary = test_scored[(test_scored.label == 1) & (test_scored.is_deceptive_attack == 0)]
    if len(ordinary):
        ordinary = ordinary.sort_values("score")
        picks.append(("ordinary attack (median score)",
                      ordinary.iloc[[len(ordinary) // 2]]))

    examples = []
    for tag, sel in picks:
        row = sel
        sc = float(row["score"].iloc[0])
        examples.append({
            "kind": tag,
            "alert_id": str(row["alert_id"].iloc[0]),
            "rule": str(row["rule_name"].iloc[0]),
            "technique": str(row["technique"].iloc[0]),
            "score": sc,
            "ground_truth": "attack" if int(row["label"].iloc[0]) else "benign",
            "explanation": explainer.explain(row),
        })
    for e in examples:
        print(f"  [{e['kind']}] score={e['score']:.3f} truth={e['ground_truth']}")
        for f in e["explanation"]:
            print(f"      {f['feature']:<22} {f['value']!s:<28} "
                  f"{f['delta']:+.4f} ({f['direction']})")

    # ------------------------------------------------------ 8. persist
    comparison.to_csv(outdir / "model_comparison.csv", index=False)
    pd.DataFrame(budget).to_csv(outdir / "fn_budget_curve.csv", index=False)
    opt["curve"].to_csv(outdir / "operating_curve.csv", index=False)
    sens.to_csv(outdir / "cost_sensitivity.csv", index=False)
    weekly_clean.to_csv(outdir / "weekly_clean.csv", index=False)
    weekly_drift.to_csv(outdir / "weekly_drift.csv", index=False)
    adv_tbl.to_csv(outdir / "adversarial.csv", index=False)
    imp.to_csv(outdir / "feature_importance.csv", index=False)
    c_report.to_csv(outdir / "cluster_report.csv", index=False)
    c_audit.to_csv(outdir / "deceptive_clusters.csv", index=False)
    pd.DataFrame([
        {"action": k, "count": v} for k, v in action_counts.items()
    ]).to_csv(outdir / "action_mix.csv", index=False)
    test.assign(score=s_test, action=actions).sample(
        min(3000, len(test)), random_state=cfg.seed
    ).to_csv(outdir / "scored_sample.csv", index=False)

    results = {
        "config": cfg.as_dict(),
        "source": source,
        "split": sp,
        "dataset": {
            "alerts": len(df),
            "days": summary["days"],
            "weeks_observed": summary["weeks_observed"],
            "attack_rate": float(df.label.mean()),
            "deceptive_fp_rate": float(df.is_deceptive_fp.mean()),
            "unique_rules": summary["unique_rules"],
            "unique_hosts": summary["unique_hosts"],
            "train": len(train), "calib": len(calib), "test": len(test),
            "train_attacks": int(y_train.sum()),
            "calib_attacks": int(y_cal.sum()),
            "test_attacks": int(y_test.sum()),
            "test_deceptive_attacks": int(test.is_deceptive_attack.sum()),
        },
        "model_comparison": comparison.to_dict(orient="records"),
        "suppression": {
            "alpha": cfg.alpha_suppress,
            "alpha_effective": cfg.alpha_suppress * cfg.alpha_safety,
            "alpha_safety": cfg.alpha_safety,
            "beta_recall": cfg.beta_recall,
            "beta_effective": cfg.beta_recall * cfg.alpha_safety,
            "modes": [mode_a, mode_b],
            "primary_mode": "B",
            "calibrated_bound": mode_b["cal_bound"],
            "threshold": selector.threshold,
            "suppressed_alerts": n_sup,
            "suppression_rate": n_sup / len(s_test),
            "realised_fn_rate": mode_b["realised_fn_rate"],
            "fn_attacks": fn_sup,
            "escalation_threshold": t_esc,
            "escalation_fraction": cfg.escalation_fraction,
            "action_mix": action_counts,
        },
        "cluster": {
            "variants": clus_variants,
            "suppressed_clusters": int(clus.suppress_cluster_.sum()),
            "coverage": c_sup / len(test),
            "fn_in_suppressed": c_fn,
            "fn_rate": (c_fn / c_sup if c_sup else 0.0),
            "refused_despite_deceptive_fps": int(c_audit["refused_despite_fps"].sum()),
        },
        "budget_curve": budget,
        "precision_at_capacity": pav,
        "deceptive_subset": strat,
        "queue": {"baseline": b, "triaged": t, "business_hours": queues["business_hours"],
                  "analysts_needed_for_sla": cap},
        "cost": {k: v for k, v in opt.items() if k != "curve"},
        "cost_sensitivity": sens.to_dict(orient="records"),
        "robustness": {
            "available": robustness_available,
            "roc_auc_clean": auc_clean,
            "roc_auc_adversarial": auc_adv,
            "adversarial": adv_tbl.to_dict(orient="records"),
            "recalibration": rec,
        },
        "top_features": imp.head(10).to_dict(orient="records"),
        "examples": examples,
    }
    (outdir / "metrics.json").write_text(
        json.dumps(_jsonable(results), indent=2), encoding="utf-8"
    )

    report = _render_report(results)
    (outdir / "report.md").write_text(report, encoding="utf-8")
    _banner(f"Done. Results written to {outdir.resolve()}")
    return results


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def _render_report(r: dict) -> str:
    d = r["dataset"]
    s = r["suppression"]
    c = r["cluster"]
    q = r["queue"]
    co = r["cost"]
    synthetic = r.get("source", "synth") == "synth"
    provenance = (
        "All figures come from a single seeded run of the synthetic mini-SOC "
        "generator, so the run is exactly reproducible."
        if synthetic
        else "All figures come from an ingested telemetry capture (see "
             "`lab/README.md`); drift and adversarial results are not "
             "available because they require injected traffic."
    )
    lines = [
        "# Automated Native ML Alert Triage — Experiment Report",
        "",
        f"> Generated by `run_experiments.py`. {provenance}",
        "",
        "## 1. Dataset",
        "",
        "| Property | Value |",
        "|---|---|",
        f"| Source | `{r.get('source', 'synth')}` |",
        f"| Alerts | {d['alerts']:,} |",
        f"| Span | {d.get('days', 0)} days, {d.get('weeks_observed', 0)} week(s) |",
        f"| Attack rate | {d['attack_rate']:.2%} |",
        f"| Deceptive-FP rate | {d['deceptive_fp_rate']:.2%} |",
        f"| Rules / hosts | {d.get('unique_rules', 0)} / {d.get('unique_hosts', 0)} |",
        f"| Split rule | {r.get('split', {}).get('mode', 'week')} |",
        f"| Train / calib / test | {d['train']:,} / {d['calib']:,} / {d['test']:,} |",
        f"| Test attacks | {d['test_attacks']:,} |",
        f"| Test *deceptive* attacks | {d['test_deceptive_attacks']:,} |",
        "",
        "## 2. Model comparison (held-out test window)",
        "",
        "| Model | ROC-AUC | PR-AUC | ECE |",
        "|---|---|---|---|",
    ]
    for row in r["model_comparison"]:
        lines.append(f"| {row['model']} | {row['roc_auc']:.4f} | "
                     f"{row['pr_auc']:.4f} | {row['ece']:.4f} |")

    # A capture with a few hundred rows cannot rank a boosted model fairly.
    # Say so in the report instead of letting a reader compare the number
    # against the 48k-alert synthetic run and conclude the model is broken.
    if d.get("train_attacks", 10**9) < 250:
        lines += [
            "",
            f"> **Small-capture caveat.** Training contains only "
            f"{d['train_attacks']:,} attack example(s) and "
            f"{d['calib_attacks']:,} calibration attack(s). ROC-AUC and PR-AUC "
            f"at this sample size are dominated by variance, and a "
            f"gradient-boosted model can fit the training window perfectly "
            f"(train AUC about 1.0) while ranking the held-out window poorly. "
            f"Treat this table as an adapter smoke test, not a model result; "
            f"see `lab/README.md`.",
        ]

    lines += [
        "",
        "## 3. Risk-controlled suppression",
        "",
        "Two guarantees are evaluated because they answer different questions:",
        "",
        f"* **Mode A** bounds the FN rate *inside the suppressed set* "
        f"(alpha = {s['alpha']:.1%}, effective {s['alpha_effective']:.2%}).",
        f"* **Mode B** (primary) bounds the share of **all** attacks that are "
        f"suppressed (beta = {s['beta_recall']:.1%}, effective "
        f"{s['beta_effective']:.2%}).",
        "",
        "Mode A is the textbook selective-classification guarantee, but with a "
        "low alert base rate it can discard a large share of real attacks while "
        "still obeying its bound. Mode B is the guarantee an SOC actually needs.",
        "",
        "| Mode | Bound | Alert suppression | FN within suppressed | "
        "Attacks missed | Recall |",
        "|---|---|---|---|---|---|",
    ]
    for m in s["modes"]:
        lines.append(
            f"| {m['mode']} | {m['cal_bound']:.4f} | "
            f"{m['suppression_rate']:.2%} | {m['realised_fn_rate']:.4f} | "
            f"{m['missed_share_of_attacks']:.2%} | {m['recall']:.2%} |"
        )
    lines += [
        "",
        f"Escalation band: the top {100 * s['escalation_fraction']:.0f}% of kept "
        f"alerts by score.",
        "",
        "Action mix on the test stream: "
        + ", ".join(f"**{k}** {v:,}" for k, v in s["action_mix"].items()) + ".",
        "",
        "### Alert reduction at a tolerated false-negative budget",
        "",
        "| FN budget | Alert reduction | Alerts kept | Attacks missed |",
        "|---|---|---|---|",
    ]
    for row in r["budget_curve"]:
        lines.append(f"| {row['fn_budget']:.1%} | {row['alert_reduction']:.2%} | "
                     f"{row['kept']:,} | {row['missed']} |")

    pav = r["precision_at_capacity"]
    lines += [
        "",
        f"At a review budget of {pav['reviewed']:,} alerts over the test window "
        f"(5% of the stream) the model's top-ranked set reaches "
        f"**precision {pav['precision']:.1%}** and "
        f"**recall {pav['recall']:.1%}**.",
        "",
        "## 4. Behavioural-cluster suppression",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Clusters suppressed (simultaneous) | {c['suppressed_clusters']} |",
        f"| Coverage (simultaneous) | {c['coverage']:.2%} |",
        f"| Attacks inside suppressed clusters | {c['fn_in_suppressed']} |",
        f"| Clusters refused despite containing deceptive FPs | "
        f"{c['refused_despite_deceptive_fps']} |",
        "",
        "Both statistical variants are reported because they answer different "
        "questions: the Bonferroni form is safe across the whole cluster set, "
        "the marginal form is what a team would actually deploy.",
        "",
        "| Variant | Clusters suppressed | Coverage | Attacks suppressed |",
        "|---|---|---|---|",
    ]
    for name, v in c["variants"].items():
        lines.append(f"| {name} | {v['clusters_suppressed']} | "
                     f"{v['coverage']:.2%} | {v['fn_in_suppressed']} |")
    lines += [
        "",
        "## 5. SOC operations impact",
        "",
        "| Metric | Baseline (review all) | Triaged |",
        "|---|---|---|",
        f"| Meantime in queue | {q['baseline']['mean_wait'] / 60:.1f} min | "
        f"{q['triaged']['mean_wait'] / 60:.1f} min |",
        f"| 95th percentile wait | {q['baseline']['p95_wait'] / 60:.1f} min | "
        f"{q['triaged']['p95_wait'] / 60:.1f} min |",
        f"| SLA breach rate | {q['baseline']['sla_breach_rate']:.1%} | "
        f"{q['triaged']['sla_breach_rate']:.1%} |",
        f"| Alerts never reviewed | {q['baseline']['unserved_frac']:.1%} | "
        f"{q['triaged']['unserved_frac']:.1%} |",
        f"| Analysts needed to hit 5% SLA | "
        f"{q['analysts_needed_for_sla']['baseline'] or '>40'} | "
        f"{q['analysts_needed_for_sla']['triaged'] or '>40'} |",
        "",
        "### Cost-optimal operating point",
        "",
        "| Quantity | Value |",
        "|---|---|",
        f"| Optimal threshold | {co['threshold']:.4f} |",
        f"| Recall at optimum | {co['recall']:.1%} |",
        f"| Alerts kept per day | {co['kept_per_day']:.0f} |",
        f"| Review cost (annual) | ${co['review_cost_annual']:,.0f} |",
        f"| Expected miss cost (annual) | ${co['miss_cost_annual']:,.0f} |",
        f"| Total (annual) | ${co['total_cost_annual']:,.0f} |",
        f"| Review-all cost (annual) | ${co['review_all_cost_annual']:,.0f} |",
        f"| **Savings** | **${co['savings_annual']:,.0f} "
        f"({co['savings_pct']:.1f}%)** |",
        "",
        "### Break-even sensitivity",
        "",
        "Suppression is only economically rational if the assumed probability "
        "that a missed alert leads to a breach is small enough. The grid below "
        "makes that assumption explicit.",
        "",
        "| P(exploit \\| miss) | Implied cost per miss | Optimal keep fraction | "
        "Optimal recall | Suppression optimal? |",
        "|---|---|---|---|---|",
    ]
    for row in r.get("cost_sensitivity", []):
        lines.append(
            f"| {row['p_exploit_given_miss']:.0e} | "
            f"${row['implicit_cost_per_miss']:,.0f} | "
            f"{row['optimal_keep_fraction']:.1%} | "
            f"{row['optimal_recall']:.1%} | "
            f"{'yes' if row['suppression_is_optimal'] else 'no'} |"
        )
    rb = r["robustness"]
    lines += ["## 6. Robustness", ""]
    if rb.get("available", True):
        lines += [
            f"ROC-AUC clean = {rb['roc_auc_clean']:.4f}; "
            f"under adversarial imitation = "
            f"{rb['roc_auc_adversarial']:.4f}.",
            "",
            "| Attack group | n | Recall |",
            "|---|---|---|",
        ]
        for row in rb["adversarial"]:
            lines.append(f"| {row['group']} | {row['n']:,} | "
                         f"{row['recall']:.1%} |")

        rec = rb["recalibration"]
        lines += [
            "",
            "Threshold recalibration after drift:",
            "",
            "| Selector | Coverage | Realised FN rate |",
            "|---|---|---|",
            f"| Stale (pre-drift) | {rec['stale']['coverage']:.2%} | "
            f"{rec['stale']['fn_rate']:.4f} |",
            f"| Recalibrated | {rec['recalibrated']['coverage']:.2%} | "
            f"{rec['recalibrated']['fn_rate']:.4f} |",
            "",
        ]
    else:
        lines += [
            "Not available for this dataset. Drift and adversarial-imitation "
            "results require **injected** traffic; manufacturing either inside "
            "a real capture would be falsification, so the section is reported "
            "as empty instead of estimated.",
            "",
            "Run the synthetic study (`python run_experiments.py`) for those "
            "two analyses, or capture a second lab period after a genuine "
            "environment change and compare the two weekly tables.",
            "",
        ]

    lines += [
        "## 7. Top features",
        "",
        "| Feature | Importance |",
        "|---|---|",
    ]
    for row in r["top_features"]:
        lines.append(f"| {row['feature']} | {row['importance']:.4f} |")

    lines += ["", "## 8. Example explanations", ""]
    for e in r["examples"]:
        lines.append(f"**{e['kind']}** — score {e['score']:.3f}, "
                     f"truth = {e['ground_truth']}")
        lines.append("")
        lines.append("| Feature | Value | Contribution | Direction |")
        lines.append("|---|---|---|---|")
        for f in e["explanation"]:
            lines.append(f"| {f['feature']} | `{f['value']}` | "
                         f"{f['delta']:+.4f} | {f['direction']} |")
        lines.append("")

    limits = [
        "---",
        "",
        "## Limitations",
        "",
    ]
    if synthetic:
        limits += [
            "1. The alert stream is **synthetic**. It validates the pipeline "
            "and the evaluation methodology, not real-world efficacy. External "
            "validity must come from the lab capture (`lab/`) or public "
            "datasets (BOTS, Mordor, EVTX-ATTACK-SAMPLES).",
            "2. Benign activity is generated from playbooks and is therefore "
            "cleaner than a real enterprise. Adversarial and drift injection "
            "only partly compensate.",
        ]
    else:
        limits += [
            "1. The capture is a **laboratory range**, not an enterprise. "
            "Attack volume, user diversity and noise are all far smaller than "
            "production; treat effect sizes as directional.",
            "2. Ground truth comes from the test schedule, so an alert whose "
            "timestamp coincides with a scheduled technique is labelled "
            "malicious even if its actual cause was incidental.",
            "3. Drift and adversarial results are unavailable (see §6).",
        ]
    limits += [
        "4. Queue parameters (arrival intensity, handling time) are assumed, "
        "not measured. A live SOC pilot is required before any operational "
        "claim.",
        "5. Label noise and alert duplication are not modelled explicitly.",
        "",
    ]
    lines += limits
    return "\n".join(lines)
