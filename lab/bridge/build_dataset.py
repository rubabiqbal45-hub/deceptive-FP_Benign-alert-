"""Build a pipeline-ready dataset from a Wazuh/Sysmon capture.

Usage
-----
    python lab/bridge/build_dataset.py \
        --alerts   lab/out/alerts.json \
        --truth    lab/out/ground_truth.csv \
        --inventory lab/inventory \
        --out      lab/out/lab_dataset.csv

Then:

    python run_experiments.py --source csv --path lab/out/lab_dataset.csv

The output satisfies ``soc_triage.schema.REQUIRED_COLUMNS``, so the entire
model / evaluation stack runs unchanged.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

try:  # package mode (tests import lab.bridge.build_dataset)
    from . import context, detect, inventory as inv_mod, label, normalize
except ImportError:  # script mode (python lab/bridge/build_dataset.py)
    import context
    import detect
    import inventory as inv_mod
    import label
    import normalize

from soc_triage.schema import REQUIRED_COLUMNS, assert_schema  # noqa: E402


FINAL_COLUMNS = list(REQUIRED_COLUMNS) + [
    "scenario_id", "playbook", "dst_ip", "src_ip",
]


def build(alerts_path: str | Path,
          truth_path: str | Path | None,
          inventory_dir: str | Path | None,
          match: str = "time+rule",
          slack_seconds: int = 90,
          blocklist: frozenset[str] | None = None,
          verbose: bool = True) -> pd.DataFrame:
    inv = inv_mod.load_inventory(inventory_dir)

    if verbose:
        print(f"  reading {alerts_path}")
    alerts = normalize.load_alerts(alerts_path)
    events = normalize.normalize(alerts)
    if verbose:
        for k, v in normalize.summary(events).items():
            print(f"    {k}: {v}")

    events = normalize.deduplicate(events)
    if verbose:
        print(f"  after dedup: {len(events):,} events")

    det = detect.detect(events)
    if verbose:
        print(f"  detections: {len(det):,}")
        cov = detect.coverage(det)
        if not cov.empty:
            print(cov.to_string(index=False))

    if det.empty:
        raise SystemExit(
            "no detections produced. Check that Sysmon events reached the "
            "manager and that event_id 1/3/10 are present."
        )

    det = context.enrich(det, events, inv,
                         blocklist=blocklist or context.DEFAULT_BLOCKLIST)

    if truth_path is None:
        raise SystemExit("--truth is required: unlabelled data cannot be evaluated")

    truth = pd.read_csv(truth_path, dtype=str)
    truth["host_id"] = truth["host"].map(
        lambda h: inv.resolve_host(h)["host_id"]
    )
    det = label.attach_labels(det, truth, match=match,
                              slack_seconds=slack_seconds)
    det = label.derive_deceptive(det)
    det["scenario_id"] = label.assign_scenarios(det)

    if int(det["label"].sum()) == 0:
        raise SystemExit(
            "no true positives. Either the atomics did not execute, or the "
            "capture window / host aliases are wrong. Check --slack-seconds "
            "and lab/out/ground_truth.csv."
        )

    start = det["ts"].min().normalize()
    out = pd.DataFrame({
        "alert_id": [f"AL-{i:06d}" for i in range(len(det))],
        "ts": det["ts"].to_numpy(),
        "week": ((det["ts"] - start).dt.days // 7 + 1).astype(int).to_numpy(),
        "dow": det["ts"].dt.day_of_week.astype(int).to_numpy(),
        "host_id": det["host_id"].to_numpy(),
        "asset_type": det["asset_type"].to_numpy(),
        "asset_criticality": det["asset_criticality"].to_numpy(),
        "user_id": det["user_id"].to_numpy(),
        "user_role": det["user_role"].to_numpy(),
        "rule_id": det["rule_id"].to_numpy(),
        "rule_name": det["rule_name"].to_numpy(),
        "technique": det["technique"].to_numpy(),
        "severity": det["severity"].to_numpy(),
        "process_name": det["process_name"].to_numpy(),
        "parent_process": det["parent_process"].to_numpy(),
        "command_line": det["command_line"].fillna("").to_numpy(),
        "event_count": det["event_count"].to_numpy(),
        "burst_size": det["burst_size"].to_numpy(),
        "lineage_depth": det["lineage_depth"].to_numpy(),
        "host_novelty": det["host_novelty"].to_numpy(),
        "peer_rarity": det["peer_rarity"].to_numpy(),
        "cmdline_distance": det["cmdline_distance"].to_numpy(),
        "dst_reputation": det["dst_reputation"].to_numpy(),
        "signed_ratio": det["signed_ratio"].to_numpy(),
        "role_asset_mismatch": det["role_asset_mismatch"].to_numpy(),
        "label": det["label"].to_numpy(),
        "is_deceptive_fp": det["is_deceptive_fp"].to_numpy(),
        "is_deceptive_attack": det["is_deceptive_attack"].to_numpy(),
        "scenario_id": det["scenario_id"].to_numpy(),
        "playbook": det["rule_id"].to_numpy(),
        "dst_ip": det["dst_ip"].to_numpy(),
        "src_ip": det["src_ip"].to_numpy(),
    })

    out = out.sort_values("ts", kind="mergesort").reset_index(drop=True)
    assert_schema(out)

    if verbose:
        print(f"\n  dataset rows      : {len(out):,}")
        print(f"  attack rate       : {out['label'].mean():.2%}")
        print(f"  deceptive FP rate : {out['is_deceptive_fp'].mean():.2%}")
        print(f"  deceptive attacks : {int(out['is_deceptive_attack'].sum()):,}")
        print(f"  span              : {out['ts'].min()} -> {out['ts'].max()}")
    return out


def _parse_blocklist(value: str | None) -> frozenset[str] | None:
    if not value:
        return None
    return frozenset(v.strip() for v in value.split(",") if v.strip())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Wazuh/Sysmon -> triage dataset")
    ap.add_argument("--alerts", required=True, help="alerts.json (NDJSON)")
    ap.add_argument("--truth", required=True, help="ground_truth.csv from run-atomics")
    ap.add_argument("--inventory", default=str(ROOT / "lab" / "inventory"))
    ap.add_argument("--out", default=str(ROOT / "lab" / "out" / "lab_dataset.csv"))
    ap.add_argument("--match", choices=("time", "time+rule"), default="time+rule")
    ap.add_argument("--slack-seconds", type=int, default=90)
    ap.add_argument("--blocklist", default=None,
                    help="comma-separated destination IPs to treat as malicious")
    args = ap.parse_args(argv)

    df = build(args.alerts, args.truth, args.inventory,
               match=args.match, slack_seconds=args.slack_seconds,
               blocklist=_parse_blocklist(args.blocklist))

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(out, index=False, encoding="utf-8")
    print(f"\n  written -> {out.resolve()}")
    print(f"  now run:  python run_experiments.py --source csv --path {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
