"""Entry point: run the full study.

    python run_experiments.py                      # synthetic study
    python run_experiments.py --quick              # smaller run for iteration
    python run_experiments.py --source csv --path lab/out/lab_dataset.csv
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import replace
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from soc_triage.config import DEFAULT  # noqa: E402
from soc_triage.pipeline import run  # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser(description="SOC alert-triage experiment runner")
    ap.add_argument("--quick", action="store_true", help="small smoke configuration")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--outdir", type=str, default=None)
    ap.add_argument("--source", choices=("synth", "csv"), default="synth",
                    help="alert source: synthetic generator or a lab dataset")
    ap.add_argument("--path", type=str, default=None,
                    help="dataset path (required when --source csv)")
    args = ap.parse_args()

    cfg = DEFAULT
    if args.quick:
        cfg = replace(cfg, n_alerts=30_000, cluster_min_size=20,
                      outdir="results_quick")
    if args.seed is not None:
        cfg = replace(cfg, seed=args.seed)
    if args.outdir is not None:
        cfg = replace(cfg, outdir=args.outdir)
    if args.source == "csv" and not args.path:
        ap.error("--source csv requires --path")

    run(cfg, source=args.source, path=args.path)


if __name__ == "__main__":
    main()
