"""Command line entry point.

    python -m de_lab.cli backtest --rules rules --attacks data/attacks --benign data/benign
    python -m de_lab.cli list-rules --rules rules
    python -m de_lab.cli inspect data/attacks/scenario.ndjson
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .backtest import run_backtest, to_markdown, write_outputs
from .normalize import load_events, summarise
from .sigma.evaluator import logsource_supported
from .sigma.model import BrokenRule, SigmaRule, load_rules

EXIT_OK = 0
EXIT_FAIL_THRESHOLD = 1
EXIT_USAGE = 2


def _cmd_backtest(args: argparse.Namespace) -> int:
    result = run_backtest(
        rules_dir=args.rules,
        attacks_dir=args.attacks,
        benign_dir=args.benign,
        fp_threshold=args.fp_threshold,
        sample_limit=args.samples,
    )

    if args.stdout:
        print(to_markdown(result))
    else:
        written = write_outputs(result, args.outdir)
        for path in written:
            print(f"wrote {path}")

    tally = result.counts()
    print(
        "verdicts: "
        + ", ".join(f"{verdict}={count}" for verdict, count in sorted(tally.items()))
    )

    if args.fail_on == "none":
        return EXIT_OK

    failing = {"invalid"} if args.fail_on == "invalid" else set()
    if args.fail_on == "noisy":
        failing |= {"invalid", "too_noisy"}
    if args.fail_on == "any":
        failing |= {"invalid", "too_noisy", "no_signal", "unvalidated", "undetermined"}

    offenders = [o.title for o in result.outcomes if o.verdict in failing]
    if offenders:
        print(f"failing verdicts ({args.fail_on}): {', '.join(offenders)}", file=sys.stderr)
        return EXIT_FAIL_THRESHOLD
    return EXIT_OK


def _cmd_list_rules(args: argparse.Namespace) -> int:
    rules = load_rules(args.rules)
    if not rules:
        print("no rules found", file=sys.stderr)
        return EXIT_OK

    for rule in rules:
        if isinstance(rule, BrokenRule):
            print(f"INVALID  {rule.relative_path}\n         {rule.error}")
            continue
        supported, reason = logsource_supported(rule.logsource)
        state = "ok" if supported else f"unvalidated ({reason})"
        techniques = ",".join(t.replace("ATTACK.", "") for t in rule.techniques) or "-"
        print(f"{state:<12} {rule.level:<8} {techniques:<24} {rule.title}")
    return EXIT_OK


def _cmd_inspect(args: argparse.Namespace) -> int:
    events = load_events(args.path)
    print(json.dumps(summarise(events), indent=2))
    return EXIT_OK


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="de-lab", description="Detection engineering workbench")
    sub = parser.add_subparsers(dest="command", required=True)

    backtest = sub.add_parser("backtest", help="score rules against attack and benign telemetry")
    backtest.add_argument("--rules", default="rules")
    backtest.add_argument("--attacks", default="data/attacks")
    backtest.add_argument("--benign", default="data/benign")
    backtest.add_argument("--outdir", default="results")
    backtest.add_argument("--fp-threshold", type=float, default=5.0,
                          help="false positives per 1,000 benign events (default: 5)")
    backtest.add_argument("--samples", type=int, default=3,
                          help="false-positive samples to keep per rule (default: 3)")
    backtest.add_argument("--stdout", action="store_true", help="print markdown instead of writing files")
    backtest.add_argument("--fail-on", choices=["none", "invalid", "noisy", "any"], default="invalid")
    backtest.set_defaults(func=_cmd_backtest)

    listing = sub.add_parser("list-rules", help="show rule inventory and parse status")
    listing.add_argument("--rules", default="rules")
    listing.set_defaults(func=_cmd_list_rules)

    inspect = sub.add_parser("inspect", help="describe a telemetry file")
    inspect.add_argument("path")
    inspect.set_defaults(func=_cmd_inspect)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
