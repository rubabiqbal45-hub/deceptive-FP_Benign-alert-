"""Backtest engine: score every rule against attack and benign telemetry.

Ground truth, stated precisely
------------------------------
Public ATT&CK datasets are *scenario*-labelled, not event-labelled: we know file
N is an execution of technique X, but individual ambient events inside it are not
annotated benign. So this engine reports two different things and never conflates
them:

* **Scenario recall** -- did the rule fire at least once somewhere in the scenario?
  This is a technique-coverage question, which is what a rule is for.
* **Benign volume** -- how many events did the rule fire on in a corpus known to
  contain no attack? Every hit there is a false positive by construction.

There is deliberately no event-level "precision" number, because computing one
would require inventing labels. When no benign corpus is supplied the verdict is
``undetermined``, not ``pass``. A missing measurement is not a clean bill of health.
"""

from __future__ import annotations

import csv
import io
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Sequence

from .normalize import load_events, normalise_record
from .sigma.evaluator import logsource_supported, matches
from .sigma.model import BrokenRule, Rule, SigmaRule, load_rules

DATA_SUFFIXES = ("*.ndjson", "*.jsonl", "*.json")

VERDICT_ORDER = {
    "pass": 0,
    "undetermined": 1,
    "too_noisy": 2,
    "no_signal": 3,
    "unvalidated": 4,
    "invalid": 5,
}

SAMPLE_FIELDS = (
    "TimeCreated",
    "Hostname",
    "Channel",
    "EventID",
    "Image",
    "ParentImage",
    "CommandLine",
    "User",
    "TargetFilename",
    "TargetObject",
    "QueryName",
    "DestinationIp",
    "DestinationPort",
)


@dataclass
class Scenario:
    name: str
    path: Path
    events: list[dict[str, Any]]


@dataclass
class Outcome:
    reference: str
    title: str
    level: str
    techniques: tuple[str, ...]
    hits_by_scenario: dict[str, int] = field(default_factory=dict)
    benign_hits: int = 0
    benign_events: int = 0
    benign_hours: float = 0.0
    samples: list[dict[str, Any]] = field(default_factory=list)
    verdict: str = "invalid"
    notes: list[str] = field(default_factory=list)

    @property
    def attack_scenarios_hit(self) -> int:
        return sum(1 for count in self.hits_by_scenario.values() if count > 0)

    def fp_per_1k(self) -> float | None:
        if self.benign_events <= 0:
            return None
        return 1000.0 * self.benign_hits / self.benign_events

    def fp_per_hour(self) -> float | None:
        if self.benign_hours <= 0:
            return None
        return self.benign_hits / self.benign_hours


@dataclass
class BacktestResult:
    outcomes: list[Outcome]
    attacks: list[Scenario]
    benign_events: int
    benign_hours: float
    fp_threshold: float
    generated_at: str

    def counts(self) -> dict[str, int]:
        tally: dict[str, int] = {}
        for outcome in self.outcomes:
            tally[outcome.verdict] = tally.get(outcome.verdict, 0) + 1
        return tally

    @property
    def worst_verdict(self) -> str:
        ranked = sorted(self.outcomes, key=lambda o: VERDICT_ORDER.get(o.verdict, 99))
        return ranked[-1].verdict if ranked else "pass"


# ------------------------------------------------------------------- loading
def _paths(root: Path) -> list[Path]:
    if not root.exists():
        return []
    found: set[Path] = set()
    for suffix in DATA_SUFFIXES:
        found.update(root.rglob(suffix))
    return sorted(found)


def load_scenarios(root: str | Path) -> list[Scenario]:
    root = Path(root)
    scenarios = []
    for path in _paths(root):
        events = load_events(path)
        if events:
            scenarios.append(Scenario(name=path.stem, path=path, events=events))
    return scenarios


def load_benign(root: str | Path) -> tuple[list[dict[str, Any]], float]:
    """Pool every benign corpus and return the events plus their hour span."""
    events: list[dict[str, Any]] = []
    stamps: list[float] = []
    for path in _paths(Path(root)):
        loaded = load_events(path)
        events.extend(loaded)
        stamps.extend(e["_ts"] for e in loaded if e.get("_ts"))

    hours = 0.0
    if stamps:
        hours = max(0.0, (max(stamps) - min(stamps)) / 3600.0)
    return events, hours


# ---------------------------------------------------------------- evaluation
def _sample(event: dict[str, Any]) -> dict[str, Any]:
    return {key: event[key] for key in SAMPLE_FIELDS if event.get(key) not in (None, "", "-")}


def _score_rule(
    rule: SigmaRule,
    attacks: Sequence[Scenario],
    benign: Sequence[dict[str, Any]],
    benign_hours: float,
    fp_threshold: float,
    sample_limit: int,
) -> Outcome:
    outcome = Outcome(
        reference=rule.path.as_posix(),
        title=rule.title,
        level=rule.level,
        techniques=rule.techniques,
    )

    for scenario in attacks:
        hits = 0
        for event in scenario.events:
            if matches(rule, event):
                hits += 1
        outcome.hits_by_scenario[scenario.name] = hits

    samples: list[dict[str, Any]] = []
    for event in benign:
        if matches(rule, event):
            outcome.benign_hits += 1
            if len(samples) < sample_limit:
                samples.append(_sample(event))
    outcome.samples = samples
    outcome.benign_events = len(benign)
    outcome.benign_hours = benign_hours

    if outcome.attack_scenarios_hit == 0:
        outcome.verdict = "no_signal"
        outcome.notes.append("fired on no attack scenario in this corpus")
    elif benign_hours <= 0 and outcome.benign_events == 0:
        outcome.verdict = "undetermined"
        outcome.notes.append("no benign corpus supplied: false-positive rate unmeasured")
    elif outcome.benign_events > 0 and (outcome.fp_per_1k() or 0.0) > fp_threshold:
        outcome.verdict = "too_noisy"
        outcome.notes.append(
            f"{outcome.fp_per_1k():.1f} false positives per 1k benign events "
            f"(policy limit {fp_threshold:.1f})"
        )
    elif outcome.benign_events == 0:
        outcome.verdict = "undetermined"
        outcome.notes.append("benign corpus had no events: false-positive rate unmeasured")
    else:
        outcome.verdict = "pass"
    return outcome


def run_backtest(
    rules_dir: str | Path,
    attacks_dir: str | Path,
    benign_dir: str | Path,
    fp_threshold: float = 5.0,
    sample_limit: int = 3,
) -> BacktestResult:
    rules = load_rules(rules_dir)
    attacks = load_scenarios(attacks_dir)
    benign, benign_hours = load_benign(benign_dir)

    outcomes: list[Outcome] = []
    for rule in rules:
        if isinstance(rule, BrokenRule):
            outcomes.append(
                Outcome(
                    reference=rule.relative_path,
                    title=rule.path.stem,
                    level="-",
                    techniques=(),
                    verdict="invalid",
                    notes=[rule.error],
                )
            )
            continue

        supported, reason = logsource_supported(rule.logsource)
        if not supported:
            outcomes.append(
                Outcome(
                    reference=rule.relative_path,
                    title=rule.title,
                    level=rule.level,
                    techniques=rule.techniques,
                    verdict="unvalidated",
                    notes=[reason],
                )
            )
            continue

        outcomes.append(
            _score_rule(rule, attacks, benign, benign_hours, fp_threshold, sample_limit)
        )

    outcomes.sort(key=lambda o: (VERDICT_ORDER.get(o.verdict, 99), o.reference))

    return BacktestResult(
        outcomes=outcomes,
        attacks=attacks,
        benign_events=len(benign),
        benign_hours=benign_hours,
        fp_threshold=fp_threshold,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    )


# ------------------------------------------------------------------- output
def _fmt(value: float | None, digits: int = 1) -> str:
    return "—" if value is None else f"{value:.{digits}f}"


def _escape(text: str) -> str:
    return text.replace("|", "\\|")


def to_markdown(result: BacktestResult) -> str:
    lines: list[str] = []
    add = lines.append

    add("# Detection backtest results")
    add("")
    add(f"Generated: {result.generated_at}  ")
    add(f"False-positive policy limit: **{result.fp_threshold:g} per 1,000 benign events**")
    add("")

    add("## Corpus")
    add("")
    add("| Set | Files | Events |")
    add("|---|---:|---:|")
    add(f"| Attack scenarios | {len(result.attacks)} | {sum(len(s.events) for s in result.attacks)} |")
    add(f"| Benign baseline | — | {result.benign_events} |")
    add("")
    if result.benign_events == 0:
        add(
            "> **No benign baseline supplied.** Every false-positive column below is "
            "`—` and every rule that fired is marked `undetermined`. This engine will "
            "not report a rule as clean when it has never seen benign traffic."
        )
        add("")
    if result.benign_hours > 0:
        add(f"Benign coverage: {result.benign_hours:.2f} hours of telemetry")
        add("")

    add("## Per-rule results")
    add("")
    add("| Rule | Level | ATT&CK | Scenarios hit | Benign hits | FP /1k | FP /hr | Verdict |")
    add("|---|---|---|---:|---:|---:|---:|---|")
    for o in result.outcomes:
        techniques = ", ".join(t.replace("ATTACK.", "") for t in o.techniques) or "—"
        scenarios = f"{o.attack_scenarios_hit}/{len(result.attacks)}" if result.attacks else "0/0"
        add(
            f"| [{_escape(o.title)}]({o.reference}) | {o.level} | {techniques} | {scenarios} | "
            f"{o.benign_hits} | {_fmt(o.fp_per_1k())} | {_fmt(o.fp_per_hour(), 2)} | **{o.verdict}** |"
        )
    add("")

    tally = result.counts()
    add("## Verdict tally")
    add("")
    add("| Verdict | Rules |")
    add("|---|---:|")
    for verdict in sorted(tally, key=lambda v: VERDICT_ORDER.get(v, 99)):
        add(f"| {verdict} | {tally[verdict]} |")
    add("")

    notes = [(o.title, note) for o in result.outcomes for note in o.notes]
    if notes:
        add("## Notes")
        add("")
        for title, note in notes:
            add(f"* **{_escape(title)}** — {note}")
        add("")

    samples = [o for o in result.outcomes if o.samples]
    if samples:
        add("## False-positive samples")
        add("")
        add("Evidence for tuning, not a summary. Each block is a benign event the rule fired on.")
        add("")
        for o in samples:
            add(f"### {_escape(o.title)}")
            add("")
            for sample in o.samples:
                rendered = ", ".join(f"`{k}={v}`" for k, v in sample.items())
                add(f"* {rendered}")
            add("")

    add("## Method")
    add("")
    add("* Sigma rules are parsed and evaluated by this repository, not by a vendor backend.")
    add("* Pocket-sized subset of the Sigma condition grammar; unsupported constructs mark a rule `invalid`.")
    add("* Logsource gating runs before field matching, so a rule cannot fire on the wrong event class.")
    add("* Attack recall is *scenario* level: did the rule fire at least once? Public ATT&CK")
    add("  datasets do not label individual events inside a scenario.")
    add("* A benign hit is a false positive by construction: the benign corpus is attack-free.")
    add("")
    return "\n".join(lines)


def to_payload(result: BacktestResult) -> dict[str, Any]:
    return {
        "generated_at": result.generated_at,
        "fp_threshold_per_1k": result.fp_threshold,
        "corpus": {
            "attack_scenarios": [
                {"name": s.name, "path": s.path.as_posix(), "events": len(s.events)}
                for s in result.attacks
            ],
            "benign_events": result.benign_events,
            "benign_hours": round(result.benign_hours, 3),
        },
        "verdicts": result.counts(),
        "rules": [
            {
                "rule": o.reference,
                "title": o.title,
                "level": o.level,
                "techniques": list(o.techniques),
                "hits_by_scenario": o.hits_by_scenario,
                "attack_scenarios_hit": o.attack_scenarios_hit,
                "benign_hits": o.benign_hits,
                "benign_events": o.benign_events,
                "fp_per_1k": None if o.fp_per_1k() is None else round(o.fp_per_1k(), 3),
                "fp_per_hour": None if o.fp_per_hour() is None else round(o.fp_per_hour(), 3),
                "verdict": o.verdict,
                "notes": o.notes,
                "samples": o.samples,
            }
            for o in result.outcomes
        ],
    }


def to_csv(result: BacktestResult) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        [
            "rule",
            "title",
            "level",
            "techniques",
            "attack_scenarios_hit",
            "attack_scenarios_total",
            "benign_hits",
            "benign_events",
            "fp_per_1k",
            "fp_per_hour",
            "verdict",
        ]
    )
    for o in result.outcomes:
        writer.writerow(
            [
                o.reference,
                o.title,
                o.level,
                ";".join(o.techniques),
                o.attack_scenarios_hit,
                len(result.attacks),
                o.benign_hits,
                o.benign_events,
                "" if o.fp_per_1k() is None else f"{o.fp_per_1k():.3f}",
                "" if o.fp_per_hour() is None else f"{o.fp_per_hour():.3f}",
                o.verdict,
            ]
        )
    return buffer.getvalue()


def write_outputs(result: BacktestResult, outdir: str | Path) -> list[Path]:
    out = Path(outdir)
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    markdown_path = out / "RESULTS.md"
    markdown_path.write_text(to_markdown(result), encoding="utf-8")
    written.append(markdown_path)

    json_path = out / "results.json"
    json_path.write_text(json.dumps(to_payload(result), indent=2), encoding="utf-8")
    written.append(json_path)

    csv_path = out / "per_rule.csv"
    csv_path.write_text(to_csv(result), encoding="utf-8")
    written.append(csv_path)

    return written
