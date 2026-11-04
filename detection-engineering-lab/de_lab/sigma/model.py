"""Parse Sigma rule files into an executable form.

Two things this module refuses to do, both deliberately:

1. **Silently ignore an unsupported modifier.** A rule using ``|base64offset``
   that we quietly treated as a substring match would under-fire and nobody
   would notice. Unsupported constructs mark the rule ``invalid`` instead.
2. **Accept a rule whose condition does not parse.** Reported as invalid with
   the offending position.

Invalid rules still appear in the report. A rule that cannot run is information;
a rule that vanishes from the results is a blind spot.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from ..yamlcompat import load_yaml
from .condition import ConditionError, compile_condition

SUPPORTED_MODIFIERS = {
    "contains",
    "startswith",
    "endswith",
    "re",
    "cased",
    "all",
    "exists",
    "base64",
    "windash",
    "i",
    "m",
    "s",
    "gt",
    "gte",
    "lt",
    "lte",
}

SUPPORTED_SERVICES = {
    "sysmon",
    "security",
    "powershell",
    "windefend",
    "applocker",
    "terminalservices",
    "dns-server",
}

RULE_SUFFIXES = ("*.yml", "*.yaml")


@dataclass(frozen=True)
class SigmaRule:
    path: Path
    id: str
    title: str
    level: str
    status: str
    description: str
    tags: tuple[str, ...]
    logsource: dict[str, Any]
    selections: dict[str, Any]
    condition_source: str
    ast: Any
    raw: dict[str, Any] = field(repr=False, default_factory=dict)

    @property
    def techniques(self) -> tuple[str, ...]:
        return tuple(
            tag.upper() for tag in self.tags if tag.lower().startswith("attack.t")
        )

    @property
    def attacks(self) -> tuple[str, ...]:
        return tuple(tag.upper() for tag in self.tags if tag.lower().startswith("attack.") and not tag.lower().startswith("attack.t"))

    @property
    def relative_path(self) -> str:
        return self.path.as_posix()


@dataclass(frozen=True)
class BrokenRule:
    path: Path
    error: str

    @property
    def relative_path(self) -> str:
        return self.path.as_posix()


Rule = SigmaRule | BrokenRule


class RuleError(ValueError):
    pass


def _split_key(key: str) -> tuple[str, list[str]]:
    parts = key.split("|")
    return parts[0], parts[1:]


def _validate_selection(name: str, selection: Any) -> None:
    blocks = selection if isinstance(selection, list) else [selection]
    if not blocks:
        raise RuleError(f"selection {name!r} is empty")

    for block in blocks:
        if not isinstance(block, dict):
            raise RuleError(
                f"selection {name!r} must be a mapping or a list of mappings, "
                f"found {type(block).__name__}"
            )
        if not block:
            raise RuleError(f"selection {name!r} contains an empty mapping")
        for key in block:
            _field, modifiers = _split_key(str(key))
            unsupported = [m for m in modifiers if m not in SUPPORTED_MODIFIERS]
            if unsupported:
                raise RuleError(
                    f"selection {name!r} uses unsupported modifier(s) "
                    f"{unsupported} in {key!r}"
                )


def parse_rule(path: Path) -> SigmaRule:
    text = path.read_text(encoding="utf-8")
    try:
        document = load_yaml(text)
    except Exception as exc:  # noqa: BLE001 - any YAML failure is a rule failure
        raise RuleError(f"YAML parse error: {exc}") from exc

    if not isinstance(document, dict):
        raise RuleError("rule file must contain a YAML mapping")

    detection = document.get("detection")
    if not isinstance(detection, dict):
        raise RuleError("missing or malformed 'detection' block")

    condition_source = detection.get("condition")
    if not isinstance(condition_source, str) or not condition_source.strip():
        raise RuleError("detection block has no 'condition'")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise RuleError("detection block has no selections")

    for name, selection in selections.items():
        _validate_selection(name, selection)

    try:
        ast = compile_condition(condition_source, selections.keys())
    except ConditionError as exc:
        raise RuleError(f"condition does not parse: {exc}") from exc

    logsource = document.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise RuleError("'logsource' must be a mapping")

    tags = document.get("tags") or []
    if not isinstance(tags, list):
        raise RuleError("'tags' must be a list")

    return SigmaRule(
        path=path,
        id=str(document.get("id") or path.stem),
        title=str(document.get("title") or path.stem),
        level=str(document.get("level") or "medium"),
        status=str(document.get("status") or "test"),
        description=str(document.get("description") or "").strip(),
        tags=tuple(str(tag) for tag in tags),
        logsource=logsource,
        selections=selections,
        condition_source=condition_source,
        ast=ast,
        raw=document,
    )


def load_rules(root: str | Path) -> list[Rule]:
    """Load every ``*.yml``/``*.yaml`` under ``root``, sorted by path."""
    root = Path(root)
    if not root.exists():
        raise FileNotFoundError(f"rule directory not found: {root}")

    paths: list[Path] = []
    for suffix in RULE_SUFFIXES:
        paths.extend(root.rglob(suffix))
    paths = sorted(set(paths))

    rules: list[Rule] = []
    for path in paths:
        try:
            rules.append(parse_rule(path))
        except RuleError as exc:
            rules.append(BrokenRule(path=path, error=str(exc)))
    return rules


def valid_rules(rules: Iterable[Rule]) -> list[SigmaRule]:
    return [rule for rule in rules if isinstance(rule, SigmaRule)]
