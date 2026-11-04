"""Match parsed Sigma rules against normalised events.

Semantics implemented, and the choices that are *not* obvious:

* Within a selection, all fields must match (AND); within a field, a list of
  values is OR unless the ``|all`` modifier is present.
* A selection written as a *list of mappings* is OR over the mappings.
* String comparison is case-insensitive unless ``|cased`` is given. This matches
  the Sigma specification, where case sensitivity is opt-in.
* Regex uses :func:`re.search`. Flags come from ``|i`` / ``|m`` / ``|s``; absent
  those, regex is case-insensitive like every other string operator. That is a
  documented deviation from pySigma, whose backends decide this per target.
* ``|base64`` encodes the *rule* value and then applies ``contains``, which is
  how Sigma defines the modifier.
* ``|windash`` treats ``-flag`` and ``/flag`` as equivalent.
* Logsource gating happens before any field matching. A rule whose logsource our
  telemetry cannot satisfy never fires, and is flagged as unvalidated rather than
  counted as a clean pass.
"""

from __future__ import annotations

import base64
import re
from typing import Any

from .model import SUPPORTED_SERVICES, SigmaRule

# Sigma category -> (Sysmon event ids, Security/other event ids)
CATEGORY_EVENT_IDS: dict[str, tuple[frozenset[int], frozenset[int]]] = {
    "process_creation": (frozenset({1}), frozenset({4688})),
    "process_termination": (frozenset({5}), frozenset({4689})),
    "network_connection": (frozenset({3}), frozenset({5156, 5158})),
    "file_event": (frozenset({11}), frozenset()),
    "file_create": (frozenset({11}), frozenset()),
    "file_delete": (frozenset({23, 26}), frozenset()),
    "file_rename": (frozenset({11}), frozenset()),
    "registry_event": (frozenset({12, 13, 14}), frozenset()),
    "registry_add": (frozenset({12}), frozenset()),
    "registry_set": (frozenset({13}), frozenset()),
    "registry_delete": (frozenset({12}), frozenset()),
    "image_load": (frozenset({7}), frozenset()),
    "dns_query": (frozenset({22}), frozenset()),
    "process_access": (frozenset({10}), frozenset()),
    "pipe_created": (frozenset({17, 18}), frozenset()),
    "wmi_event": (frozenset({19, 20, 21}), frozenset()),
    "create_remote_thread": (frozenset({8}), frozenset()),
}

SERVICE_CHANNEL_CLASS = {
    "sysmon": "sysmon",
    "security": "security",
    "powershell": "powershell",
    "windefend": "other",
    "applocker": "other",
    "terminalservices": "other",
    "dns-server": "other",
}


def logsource_supported(logsource: dict[str, Any]) -> tuple[bool, str]:
    """Can this engine evaluate the rule's logsource at all?"""
    service = logsource.get("service")
    if service is not None and str(service).lower() not in SUPPORTED_SERVICES:
        return False, f"unsupported logsource service {service!r}"

    category = logsource.get("category")
    if category is not None and str(category).lower() not in CATEGORY_EVENT_IDS:
        return False, f"unsupported logsource category {category!r}"

    product = logsource.get("product")
    if product is not None and str(product).lower() not in ("windows", "win32"):
        return False, f"non-Windows logsource product {product!r}"

    return True, ""


def logsource_matches(logsource: dict[str, Any], event: dict[str, Any]) -> bool:
    service = logsource.get("service")
    if service is not None:
        expected = SERVICE_CHANNEL_CLASS.get(str(service).lower())
        if expected is not None and event.get("_channel_class") != expected:
            return False

    category = logsource.get("category")
    if category is not None:
        sysmon_ids, other_ids = CATEGORY_EVENT_IDS[str(category).lower()]
        allowed = set(sysmon_ids)
        if event.get("_channel_class") != "sysmon":
            allowed = set(other_ids)
        if event.get("_event_id") not in allowed:
            return False

    return True


# --------------------------------------------------------------------- fields
def lookup(event: dict[str, Any], field: str) -> Any:
    """Field access with a case-insensitive fallback.

    Exact lookup is the fast path; the fallback only runs when an exact key is
    absent, which is rare because the normaliser emits canonical casing.
    """
    if field in event:
        return event[field]
    lowered = field.lower()
    for key, value in event.items():
        if key.lower() == lowered:
            return value
    return None


def _cmp(actual: Any, expected: Any) -> int | None:
    """Numeric comparison where possible, ``None`` when not comparable."""
    try:
        return (float(actual) > float(expected)) - (float(actual) < float(expected))
    except (TypeError, ValueError):
        return None


def _as_text(value: Any, cased: bool) -> str:
    text = str(value)
    return text if cased else text.lower()


def _windash_variants(expected: Any) -> list[str]:
    text = str(expected)
    if text[:1] in ("-", "/"):
        return [text, "-" + text[1:], "/" + text[1:]]
    return [text]


def _match_one(actual: Any, expected: Any, modifiers: set[str]) -> bool:
    if actual is None:
        return False

    if "exists" in modifiers:
        return (actual is not None) == bool(expected)

    if "gt" in modifiers or "gte" in modifiers or "lt" in modifiers or "lte" in modifiers:
        comparison = _cmp(actual, expected)
        if comparison is None:
            return False
        if "gt" in modifiers:
            return comparison > 0
        if "gte" in modifiers:
            return comparison >= 0
        if "lt" in modifiers:
            return comparison < 0
        return comparison <= 0

    cased = "cased" in modifiers

    if "re" in modifiers:
        flags = 0 if cased else re.IGNORECASE
        if "i" in modifiers:
            flags |= re.IGNORECASE
        if "m" in modifiers:
            flags |= re.MULTILINE
        if "s" in modifiers:
            flags |= re.DOTALL
        try:
            return re.search(str(expected), str(actual), flags) is not None
        except re.error:
            return False

    if "base64" in modifiers:
        encoded = base64.b64encode(str(expected).encode("utf-8")).decode("ascii")
        return _as_text(encoded, cased) in _as_text(actual, cased)

    candidates = _windash_variants(expected) if "windash" in modifiers else [str(expected)]
    haystack = _as_text(actual, cased)

    for candidate in candidates:
        needle = _as_text(candidate, cased)
        if "contains" in modifiers:
            if needle in haystack:
                return True
        elif "startswith" in modifiers:
            if haystack.startswith(needle):
                return True
        elif "endswith" in modifiers:
            if haystack.endswith(needle):
                return True
        elif haystack == needle:
            return True

    return False


def match_selection(selection: Any, event: dict[str, Any]) -> bool:
    blocks = selection if isinstance(selection, list) else [selection]
    return any(_match_block(block, event) for block in blocks)


def _match_block(block: dict[str, Any], event: dict[str, Any]) -> bool:
    for key, expected in block.items():
        parts = str(key).split("|")
        field, modifiers = parts[0], set(parts[1:])
        actual = lookup(event, field)

        if "exists" in modifiers:
            if (actual is not None) != bool(expected):
                return False
            continue

        values = expected if isinstance(expected, list) else [expected]
        combine_all = "all" in modifiers
        results = (_match_one(actual, value, modifiers) for value in values)
        if combine_all:
            if not all(results):
                return False
        else:
            if not any(results):
                return False
    return True


def matches(rule: SigmaRule, event: dict[str, Any]) -> bool:
    """True when ``event`` satisfies the rule's logsource and condition."""
    if not logsource_matches(rule.logsource, event):
        return False

    from .condition import evaluate

    matched = {
        name: match_selection(selection, event)
        for name, selection in rule.selections.items()
    }
    return evaluate(rule.ast, matched)
