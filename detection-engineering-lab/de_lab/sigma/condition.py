"""A parser and evaluator for the subset of Sigma's ``condition`` grammar.

Supported
---------
* ``and``, ``or``, ``not`` with the documented precedence (``not`` > ``and`` > ``or``)
* parentheses
* ``all of them`` / ``any of them`` / ``1 of them`` / ``N of them``
* ``all of selection_*`` / ``1 of selection_*`` (glob over selection names)

Anything outside that subset raises :class:`ConditionError` at compile time.
Refusing to parse is deliberate: a silently mis-parsed condition produces a rule
that looks healthy and never fires, which is the worst possible failure mode for
a detection.
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass
from typing import Any, Iterable

KEYWORDS = {"and", "or", "not", "of", "all", "any", "them"}


class ConditionError(ValueError):
    def __init__(self, message: str, position: int = 0) -> None:
        super().__init__(f"{message} (at position {position})")
        self.position = position


@dataclass(frozen=True)
class Token:
    kind: str
    value: Any
    position: int


def tokenize(source: str) -> list[Token]:
    tokens: list[Token] = []
    index, length = 0, len(source)

    while index < length:
        char = source[index]

        if char.isspace():
            index += 1
            continue

        if char in "()":
            tokens.append(Token(char, char, index))
            index += 1
            continue

        if char.isdigit():
            end = index
            while end < length and source[end].isdigit():
                end += 1
            tokens.append(Token("INT", int(source[index:end]), index))
            index = end
            continue

        if char.isalpha() or char == "_":
            end = index
            while end < length and (source[end].isalnum() or source[end] in "_.*-"):
                end += 1
            word = source[index:end]
            lowered = word.lower()
            if lowered in KEYWORDS:
                tokens.append(Token(lowered.upper(), lowered, index))
            else:
                tokens.append(Token("IDENT", word, index))
            index = end
            continue

        raise ConditionError(f"unexpected character {char!r}", index)

    return tokens


class _Parser:
    def __init__(self, tokens: list[Token], selection_names: Iterable[str]) -> None:
        self.tokens = tokens
        self.position = 0
        self.selection_names = list(selection_names)

    # ---------------------------------------------------------------- helpers
    def peek(self) -> Token | None:
        return self.tokens[self.position] if self.position < len(self.tokens) else None

    def take(self) -> Token:
        token = self.peek()
        if token is None:
            raise ConditionError("unexpected end of condition", self._end_position())
        self.position += 1
        return token

    def expect(self, kind: str) -> Token:
        token = self.take()
        if token.kind != kind:
            raise ConditionError(f"expected {kind}, found {token.kind}", token.position)
        return token

    def _end_position(self) -> int:
        return self.tokens[-1].position if self.tokens else 0

    # ----------------------------------------------------------------- grammar
    def parse(self) -> Any:
        if not self.tokens:
            raise ConditionError("empty condition")
        node = self.parse_or()
        if self.peek() is not None:
            token = self.peek()
            raise ConditionError(f"unexpected trailing token {token.value!r}", token.position)  # type: ignore[union-attr]
        return node

    def parse_or(self) -> Any:
        node = self.parse_and()
        while self.peek() is not None and self.peek().kind == "OR":  # type: ignore[union-attr]
            self.take()
            node = ("or", node, self.parse_and())
        return node

    def parse_and(self) -> Any:
        node = self.parse_not()
        while self.peek() is not None and self.peek().kind == "AND":  # type: ignore[union-attr]
            self.take()
            node = ("and", node, self.parse_not())
        return node

    def parse_not(self) -> Any:
        token = self.peek()
        if token is not None and token.kind == "NOT":
            self.take()
            return ("not", self.parse_not())
        return self.parse_primary()

    def parse_primary(self) -> Any:
        token = self.take()

        if token.kind == "(":
            node = self.parse_or()
            self.expect(")")
            return node

        if token.kind == "INT":
            self.expect("OF")
            return self.parse_quantified(token.value)

        if token.kind in ("ALL", "ANY"):
            self.expect("OF")
            return self.parse_quantified(token.value)

        if token.kind == "IDENT":
            if token.value not in self.selection_names:
                raise ConditionError(
                    f"condition references unknown selection {token.value!r}", token.position
                )
            return ("sel", token.value)

        raise ConditionError(f"unexpected token {token.value!r}", token.position)

    def parse_quantified(self, quantifier: int | str) -> Any:
        target = self.take()
        if target.kind not in ("THEM", "IDENT"):
            raise ConditionError(
                f"expected 'them' or a selection pattern, found {target.value!r}",
                target.position,
            )

        if target.kind == "THEM":
            names = list(self.selection_names)
        else:
            names = [name for name in self.selection_names if fnmatch.fnmatchcase(name, target.value)]

        if not names:
            raise ConditionError(
                f"quantified reference {target.value!r} matches no selection", target.position
            )

        quantity = "all" if quantifier == "all" else (1 if quantifier == "any" else quantifier)
        return ("of", quantity, tuple(names))


def compile_condition(source: str, selection_names: Iterable[str]) -> Any:
    """Tokenise, parse and return an AST for ``source``."""
    return _Parser(tokenize(source), selection_names).parse()


def evaluate(node: Any, matched: dict[str, bool]) -> bool:
    """Evaluate a compiled AST against ``{selection_name: matched}``."""
    kind = node[0]

    if kind == "sel":
        return bool(matched.get(node[1], False))

    if kind == "not":
        return not evaluate(node[1], matched)

    if kind == "and":
        return evaluate(node[1], matched) and evaluate(node[2], matched)

    if kind == "or":
        return evaluate(node[1], matched) or evaluate(node[2], matched)

    if kind == "of":
        quantity, names = node[1], node[2]
        hits = sum(1 for name in names if matched.get(name, False))
        if quantity == "all":
            return hits == len(names)
        return hits >= int(quantity)

    raise ConditionError(f"unknown AST node {kind!r}")  # pragma: no cover


def referenced_selections(node: Any) -> set[str]:
    """Every selection name a compiled condition can consult."""
    kind = node[0]
    if kind == "sel":
        return {node[1]}
    if kind == "not":
        return referenced_selections(node[1])
    if kind in ("and", "or"):
        return referenced_selections(node[1]) | referenced_selections(node[2])
    if kind == "of":
        return set(node[2])
    return set()  # pragma: no cover
