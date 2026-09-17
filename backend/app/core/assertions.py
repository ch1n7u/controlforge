"""The assertion language: declarative expectations over typed facts.

An assertion never sees tool output. It selects facts by type and optional
field match, then applies one operator. The evaluator (added with the runner)
turns that into PASS / FAIL / INCONCLUSIVE / NOT_APPLICABLE.

Structure
---------
An assertion is a tree. Interior nodes are groups::

    {"all": [<assertion>, ...]}     every child must pass
    {"any": [<assertion>, ...]}     at least one child must pass

Leaf nodes select facts and compare::

    {
      "fact": "http_header",
      "where": {"value.name": "strict-transport-security"},
      "op": "exists",
      "value": ...            # only for operators that compare
      "value_path": "max-age",  # optional; dotted path into the fact's value
      "severity": "high",       # optional; overrides the test's severity
      "reason": "..."           # optional; shown to the operator
    }

``where`` matches fact columns by bare name (``subject``, ``key``) and into the
fact's JSON value by a dotted ``value.`` path. Any other key is rejected, so a
misspelled selector is an error rather than a silently-ignored condition.

Evaluation semantics
--------------------
A leaf first resolves its selection. Operators split into two groups:

* ``not_exists`` and the ``count_*`` operators evaluate the *size* of the
  selection, so an empty selection is a meaningful observation.
* every other operator needs something to compare. An empty selection is
  INCONCLUSIVE - the engine observed nothing, which is not evidence that a
  control is in place. This is the rule that keeps a broken engine from
  producing a green dashboard.

For a non-empty selection the comparison must hold for *every* selected fact;
one dissenting fact fails the assertion. Reasons name the fact that dissented.

Groups combine child results without letting a definite answer be diluted by
an indefinite one:

* ``all``: any FAIL -> FAIL; else any INCONCLUSIVE -> INCONCLUSIVE; all
  NOT_APPLICABLE -> NOT_APPLICABLE; else PASS.
* ``any``: any PASS -> PASS; else any INCONCLUSIVE -> INCONCLUSIVE; all
  NOT_APPLICABLE -> NOT_APPLICABLE; else FAIL.

A test whose assertion references a fact type its engine cannot emit could only
ever be INCONCLUSIVE, so :func:`validate_assertion` refuses it at authoring
time against the engine catalogue.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from app.models.enums import AssertionStatus, Severity

# Operators that inspect the selection itself rather than comparing values.
SELECTION_OPERATORS = frozenset({"exists", "not_exists", "count_eq", "count_gte", "count_lte"})

# Operators that compare a resolved value against ``value``.
COMPARISON_OPERATORS = frozenset(
    {
        "eq",
        "ne",
        "in",
        "not_in",
        "contains",
        "not_contains",
        "matches",
        "not_matches",
        "gt",
        "gte",
        "lt",
        "lte",
    }
)

OPERATORS = SELECTION_OPERATORS | COMPARISON_OPERATORS

GROUP_KEYS = ("all", "any")

MAX_DEPTH = 8
MAX_CHILDREN = 64
MAX_REASON = 500

_COUNT_OPERATOR_TARGETS = {"count_eq": "eq", "count_gte": "gte", "count_lte": "lte"}

_WHERE_COLUMNS = ("subject", "key")
_FACT_FIELD_RE = re.compile(r"^[A-Za-z0-9_.-]{1,160}$")
_PATH_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,160}$")


class AssertionInvalid(ValueError):
    """The assertion is malformed or unsatisfiable for the chosen engine."""


def _check_value_path(path: Any, where: str) -> None:
    if not isinstance(path, str) or not _PATH_RE.match(path):
        raise AssertionInvalid(f"{where}: {path!r} is not a valid dotted value path")


def _check_where(where: Any, where_label: str) -> None:
    if where is None:
        return
    if not isinstance(where, dict):
        raise AssertionInvalid(f"{where_label}: 'where' must be an object")
    for key in where:
        if key in _WHERE_COLUMNS:
            continue
        if key.startswith("value.") and _FACT_FIELD_RE.match(key):
            continue
        raise AssertionInvalid(
            f"{where_label}: selector {key!r} is not one of {', '.join(_WHERE_COLUMNS)} "
            "or a 'value.<field>' path"
        )


def _validate_leaf(node: dict, where_label: str, allowed_facts: frozenset[str]) -> None:
    fact_type = node.get("fact")
    if not isinstance(fact_type, str) or not fact_type:
        raise AssertionInvalid(f"{where_label}: 'fact' must be a non-empty string")

    if allowed_facts and fact_type not in allowed_facts:
        allowed = ", ".join(sorted(allowed_facts)) or "none"
        raise AssertionInvalid(
            f"{where_label}: the selected engine never emits {fact_type!r} facts "
            f"(it emits: {allowed}), so this assertion could only ever be "
            "INCONCLUSIVE"
        )

    op = node.get("op", "exists")
    if op not in OPERATORS:
        raise AssertionInvalid(
            f"{where_label}: unknown operator {op!r} "
            f"(supported: {', '.join(sorted(OPERATORS))})"
        )

    _check_where(node.get("where"), where_label)

    if "value_path" in node:
        _check_value_path(node["value_path"], where_label)

    if op in ("matches", "not_matches"):
        # A pattern that does not compile would make every run INCONCLUSIVE,
        # which is a slow way to learn about a typo.
        pattern = node.get("value")
        if not isinstance(pattern, str):
            raise AssertionInvalid(f"{where_label}: operator {op!r} requires a string 'value'")
        try:
            re.compile(pattern)
        except re.error as exc:
            raise AssertionInvalid(f"{where_label}: invalid regular expression: {exc}") from exc

    if op in COMPARISON_OPERATORS and "value" not in node:
        raise AssertionInvalid(f"{where_label}: operator {op!r} requires a 'value'")
    if op in _COUNT_OPERATOR_TARGETS:
        target = node.get("value")
        if not isinstance(target, int) or isinstance(target, bool) or target < 0:
            raise AssertionInvalid(
                f"{where_label}: operator {op!r} requires a non-negative integer 'value'"
            )

    severity = node.get("severity")
    if severity is not None and severity not in set(Severity):
        raise AssertionInvalid(
            f"{where_label}: unknown severity {severity!r} "
            f"(supported: {', '.join(s.value for s in Severity)})"
        )

    reason = node.get("reason")
    if reason is not None and (not isinstance(reason, str) or len(reason) > MAX_REASON):
        raise AssertionInvalid(
            f"{where_label}: 'reason' must be a string of at most {MAX_REASON} characters"
        )

    unknown = set(node) - {
        "fact",
        "op",
        "where",
        "value",
        "value_path",
        "severity",
        "reason",
    }
    if unknown:
        raise AssertionInvalid(
            f"{where_label}: unknown field(s) {', '.join(sorted(unknown))}"
        )


def validate_assertion(node: Any, allowed_facts: frozenset[str]) -> None:
    """Raise :class:`AssertionInvalid` unless ``node`` is a usable assertion.

    ``allowed_facts`` is the fact-type set of the engine the assertion will run
    against. Pass an empty set to skip that check (used when re-validating a
    stored test whose engine is no longer in the catalogue).
    """

    def walk(current: Any, label: str, depth: int) -> None:
        if depth > MAX_DEPTH:
            raise AssertionInvalid(f"{label}: nested more than {MAX_DEPTH} levels deep")
        if not isinstance(current, dict):
            raise AssertionInvalid(f"{label}: must be an object")

        groups = [key for key in GROUP_KEYS if key in current]
        if groups:
            if len(current) != 1 or len(groups) != 1:
                raise AssertionInvalid(
                    f"{label}: a group takes exactly one of {' / '.join(GROUP_KEYS)} "
                    "and nothing else"
                )
            children = current[groups[0]]
            if not isinstance(children, list) or not children:
                raise AssertionInvalid(f"{label}: group {groups[0]!r} must be a non-empty list")
            if len(children) > MAX_CHILDREN:
                raise AssertionInvalid(
                    f"{label}: group {groups[0]!r} has more than {MAX_CHILDREN} children"
                )
            for index, child in enumerate(children):
                walk(child, f"{label}.{groups[0]}[{index}]", depth + 1)
            return

        if "fact" not in current:
            raise AssertionInvalid(
                f"{label}: expected a '{GROUP_KEYS[0]}' / '{GROUP_KEYS[1]}' group "
                "or a leaf with a 'fact'"
            )
        _validate_leaf(current, label, allowed_facts)

    walk(node, "assertion", 0)


def describe_assertion(node: dict) -> str:
    """One-line human summary, for lists and log lines."""
    if "all" in node:
        return f"all of {len(node['all'])} conditions"
    if "any" in node:
        return f"any of {len(node['any'])} conditions"
    selector = node.get("where") or {}
    target = ", ".join(f"{k}={v}" for k, v in selector.items())
    label = f"{node.get('fact')}"
    if target:
        label = f"{label}[{target}]"
    return f"{label} {node.get('op', 'exists')}"


# ------------------------------------------------------------- evaluation --

# A confidence of exactly zero means the engine tried and could not observe
# anything. Such a fact is a record that the question was asked, not an answer
# to it, and it is kept out of every comparison below.
UNOBSERVED_CONFIDENCE = 0.0

MISSING = object()

_INDEXED = re.compile(r"^([A-Za-z0-9_-]+)(?:\[(\d+)\])?$")


@dataclass(frozen=True, slots=True)
class AssertionOutcome:
    status: AssertionStatus
    reason: str
    severity: Severity
    fact_ids: tuple[int, ...]
    matched: int
    unobserved: int

    @property
    def passed(self) -> bool:
        return self.status is AssertionStatus.PASS


def _resolve(value: Any, path: str) -> Any:
    """Follow a dotted path into a fact's JSON value, or return ``MISSING``."""
    current = value
    for part in path.split("."):
        match = _INDEXED.match(part)
        if not match:
            return MISSING
        if not isinstance(current, dict) or match.group(1) not in current:
            return MISSING
        current = current[match.group(1)]
        if match.group(2) is not None:
            if not isinstance(current, list):
                return MISSING
            index = int(match.group(2))
            if index >= len(current):
                return MISSING
            current = current[index]
    return current


def _matches_where(fact, where: dict) -> bool:
    for selector, expected in where.items():
        if selector == "subject":
            actual = fact.subject
        elif selector == "key":
            actual = fact.key
        else:
            actual = _resolve(fact.value, selector[len("value.") :])
            if actual is MISSING:
                return False
        # A list field matches when it contains the value. Without this,
        # selecting on something like a finding's tags would only ever work if
        # the author knew the exact list.
        if isinstance(actual, list):
            if expected not in actual:
                return False
        elif actual != expected:
            return False
    return True


def _as_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _compare(op: str, observed: Any, expected: Any) -> bool | None:
    """Compare one value. ``None`` means the comparison could not be made.

    "Could not be made" is not the same as False: a missing field, a field that
    holds no value, or a non-numeric operand leaves the question open, and the
    caller turns that into INCONCLUSIVE rather than into a failure or a pass.
    """
    if observed is MISSING:
        return None
    if observed is None and expected is not None:
        # A null field is a fact declining to state a value: an unset sshd
        # keyword whose effective default the engine cannot read, an absent
        # attribute that was not modelled as a definite absence. Compared as a
        # distinct value it would fail ``eq`` and - worse - satisfy ``ne`` or
        # ``not_in``, so an assertion like "SameSite is Lax or Strict" could
        # pass on a cookie that carries no SameSite at all. Asking whether the
        # field is null still works.
        return None
    if op == "eq":
        return observed == expected
    if op == "ne":
        return observed != expected
    if op in ("in", "not_in"):
        if not isinstance(expected, list):
            return None
        inside = any(observed == item for item in expected)
        return inside if op == "in" else not inside
    if op in ("contains", "not_contains"):
        if isinstance(observed, str) and isinstance(expected, str):
            inside = expected in observed
        elif isinstance(observed, list):
            inside = expected in observed
        else:
            return None
        return inside if op == "contains" else not inside
    if op in ("matches", "not_matches"):
        if not isinstance(expected, str):
            return None
        subject = observed if isinstance(observed, str) else str(observed)
        try:
            found = re.search(expected, subject) is not None
        except re.error:
            return None
        return found if op == "matches" else not found
    if op in ("gt", "gte", "lt", "lte"):
        left, right = _as_number(observed), _as_number(expected)
        if left is None or right is None:
            return None
        if op == "gt":
            return left > right
        if op == "gte":
            return left >= right
        if op == "lt":
            return left < right
        return left <= right
    return None


def _fact_label(fact) -> str:
    return f"{fact.fact_type}[{fact.key or fact.subject or '?'}]"


def _show(value: Any, limit: int = 60) -> str:
    text = repr(value)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _leaf_outcome(node: dict, facts: list, default_severity: Severity) -> AssertionOutcome:
    op = node.get("op", "exists")
    where = node.get("where") or {}
    severity = Severity(node["severity"]) if node.get("severity") else default_severity
    note = node.get("reason")

    selected = [f for f in facts if f.fact_type == node["fact"] and _matches_where(f, where)]
    observed = [f for f in selected if getattr(f, "confidence", 1.0) > UNOBSERVED_CONFIDENCE]
    unobserved = [f for f in selected if getattr(f, "confidence", 1.0) <= UNOBSERVED_CONFIDENCE]

    ids = tuple(fid for fid in (getattr(f, "id", None) for f in observed) if fid is not None)
    matched, blind = len(observed), len(unobserved)

    def outcome(status: AssertionStatus, reason: str) -> AssertionOutcome:
        text = f"{note}: {reason}" if note and status is not AssertionStatus.PASS else (note or reason)
        return AssertionOutcome(status, text[:MAX_REASON], severity, ids, matched, blind)

    selector = (
        f"{node['fact']} facts"
        if not where
        else f"{node['fact']} facts matching {', '.join(f'{k}={v!r}' for k, v in where.items())}"
    )

    if op in ("exists", "not_exists"):
        if observed:
            if op == "exists":
                return outcome(AssertionStatus.PASS, f"{_fact_label(observed[0])} was observed")
            return outcome(
                AssertionStatus.FAIL,
                f"{selector} matched {_fact_label(observed[0])}, which should not be present",
            )
        if blind:
            return outcome(
                AssertionStatus.INCONCLUSIVE,
                f"{selector} matched {blind} fact(s) that could not be observed",
            )
        if op == "exists":
            return outcome(AssertionStatus.FAIL, f"{selector} matched nothing")
        return outcome(AssertionStatus.PASS, f"{selector} matched nothing, as expected")

    if op in _COUNT_OPERATOR_TARGETS:
        expected = node["value"]
        counted = matched
        if op == "count_eq":
            if counted == expected and not blind:
                return outcome(AssertionStatus.PASS, f"{counted} matching fact(s), as expected")
            if counted > expected:
                return outcome(AssertionStatus.FAIL, f"{counted} matching fact(s), expected {expected}")
            if blind:
                return outcome(
                    AssertionStatus.INCONCLUSIVE,
                    f"{counted} observed of {counted + blind} matching fact(s), expected {expected}",
                )
            return outcome(AssertionStatus.FAIL, f"{counted} matching fact(s), expected {expected}")
        if op == "count_gte":
            # A lower bound that is already met cannot be lowered by anything
            # that was not observed.
            if counted >= expected:
                return outcome(AssertionStatus.PASS, f"{counted} matching fact(s), at least {expected} expected")
            if blind:
                return outcome(
                    AssertionStatus.INCONCLUSIVE,
                    f"{counted} observed of {counted + blind} matching fact(s), at least {expected} expected",
                )
            return outcome(AssertionStatus.FAIL, f"{counted} matching fact(s), at least {expected} expected")
        # count_lte
        if counted > expected:
            return outcome(AssertionStatus.FAIL, f"{counted} matching fact(s), at most {expected} expected")
        if blind:
            return outcome(
                AssertionStatus.INCONCLUSIVE,
                f"{counted} observed of {counted + blind} matching fact(s), at most {expected} expected",
            )
        return outcome(AssertionStatus.PASS, f"{counted} matching fact(s), at most {expected} expected")

    # Comparison operators.
    if not observed:
        if blind:
            return outcome(
                AssertionStatus.INCONCLUSIVE,
                f"{selector} matched {blind} fact(s) that could not be observed",
            )
        return outcome(AssertionStatus.INCONCLUSIVE, f"{selector} matched nothing to compare")

    value_path = node.get("value_path")
    expected = node.get("value")
    dissenters: list[str] = []
    incomparable: list[str] = []

    for fact in observed:
        actual = _resolve(fact.value, value_path) if value_path else fact.value
        verdict = _compare(op, actual, expected)
        if verdict is None:
            incomparable.append(f"{_fact_label(fact)}={_show(actual)}")
        elif not verdict:
            shown = f"{value_path}={_show(actual)}" if value_path else _show(actual)
            dissenters.append(f"{_fact_label(fact)} ({shown})")

    if dissenters:
        # A definite observation of a violation outranks anything that could
        # not be read: one fact that dissents decides the assertion.
        detail = ", ".join(dissenters[:3])
        if len(dissenters) > 3:
            detail += f", and {len(dissenters) - 3} more"
        return outcome(
            AssertionStatus.FAIL,
            f"{len(dissenters)} of {matched} matching fact(s) failed "
            f"{op} {_show(expected)}: {detail}",
        )
    if incomparable:
        detail = ", ".join(incomparable[:3])
        return outcome(
            AssertionStatus.INCONCLUSIVE,
            f"could not compare {op} {_show(expected)} against {detail}",
        )
    if blind:
        return outcome(
            AssertionStatus.INCONCLUSIVE,
            f"{matched} fact(s) satisfied {op} {_show(expected)}, but {blind} could not be observed",
        )
    return outcome(
        AssertionStatus.PASS,
        f"all {matched} matching fact(s) satisfied {op} {_show(expected)}",
    )


def evaluate(
    node: dict,
    facts: list,
    *,
    default_severity: Severity = Severity.MEDIUM,
) -> AssertionOutcome:
    """Evaluate an assertion against one run's facts.

    ``facts`` may be ORM rows or engine ``FactDraft`` objects - anything with
    ``fact_type``, ``subject``, ``key``, ``value`` and ``confidence``.
    """
    if "all" in node or "any" in node:
        key = "all" if "all" in node else "any"
        children = [evaluate(child, facts, default_severity=default_severity) for child in node[key]]
        statuses = [child.status for child in children]

        if key == "all":
            if AssertionStatus.FAIL in statuses:
                chosen = next(c for c in children if c.status is AssertionStatus.FAIL)
                status = AssertionStatus.FAIL
            elif AssertionStatus.INCONCLUSIVE in statuses:
                chosen = next(c for c in children if c.status is AssertionStatus.INCONCLUSIVE)
                status = AssertionStatus.INCONCLUSIVE
            elif all(s is AssertionStatus.NOT_APPLICABLE for s in statuses):
                chosen = children[0]
                status = AssertionStatus.NOT_APPLICABLE
            else:
                chosen = next(c for c in children if c.status is AssertionStatus.PASS)
                status = AssertionStatus.PASS
            reason = f"all of {len(children)}: {chosen.reason}"
        else:
            if AssertionStatus.PASS in statuses:
                chosen = next(c for c in children if c.status is AssertionStatus.PASS)
                status = AssertionStatus.PASS
            elif AssertionStatus.INCONCLUSIVE in statuses:
                chosen = next(c for c in children if c.status is AssertionStatus.INCONCLUSIVE)
                status = AssertionStatus.INCONCLUSIVE
            elif all(s is AssertionStatus.NOT_APPLICABLE for s in statuses):
                chosen = children[0]
                status = AssertionStatus.NOT_APPLICABLE
            else:
                chosen = next(c for c in children if c.status is AssertionStatus.FAIL)
                status = AssertionStatus.FAIL
            reason = f"any of {len(children)}: {chosen.reason}"

        return AssertionOutcome(
            status=status,
            reason=reason[:MAX_REASON],
            severity=default_severity,
            fact_ids=tuple(fid for child in children for fid in child.fact_ids),
            matched=sum(child.matched for child in children),
            unobserved=sum(child.unobserved for child in children),
        )

    return _leaf_outcome(node, facts, default_severity)
