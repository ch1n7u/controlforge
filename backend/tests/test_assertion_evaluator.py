"""The evaluator: turning facts into PASS, FAIL, INCONCLUSIVE or NOT_APPLICABLE.

This is where the platform's credibility lives. Every test here is a case where
a simpler evaluator would have produced a green dashboard from a question that
was never actually answered - an engine that observed nothing, a field that was
absent, a tool that reported it could not read the result.
"""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from app.core.assertions import MISSING, AssertionOutcome, _compare, _resolve, evaluate
from app.models.enums import AssertionStatus, Severity


@dataclass
class FakeFact:
    fact_type: str
    key: str = "k"
    subject: str = "lab.local"
    value: dict | None = None
    confidence: float = 1.0
    id: int | None = None

    def __post_init__(self):
        if self.value is None:
            self.value = {}


def header(name: str, present: bool = True, *, confidence: float = 1.0, fact_id: int | None = None, **extra) -> FakeFact:
    return FakeFact(
        fact_type="http_header",
        key=f"header:{name}",
        value={"name": name, "present": present, **extra},
        confidence=confidence,
        id=fact_id,
    )


def status(node, facts, severity=Severity.MEDIUM) -> AssertionStatus:
    return evaluate(node, facts, default_severity=severity).status


# --------------------------------------------------------------- selection --


def test_exists_passes_when_the_thing_was_observed():
    facts = [header("strict-transport-security")]
    assert (
        status(
            {"fact": "http_header", "where": {"value.name": "strict-transport-security"}, "op": "exists"},
            facts,
        )
        is AssertionStatus.PASS
    )


def test_exists_fails_when_the_selection_is_empty():
    """No header observed at all is a real answer: the header is not there."""
    assert status({"fact": "http_header", "op": "exists"}, []) is AssertionStatus.FAIL


def test_not_exists_passes_on_an_empty_selection():
    assert status({"fact": "http_header", "op": "not_exists"}, []) is AssertionStatus.PASS


def test_not_exists_fails_when_the_thing_is_present():
    facts = [header("server")]
    assert status({"fact": "http_header", "op": "not_exists"}, facts) is AssertionStatus.FAIL


def test_a_selector_over_another_fact_type_is_not_a_match():
    facts = [header("server")]
    assert (
        status({"fact": "http_cookie", "op": "exists"}, facts) is AssertionStatus.FAIL
    )


def test_a_list_field_matches_when_it_contains_the_value():
    facts = [
        FakeFact(
            fact_type="nuclei_finding",
            value={"template_id": "x", "tags": ["exposure", "cve"]},
        )
    ]
    node = {"fact": "nuclei_finding", "where": {"value.tags": "exposure"}, "op": "exists"}
    assert status(node, facts) is AssertionStatus.PASS


# ------------------------------------------------------- unobserved facts --


def test_a_fact_that_could_not_be_observed_makes_exists_inconclusive():
    """The engine asked the question and could not get an answer.

    Reporting that as PASS would be the single worst failure this platform
    could have, so it must not happen.
    """
    facts = [header("strict-transport-security", confidence=0.0)]
    node = {"fact": "http_header", "where": {"value.name": "strict-transport-security"}, "op": "exists"}
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.INCONCLUSIVE
    assert "could not be observed" in outcome.reason
    assert outcome.unobserved == 1
    assert outcome.fact_ids == ()


def test_a_fact_that_could_not_be_observed_does_not_satisfy_not_exists_either():
    facts = [header("server", confidence=0.0)]
    assert status({"fact": "http_header", "op": "not_exists"}, facts) is AssertionStatus.INCONCLUSIVE


def test_a_comparison_that_could_not_be_observed_is_inconclusive():
    facts = [FakeFact(fact_type="tls_vulnerability", key="heartbleed", value={"vulnerable": None}, confidence=0.0)]
    node = {"fact": "tls_vulnerability", "op": "eq", "value_path": "vulnerable", "value": False}
    assert status(node, facts) is AssertionStatus.INCONCLUSIVE


def test_a_definite_failure_outranks_an_unobserved_fact():
    """One observed violation decides it; uncertainty must not dilute it."""
    facts = [
        header("x-frame-options", present=False),
        header("x-content-type-options", confidence=0.0),
    ]
    node = {"fact": "http_header", "op": "eq", "value_path": "present", "value": True}
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.FAIL
    assert "failed eq" in outcome.reason
    assert outcome.fact_ids == ()  # the unobserved fact contributes no evidence


# ------------------------------------------------------------- comparisons --


def test_every_selected_fact_must_satisfy_the_comparison():
    facts = [header("a", present=True), header("b", present=False)]
    node = {"fact": "http_header", "op": "eq", "value_path": "present", "value": True}
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.FAIL
    assert "header:b" in outcome.reason


def test_a_dissenting_fact_is_named_in_the_reason():
    facts = [header("x-frame-options", present=False)]
    node = {"fact": "http_header", "op": "eq", "value_path": "present", "value": True}
    assert "x-frame-options" in evaluate(node, facts).reason


def test_comparing_a_field_that_is_not_there_is_inconclusive_not_a_failure():
    facts = [FakeFact(fact_type="port_state", value={"port": 22})]
    node = {"fact": "port_state", "op": "eq", "value_path": "open", "value": True}
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.INCONCLUSIVE
    assert "could not compare" in outcome.reason


def test_comparing_a_non_numeric_operand_is_inconclusive():
    facts = [FakeFact(fact_type="file_mode", value={"mode": "0750"})]
    node = {"fact": "file_mode", "op": "lte", "value_path": "mode_bits", "value": 0o750}
    assert status(node, facts) is AssertionStatus.INCONCLUSIVE


@pytest.mark.parametrize(
    ("op", "observed", "expected", "verdict"),
    [
        ("eq", "tls1_2", "tls1_2", True),
        ("ne", "tls1_2", "tls1_0", True),
        ("in", "high", ["low", "medium", "high"], True),
        ("not_in", "info", ["high", "critical"], True),
        ("contains", "max-age=31536000", "max-age", True),
        ("not_contains", "max-age=31536000", "includeSubDomains", True),
        ("matches", "TLSv1.3", r"^TLSv1\.[23]$", True),
        ("not_matches", "TLSv1.0", r"^TLSv1\.[23]$", True),
        ("gt", 3, 2, True),
        ("gte", 2048, 2048, True),
        ("lt", 100, 90, False),
        ("lte", 4, 4, True),
    ],
)
def test_the_comparison_operators(op, observed, expected, verdict):
    assert _compare(op, observed, expected) is verdict


def test_in_with_a_non_list_is_not_comparable():
    assert _compare("in", "x", "not-a-list") is None


def test_a_missing_operand_is_not_comparable():
    assert _compare("eq", MISSING, "anything") is None


def test_a_null_field_is_not_comparable_rather_than_a_value():
    """A fact that reports a field as null has said nothing about it. Read as a
    value it would fail every ``eq`` and satisfy every ``ne``/``not_in``: the
    assertion "SameSite is strict or lax" would pass on a cookie with no
    SameSite at all, which is the weakness the control exists to catch."""
    for op, expected in (
        ("eq", True),
        ("ne", True),
        ("in", ["strict", "lax"]),
        ("not_in", ["none"]),
        ("contains", "lax"),
        ("not_contains", "lax"),
        ("gte", 1),
    ):
        assert _compare(op, None, expected) is None, op


def test_asking_whether_a_field_is_null_still_answers():
    assert _compare("eq", None, None) is True
    assert _compare("ne", None, None) is False


def test_a_null_field_leaves_the_assertion_inconclusive_not_failed():
    fact = FakeFact(
        fact_type="http_cookie",
        key="session",
        value={"name": "session", "samesite": None},
    )
    node = {
        "fact": "http_cookie",
        "where": {"key": "session"},
        "op": "in",
        "value_path": "samesite",
        "value": ["strict", "lax"],
    }
    outcome = evaluate(node, [fact])
    assert outcome.status is AssertionStatus.INCONCLUSIVE
    assert "could not compare" in outcome.reason


def test_an_observed_absence_is_decided_not_left_open():
    """The counterpart of the rule above: an engine that reports an absence as a
    definite value (``samesite: false``) gets a verdict, not an inconclusive."""
    fact = FakeFact(
        fact_type="http_cookie",
        key="session",
        value={"name": "session", "samesite": False},
    )
    node = {
        "fact": "http_cookie",
        "where": {"key": "session"},
        "op": "in",
        "value_path": "samesite",
        "value": ["strict", "lax"],
    }
    assert evaluate(node, [fact]).status is AssertionStatus.FAIL


# ------------------------------------------------------------------ paths --


def test_a_dotted_path_reaches_into_nested_values():
    assert _resolve({"cert": {"bits": 2048}}, "cert.bits") == 2048


def test_an_indexed_path_reaches_into_lists():
    assert _resolve({"tags": ["a", "b"]}, "tags[1]") == "b"


def test_an_absent_path_is_missing():
    assert _resolve({"a": 1}, "b") is MISSING
    assert _resolve({"tags": []}, "tags[0]") is MISSING
    assert _resolve({"a": "not-a-dict"}, "a.b") is MISSING


# ----------------------------------------------------------------- counts --


def test_count_eq_matches_the_size_of_the_selection():
    facts = [FakeFact(fact_type="path_exposed", key=f"p{i}") for i in range(3)]
    node = {"fact": "path_exposed", "op": "count_eq", "value": 3}
    assert status(node, facts) is AssertionStatus.PASS


def test_count_eq_fails_when_there_are_more_than_expected():
    """Three exposed paths is not "two exposed paths"."""
    facts = [FakeFact(fact_type="path_exposed", key=f"p{i}") for i in range(3)]
    node = {"fact": "path_exposed", "op": "count_eq", "value": 2}
    assert status(node, facts) is AssertionStatus.FAIL


def test_count_lte_fails_when_the_count_is_definitely_over():
    facts = [FakeFact(fact_type="path_exposed", key=f"p{i}") for i in range(3)]
    node = {"fact": "path_exposed", "op": "count_lte", "value": 2}
    assert status(node, facts) is AssertionStatus.FAIL


def test_count_gte_passes_on_a_lower_bound_that_is_already_met():
    """Unobserved facts could only make the count larger, so the bound holds."""
    facts = [
        FakeFact(fact_type="port_state", key="tcp/22", value={"open": True}),
        FakeFact(fact_type="port_state", key="tcp/80", value={"open": True}, confidence=0.0),
    ]
    node = {"fact": "port_state", "op": "count_gte", "value": 1}
    assert status(node, facts) is AssertionStatus.PASS


def test_count_lte_becomes_inconclusive_when_facts_could_not_be_observed():
    """An upper bound is exactly the claim an unobserved fact could break."""
    facts = [
        FakeFact(fact_type="path_exposed", key="p1"),
        FakeFact(fact_type="path_exposed", key="p2", confidence=0.0),
    ]
    node = {"fact": "path_exposed", "op": "count_lte", "value": 1}
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.INCONCLUSIVE
    assert "1 observed of 2" in outcome.reason


def test_count_eq_with_nothing_selected_fails():
    assert status({"fact": "path_exposed", "op": "count_eq", "value": 0}, []) is AssertionStatus.PASS
    assert status({"fact": "path_exposed", "op": "count_eq", "value": 1}, []) is AssertionStatus.FAIL


# ----------------------------------------------------------------- groups --


def test_all_fails_if_any_child_fails():
    facts = [header("a")]
    node = {
        "all": [
            {"fact": "http_header", "where": {"value.name": "a"}, "op": "exists"},
            {"fact": "http_header", "where": {"value.name": "b"}, "op": "exists"},
        ]
    }
    outcome = evaluate(node, facts)
    assert outcome.status is AssertionStatus.FAIL
    assert outcome.reason.startswith("all of 2")


def test_all_is_inconclusive_when_a_child_is_inconclusive_and_none_failed():
    facts = [header("a", confidence=0.0)]
    node = {
        "all": [
            {"fact": "http_header", "where": {"value.name": "a"}, "op": "exists"},
            {"fact": "http_header", "op": "not_exists", "where": {"value.name": "z"}},
        ]
    }
    assert evaluate(node, facts).status is AssertionStatus.INCONCLUSIVE


def test_all_lets_a_definite_failure_outrank_an_inconclusive_child():
    facts = [header("a", present=False), header("b", confidence=0.0)]
    node = {
        "all": [
            {"fact": "http_header", "where": {"value.name": "b"}, "op": "exists"},
            {"fact": "http_header", "where": {"value.name": "a"}, "op": "eq", "value_path": "present", "value": True},
        ]
    }
    assert evaluate(node, facts).status is AssertionStatus.FAIL


def test_any_passes_on_the_first_child_that_passes():
    facts = [header("b")]
    node = {
        "any": [
            {"fact": "http_header", "where": {"value.name": "a"}, "op": "exists"},
            {"fact": "http_header", "where": {"value.name": "b"}, "op": "exists"},
        ]
    }
    assert evaluate(node, facts).status is AssertionStatus.PASS


def test_any_does_not_pass_on_an_inconclusive_child_alone():
    """Nothing was established, so nothing may be reported as satisfied."""
    facts = [header("a", confidence=0.0)]
    node = {"any": [{"fact": "http_header", "where": {"value.name": "a"}, "op": "exists"}]}
    assert evaluate(node, facts).status is AssertionStatus.INCONCLUSIVE


def test_a_group_with_no_children_to_evaluate_is_not_a_pass():
    facts = []
    node = {"any": [{"fact": "http_header", "op": "exists"}]}
    assert evaluate(node, facts).status is AssertionStatus.FAIL


# ------------------------------------------------------- severity & reasons --


def test_a_leaf_severity_overrides_the_default():
    node = {"fact": "http_header", "op": "exists", "severity": "critical"}
    assert evaluate(node, [header("a")]).severity is Severity.CRITICAL


def test_the_default_severity_is_used_when_the_leaf_has_none():
    out = evaluate({"fact": "http_header", "op": "exists"}, [header("a")], default_severity=Severity.LOW)
    assert out.severity is Severity.LOW


def test_the_authors_reason_is_carried_into_the_outcome():
    node = {"fact": "http_header", "op": "exists", "reason": "HSTS must be set on every response"}
    out = evaluate(node, [header("a")])
    assert out.reason.startswith("HSTS must be set on every response")


def test_a_failure_reason_keeps_both_the_intent_and_the_dissent():
    node = {
        "fact": "http_header",
        "where": {"value.name": "a"},
        "op": "eq",
        "value_path": "present",
        "value": True,
        "reason": "the header must be present",
    }
    out = evaluate(node, [header("a", present=False)])
    assert "the header must be present" in out.reason
    assert "failed" in out.reason


def test_an_outcome_records_the_facts_it_used_as_evidence():
    facts = [header("a", fact_id=11), header("b", fact_id=12, confidence=0.0)]
    out = evaluate({"fact": "http_header", "op": "exists"}, facts)
    assert out.fact_ids == (11,)
    assert out.matched == 1 and out.unobserved == 1


def test_reasons_are_bounded():
    facts = [header(f"h{i}", present=False) for i in range(20)]
    node = {"fact": "http_header", "op": "eq", "value_path": "present", "value": True}
    out = evaluate(node, facts)
    assert out.status is AssertionStatus.FAIL
    assert len(out.reason) <= 500
    assert "and 17 more" in out.reason


def test_evaluating_an_unsatisfiable_selector_never_passes():
    """A selector that matches nothing must not be silently treated as fine."""
    for op in ("exists", "eq"):
        node = {"fact": "nothing_like_this", "op": op, "where": {"value.x": 1}}
        if op == "eq":
            node["value"] = 1
            node["value_path"] = "x"
        assert status(node, [header("a")]) is not AssertionStatus.PASS


def test_the_outcome_is_immutable():
    out = evaluate({"fact": "http_header", "op": "exists"}, [header("a")])
    with pytest.raises(Exception):
        out.status = AssertionStatus.FAIL  # type: ignore[misc]
    assert isinstance(out, AssertionOutcome)
