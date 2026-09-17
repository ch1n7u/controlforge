"""The assertion validator.

A validation test is only as good as its assertion. These tests are mostly
about refusals: the interesting failure is a test that looks fine in the editor
and can only ever come back INCONCLUSIVE, or one whose typo silently drops a
condition and turns a strict test into a lenient one.
"""

from __future__ import annotations

import pytest

from app.core.assertions import (
    MAX_CHILDREN,
    MAX_DEPTH,
    OPERATORS,
    AssertionInvalid,
    describe_assertion,
    validate_assertion,
)

HEADER_FACTS = frozenset({"http_header", "http_response", "http_cookie"})


def ok(node, facts=HEADER_FACTS) -> None:
    validate_assertion(node, facts)


def refused(node, facts=HEADER_FACTS, contains: str | None = None) -> None:
    with pytest.raises(AssertionInvalid) as excinfo:
        validate_assertion(node, facts)
    if contains:
        assert contains in str(excinfo.value), str(excinfo.value)


# ------------------------------------------------------------------ accepted --


def test_a_minimal_leaf_is_valid():
    ok({"fact": "http_header"})


def test_the_operator_defaults_to_exists():
    """Omitting the operator must not mean 'no condition' - it means presence."""
    ok({"fact": "http_header", "where": {"value.name": "strict-transport-security"}})


@pytest.mark.parametrize("op", sorted(OPERATORS))
def test_every_advertised_operator_is_accepted(op):
    node = {"fact": "http_header", "op": op}
    if op in {"count_eq", "count_gte", "count_lte"}:
        node["value"] = 1
    elif op not in {"exists", "not_exists"}:
        node["value"] = "x"
    ok(node)


def test_groups_nest():
    ok(
        {
            "all": [
                {"any": [{"fact": "http_header"}, {"fact": "http_cookie"}]},
                {
                    "all": [
                        {"fact": "http_response", "op": "eq", "value": 200},
                    ]
                },
            ]
        }
    )


def test_bare_value_selector_paths_are_accepted():
    ok({"fact": "http_cookie", "where": {"value.name": "session", "value.secure": False}})


def test_column_selectors_are_accepted():
    ok({"fact": "http_header", "where": {"key": "server", "subject": "example.test"}})


def test_an_empty_allowed_set_skips_the_fact_type_check():
    """Stored tests are re-validated when their engine leaves the catalogue."""
    ok({"fact": "some_retired_fact_type"}, facts=frozenset())


# ------------------------------------------------------------------- refused --


def test_a_fact_type_the_engine_cannot_emit_is_refused_with_the_real_options():
    refused(
        {"fact": "port_state"},
        contains="the selected engine never emits 'port_state' facts",
    )
    refused({"fact": "port_state"})  # the message must name what it does emit


def test_the_fact_type_refusal_lists_what_the_engine_does_emit():
    with pytest.raises(AssertionInvalid) as excinfo:
        validate_assertion({"fact": "nuclei_finding"}, HEADER_FACTS)
    message = str(excinfo.value)
    assert "http_header" in message and "http_cookie" in message


def test_an_unknown_operator_is_refused():
    refused({"fact": "http_header", "op": "equals"}, contains="unknown operator")


def test_a_comparison_without_a_value_is_refused():
    refused({"fact": "http_response", "op": "eq"}, contains="requires a 'value'")
    refused({"fact": "http_header", "op": "matches"}, contains="requires a string 'value'")


def test_a_pattern_that_does_not_compile_is_refused_at_authoring_time():
    """Otherwise every run silently comes back INCONCLUSIVE."""
    refused({"fact": "http_header", "op": "matches", "value": "([unclosed"}, contains="invalid regular expression")
    refused({"fact": "http_header", "op": "not_matches", "value": r"a{2,1}"}, contains="invalid regular expression")


def test_exists_and_not_exists_take_no_value():
    ok({"fact": "http_header", "op": "exists"})
    ok({"fact": "http_header", "op": "not_exists"})


@pytest.mark.parametrize("bad", ["2", -1, 1.5, True, None])
def test_count_operators_require_a_non_negative_integer(bad):
    refused({"fact": "http_header", "op": "count_eq", "value": bad})


def test_count_zero_is_accepted():
    ok({"fact": "http_header", "op": "count_eq", "value": 0})


def test_an_unknown_where_selector_is_refused():
    """A typo'd selector must be an error, not a condition that never matches."""
    refused(
        {"fact": "http_header", "where": {"nmae": "x"}},
        contains="is not one of subject, key",
    )


def test_a_bare_value_key_in_where_is_refused():
    refused({"fact": "http_header", "where": {"value": "x"}}, contains="value.<field>")


def test_a_bad_value_path_is_refused():
    refused({"fact": "http_header", "value_path": "!!"}, contains="dotted value path")


def test_an_unknown_leaf_field_is_refused():
    """extra fields are rejected so a misspelled condition cannot be dropped."""
    refused({"fact": "http_header", "operator": "eq", "value": 1}, contains="unknown field")


def test_an_unknown_severity_is_refused():
    refused({"fact": "http_header", "severity": "urgent"}, contains="unknown severity")


@pytest.mark.parametrize("severity", ["info", "low", "medium", "high", "critical"])
def test_every_real_severity_is_accepted(severity):
    ok({"fact": "http_header", "severity": severity})


def test_an_overlong_reason_is_refused():
    refused({"fact": "http_header", "reason": "x" * 501}, contains="reason")


def test_a_group_taking_both_all_and_any_is_refused():
    refused({"all": [{"fact": "http_header"}], "any": [{"fact": "http_header"}]})


def test_a_group_with_a_sibling_key_is_refused():
    refused({"all": [{"fact": "http_header"}], "note": "hi"}, contains="and nothing else")


def test_an_empty_group_is_refused():
    refused({"all": []}, contains="non-empty list")
    refused({"any": []}, contains="non-empty list")


def test_a_group_over_the_child_limit_is_refused():
    refused(
        {"all": [{"fact": "http_header"}] * (MAX_CHILDREN + 1)},
        contains="more than",
    )


def test_nesting_deeper_than_the_limit_is_refused():
    node = {"fact": "http_header"}
    for _ in range(MAX_DEPTH + 1):
        node = {"all": [node]}
    refused(node, contains="levels deep")


def test_a_non_object_node_is_refused():
    refused(["fact", "http_header"], contains="must be an object")
    refused("http_header", contains="must be an object")


def test_a_node_with_neither_group_nor_fact_is_refused():
    refused({"where": {"key": "server"}}, contains="or a leaf with a 'fact'")


def test_an_empty_fact_name_is_refused():
    refused({"fact": ""}, contains="non-empty string")


# ------------------------------------------------------------------ describe --


def test_describe_summarises_a_leaf():
    assert (
        describe_assertion(
            {"fact": "http_header", "where": {"value.name": "hsts"}, "op": "exists"}
        )
        == "http_header[value.name=hsts] exists"
    )


def test_describe_summarises_a_group():
    assert describe_assertion({"all": [{"fact": "a"}, {"fact": "b"}]}) == "all of 2 conditions"
    assert describe_assertion({"any": [{"fact": "a"}]}) == "any of 1 conditions"
