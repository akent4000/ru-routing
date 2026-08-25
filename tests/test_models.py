import json
from dataclasses import FrozenInstanceError

import pytest

from ru_routing.models import Category, Dataset, RuleEntry, RuleKind


def entry(value: str, *, source: str = "fixture") -> RuleEntry:
    return RuleEntry(kind=RuleKind.DOMAIN, value=value, sources=frozenset({source}))


def test_dataset_json_is_order_independent():
    a = Dataset(
        categories={"ru": Category("ru", frozenset({entry("b.ru"), entry("a.ru")}))}
    )
    b = Dataset(
        categories={"ru": Category("ru", frozenset({entry("a.ru"), entry("b.ru")}))}
    )

    assert a.to_canonical_json() == b.to_canonical_json()


def test_dataset_json_has_stable_category_entry_and_provenance_order():
    dataset = Dataset(
        categories={
            "z": Category("z", frozenset({entry("z.ru", source="second")})),
            "a": Category(
                "a", frozenset({entry("a.ru", source="z"), entry("b.ru", source="a")})
            ),
        }
    )

    assert json.loads(dataset.to_canonical_json()) == {
        "categories": {
            "a": {
                    "entries": [
                        {
                            "attributes": [],
                            "kind": "domain",
                            "memberships": [],
                            "sources": ["z"],
                            "value": "a.ru",
                        },
                        {
                            "attributes": [],
                            "kind": "domain",
                            "memberships": [],
                            "sources": ["a"],
                            "value": "b.ru",
                        },
                ]
            },
            "z": {
                    "entries": [
                        {
                            "attributes": [],
                            "kind": "domain",
                            "memberships": [],
                            "sources": ["second"],
                            "value": "z.ru",
                        }
                ]
            },
        }
    }


def test_canonical_contracts_cannot_be_mutated_after_construction():
    rule = entry("example.ru")
    dataset = Dataset(categories={"ru": Category("ru", frozenset({rule}))})

    with pytest.raises(FrozenInstanceError):
        rule.value = "changed.ru"  # type: ignore[misc]
    with pytest.raises(TypeError):
        dataset.categories["other"] = Category("other", frozenset())


def test_rule_entry_retains_immutable_source_category_membership():
    rule = RuleEntry(
        kind=RuleKind.DOMAIN,
        value="example.com",
        sources=frozenset({"fixture/source"}),
        memberships=frozenset({("fixture/source", "inside")}),
    )

    assert rule.memberships == frozenset({("fixture/source", "inside")})
