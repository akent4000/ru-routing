"""Strict adapters for declared text and binary routing-source layouts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from pathlib import Path
from typing import Iterable, Mapping, Protocol

from .config import SourceDefinition
from .models import RuleKind


class ParseError(ValueError):
    """Raised when an upstream source cannot be interpreted safely."""


@dataclass(frozen=True)
class GeodataRule:
    """One category-selected rule emitted by a native geodata adapter."""

    kind: RuleKind
    value: str
    attributes: frozenset[str] = frozenset()


class GeodataReader(Protocol):
    """Boundary for a native decoder of geoip.dat and geosite.dat artifacts."""

    def read(
        self, input_type: str, category: str, artifact: Path
    ) -> Iterable[GeodataRule]: ...


@dataclass(frozen=True)
class RawRule:
    """A source rule with category, attributes, and precise origin context."""

    source: str
    category: str
    kind: RuleKind
    value: str
    path: Path
    line: int | None
    attributes: frozenset[str] = frozenset()
    affiliations: frozenset[str] = frozenset()


@dataclass(frozen=True)
class _Inclusion:
    source: str
    required_attributes: frozenset[str]
    forbidden_attributes: frozenset[str]
    path: Path
    line: int


@dataclass(frozen=True)
class _ParsedList:
    entries: tuple[RawRule, ...]
    inclusions: tuple[_Inclusion, ...]


_DLC_KINDS = {
    "full": RuleKind.DOMAIN,
    "domain": RuleKind.DOMAIN_SUFFIX,
    "keyword": RuleKind.DOMAIN_KEYWORD,
    "regexp": RuleKind.DOMAIN_REGEX,
}


def parse_source(
    source: SourceDefinition,
    paths: Mapping[str, tuple[Path, ...]],
    *,
    geodata_reader: GeodataReader | None = None,
) -> Iterable[RawRule]:
    """Yield category-aware rules according to a declared source layout."""

    _validate_paths(source, paths)
    if source.input_type == "plain_text":
        if source.layout not in {"per_category_urls", "release_assets"}:
            raise ParseError(f"{source.name}: invalid plain-text source layout")
        yield from _parse_plain_text(source, paths)
        return
    if source.input_type in {"geoip_dat", "geosite_dat"}:
        if source.layout != "single_artifact":
            raise ParseError(f"{source.name}: invalid binary source layout")
        if geodata_reader is None:
            categories = ", ".join(source.expected_categories)
            raise ParseError(
                f"{source.name}: {categories}: binary geodata requires a geodata reader"
            )
        for category in source.expected_categories:
            for artifact in paths[category]:
                try:
                    rules = geodata_reader.read(source.input_type, category, artifact)
                    for rule in rules:
                        yield _geodata_raw_rule(source, category, artifact, rule)
                except ParseError:
                    raise
                except Exception as error:
                    raise ParseError(
                        f"{source.name}: {artifact}: {category}: geodata reader failed"
                    ) from error
        return
    raise ParseError(f"{source.name}: unsupported input type {source.input_type!r}")


def _validate_paths(
    source: SourceDefinition, paths: Mapping[str, tuple[Path, ...]]
) -> None:
    if set(paths) != set(source.expected_categories):
        raise ParseError(f"{source.name}: paths must define every expected category")
    if any(not category_paths for category_paths in paths.values()):
        raise ParseError(f"{source.name}: category paths must not be empty")


def _geodata_raw_rule(
    source: SourceDefinition, category: str, artifact: Path, rule: GeodataRule
) -> RawRule:
    if not isinstance(rule, GeodataRule):
        raise ParseError(
            f"{source.name}: {artifact}: {category}: "
            "geodata reader returned invalid rule"
        )
    return RawRule(
        source=source.name,
        category=category,
        kind=rule.kind,
        value=rule.value,
        path=artifact,
        line=None,
        attributes=frozenset(rule.attributes),
    )


def _parse_plain_text(
    source: SourceDefinition, paths: Mapping[str, tuple[Path, ...]]
) -> Iterable[RawRule]:
    parsed_lists = {
        category: _read_list(source.name, category, category_paths)
        for category, category_paths in paths.items()
    }
    lookup = {category.lower(): category for category in parsed_lists}

    for category in source.expected_categories:
        for rule in _resolve_list(source.name, category, parsed_lists, lookup, ()):
            yield replace(
                rule,
                category=category,
                attributes=_rule_attributes(rule),
                affiliations=frozenset(),
            )
    for parsed in parsed_lists.values():
        for rule in parsed.entries:
            for affiliation in _affiliations(rule):
                yield replace(
                    rule,
                    category=affiliation,
                    attributes=_rule_attributes(rule),
                    affiliations=frozenset(),
                )


def _read_list(
    source: str, category: str, paths: tuple[Path, ...]
) -> _ParsedList:
    entries: list[RawRule] = []
    inclusions: list[_Inclusion] = []
    for path in paths:
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except UnicodeDecodeError as error:
            raise ParseError(f"{source}: {path}: input is not UTF-8") from error
        except OSError as error:
            raise ParseError(f"{source}: {path}: cannot read input") from error
        for line_number, line in enumerate(lines, start=1):
            item = _parse_line(source, category, path, line_number, line)
            if isinstance(item, RawRule):
                entries.append(item)
            elif item is not None:
                inclusions.append(item)
    return _ParsedList(tuple(entries), tuple(inclusions))


def _parse_line(
    source: str, category: str, path: Path, line_number: int, line: str
) -> RawRule | _Inclusion | None:
    text = line.partition("#")[0].strip()
    if not text:
        return None
    fields = text.split()
    raw_value = fields[0]
    prefix, separator, value = raw_value.partition(":")
    prefix = prefix.lower()
    if separator and prefix == "include":
        return _parse_inclusion(source, path, line_number, value, fields[1:])
    if separator and prefix in _DLC_KINDS:
        if not value:
            _raise(source, path, line_number, "empty domain-list rule value")
        kind = _DLC_KINDS[prefix]
    elif separator and "/" not in raw_value:
        _raise(source, path, line_number, f"unsupported rule kind {prefix!r}")
    else:
        kind = RuleKind.CIDR if "/" in raw_value else RuleKind.DOMAIN
        value = raw_value
    attributes, affiliations = _parse_entry_fields(
        source, path, line_number, fields[1:]
    )
    return RawRule(
        source=source,
        category=category,
        kind=kind,
        value=value,
        path=path,
        line=line_number,
        attributes=attributes,
        affiliations=affiliations,
    )


def _parse_inclusion(
    source: str, path: Path, line: int, target: str, fields: list[str]
) -> _Inclusion:
    target_name = _list_name(source, path, line, target, "included list")
    required: set[str] = set()
    forbidden: set[str] = set()
    for field in fields:
        if not field.startswith("@"):
            _raise(source, path, line, f"unexpected inclusion field {field!r}")
        name = field[1:]
        if name.startswith("-") or name.startswith("!"):
            forbidden.add(_attribute(source, path, line, name[1:]))
        else:
            required.add(_attribute(source, path, line, name))
    return _Inclusion(
        source=target_name,
        required_attributes=frozenset(required),
        forbidden_attributes=frozenset(forbidden),
        path=path,
        line=line,
    )


def _parse_entry_fields(
    source: str, path: Path, line: int, fields: list[str]
) -> tuple[frozenset[str], frozenset[str]]:
    attributes: set[str] = set()
    affiliations: set[str] = set()
    for field in fields:
        if field.startswith("@"):
            attributes.add(_attribute(source, path, line, field[1:]))
        elif field.startswith("&"):
            affiliations.add(_list_name(source, path, line, field[1:], "affiliation"))
        else:
            _raise(source, path, line, f"unexpected text after rule value {field!r}")
    return frozenset(attributes), frozenset(affiliations)


def _attribute(source: str, path: Path, line: int, value: str) -> str:
    normalized = value.lower()
    if not normalized or any(
        not (character.isascii() and (character.isalnum() or character == "!"))
        for character in normalized
    ):
        _raise(source, path, line, f"invalid attribute {value!r}")
    return normalized


def _list_name(source: str, path: Path, line: int, value: str, label: str) -> str:
    normalized = value.lower()
    if not normalized or any(
        not (character.isascii() and (character.isalnum() or character in "!-"))
        for character in normalized
    ):
        _raise(source, path, line, f"invalid {label} {value!r}")
    return normalized


def _resolve_list(
    source: str,
    category: str,
    parsed_lists: Mapping[str, _ParsedList],
    lookup: Mapping[str, str],
    stack: tuple[str, ...],
) -> Iterable[RawRule]:
    normalized = category.lower()
    if normalized in stack:
        chain = " -> ".join((*stack, normalized))
        raise ParseError(f"{source}: include cycle: {chain}")
    try:
        parsed = parsed_lists[lookup[normalized]]
    except KeyError as error:
        raise ParseError(f"{source}: missing include target {category!r}") from error
    next_stack = (*stack, normalized)
    yield from parsed.entries
    for inclusion in parsed.inclusions:
        target = inclusion.source
        if target not in lookup:
            _raise(
                source,
                inclusion.path,
                inclusion.line,
                f"missing include target {target!r}",
            )
        for rule in _resolve_list(source, target, parsed_lists, lookup, next_stack):
            attributes = _rule_attributes(rule)
            if inclusion.required_attributes <= attributes and not (
                inclusion.forbidden_attributes & attributes
            ):
                yield rule


def _rule_attributes(rule: RawRule) -> frozenset[str]:
    return rule.attributes


def _affiliations(rule: RawRule) -> frozenset[str]:
    return rule.affiliations


def _raise(source: str, path: Path, line: int, message: str) -> None:
    raise ParseError(f"{source}: {path}:{line}: {message}")
