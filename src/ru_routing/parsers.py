"""Strict adapters for declared text and binary routing-source layouts."""

from __future__ import annotations

import ipaddress
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


class ProtobufGeodataReader:
    """Decode v2fly ``GeoSiteList`` and ``GeoIPList`` protobuf artifacts.

    The pinned binary inputs use the small stable wire contract declared in
    v2fly/v2ray-core's ``app/router/routercommon/common.proto``.  Decoding the
    needed fields directly keeps live builds independent of an unpinned Python
    protobuf runtime or a network-fetched Go helper.
    """

    def __init__(self) -> None:
        self._categories_by_artifact: dict[Path, dict[str, tuple[bytes, ...]]] = {}

    def read(
        self, input_type: str, category: str, artifact: Path
    ) -> Iterable[GeodataRule]:
        artifact_path = Path(artifact)
        categories = self._categories_by_artifact.get(artifact_path)
        if categories is None:
            try:
                document = artifact_path.read_bytes()
            except OSError as error:
                raise ParseError(
                    f"{artifact}: cannot read geodata artifact"
                ) from error
            artifact_context = f"{artifact}: geodata"
            grouped: dict[str, list[bytes]] = {}
            for entry in _message_bytes(document, 1, artifact_context):
                label = _message_string(entry, 1, artifact_context).casefold()
                grouped.setdefault(label, []).append(entry)
            categories = {
                label: tuple(entries) for label, entries in grouped.items()
            }
            self._categories_by_artifact[artifact_path] = categories
        context = f"{artifact}: {category}"
        matches = categories.get(category.casefold(), ())
        if not matches:
            raise ParseError(f"{context}: category not found in geodata artifact")
        if len(matches) != 1:
            raise ParseError(f"{context}: duplicate category in geodata artifact")
        if input_type == "geosite_dat":
            return tuple(_decode_geosite(matches[0], context))
        if input_type == "geoip_dat":
            return tuple(_decode_geoip(matches[0], context))
        raise ParseError(f"{context}: unsupported geodata input type {input_type!r}")


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

_GEOSITE_KINDS = {
    0: RuleKind.DOMAIN_KEYWORD,
    1: RuleKind.DOMAIN_REGEX,
    2: RuleKind.DOMAIN_SUFFIX,
    3: RuleKind.DOMAIN,
}


def _decode_geosite(message: bytes, context: str) -> Iterable[GeodataRule]:
    for domain in _message_bytes(message, 2, context):
        domain_type = _message_varint(domain, 1, context, default=0)
        try:
            kind = _GEOSITE_KINDS[domain_type]
        except KeyError as error:
            raise ParseError(
                f"{context}: unsupported geosite domain type {domain_type}"
            ) from error
        value = _message_string(domain, 2, context)
        if not value:
            raise ParseError(f"{context}: geosite domain value is empty")
        attributes = frozenset(
            key
            for attribute in _message_bytes(domain, 3, context)
            if (key := _decode_attribute(attribute, context)) is not None
        )
        yield GeodataRule(kind=kind, value=value, attributes=attributes)


def _decode_attribute(message: bytes, context: str) -> str | None:
    key = _message_string(message, 1, context)
    if not key:
        raise ParseError(f"{context}: geosite attribute key is empty")
    bool_values = _message_varints(message, 2, context)
    int_values = _message_varints(message, 3, context)
    if bool_values:
        return key if bool_values[-1] != 0 else None
    if int_values:
        return key
    raise ParseError(f"{context}: geosite attribute has no typed value")


def _decode_geoip(message: bytes, context: str) -> Iterable[GeodataRule]:
    if _message_varint(message, 3, context, default=0) != 0:
        raise ParseError(f"{context}: inverse-match GeoIP categories are unsupported")
    for cidr in _message_bytes(message, 2, context):
        addresses = _message_bytes(cidr, 1, context)
        if len(addresses) != 1 or len(addresses[0]) not in {4, 16}:
            raise ParseError(f"{context}: invalid geodata CIDR address bytes")
        prefix = _message_varint(cidr, 2, context, default=0)
        maximum = 32 if len(addresses[0]) == 4 else 128
        if prefix > maximum:
            raise ParseError(f"{context}: invalid geodata CIDR prefix {prefix}")
        try:
            network = ipaddress.ip_network(
                (ipaddress.ip_address(addresses[0]), prefix), strict=True
            )
        except ValueError as error:
            raise ParseError(f"{context}: invalid geodata CIDR network") from error
        yield GeodataRule(kind=RuleKind.CIDR, value=str(network))


def _message_string(message: bytes, field: int, context: str) -> str:
    values = _message_bytes(message, field, context)
    if not values:
        return ""
    try:
        return values[-1].decode("utf-8")
    except UnicodeDecodeError as error:
        raise ParseError(f"{context}: geodata string is not UTF-8") from error


def _message_bytes(message: bytes, field: int, context: str) -> tuple[bytes, ...]:
    values = []
    for number, wire_type, value in _protobuf_fields(message, context):
        if number != field:
            continue
        if wire_type != 2:
            raise ParseError(f"{context}: invalid protobuf wire type for field {field}")
        values.append(value)
    return tuple(values)


def _message_varints(message: bytes, field: int, context: str) -> tuple[int, ...]:
    values = []
    for number, wire_type, value in _protobuf_fields(message, context):
        if number != field:
            continue
        if wire_type != 0:
            raise ParseError(f"{context}: invalid protobuf wire type for field {field}")
        values.append(value)
    return tuple(values)


def _message_varint(
    message: bytes, field: int, context: str, *, default: int
) -> int:
    values = _message_varints(message, field, context)
    return values[-1] if values else default


def _protobuf_fields(
    message: bytes, context: str
) -> Iterable[tuple[int, int, int | bytes]]:
    offset = 0
    while offset < len(message):
        key, offset = _protobuf_varint(message, offset, context)
        field = key >> 3
        wire_type = key & 0x07
        if field == 0:
            raise ParseError(f"{context}: invalid protobuf field number")
        if wire_type == 0:
            value, offset = _protobuf_varint(message, offset, context)
        elif wire_type == 1:
            end = offset + 8
            if end > len(message):
                raise ParseError(f"{context}: truncated fixed64 protobuf field")
            value = message[offset:end]
            offset = end
        elif wire_type == 2:
            length, offset = _protobuf_varint(message, offset, context)
            end = offset + length
            if end > len(message):
                raise ParseError(f"{context}: truncated protobuf bytes field")
            value = message[offset:end]
            offset = end
        elif wire_type == 5:
            end = offset + 4
            if end > len(message):
                raise ParseError(f"{context}: truncated fixed32 protobuf field")
            value = message[offset:end]
            offset = end
        else:
            raise ParseError(f"{context}: unsupported protobuf wire type {wire_type}")
        yield field, wire_type, value


def _protobuf_varint(
    message: bytes, offset: int, context: str
) -> tuple[int, int]:
    value = 0
    for shift in range(0, 70, 7):
        if offset >= len(message):
            raise ParseError(f"{context}: truncated protobuf varint")
        byte = message[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
    raise ParseError(f"{context}: oversized protobuf varint")


def parse_source(
    source: SourceDefinition,
    paths: Mapping[str, tuple[Path, ...]],
    *,
    geodata_reader: GeodataReader | None = None,
) -> Iterable[RawRule]:
    """Yield category-aware rules according to a declared source layout."""

    _validate_paths(source, paths)
    if source.input_type in {"plain_text", "builtin"}:
        # "builtin" sources (e.g. the static private-network CIDR list)
        # are content-identical to plain_text: one rule per non-comment
        # line, no fetch involved. Reuse the same parser.
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
        category: _read_list(
            source.name, source.bare_domain_kind, category, category_paths
        )
        for category, category_paths in paths.items()
    }
    parsed_lists = _materialize_affiliations(parsed_lists)
    lookup = {category.lower(): category for category in parsed_lists}

    categories = (*source.expected_categories, *(
        category
        for category in parsed_lists
        if category not in source.expected_categories
    ))
    for category in categories:
        for rule in _resolve_list(source.name, category, parsed_lists, lookup, ()):
            yield replace(
                rule,
                category=category,
                attributes=_rule_attributes(rule),
                affiliations=frozenset(),
            )


def _materialize_affiliations(
    parsed_lists: Mapping[str, _ParsedList],
) -> dict[str, _ParsedList]:
    """Add affiliation targets before resolving include directives."""

    result = dict(parsed_lists)
    lookup = {category.lower(): category for category in result}
    affiliated: dict[str, list[RawRule]] = {}
    for parsed in parsed_lists.values():
        for rule in parsed.entries:
            for affiliation in _affiliations(rule):
                affiliated.setdefault(affiliation, []).append(rule)
    for affiliation, rules in affiliated.items():
        category = lookup.get(affiliation, affiliation)
        existing = result.get(category)
        if existing is None:
            result[category] = _ParsedList(tuple(rules), ())
        else:
            result[category] = _ParsedList(
                entries=(*existing.entries, *rules),
                inclusions=existing.inclusions,
            )
    return result


def _read_list(
    source: str,
    bare_domain_kind: RuleKind,
    category: str,
    paths: tuple[Path, ...],
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
            item = _parse_line(
                source, bare_domain_kind, category, path, line_number, line
            )
            if isinstance(item, RawRule):
                entries.append(item)
            elif item is not None:
                inclusions.append(item)
    return _ParsedList(tuple(entries), tuple(inclusions))


def _parse_line(
    source: str,
    bare_domain_kind: RuleKind,
    category: str,
    path: Path,
    line_number: int,
    line: str,
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
        kind = RuleKind.CIDR if "/" in raw_value else bare_domain_kind
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
        if name.startswith("-"):
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
