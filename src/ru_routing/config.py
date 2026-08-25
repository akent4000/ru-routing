"""Strict, immutable loaders for the routing source and category policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml

from .models import PolicyTier


class ConfigError(ValueError):
    """Raised when a version-controlled policy file is invalid."""


class _UniqueKeyLoader(yaml.SafeLoader):
    """YAML loader that refuses mappings with silently overwritten keys."""


def _construct_unique_mapping(
    loader: _UniqueKeyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[Any, Any]:
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ConfigError(f"duplicate YAML key: {key!r}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


@dataclass(frozen=True)
class LicenseMetadata:
    """Reviewed licensing details required for redistribution."""

    spdx: str
    redistribution_reviewed: bool


@dataclass(frozen=True)
class FreshnessRule:
    """Maximum accepted source and, when applicable, sync age."""

    max_age_hours: int
    max_sync_lag_hours: int | None = None


@dataclass(frozen=True)
class SourceDefinition:
    """A required upstream and its immutable identity and handling metadata."""

    name: str
    url: str
    input_type: str
    required: bool
    expected_categories: tuple[str, ...]
    attribution: str
    license: LicenseMetadata
    freshness: FreshnessRule

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_categories", tuple(self.expected_categories))


@dataclass(frozen=True)
class SourceRegistry:
    """The complete initial upstream registry."""

    sources: tuple[SourceDefinition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))

    def declared_category_keys(self) -> frozenset[str]:
        """Return the complete explicit set of ``source:category`` keys."""

        return frozenset(
            f"{source.name}:{category}"
            for source in self.sources
            for category in source.expected_categories
        )


@dataclass(frozen=True)
class CategoryMapping:
    """How one upstream category becomes a canonical category."""

    source: str
    source_category: str
    canonical_category: str
    datasets: frozenset[str]
    tier: PolicyTier

    def __post_init__(self) -> None:
        object.__setattr__(self, "datasets", frozenset(self.datasets))


@dataclass(frozen=True)
class CategoryPolicy:
    """Explicit source-category mapping and conflict policy."""

    source_categories: Mapping[str, CategoryMapping]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "source_categories", MappingProxyType(dict(self.source_categories))
        )


@dataclass(frozen=True)
class ThresholdPolicy:
    """Version-controlled anomaly bounds for category counts and total size."""

    category_count_change_ratio: float
    size_change_ratio: float


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error}") from error
    try:
        loaded = yaml.load(contents, Loader=_UniqueKeyLoader)
    except yaml.YAMLError as error:
        raise ConfigError(f"invalid YAML in {path}: {error}") from error
    if not isinstance(loaded, dict):
        raise ConfigError(f"{path} must contain a mapping")
    return loaded


def _require_fields(value: Mapping[str, Any], fields: set[str], context: str) -> None:
    actual = set(value)
    missing = fields - actual
    unknown = actual - fields
    if missing:
        raise ConfigError(f"{context} is missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ConfigError(f"{context} has unknown fields: {', '.join(sorted(unknown))}")


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{context} must be a non-empty string")
    return value


def _positive_int(value: Any, context: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigError(f"{context} must be a positive integer")
    return value


def _ratio(value: Any, context: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{context} must be a number between zero and one")
    result = float(value)
    if not 0 < result <= 1:
        raise ConfigError(f"{context} must be a number between zero and one")
    return result


def _source_category_key(source: str, source_category: str) -> str:
    return f"{source}:{source_category}"


def load_registry(path: Path) -> SourceRegistry:
    """Load every initial required upstream from a strict source registry."""

    document = _load_yaml(path)
    _require_fields(document, {"sources"}, "source registry")
    raw_sources = document["sources"]
    if not isinstance(raw_sources, list) or not raw_sources:
        raise ConfigError("source registry sources must be a non-empty list")

    sources: list[SourceDefinition] = []
    names: set[str] = set()
    for index, raw_source in enumerate(raw_sources):
        context = f"sources[{index}]"
        if not isinstance(raw_source, dict):
            raise ConfigError(f"{context} must be a mapping")
        _require_fields(
            raw_source,
            {
                "name",
                "url",
                "input_type",
                "required",
                "expected_categories",
                "attribution",
                "license",
                "freshness",
            },
            context,
        )
        name = _string(raw_source["name"], f"{context}.name")
        if name in names:
            raise ConfigError(f"duplicate source name: {name}")
        names.add(name)
        url = _string(raw_source["url"], f"{context}.url")
        parsed_url = urlparse(url)
        if parsed_url.scheme != "https" or not parsed_url.netloc:
            raise ConfigError(f"{context}.url must be an HTTPS URL")
        if raw_source["required"] is not True:
            raise ConfigError(
                f"{context}.required must be true for the initial registry"
            )
        expected_categories = raw_source["expected_categories"]
        if not isinstance(expected_categories, list) or not expected_categories:
            raise ConfigError(f"{context}.expected_categories must be a non-empty list")
        categories = tuple(
            _string(category, f"{context}.expected_categories")
            for category in expected_categories
        )
        if len(set(categories)) != len(categories):
            raise ConfigError(f"{context}.expected_categories contains duplicates")
        raw_license = raw_source["license"]
        if not isinstance(raw_license, dict):
            raise ConfigError(f"{context}.license must be a mapping")
        _require_fields(
            raw_license, {"spdx", "redistribution_reviewed"}, f"{context}.license"
        )
        license_metadata = LicenseMetadata(
            spdx=_string(raw_license["spdx"], f"{context}.license.spdx"),
            redistribution_reviewed=raw_license["redistribution_reviewed"] is True,
        )
        if not license_metadata.redistribution_reviewed:
            raise ConfigError(f"{context}.license.redistribution_reviewed must be true")
        raw_freshness = raw_source["freshness"]
        if not isinstance(raw_freshness, dict):
            raise ConfigError(f"{context}.freshness must be a mapping")
        allowed_freshness = {"max_age_hours", "max_sync_lag_hours"}
        unknown_freshness = set(raw_freshness) - allowed_freshness
        if unknown_freshness or "max_age_hours" not in raw_freshness:
            raise ConfigError(
                f"{context}.freshness must declare only known freshness fields"
            )
        sync_lag = raw_freshness.get("max_sync_lag_hours")
        sources.append(
            SourceDefinition(
                name=name,
                url=url,
                input_type=_string(raw_source["input_type"], f"{context}.input_type"),
                required=True,
                expected_categories=categories,
                attribution=_string(
                    raw_source["attribution"], f"{context}.attribution"
                ),
                license=license_metadata,
                freshness=FreshnessRule(
                    max_age_hours=_positive_int(
                        raw_freshness["max_age_hours"],
                        f"{context}.freshness.max_age_hours",
                    ),
                    max_sync_lag_hours=(
                        _positive_int(
                            sync_lag, f"{context}.freshness.max_sync_lag_hours"
                        )
                        if sync_lag is not None
                        else None
                    ),
                ),
            )
        )
    return SourceRegistry(tuple(sources))


def load_policy(path: Path) -> CategoryPolicy:
    """Load explicit canonical mappings, target datasets, and conflict tiers."""

    document = _load_yaml(path)
    _require_fields(document, {"mappings"}, "category policy")
    raw_mappings = document["mappings"]
    if not isinstance(raw_mappings, list) or not raw_mappings:
        raise ConfigError("category policy mappings must be a non-empty list")
    mappings: dict[str, CategoryMapping] = {}
    for index, raw_mapping in enumerate(raw_mappings):
        context = f"mappings[{index}]"
        if not isinstance(raw_mapping, dict):
            raise ConfigError(f"{context} must be a mapping")
        _require_fields(
            raw_mapping,
            {"source", "source_category", "canonical_category", "datasets", "tier"},
            context,
        )
        source = _string(raw_mapping["source"], f"{context}.source")
        source_category = _string(
            raw_mapping["source_category"], f"{context}.source_category"
        )
        key = _source_category_key(source, source_category)
        if key in mappings:
            raise ConfigError(f"duplicate category mapping: {key}")
        raw_datasets = raw_mapping["datasets"]
        if not isinstance(raw_datasets, list) or not raw_datasets:
            raise ConfigError(f"{context}.datasets must be a non-empty list")
        datasets = frozenset(
            _string(dataset, f"{context}.datasets") for dataset in raw_datasets
        )
        if datasets - {"lite", "server"} or len(datasets) != len(raw_datasets):
            raise ConfigError(
                f"{context}.datasets must uniquely use lite and/or server"
            )
        try:
            tier = PolicyTier(_string(raw_mapping["tier"], f"{context}.tier"))
        except ValueError as error:
            raise ConfigError(f"{context}.tier is not a known policy tier") from error
        mappings[key] = CategoryMapping(
            source=source,
            source_category=source_category,
            canonical_category=_string(
                raw_mapping["canonical_category"], f"{context}.canonical_category"
            ),
            datasets=datasets,
            tier=tier,
        )
    return CategoryPolicy(mappings)


def load_thresholds(path: Path) -> ThresholdPolicy:
    """Load strict count and total-size anomaly bounds."""

    document = _load_yaml(path)
    _require_fields(
        document,
        {"category_count_change_ratio", "size_change_ratio"},
        "threshold policy",
    )
    return ThresholdPolicy(
        category_count_change_ratio=_ratio(
            document["category_count_change_ratio"], "category_count_change_ratio"
        ),
        size_change_ratio=_ratio(document["size_change_ratio"], "size_change_ratio"),
    )
