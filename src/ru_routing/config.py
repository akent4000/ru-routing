"""Strict, immutable loaders for the routing source and category policy."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlparse

import yaml

from .models import PolicyTier, RuleKind

INITIAL_SOURCE_IDS = frozenset(
    {
        "aireps/geosite",
        "runetfreedom/russia-v2ray-rules-dat",
        "jutsu-dev/ru-route-lists",
        "Loyalsoldier/v2ray-rules-dat",
        "itdoginfo/allow-domains",
        "hydraponique/roscomvpn-geoip",
        "kirilllavrov/RU-domain-list-for-whitelist",
        "builtin/private-networks",
        "Hipo/university-domains-list",
        "local/universities-ru-overlay",
    }
)

SUPPORTED_SOURCE_LAYOUTS = {
    "geoip_dat": frozenset({"single_artifact"}),
    "geosite_dat": frozenset({"single_artifact"}),
    "plain_text": frozenset({"per_category_urls", "release_assets"}),
    "university_domains_json": frozenset({"single_artifact"}),
    "local_text": frozenset({"repository_file"}),
    "builtin": frozenset({"per_category_urls"}),
}


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
        if not isinstance(key, str):
            raise ConfigError("YAML mapping keys must be strings")
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
    layout: str
    required: bool
    expected_categories: tuple[str, ...]
    category_locations: Mapping[str, tuple[str, ...]]
    attribution: str
    license: LicenseMetadata
    freshness: FreshnessRule
    bare_domain_kind: RuleKind = RuleKind.DOMAIN

    def __post_init__(self) -> None:
        object.__setattr__(self, "expected_categories", tuple(self.expected_categories))
        object.__setattr__(
            self,
            "category_locations",
            MappingProxyType(
                {
                    category: tuple(locations)
                    for category, locations in self.category_locations.items()
                }
            ),
        )


@dataclass(frozen=True)
class SourceRegistry:
    """The complete initial upstream registry."""

    sources: tuple[SourceDefinition, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "sources", tuple(self.sources))

    def resolve(self, source_id: str) -> SourceDefinition:
        """Resolve an entry provenance source ID to its registered source."""

        for source in self.sources:
            if source.name == source_id:
                return source
        raise ConfigError(f"unknown source ID: {source_id}")

    def attribution_for(self, source_id: str) -> str:
        """Return immutable attribution for a registered provenance source ID."""

        return self.resolve(source_id).attribution

    def fixture_overrides(self, overrides: Mapping[str, Path]) -> Mapping[str, Path]:
        """Validate fixture-only inputs without weakening the live registry."""

        resolved: dict[str, Path] = {}
        for source_id, path in overrides.items():
            self.resolve(source_id)
            if not isinstance(path, Path):
                raise ConfigError(f"fixture override for {source_id} must be a Path")
            resolved[source_id] = path
        return MappingProxyType(resolved)

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
class CanonicalCategoryPolicy:
    """Dataset scope and conflict tier resolved by canonical category name."""

    name: str
    datasets: frozenset[str]
    tier: PolicyTier

    def __post_init__(self) -> None:
        object.__setattr__(self, "datasets", frozenset(self.datasets))


@dataclass(frozen=True)
class CategoryPolicy:
    """Explicit source-category mapping and conflict policy."""

    source_categories: Mapping[str, CategoryMapping]
    canonical_categories: Mapping[str, CanonicalCategoryPolicy]

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "source_categories", MappingProxyType(dict(self.source_categories))
        )
        object.__setattr__(
            self,
            "canonical_categories",
            MappingProxyType(dict(self.canonical_categories)),
        )

    def canonical_category(self, name: str) -> CanonicalCategoryPolicy:
        """Resolve the dataset scope and conflict tier for a canonical category."""

        try:
            return self.canonical_categories[name]
        except KeyError as error:
            raise ConfigError(f"unknown canonical category: {name}") from error


@dataclass(frozen=True)
class SourceRemovalMigration:
    """Reviewed anomaly resets for one exact policy and source transition."""

    expected_previous_policy_fingerprint: str
    expected_current_policy_fingerprint: str
    removed_source_ids: frozenset[str]
    reset_category_keys: frozenset[str]
    reset_size: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "removed_source_ids", frozenset(self.removed_source_ids)
        )
        object.__setattr__(
            self, "reset_category_keys", frozenset(self.reset_category_keys)
        )


@dataclass(frozen=True)
class CategoryScopeMigration:
    """Reviewed anomaly reset for one exact policy transition that reshapes
    a canonical category's dataset scope (e.g. moving a category out of
    ``lite``) without removing any upstream source.

    Distinct from ``SourceRemovalMigration``: that mechanism requires the
    current source set to be a strict subset of the previous one (an actual
    upstream removed from ``sources.yaml``). This one has no such
    precondition -- it only requires both policy fingerprints to match
    exactly, since a pure ``categories.yaml`` ``datasets:`` scope edit
    changes the policy fingerprint but touches no source.
    """

    expected_previous_policy_fingerprint: str
    expected_current_policy_fingerprint: str
    reset_category_keys: frozenset[str]
    reset_size: bool

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "reset_category_keys", frozenset(self.reset_category_keys)
        )


@dataclass(frozen=True)
class ThresholdPolicy:
    """Version-controlled anomaly bounds and reviewed baseline migrations."""

    category_count_change_ratio: float
    size_change_ratio: float
    source_removal_migrations: tuple[SourceRemovalMigration, ...] = ()
    category_scope_migrations: tuple[CategoryScopeMigration, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "source_removal_migrations", tuple(self.source_removal_migrations)
        )
        object.__setattr__(
            self, "category_scope_migrations", tuple(self.category_scope_migrations)
        )


def _load_yaml(path: Path) -> Mapping[str, Any]:
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as error:
        raise ConfigError(f"cannot read {path}: {error}") from error
    try:
        loaded = yaml.load(contents, Loader=_UniqueKeyLoader)
    except (TypeError, yaml.YAMLError) as error:
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


def _https_url(value: Any, context: str) -> str:
    url = _string(value, context)
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https" or not parsed_url.netloc:
        raise ConfigError(f"{context} must be an HTTPS URL")
    return url


def _repository_relative_location(value: Any, context: str) -> str:
    location = _string(value, context)
    path = Path(location)
    if path.is_absolute() or ".." in path.parts:
        raise ConfigError(f"{context} must be a repository-relative path")
    return location


def _category_locations(
    value: Any,
    categories: tuple[str, ...],
    context: str,
    location_validator: Any,
) -> Mapping[str, tuple[str, ...]]:
    if not isinstance(value, dict):
        raise ConfigError(f"{context} must be a mapping")
    if set(value) != set(categories):
        raise ConfigError(f"{context} must define every expected category exactly once")
    locations: dict[str, tuple[str, ...]] = {}
    for category, raw_locations in value.items():
        if isinstance(raw_locations, str):
            raw_locations = [raw_locations]
        if not isinstance(raw_locations, list) or not raw_locations:
            raise ConfigError(f"{context}.{category} must be a non-empty location list")
        category_locations = tuple(
            location_validator(location, f"{context}.{category}")
            for location in raw_locations
        )
        if len(set(category_locations)) != len(category_locations):
            raise ConfigError(f"{context}.{category} contains duplicate URLs")
        locations[category] = category_locations
    return locations


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
        required_source_fields = {
            "name",
            "url",
            "input_type",
            "layout",
            "required",
            "expected_categories",
            "category_locations",
            "attribution",
            "license",
            "freshness",
        }
        optional_source_fields = {"bare_domain_kind"}
        missing_source_fields = required_source_fields - set(raw_source)
        unknown_source_fields = set(raw_source) - (
            required_source_fields | optional_source_fields
        )
        if missing_source_fields:
            raise ConfigError(
                f"{context} is missing fields: "
                f"{', '.join(sorted(missing_source_fields))}"
            )
        if unknown_source_fields:
            raise ConfigError(
                f"{context} has unknown fields: "
                f"{', '.join(sorted(unknown_source_fields))}"
            )
        name = _string(raw_source["name"], f"{context}.name")
        if name in names:
            raise ConfigError(f"duplicate source name: {name}")
        names.add(name)
        url = _https_url(raw_source["url"], f"{context}.url")
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
        input_type = _string(raw_source["input_type"], f"{context}.input_type")
        layout = _string(raw_source["layout"], f"{context}.layout")
        if input_type not in SUPPORTED_SOURCE_LAYOUTS:
            raise ConfigError(f"{context}.input_type is not supported")
        if layout not in SUPPORTED_SOURCE_LAYOUTS[input_type]:
            raise ConfigError(f"{context}.layout is not valid for {input_type}")
        has_bare_domain_kind = "bare_domain_kind" in raw_source
        if has_bare_domain_kind and input_type != "plain_text":
            raise ConfigError(
                f"{context}.bare_domain_kind is only valid for plain_text sources"
            )
        bare_domain_kind_by_name = {
            "domain": RuleKind.DOMAIN,
            "domain_suffix": RuleKind.DOMAIN_SUFFIX,
        }
        if not has_bare_domain_kind:
            bare_domain_kind = RuleKind.DOMAIN
        else:
            bare_domain_kind_name = _string(
                raw_source["bare_domain_kind"], f"{context}.bare_domain_kind"
            )
            if bare_domain_kind_name not in bare_domain_kind_by_name:
                raise ConfigError(
                    f"{context}.bare_domain_kind must be one of: domain, domain_suffix"
                )
            bare_domain_kind = bare_domain_kind_by_name[bare_domain_kind_name]
        category_locations = _category_locations(
            raw_source["category_locations"],
            categories,
            f"{context}.category_locations",
            (
                _repository_relative_location
                if input_type == "local_text"
                else _https_url
            ),
        )
        if layout == "single_artifact" and any(
            locations != (url,) for locations in category_locations.values()
        ):
            raise ConfigError(f"{context}.single_artifact locations must equal its URL")
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
                input_type=input_type,
                layout=layout,
                required=True,
                expected_categories=categories,
                category_locations=category_locations,
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
                bare_domain_kind=bare_domain_kind,
            )
        )
    if names != INITIAL_SOURCE_IDS:
        missing = INITIAL_SOURCE_IDS - names
        unexpected = names - INITIAL_SOURCE_IDS
        details = []
        if missing:
            details.append(f"missing: {', '.join(sorted(missing))}")
        if unexpected:
            details.append(f"unexpected: {', '.join(sorted(unexpected))}")
        raise ConfigError(
            f"initial source IDs must match exactly ({'; '.join(details)})"
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
    canonical_categories: dict[str, CanonicalCategoryPolicy] = {}
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
        canonical_category = _string(
            raw_mapping["canonical_category"], f"{context}.canonical_category"
        )
        canonical_policy = CanonicalCategoryPolicy(
            name=canonical_category,
            datasets=datasets,
            tier=tier,
        )
        existing_policy = canonical_categories.get(canonical_category)
        if existing_policy and existing_policy != canonical_policy:
            raise ConfigError(
                f"{context} conflicts with canonical category {canonical_category}"
            )
        canonical_categories[canonical_category] = canonical_policy
        mappings[key] = CategoryMapping(
            source=source,
            source_category=source_category,
            canonical_category=canonical_category,
            datasets=datasets,
            tier=tier,
        )
    return CategoryPolicy(mappings, canonical_categories)


def _unique_string_set(value: Any, context: str) -> frozenset[str]:
    if not isinstance(value, list) or not value:
        raise ConfigError(f"{context} must be a non-empty list")
    strings = tuple(_string(item, context) for item in value)
    if len(set(strings)) != len(strings):
        raise ConfigError(f"{context} contains duplicates")
    return frozenset(strings)


def _sha256_fingerprint(value: Any, context: str) -> str:
    fingerprint = _string(value, context)
    if len(fingerprint) != 64 or any(
        character not in "0123456789abcdef" for character in fingerprint
    ):
        raise ConfigError(f"{context} must be a lowercase SHA-256 fingerprint")
    return fingerprint


def _reset_category_keys(value: Any, context: str) -> frozenset[str]:
    reset_category_keys = _unique_string_set(value, context)
    for category_key in reset_category_keys:
        dataset, separator, category = category_key.partition(":")
        if (
            separator != ":"
            or dataset not in {"lite", "server"}
            or not category
            or ":" in category
        ):
            raise ConfigError(f"{context} contains invalid key {category_key!r}")
    return reset_category_keys


def _reset_size(value: Any, context: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{context} must be a boolean")
    return value


def _source_removal_migrations(value: Any) -> tuple[SourceRemovalMigration, ...]:
    if not isinstance(value, list):
        raise ConfigError("source_removal_migrations must be a list")
    migrations: list[SourceRemovalMigration] = []
    seen_removed_sets: set[frozenset[str]] = set()
    for index, raw_migration in enumerate(value):
        context = f"source_removal_migrations[{index}]"
        if not isinstance(raw_migration, dict):
            raise ConfigError(f"{context} must be a mapping")
        _require_fields(
            raw_migration,
            {
                "expected_previous_policy_fingerprint",
                "expected_current_policy_fingerprint",
                "removed_source_ids",
                "reset_category_keys",
                "reset_size",
            },
            context,
        )
        expected_previous_policy_fingerprint = _sha256_fingerprint(
            raw_migration["expected_previous_policy_fingerprint"],
            f"{context}.expected_previous_policy_fingerprint",
        )
        expected_current_policy_fingerprint = _sha256_fingerprint(
            raw_migration["expected_current_policy_fingerprint"],
            f"{context}.expected_current_policy_fingerprint",
        )
        removed_source_ids = _unique_string_set(
            raw_migration["removed_source_ids"], f"{context}.removed_source_ids"
        )
        if removed_source_ids in seen_removed_sets:
            raise ConfigError(
                f"{context}.removed_source_ids duplicates another migration"
            )
        seen_removed_sets.add(removed_source_ids)
        reset_category_keys = _reset_category_keys(
            raw_migration["reset_category_keys"], f"{context}.reset_category_keys"
        )
        reset_size = _reset_size(raw_migration["reset_size"], f"{context}.reset_size")
        migrations.append(
            SourceRemovalMigration(
                expected_previous_policy_fingerprint=(
                    expected_previous_policy_fingerprint
                ),
                expected_current_policy_fingerprint=(
                    expected_current_policy_fingerprint
                ),
                removed_source_ids=removed_source_ids,
                reset_category_keys=reset_category_keys,
                reset_size=reset_size,
            )
        )
    return tuple(migrations)


def _category_scope_migrations(value: Any) -> tuple[CategoryScopeMigration, ...]:
    if not isinstance(value, list):
        raise ConfigError("category_scope_migrations must be a list")
    migrations: list[CategoryScopeMigration] = []
    seen_fingerprint_pairs: set[tuple[str, str]] = set()
    for index, raw_migration in enumerate(value):
        context = f"category_scope_migrations[{index}]"
        if not isinstance(raw_migration, dict):
            raise ConfigError(f"{context} must be a mapping")
        _require_fields(
            raw_migration,
            {
                "expected_previous_policy_fingerprint",
                "expected_current_policy_fingerprint",
                "reset_category_keys",
                "reset_size",
            },
            context,
        )
        expected_previous_policy_fingerprint = _sha256_fingerprint(
            raw_migration["expected_previous_policy_fingerprint"],
            f"{context}.expected_previous_policy_fingerprint",
        )
        expected_current_policy_fingerprint = _sha256_fingerprint(
            raw_migration["expected_current_policy_fingerprint"],
            f"{context}.expected_current_policy_fingerprint",
        )
        fingerprint_pair = (
            expected_previous_policy_fingerprint,
            expected_current_policy_fingerprint,
        )
        if fingerprint_pair in seen_fingerprint_pairs:
            raise ConfigError(
                f"{context} duplicates another migration's fingerprint pair"
            )
        seen_fingerprint_pairs.add(fingerprint_pair)
        reset_category_keys = _reset_category_keys(
            raw_migration["reset_category_keys"], f"{context}.reset_category_keys"
        )
        reset_size = _reset_size(raw_migration["reset_size"], f"{context}.reset_size")
        migrations.append(
            CategoryScopeMigration(
                expected_previous_policy_fingerprint=(
                    expected_previous_policy_fingerprint
                ),
                expected_current_policy_fingerprint=(
                    expected_current_policy_fingerprint
                ),
                reset_category_keys=reset_category_keys,
                reset_size=reset_size,
            )
        )
    return tuple(migrations)


def load_thresholds(path: Path) -> ThresholdPolicy:
    """Load strict anomaly bounds and explicitly reviewed baseline migrations."""

    document = _load_yaml(path)
    _require_fields(
        document,
        {
            "category_count_change_ratio",
            "size_change_ratio",
            "source_removal_migrations",
            "category_scope_migrations",
        },
        "threshold policy",
    )
    return ThresholdPolicy(
        category_count_change_ratio=_ratio(
            document["category_count_change_ratio"], "category_count_change_ratio"
        ),
        size_change_ratio=_ratio(document["size_change_ratio"], "size_change_ratio"),
        source_removal_migrations=_source_removal_migrations(
            document["source_removal_migrations"]
        ),
        category_scope_migrations=_category_scope_migrations(
            document["category_scope_migrations"]
        ),
    )
