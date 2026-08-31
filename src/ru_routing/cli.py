"""Command-line surface for the RU routing pipeline.

Orchestrates the pipeline stages built in Tasks 3-9
(``fetch``/``parsers``/``normalize``/``resolve``/``generate``/``render``/
``validate``/``package``) behind the ``fetch``, ``build``, ``check``,
``release-decision``, ``publish``, and ``rollback`` subcommands.
``publish``/``rollback`` wire directly to Task 11's
``src/ru_routing/publish.py`` (``publish_release``/``rollback``,
``CliBackend`` and ``YandexS3Credentials``).

Stage ordering for ``build``/``check`` (see the design doc's "Build
Architecture" section for the seven canonical stages: fetch, normalize,
resolve, generate, validate, package, publish):

1. obtain rules -- either read them live via ``fetch_all`` + ``parse_source``
   (``--inputs``, a prior ``fetch`` output directory) or synthesize them from
   the committed fixture registry (``--fixtures``, for PR validation);
2. ``normalize_sources`` across every source at once (not per-source --
   ``normalize_sources`` is designed to receive the complete set so
   provenance dedup/union happens globally, per its docstring);
3. ``resolve_datasets`` to get the lite/server ``ResolvedBuild``;
4. ``generate_all`` to compile every native artifact into ``dist``;
5. ``render_examples`` immediately alongside generation -- it populates
   ``dist/examples``, which the Output Contract requires and which
   ``package_build``'s ``SHA256SUMS``/``manifest.json`` step must already see
   on disk. It needs a concrete ``version`` string, so ``build`` computes the
   release version via ``plan_release`` *before* calling it (a lightweight,
   side-effect-free planning call -- it only hashes already-resolved data and
   reads the previous manifest, it does not write anything) rather than
   deferring example rendering until after packaging;
6. ``validate_build`` to catch structural/semantic/native-load problems;
7. ``package_build`` to write ``SHA256SUMS``, ``manifest.json``, and the
   deterministic archive (this repeats the fingerprinting internally via its
   own ``plan_release`` call, which is safe/idempotent since nothing
   resolved-build-affecting changed between the two calls).

``check`` runs the same stages as ``build`` (it *is* the fixture-driven PR
validation path) but does not require a persistent ``--dist``; a temporary
directory is used if none is given. ``package_build``'s archive step still
runs (validation depends on artifacts already existing in ``dist``, and
packaging is comparatively cheap once they do), but no separate "publish"
happens either way in this task.

``release-decision`` is a CLI-level convenience, not one of the seven
documented pipeline stages: it runs fetch/fixtures -> normalize -> resolve,
computes fingerprints, and calls ``plan_release`` to report whether a release
would be warranted, without running generate/validate/package. This lets a
scheduled workflow cheaply short-circuit before paying for the full native
toolchain when nothing changed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import shutil
import sys
import tempfile
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Mapping

import httpx

from .config import (
    CategoryPolicy,
    ConfigError,
    SourceDefinition,
    SourceRegistry,
    load_policy,
    load_registry,
    load_thresholds,
)
from .fetch import DegradedSource, FetchedInputs, FetchedSource, fetch_all
from .generate import GenerationError, NativeTools, generate_all
from .models import RuleKind
from .normalize import NormalizationError, normalize_sources
from .package import (
    AnomalyError,
    BuildMetadata,
    Manifest,
    PackagingError,
    PolicyConfigs,
    package_build,
    plan_release,
)
from .parsers import GeodataRule, ParseError, ProtobufGeodataReader
from .publish import (
    CliBackend,
    PublishBackend,
    PublishError,
    PublishPlan,
    YandexS3Credentials,
    publish_release,
)
from .publish import (
    rollback as rollback_release,
)
from .render import render_examples
from .resolve import ResolutionError, resolve_datasets
from .tooling import CompletedTool, ToolRunner
from .validate import ValidationError, ValidationThresholds, validate_build

COMMANDS = ("fetch", "build", "check", "release-decision", "publish", "rollback")

_DEFAULT_CDN_BASE = "https://routing.akent.site/latest"
_PUBLISH_ERROR_EXIT_CODE = 4


def _default_templates_dir() -> Path:
    """Locate ``examples/templates`` for both a source checkout and a pip install.

    In a source checkout (or the ``pythonpath = ["src"]`` test layout),
    ``cli.py`` lives at ``<repo>/src/ru_routing/cli.py``, so the repo root is
    two parents up. Once installed as a wheel (as the Docker image does via
    ``pip install /work``), ``cli.py`` instead lives under something like
    ``/usr/local/lib/python3.11/site-packages/ru_routing/cli.py`` -- there is
    no repo root to walk up to, since ``examples/`` is not currently
    packaged as installed package data. The Docker image copies the repo's
    ``examples/`` directory to ``/work/examples`` alongside the installed
    package, so that well-known location is checked as a fallback. Callers
    needing a different location can always override via ``--templates-dir``.
    """

    repo_relative = Path(__file__).resolve().parents[2] / "examples" / "templates"
    if repo_relative.is_dir():
        return repo_relative
    docker_image_location = Path("/work/examples/templates")
    if docker_image_location.is_dir():
        return docker_image_location
    return repo_relative


class PipelineCliError(RuntimeError):
    """Raised for CLI-level orchestration failures with a clear message."""


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level parser and wire every subcommand's arguments."""

    parser = argparse.ArgumentParser(prog="ru-routing")
    subcommands = parser.add_subparsers(dest="command", title="pipeline commands")
    for command in COMMANDS:
        command_parser = subcommands.add_parser(
            command, help=f"{command} routing pipeline data"
        )
        _add_common_config_argument(command_parser)
        if command == "fetch":
            _add_fetch_arguments(command_parser)
        elif command in ("build", "check"):
            _add_build_arguments(command_parser, require_dist=command == "build")
        elif command == "release-decision":
            _add_release_decision_arguments(command_parser)
        elif command == "publish":
            _add_publish_arguments(command_parser)
        elif command == "rollback":
            _add_rollback_arguments(command_parser)
        if command == "check":
            command_parser.add_argument(
                "--config-only",
                action="store_true",
                help="validate policy configuration only, without a full build",
            )
    return parser


def _add_common_config_argument(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--config",
        type=Path,
        default=Path("config"),
        metavar="CONFIG_ROOT",
        help=(
            "directory containing sources.yaml, categories.yaml, "
            "and thresholds.yaml"
        ),
    )


def _add_fetch_arguments(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--destination",
        type=Path,
        required=True,
        metavar="DIR",
        help="directory to atomically populate with fetched source objects",
    )
    command_parser.add_argument(
        "--offline-fixtures",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "skip live HTTP fetch and instead write a fetch_all-shaped "
            "output tree (objects/, metadata/) from a committed fixture "
            "registry directory (see tests/fixtures/upstreams/registry); "
            "for tests and offline reproduction, not for production use"
        ),
    )


def _add_build_arguments(
    command_parser: argparse.ArgumentParser, *, require_dist: bool
) -> None:
    source_group = command_parser.add_mutually_exclusive_group()
    source_group.add_argument(
        "--fixtures",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "read a committed fixture registry directory instead of live "
            "or previously fetched sources (see "
            "tests/fixtures/upstreams/registry for the layout: one "
            "<source>--<category>.<ext> file per declared source/category, "
            ".dat for geoip_dat/geosite_dat sources and any other "
            "extension for plain_text sources)"
        ),
    )
    source_group.add_argument(
        "--inputs",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "read a prior `ru-routing fetch` output directory (the same "
            "objects/+metadata/ tree fetch_all itself writes) instead of "
            "fetching or reading fixtures"
        ),
    )
    command_parser.add_argument(
        "--dist",
        type=Path,
        required=require_dist,
        default=None,
        metavar="DIR",
        help="output directory for the complete build tree",
    )
    command_parser.add_argument(
        "--fake-native-tools",
        action="store_true",
        help=(
            "use an in-process fake for dlc/geoip/sing-box/mihomo/xray "
            "instead of real binaries on PATH, and skip the deterministic "
            "rebuild check; for sandboxed/CI environments without the "
            "pinned native toolchain, not for a real release build"
        ),
    )
    command_parser.add_argument(
        "--built-at",
        default=None,
        metavar="ISO8601",
        help=(
            "timezone-aware ISO 8601 build timestamp (defaults to now in "
            "UTC); fixed mainly for deterministic tests"
        ),
    )
    command_parser.add_argument(
        "--previous-manifest",
        type=Path,
        default=None,
        metavar="FILE",
        help="prior manifest.json to diff against for anomaly/versioning checks",
    )
    command_parser.add_argument(
        "--cdn-base",
        default=_DEFAULT_CDN_BASE,
        metavar="URL",
        help="CDN base URL substituted into rendered example configs",
    )
    command_parser.add_argument(
        "--templates-dir",
        type=Path,
        default=None,
        metavar="DIR",
        help=(
            "directory of example config templates (defaults to "
            "examples/templates in a source checkout, or /work/examples/"
            "templates inside the Docker builder image)"
        ),
    )


def _add_release_decision_arguments(command_parser: argparse.ArgumentParser) -> None:
    source_group = command_parser.add_mutually_exclusive_group()
    source_group.add_argument("--fixtures", type=Path, default=None, metavar="DIR")
    source_group.add_argument("--inputs", type=Path, default=None, metavar="DIR")
    command_parser.add_argument(
        "--previous-manifest", type=Path, default=None, metavar="FILE"
    )
    command_parser.add_argument("--built-at", default=None, metavar="ISO8601")


def _add_repo_argument(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--repo",
        default=None,
        metavar="OWNER/NAME",
        help=(
            "GitHub repository the release is published to (owner/name); "
            "defaults to the $GITHUB_REPOSITORY environment variable "
            "(set automatically by GitHub Actions) if not given"
        ),
    )


def _add_publish_arguments(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--dist",
        type=Path,
        required=True,
        metavar="DIR",
        help=(
            "completed build directory to publish, containing manifest.json, "
            "SHA256SUMS, and every artifact named by manifest.json's "
            "checksums; the release archive is expected as its sibling "
            "(<dist's parent>/<version>.tar.gz, per manifest.json's "
            "archive_filename)"
        ),
    )
    command_parser.add_argument(
        "--previous-manifest",
        type=Path,
        default=None,
        metavar="FILE",
        help=(
            "manifest.json currently live in object storage (the root /manifest.json), "
            "naming the prior version publication cleanup restores "
            "/latest/* from if this publish fails partway through; omit for "
            "an initial release with nothing previously published"
        ),
    )
    _add_repo_argument(command_parser)


def _add_rollback_arguments(command_parser: argparse.ArgumentParser) -> None:
    command_parser.add_argument(
        "--version",
        required=True,
        metavar="VERSION",
        help="previously published version to roll /latest/* back to",
    )
    command_parser.add_argument(
        "--target-manifest",
        type=Path,
        required=True,
        metavar="FILE",
        help=(
            "local copy of the immutable manifest.json published for "
            "--version (download /releases/<version>/manifest.json or use a "
            "backup of that file, not the archive-internal release/manifest.json); "
            "rollback does not rebuild anything and has no --dist of its own, "
            "so this file's checksums are what tell rollback which objects "
            "under releases/<version>/ to re-copy into /latest/* and what "
            "sha256 to verify the copy against"
        ),
    )
    _add_repo_argument(command_parser)


def main(argv: Sequence[str] | None = None) -> int:
    """Parse a pipeline command and dispatch it to its handler."""

    parser = build_parser()
    try:
        arguments = parser.parse_args(argv)
    except SystemExit as error:
        return int(error.code)
    if arguments.command is None:
        parser.print_help()
        return 0

    handler = _HANDLERS.get(arguments.command)
    if handler is None:  # pragma: no cover - COMMANDS/_HANDLERS kept in sync
        print(
            f"ru-routing: error: {arguments.command} is not wired yet",
            file=sys.stderr,
        )
        return 2
    return handler(arguments)


def run() -> None:
    """Run the command-line application."""

    raise SystemExit(main())


# ---------------------------------------------------------------------------
# check --config-only (unchanged behavior from the pre-Task-10 stub)
# ---------------------------------------------------------------------------


def _validate_config_only(config_root: Path) -> None:
    registry = load_registry(config_root / "sources.yaml")
    policy = load_policy(config_root / "categories.yaml")
    load_thresholds(config_root / "thresholds.yaml")
    if set(policy.source_categories) != registry.declared_category_keys():
        raise ConfigError(
            "source registry and category policy do not map the same keys"
        )


def _handle_check(arguments: argparse.Namespace) -> int:
    if getattr(arguments, "config_only", False):
        try:
            _validate_config_only(arguments.config)
        except ConfigError as error:
            print(f"ru-routing: invalid configuration: {error}", file=sys.stderr)
            return 2
        print("ru-routing: configuration is valid")
        return 0

    if arguments.fixtures is None and arguments.inputs is None:
        print(
            "ru-routing: error: check requires --fixtures or --inputs",
            file=sys.stderr,
        )
        return 2

    with _dist_directory(arguments.dist) as dist:
        try:
            _run_build(arguments, dist)
        except PipelineCliError as error:
            print(f"ru-routing: check failed: {error}", file=sys.stderr)
            return 1
    print("ru-routing: check passed")
    return 0


class _TempDist:
    """Context manager yielding either the requested ``--dist`` or a scratch dir."""

    def __init__(self, requested: Path | None) -> None:
        self._requested = requested
        self._temp: tempfile.TemporaryDirectory | None = None

    def __enter__(self) -> Path:
        if self._requested is not None:
            return self._requested
        self._temp = tempfile.TemporaryDirectory(prefix="ru-routing-check-")
        return Path(self._temp.name) / "dist"

    def __exit__(self, *exc_info: object) -> None:
        if self._temp is not None:
            self._temp.cleanup()


def _dist_directory(requested: Path | None) -> _TempDist:
    return _TempDist(requested)


# ---------------------------------------------------------------------------
# fetch
# ---------------------------------------------------------------------------


def _handle_fetch(arguments: argparse.Namespace) -> int:
    try:
        registry = load_registry(arguments.config / "sources.yaml")
    except ConfigError as error:
        print(f"ru-routing: invalid configuration: {error}", file=sys.stderr)
        return 2

    if arguments.offline_fixtures is not None:
        try:
            _write_offline_fetch_tree(
                registry, arguments.offline_fixtures, arguments.destination
            )
        except PipelineCliError as error:
            print(f"ru-routing: fetch failed: {error}", file=sys.stderr)
            return 1
        print(
            f"ru-routing: wrote offline fixture fetch tree to {arguments.destination}"
        )
        return 0

    try:
        with httpx.Client() as client:
            fetch_all(registry, arguments.destination, client)
    except Exception as error:  # noqa: BLE001 - fetch.FetchError plus transport errors
        print(f"ru-routing: fetch failed: {error}", file=sys.stderr)
        return 1
    print(f"ru-routing: fetched sources into {arguments.destination}")
    return 0


def _write_offline_fetch_tree(
    registry: SourceRegistry, fixtures_dir: Path, destination: Path
) -> None:
    """Write a fetch_all-shaped ``objects/``+``metadata/`` tree from fixtures.

    Mirrors ``fetch.fetch_all``'s on-disk contract exactly (see
    ``fetch.py``'s ``_write_metadata``) so ``build --inputs`` can read the
    result exactly as it would a real fetch, without any network access.
    This is an offline reproduction aid for tests/PR fixture flows, not a
    replacement for the real HTTP ``fetch_all`` path.
    """

    destination = Path(destination)
    objects_dir = destination / "objects"
    metadata_dir = destination / "metadata"
    objects_dir.mkdir(parents=True, exist_ok=True)
    metadata_dir.mkdir(parents=True, exist_ok=True)

    for source in registry.sources:
        object_paths: dict[str, tuple[Path, ...]] = {}
        for category in source.expected_categories:
            fixture_path = _fixture_file_for(fixtures_dir, source.name, category)
            if fixture_path is None:
                raise PipelineCliError(
                    f"no fixture file for {source.name}:{category} under "
                    f"{fixtures_dir}"
                )
            data = fixture_path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            target = objects_dir / digest
            if not target.exists():
                target.write_bytes(data)
            object_paths[category] = (target,)

        fetched = FetchedSource(
            name=source.name,
            resolved_revision="0" * 40,
            sha256="0" * 64,
            license=source.license,
            object_paths=object_paths,
            observed_freshness_lag_hours=None,
        )
        _write_offline_metadata(metadata_dir, destination, source, fetched)


def _write_offline_metadata(
    metadata_dir: Path,
    destination: Path,
    source: SourceDefinition,
    fetched: FetchedSource,
) -> None:
    objects = {
        category: [
            {
                "path": str(path.relative_to(destination)),
                "sha256": path.name,
            }
            for path in paths
        ]
        for category, paths in sorted(fetched.object_paths.items())
    }
    document = {
        "attribution": source.attribution,
        "license": {
            "redistribution_reviewed": source.license.redistribution_reviewed,
            "spdx": source.license.spdx,
        },
        "name": source.name,
        "objects": objects,
        "observed_freshness_age_hours": 0.0,
        "observed_freshness_lag_hours": fetched.observed_freshness_lag_hours,
        "resolved_revision": fetched.resolved_revision,
        "sha256": fetched.sha256,
    }
    (metadata_dir / f"{source.name.replace('/', '--')}.json").write_text(
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _fixture_file_for(
    fixtures_dir: Path, source_name: str, category: str
) -> Path | None:
    safe_name = source_name.replace("/", "_")
    prefix = f"{safe_name}--{category}"
    for candidate in sorted(Path(fixtures_dir).glob(f"{prefix}.*")):
        return candidate
    return None


# ---------------------------------------------------------------------------
# Shared rule acquisition: --fixtures / --inputs
# ---------------------------------------------------------------------------


class _FixtureGeodataReader:
    """Deterministic geodata decoder for --fixtures ``.dat`` placeholders.

    Loosely mirrors ``tests/test_examples.py``'s ``_FixtureGeodataReader``:
    real geoip_dat/geosite_dat artifacts are opaque binary blobs that only a
    real v2fly-format decoder can read, so PR/fixture builds substitute one
    synthetic entry per (input_type, category) instead. Unlike that
    single-process test helper, this one is exercised across separate CLI
    invocations that must produce byte-identical output (the whole point of
    ``--fixtures`` reproducibility), so it derives the index from a stable
    SHA-256 digest rather than Python's built-in ``hash()`` -- ``hash()`` on
    str/tuple is salted per-process by ``PYTHONHASHSEED`` and differs on
    every fresh interpreter, which silently broke determinism across two
    separate ``ru-routing build`` runs during Task 10's Docker
    verification.
    """

    def read(self, input_type: str, category: str, artifact: Path):
        digest = hashlib.sha256(f"{input_type}:{category}".encode("utf-8")).digest()
        index = int.from_bytes(digest[:4], "big") % 250 + 1
        if input_type == "geoip_dat":
            return (GeodataRule(kind=RuleKind.CIDR, value=f"203.0.{index}.0/24"),)
        return (GeodataRule(kind=RuleKind.DOMAIN_SUFFIX, value=f"fixture{index}.test"),)


def _fetched_sources_from_fixtures(
    registry: SourceRegistry, fixtures_dir: Path
) -> FetchedInputs:
    fetched: list[FetchedSource] = []
    for source in registry.sources:
        object_paths: dict[str, tuple[Path, ...]] = {}
        for category in source.expected_categories:
            fixture_path = _fixture_file_for(fixtures_dir, source.name, category)
            if fixture_path is None:
                raise PipelineCliError(
                    f"no fixture file for {source.name}:{category} under "
                    f"{fixtures_dir}"
                )
            object_paths[category] = (fixture_path,)
        fetched.append(
            FetchedSource(
                name=source.name,
                resolved_revision="0" * 40,
                sha256="0" * 64,
                license=source.license,
                object_paths=object_paths,
                observed_freshness_lag_hours=None,
            )
        )
    return FetchedInputs(sources=tuple(fetched), degraded_sources=())


def _fetched_sources_from_inputs(
    registry: SourceRegistry, inputs_dir: Path
) -> FetchedInputs:
    """Reconstruct FetchedSource tuples from a prior `fetch` output directory.

    Reads exactly the metadata documents fetch_all/_write_metadata writes
    (``<inputs>/metadata/<source>.json``), resolving each recorded object
    path (relative to ``inputs_dir``, per ``_write_metadata``) back to a
    concrete ``Path`` under ``<inputs>/objects/``.
    """

    inputs_dir = Path(inputs_dir)
    metadata_dir = inputs_dir / "metadata"
    objects_dir = inputs_dir / "objects"
    if not metadata_dir.is_dir():
        raise PipelineCliError(
            f"{inputs_dir} does not look like a fetch output directory "
            "(missing metadata/)"
        )
    if not objects_dir.is_dir():
        raise PipelineCliError(
            f"{inputs_dir} does not look like a fetch output directory "
            "(missing objects/)"
        )
    objects_root = objects_dir.resolve()
    digest_cache: dict[Path, str] = {}
    fetched: list[FetchedSource] = []
    degraded_sources: list[DegradedSource] = []
    for source in registry.sources:
        metadata_path = metadata_dir / f"{source.name.replace('/', '--')}.json"
        if not metadata_path.is_file():
            raise PipelineCliError(
                f"no fetched metadata for {source.name} under {inputs_dir}"
            )
        document = json.loads(metadata_path.read_text(encoding="utf-8"))
        if not isinstance(document, dict):
            raise PipelineCliError(
                f"{source.name}: fetched metadata must be a JSON object"
            )
        quarantine_fields = {
            "status",
            "reason",
            "excluded_from_build",
            "max_age_hours",
        }
        present_quarantine_fields = quarantine_fields & document.keys()
        if "objects" in document and present_quarantine_fields:
            raise PipelineCliError(
                f"{source.name}: quarantine metadata cannot contain objects"
            )
        if "objects" not in document:
            degraded_sources.append(_degraded_source_from_metadata(source, document))
            continue
        object_paths = {
            category: tuple(
                _validated_input_object_path(
                    source.name,
                    category,
                    entry,
                    inputs_dir=inputs_dir,
                    objects_root=objects_root,
                    digest_cache=digest_cache,
                )
                for entry in entries
            )
            for category, entries in document["objects"].items()
        }
        fetched.append(
            FetchedSource(
                name=document["name"],
                resolved_revision=document["resolved_revision"],
                sha256=document["sha256"],
                license=source.license,
                object_paths=object_paths,
                observed_freshness_lag_hours=document.get(
                    "observed_freshness_lag_hours"
                ),
            )
        )
    return FetchedInputs(
        sources=tuple(fetched), degraded_sources=tuple(degraded_sources)
    )


def _degraded_source_from_metadata(
    source: SourceDefinition, document: Mapping[str, object]
) -> DegradedSource:
    """Validate and reconstruct one stale-source quarantine record."""

    if document.get("name") != source.name:
        raise PipelineCliError(
            f"{source.name}: quarantine metadata has an unexpected source name"
        )
    if document.get("status") != "degraded":
        raise PipelineCliError(f"{source.name}: quarantine status must be degraded")
    if document.get("reason") != "stale":
        raise PipelineCliError(f"{source.name}: quarantine reason must be stale")
    if document.get("excluded_from_build") is not True:
        raise PipelineCliError(
            f"{source.name}: quarantine must be excluded from build"
        )
    age = document.get("observed_freshness_age_hours")
    if (
        isinstance(age, bool)
        or not isinstance(age, (int, float))
        or not math.isfinite(age)
        or age < 0
    ):
        raise PipelineCliError(
            f"{source.name}: quarantine observed freshness age must be non-negative"
        )
    maximum = document.get("max_age_hours")
    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise PipelineCliError(
            f"{source.name}: quarantine maximum age must be a positive integer"
        )
    return DegradedSource(
        name=source.name,
        status="degraded",
        reason="stale",
        excluded_from_build=True,
        observed_freshness_age_hours=float(age),
        max_age_hours=maximum,
    )


def _validated_input_object_path(
    source_name: str,
    category: str,
    entry: Mapping[str, object],
    *,
    inputs_dir: Path,
    objects_root: Path,
    digest_cache: dict[Path, str],
) -> Path:
    relative = entry.get("path")
    if not isinstance(relative, str) or not relative:
        raise PipelineCliError(
            f"{source_name}: {category}: fetched object entry is missing a valid path"
        )
    expected_digest = entry.get("sha256")
    if not _is_sha256(expected_digest):
        raise PipelineCliError(
            f"{source_name}: {category}: fetched object {relative} "
            "has an invalid sha256"
        )
    lexical = PurePosixPath(relative)
    if (
        lexical.is_absolute()
        or ".." in lexical.parts
        or not lexical.parts
        or lexical.parts[0] != "objects"
        or str(lexical) != relative
    ):
        raise PipelineCliError(
            f"{source_name}: {category}: fetched object path {relative!r} is unsafe"
        )
    candidate = inputs_dir / relative
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as error:
        raise PipelineCliError(
            f"{source_name}: {category}: cannot read fetched object {relative}: {error}"
        ) from error
    try:
        resolved.relative_to(objects_root)
    except ValueError as error:
        raise PipelineCliError(
            f"{source_name}: {category}: fetched object path {relative!r} "
            "resolves outside objects/"
        ) from error
    actual_digest = digest_cache.get(resolved)
    if actual_digest is None:
        actual_digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        digest_cache[resolved] = actual_digest
    if actual_digest != expected_digest:
        raise PipelineCliError(
            f"{source_name}: {category}: fetched object checksum mismatch "
            f"for {relative}"
        )
    return resolved


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _load_rules(
    arguments: argparse.Namespace, registry: SourceRegistry
) -> FetchedInputs:
    if arguments.fixtures is not None:
        return _fetched_sources_from_fixtures(registry, arguments.fixtures)
    if arguments.inputs is not None:
        return _fetched_sources_from_inputs(registry, arguments.inputs)
    raise PipelineCliError("either --fixtures or --inputs must be given")


def _affected_category_keys(
    policy: CategoryPolicy, degraded_sources: tuple[DegradedSource, ...]
) -> frozenset[str]:
    """Return dataset-qualified category keys affected by quarantined sources."""

    names = {source.name for source in degraded_sources}
    return frozenset(
        f"{dataset}:{mapping.canonical_category}"
        for mapping in policy.source_categories.values()
        if mapping.source in names
        for dataset in mapping.datasets
    )


# ---------------------------------------------------------------------------
# Fake native tools (--fake-native-tools)
# ---------------------------------------------------------------------------


class _FakeToolExecutor:
    """In-process stand-in for dlc/geoip/sing-box/mihomo/xray on PATH.

    Writes a small deterministic placeholder to whatever output path each
    real tool's argv shape implies (mirrors ``FakeRunner`` in
    ``tests/test_generate.py``/``tests/test_validate.py``) so
    ``generate_all``/``validate_build`` succeed without the pinned native
    toolchain this sandboxed environment does not have.
    """

    tool_versions = {
        "dlc": "fake-dlc",
        "geoip": "fake-geoip",
        "sing-box": "fake-sing-box",
        "mihomo": "fake-mihomo",
        "xray": "fake-xray",
    }

    def run(self, argv: Sequence[str], cwd: Path) -> CompletedTool:
        command = tuple(argv)
        working_directory = Path(cwd)
        output = self._output_for(command, working_directory)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(f"fake output for {command[0]}\n".encode())
        return CompletedTool(command, working_directory, 0, "ok\n", "")

    @staticmethod
    def _output_for(command: tuple[str, ...], cwd: Path) -> Path | None:
        name = command[0]
        if name.endswith("dlc") or name == "dlc-tool":
            output_dir = _flag(command, "--outputdir")
            output_name = _flag(command, "--outputname")
            if output_dir and output_name:
                return Path(output_dir) / output_name
            return None
        if name.endswith("geoip") or name == "geoip-tool":
            return cwd / "geoip.dat"
        if "sing-box" in name and "--output" in command:
            return Path(command[command.index("--output") + 1])
        if "mihomo" in name and "convert-ruleset" in command:
            return Path(command[-1])
        if name.endswith("xray") or "sing-box" in name or "mihomo" in name:
            # Config-validation / decompile calls that only need a
            # successful exit code, not a produced file (validate.py checks
            # decompile/convert output existence separately for those argv
            # shapes it cares about, matched above).
            if "rule-set" in command and "decompile" in command:
                idx = command.index("--output")
                return Path(command[idx + 1])
            if "convert-ruleset" in command:
                return Path(command[-1])
            return None
        return None


def _flag(command: tuple[str, ...], name: str) -> str | None:
    for part in command:
        if part.startswith(f"{name}="):
            return part.split("=", 1)[1]
    return None


def _native_tools(arguments: argparse.Namespace) -> NativeTools:
    if getattr(arguments, "fake_native_tools", False):
        return NativeTools(runner=_FakeToolExecutor())
    return NativeTools(runner=ToolRunner())


# ---------------------------------------------------------------------------
# build / check shared pipeline
# ---------------------------------------------------------------------------


def _built_at(arguments: argparse.Namespace) -> str:
    if getattr(arguments, "built_at", None):
        return arguments.built_at
    return datetime.now(timezone.utc).isoformat()


def _previous_manifest(arguments: argparse.Namespace) -> Mapping[str, object] | None:
    path = getattr(arguments, "previous_manifest", None)
    if path is None:
        return None
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise PipelineCliError(
            f"cannot read previous manifest {path}: {error}"
        ) from error


def _load_all_configs(config_root: Path):
    registry = load_registry(config_root / "sources.yaml")
    policy = load_policy(config_root / "categories.yaml")
    thresholds = load_thresholds(config_root / "thresholds.yaml")
    return registry, policy, thresholds


def _policy_configs(config_root: Path, policy) -> PolicyConfigs:
    return PolicyConfigs(
        source_registry_bytes=(config_root / "sources.yaml").read_bytes(),
        category_mapping_bytes=(config_root / "categories.yaml").read_bytes(),
    )


def _geodata_reader(arguments: argparse.Namespace):
    """Return the geoip_dat/geosite_dat decoder appropriate to the rule source.

    ``--fixtures`` contains placeholder bytes and therefore retains its stable
    synthetic reader. ``--inputs`` is a real fetch output and uses the strict
    v2fly protobuf reader for the pinned ``geoip_dat``/``geosite_dat`` sources.
    """

    if arguments.fixtures is not None:
        return _FixtureGeodataReader()
    return ProtobufGeodataReader()


def _run_build(arguments: argparse.Namespace, dist: Path) -> None:
    """Run fetch-acquisition through package_build against a caller-visible ``dist``.

    Wraps the whole multi-stage sequence in an outer staging directory and
    only atomically replaces the real ``dist`` once every stage below has
    succeeded (mirrors the staged-dir-then-``os.replace`` convention already
    used one level down, inside each individual stage -- see
    ``generate.py``'s ``_publish_tree``/``render.py``'s ``_staged_directory``).
    Each inner stage still does its own internal atomic staging-and-replace,
    but against a path inside this outer staging directory rather than the
    real ``dist`` -- that inner atomicity keeps each stage's own artifacts
    internally consistent, while this outer swap ensures the caller never
    observes a partial cross-stage tree (e.g. generate succeeded but
    validate/package did not). Without this, a failure after ``generate_all``
    would otherwise leave the caller-visible ``--dist`` populated with a
    generate-only partial tree (no manifest.json, no examples/, no
    SHA256SUMS) despite the command correctly reporting a nonzero exit code.
    """

    destination = Path(dist)
    destination.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=destination.parent)
    )
    try:
        _run_build_stages(arguments, stage)
        _publish_dist(stage, destination)
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _publish_dist(stage: Path, destination: Path) -> None:
    """Atomically replace ``destination`` with the now-complete ``stage`` tree."""

    backup = destination.with_name(f".{destination.name}.previous")
    if backup.exists():
        shutil.rmtree(backup)
    try:
        if destination.exists():
            os.replace(destination, backup)
        os.replace(stage, destination)
    except OSError:
        if backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    else:
        if backup.exists():
            shutil.rmtree(backup)


def _run_build_stages(arguments: argparse.Namespace, dist: Path) -> None:
    """Run the generate -> render_examples -> validate -> package sequence.

    ``dist`` here is the outer staging directory ``_run_build`` created, not
    the caller-visible ``--dist`` path; raises ``PipelineCliError``.
    """

    try:
        registry, policy, threshold_policy = _load_all_configs(arguments.config)
        fetched = _load_rules(arguments, registry)
        rules = normalize_sources(
            fetched.sources,
            registry=registry,
            geodata_reader=_geodata_reader(arguments),
        )
        resolved = resolve_datasets(rules, policy)

        tools = _native_tools(arguments)
        generate_all(resolved, dist, tools)

        thresholds = ValidationThresholds(
            check_determinism=not getattr(arguments, "fake_native_tools", False)
        )
        validate_build(resolved, dist, thresholds, tools)
        tool_versions = tools.tool_versions(dist)

        built_at = _built_at(arguments)
        previous_manifest = _previous_manifest(arguments)
        metadata_for_version = BuildMetadata(
            build=resolved,
            policy_configs=_policy_configs(arguments.config, policy),
            sources=fetched.sources,
            degraded_sources=fetched.degraded_sources,
            quarantined_category_keys=_affected_category_keys(
                policy, fetched.degraded_sources
            ),
            conflicts=resolved.conflicts,
            thresholds=threshold_policy,
            previous_manifest=previous_manifest,
            built_at=built_at,
            tool_versions=tool_versions,
        )
        decision = plan_release(metadata_for_version)
        templates_dir = getattr(arguments, "templates_dir", None) or (
            _default_templates_dir()
        )
        render_examples(
            templates_dir,
            dist,
            version=decision.version or "unreleased",
            cdn_base=getattr(arguments, "cdn_base", _DEFAULT_CDN_BASE),
        )

        metadata = BuildMetadata(
            build=resolved,
            policy_configs=_policy_configs(arguments.config, policy),
            sources=fetched.sources,
            degraded_sources=fetched.degraded_sources,
            quarantined_category_keys=_affected_category_keys(
                policy, fetched.degraded_sources
            ),
            conflicts=resolved.conflicts,
            thresholds=threshold_policy,
            previous_manifest=previous_manifest,
            built_at=built_at,
            tool_versions=tool_versions,
        )
        package_build(dist, metadata)
    except (
        ConfigError,
        NormalizationError,
        ResolutionError,
        GenerationError,
        ValidationError,
        PackagingError,
        AnomalyError,
        ParseError,
    ) as error:
        raise PipelineCliError(str(error)) from error


def _handle_build(arguments: argparse.Namespace) -> int:
    if arguments.fixtures is None and arguments.inputs is None:
        print(
            "ru-routing: error: build requires --fixtures or --inputs",
            file=sys.stderr,
        )
        return 2
    try:
        _run_build(arguments, arguments.dist)
    except PipelineCliError as error:
        print(f"ru-routing: build failed: {error}", file=sys.stderr)
        return 1
    print(f"ru-routing: build complete: {arguments.dist}")
    return 0


# ---------------------------------------------------------------------------
# release-decision
# ---------------------------------------------------------------------------


def _handle_release_decision(arguments: argparse.Namespace) -> int:
    if arguments.fixtures is None and arguments.inputs is None:
        print(
            "ru-routing: error: release-decision requires --fixtures or --inputs",
            file=sys.stderr,
        )
        return 2
    try:
        registry, policy, _ = _load_all_configs(arguments.config)
        fetched = _load_rules(arguments, registry)
        rules = normalize_sources(
            fetched.sources,
            registry=registry,
            geodata_reader=_geodata_reader(arguments),
        )
        resolved = resolve_datasets(rules, policy)
        threshold_policy = load_thresholds(arguments.config / "thresholds.yaml")

        metadata = BuildMetadata(
            build=resolved,
            policy_configs=_policy_configs(arguments.config, policy),
            sources=fetched.sources,
            degraded_sources=fetched.degraded_sources,
            quarantined_category_keys=_affected_category_keys(
                policy, fetched.degraded_sources
            ),
            conflicts=resolved.conflicts,
            thresholds=threshold_policy,
            previous_manifest=_previous_manifest(arguments),
            built_at=_built_at(arguments),
        )
        decision = plan_release(metadata)
    except (
        ConfigError,
        NormalizationError,
        ResolutionError,
        AnomalyError,
        PipelineCliError,
    ) as error:
        print(f"ru-routing: release-decision failed: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "should_release": decision.should_release,
                "version": decision.version,
                "reason": decision.reason,
                "content_fingerprint": decision.content_fingerprint,
                "policy_fingerprint": decision.policy_fingerprint,
            },
            sort_keys=True,
        )
    )
    return 0


# ---------------------------------------------------------------------------
# publish / rollback
# ---------------------------------------------------------------------------


def _default_backend_factory(repo: str) -> PublishBackend:
    """Build the real, production ``CliBackend`` wired to live credentials.

    Reads Yandex S3 credentials from the process environment via
    ``YandexS3Credentials.from_env`` (raising
    ``PublishError`` naming any missing variable -- never a value -- if one
    is absent). This is the default used by ``_handle_publish``/
    ``_handle_rollback``; tests instead pass a factory returning a
    ``FakeBackend`` (see ``backend_factory`` below), the same seam
    ``_native_tools``/``--fake-native-tools`` uses to keep ``build``
    testable without the real native toolchain.
    """

    yandex_s3 = YandexS3Credentials.from_env(os.environ)
    return CliBackend(yandex_s3=yandex_s3, repo=repo)


def _resolve_repo(arguments: argparse.Namespace) -> str:
    repo = getattr(arguments, "repo", None) or os.environ.get("GITHUB_REPOSITORY")
    if not repo:
        raise PublishError(
            "no repository given: pass --repo or set the $GITHUB_REPOSITORY "
            "environment variable"
        )
    return repo


def _load_manifest_file(path: Path) -> Manifest:
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except OSError as error:
        raise PublishError(f"cannot read manifest file {path}: {error}") from error
    except json.JSONDecodeError as error:
        raise PublishError(
            f"manifest file {path} is not valid JSON: {error}"
        ) from error
    try:
        return Manifest.from_json_dict(document)
    except KeyError as error:
        raise PublishError(
            f"manifest file {path} is missing required field {error}"
        ) from error


def _build_publish_plan(arguments: argparse.Namespace) -> PublishPlan:
    dist = Path(arguments.dist)
    manifest_path = dist / "manifest.json"
    if not manifest_path.is_file():
        raise PublishError(f"no manifest.json found in --dist directory {dist}")
    manifest = _load_manifest_file(manifest_path)

    if not manifest.archive_filename:
        raise PublishError(
            f"manifest.json in {dist} has no archive_filename; it does not "
            "look like a completed, packaged build"
        )
    archive_path = dist.parent / manifest.archive_filename
    if not archive_path.is_file():
        raise PublishError(
            f"release archive {archive_path} (named by manifest.json's "
            "archive_filename) does not exist next to --dist"
        )

    previous_manifest = None
    if arguments.previous_manifest is not None:
        previous_manifest = _load_manifest_file(arguments.previous_manifest)

    return PublishPlan(
        manifest=manifest,
        dist=dist,
        archive_path=archive_path,
        previous_manifest=previous_manifest,
    )


def _handle_publish(
    arguments: argparse.Namespace,
    *,
    backend_factory: Callable[[str], PublishBackend] = _default_backend_factory,
) -> int:
    try:
        repo = _resolve_repo(arguments)
        plan = _build_publish_plan(arguments)
        backend = backend_factory(repo)
        version = publish_release(plan, backend)
    except PublishError as error:
        print(f"ru-routing: publish failed: {error}", file=sys.stderr)
        return _PUBLISH_ERROR_EXIT_CODE
    print(f"ru-routing: published {version}")
    return 0


def _handle_rollback(
    arguments: argparse.Namespace,
    *,
    backend_factory: Callable[[str], PublishBackend] = _default_backend_factory,
) -> int:
    try:
        repo = _resolve_repo(arguments)
        target_manifest = _load_manifest_file(arguments.target_manifest)
        backend = backend_factory(repo)
        version = rollback_release(
            arguments.version, backend, target_manifest=target_manifest
        )
    except PublishError as error:
        print(f"ru-routing: rollback failed: {error}", file=sys.stderr)
        return _PUBLISH_ERROR_EXIT_CODE
    print(f"ru-routing: rolled back to {version}")
    return 0


_HANDLERS = {
    "fetch": _handle_fetch,
    "build": _handle_build,
    "check": _handle_check,
    "release-decision": _handle_release_decision,
    "publish": _handle_publish,
    "rollback": _handle_rollback,
}


if __name__ == "__main__":
    run()
