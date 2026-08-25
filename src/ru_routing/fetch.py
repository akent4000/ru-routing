"""Deterministic, transactional fetching of required routing inputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping
from urllib.parse import urlparse

import httpx

from .config import LicenseMetadata, SourceDefinition, SourceRegistry

_REQUEST_TIMEOUT = httpx.Timeout(connect=5.0, read=30.0, write=30.0, pool=5.0)
_MAX_RETRIES = 3
_RETRY_DELAY_SECONDS = 0.1
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GITHUB_RAW_HOST = "raw.githubusercontent.com"


class FetchError(RuntimeError):
    """Raised when a required source cannot be resolved or validated."""


@dataclass(frozen=True)
class FetchedSource:
    """Resolved, validated source provenance and its downloaded objects."""

    name: str
    resolved_revision: str
    sha256: str
    license: LicenseMetadata
    object_paths: Mapping[str, tuple[Path, ...]]
    observed_freshness_lag_hours: float | None

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "object_paths",
            MappingProxyType(
                {
                    category: tuple(paths)
                    for category, paths in self.object_paths.items()
                }
            ),
        )


@dataclass(frozen=True)
class _Release:
    revision: str
    published_at: datetime
    commit_at: datetime
    assets: Mapping[str, tuple[str, str | None]]


def fetch_all(
    registry: SourceRegistry, destination: Path, client: httpx.Client
) -> tuple[FetchedSource, ...]:
    """Fetch every required source into ``destination`` as one transaction.

    The prior destination is left untouched until every upstream has been
    resolved, downloaded, checksummed, and checked for freshness.
    """

    destination = Path(destination)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{destination.name}.staging-", dir=destination.parent)
    )
    try:
        objects_dir = staging / "objects"
        metadata_dir = staging / "metadata"
        objects_dir.mkdir()
        metadata_dir.mkdir()
        staged = tuple(
            _fetch_source(source, objects_dir, metadata_dir, client)
            for source in registry.sources
        )
        _replace_directory(staging, destination)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    return tuple(
        FetchedSource(
            name=item.name,
            resolved_revision=item.resolved_revision,
            sha256=item.sha256,
            license=item.license,
            object_paths={
                category: tuple(
                    destination / path.relative_to(staging) for path in paths
                )
                for category, paths in item.object_paths.items()
            },
            observed_freshness_lag_hours=item.observed_freshness_lag_hours,
        )
        for item in staged
    )


def _fetch_source(
    source: SourceDefinition,
    objects_dir: Path,
    metadata_dir: Path,
    client: httpx.Client,
) -> FetchedSource:
    _validate_license(source)
    try:
        release = _resolve_release(source, client)
        if release is None:
            revision, source_time = _resolve_raw_commit(source, client)
            locations = source.category_locations
        else:
            revision = release.revision
            source_time = release.published_at
            locations = _release_locations(source, release)
        age_hours = _age_hours(source_time)
        if age_hours > source.freshness.max_age_hours:
            raise FetchError("freshness age exceeds declared limit")
        lag_hours = _sync_lag_hours(source, release, client)
        if (
            lag_hours is not None
            and source.freshness.max_sync_lag_hours is not None
            and lag_hours > source.freshness.max_sync_lag_hours
        ):
            raise FetchError("synchronization lag exceeds declared limit")
        paths, object_digests = _download_locations(
            source, locations, objects_dir, client
        )
        source_digest = _source_digest(object_digests)
        fetched = FetchedSource(
            name=source.name,
            resolved_revision=revision,
            sha256=source_digest,
            license=source.license,
            object_paths=paths,
            observed_freshness_lag_hours=lag_hours,
        )
        _write_metadata(metadata_dir, source, fetched, age_hours, object_digests)
        return fetched
    except FetchError as error:
        raise FetchError(f"fetch failed for source {source.name}: {error}") from error
    except (OSError, ValueError, httpx.HTTPError) as error:
        raise FetchError(
            f"fetch failed for source {source.name}: request failed"
        ) from error


def _validate_license(source: SourceDefinition) -> None:
    if not source.license.redistribution_reviewed or not source.license.spdx:
        raise FetchError("license is not approved for redistribution")


def _resolve_release(source: SourceDefinition, client: httpx.Client) -> _Release | None:
    endpoint = _release_endpoint(source.url)
    if endpoint is None:
        return None
    document = _json_response(source.name, endpoint, client)
    tag_name = _required_string(document, "tag_name")
    target = _required_string(document, "target_commitish")
    published_at = _required_datetime(document, "published_at")
    owner, repository = _github_repository(endpoint)
    commit = _json_response(
        source.name,
        f"https://api.github.com/repos/{owner}/{repository}/commits/{target}",
        client,
    )
    revision = _required_string(commit, "sha")
    commit_at = _commit_datetime(commit)
    raw_assets = document.get("assets")
    if not isinstance(raw_assets, list):
        raise FetchError("release metadata has no assets")
    assets: dict[str, tuple[str, str | None]] = {}
    for asset in raw_assets:
        if not isinstance(asset, dict):
            raise FetchError("release metadata contains an invalid asset")
        name = _required_string(asset, "name")
        url = _required_string(asset, "browser_download_url")
        digest = asset.get("digest")
        if digest is not None and not isinstance(digest, str):
            raise FetchError("release asset checksum is invalid")
        assets[name] = (url, _parse_digest(digest) if digest else None)
    if not assets:
        raise FetchError("release metadata has no assets")
    # The release tag is recorded in metadata by the caller's resolved commit;
    # validating it here ensures an incomplete release response is never accepted.
    if not tag_name:
        raise FetchError("release metadata has no tag")
    return _Release(revision, published_at, commit_at, MappingProxyType(assets))


def _resolve_raw_commit(
    source: SourceDefinition, client: httpx.Client
) -> tuple[str, datetime]:
    parsed = urlparse(source.url)
    if parsed.hostname != _GITHUB_RAW_HOST:
        raise FetchError("source is not a resolvable GitHub revision")
    segments = [part for part in parsed.path.split("/") if part]
    if len(segments) < 4:
        raise FetchError("source does not include an immutable revision")
    owner, repository, revision = segments[:3]
    commit = _json_response(
        source.name,
        f"https://api.github.com/repos/{owner}/{repository}/commits/{revision}",
        client,
    )
    resolved = _required_string(commit, "sha")
    return resolved, _commit_datetime(commit)


def _sync_lag_hours(
    source: SourceDefinition, release: _Release | None, client: httpx.Client
) -> float | None:
    if source.name != "aireps/geosite" or release is None:
        return None
    document = _json_response(
        source.name,
        "https://api.github.com/repos/v2fly/domain-list-community/commits?per_page=1",
        client,
    )
    if not isinstance(document, list) or not document:
        raise FetchError("v2fly metadata has no commit")
    newest = document[0]
    if not isinstance(newest, dict):
        raise FetchError("v2fly metadata has an invalid commit")
    upstream_time = _commit_datetime(newest)
    return round(
        max(0.0, (upstream_time - release.commit_at).total_seconds() / 3600), 6
    )


def _release_locations(
    source: SourceDefinition, release: _Release
) -> Mapping[str, tuple[tuple[str, str | None], ...]]:
    locations: dict[str, tuple[tuple[str, str | None], ...]] = {}
    for category, category_locations in source.category_locations.items():
        resolved: list[tuple[str, str | None]] = []
        for location in category_locations:
            asset_name = Path(urlparse(location).path).name
            try:
                resolved.append(release.assets[asset_name])
            except KeyError as error:
                raise FetchError("release is missing a required asset") from error
        locations[category] = tuple(resolved)
    return MappingProxyType(locations)


def _download_locations(
    source: SourceDefinition,
    locations: Mapping[str, tuple[str, ...]]
    | Mapping[str, tuple[tuple[str, str | None], ...]],
    objects_dir: Path,
    client: httpx.Client,
) -> tuple[Mapping[str, tuple[Path, ...]], tuple[str, ...]]:
    downloaded: dict[tuple[str, str | None], tuple[Path, str]] = {}
    paths: dict[str, tuple[Path, ...]] = {}
    ordered_digests: list[str] = []
    for category, category_locations in locations.items():
        category_paths: list[Path] = []
        for location in category_locations:
            request = location if isinstance(location, tuple) else (location, None)
            if request not in downloaded:
                downloaded[request] = _download_object(
                    source.name, request[0], request[1], objects_dir, client
                )
            path, digest = downloaded[request]
            category_paths.append(path)
            ordered_digests.append(digest)
        paths[category] = tuple(category_paths)
    return MappingProxyType(paths), tuple(ordered_digests)


def _download_object(
    source_name: str,
    url: str,
    expected_digest: str | None,
    objects_dir: Path,
    client: httpx.Client,
) -> tuple[Path, str]:
    for attempt in range(_MAX_RETRIES + 1):
        temporary: Path | None = None
        try:
            response_context = client.stream(
                "GET", url, follow_redirects=True, timeout=_REQUEST_TIMEOUT
            )
            with response_context as response:
                if response.status_code >= 500:
                    raise _RetryableResponse()
                if response.status_code >= 400:
                    raise FetchError("upstream returned a non-success status")
                descriptor, name = tempfile.mkstemp(
                    prefix=".download-", dir=objects_dir
                )
                temporary = Path(name)
                digest = hashlib.sha256()
                has_content = False
                with os.fdopen(descriptor, "wb") as output:
                    for chunk in response.iter_bytes():
                        digest.update(chunk)
                        has_content = has_content or bool(chunk.strip())
                        output.write(chunk)
            actual_digest = digest.hexdigest()
            if not has_content:
                raise FetchError("required input is empty")
            if expected_digest is not None and actual_digest != expected_digest:
                raise FetchError("download checksum does not match release metadata")
            target = objects_dir / actual_digest
            if target.exists():
                temporary.unlink()
            else:
                os.replace(temporary, target)
            return target, actual_digest
        except _RetryableResponse:
            if attempt == _MAX_RETRIES:
                raise FetchError(
                    "upstream remained unavailable after retries"
                ) from None
            time.sleep(_RETRY_DELAY_SECONDS * (2**attempt))
        except httpx.TransportError:
            if attempt == _MAX_RETRIES:
                raise FetchError("upstream transport failed after retries") from None
            time.sleep(_RETRY_DELAY_SECONDS * (2**attempt))
        finally:
            if temporary is not None and temporary.exists():
                temporary.unlink()
    raise AssertionError("retry loop must return or raise")


class _RetryableResponse(Exception):
    """Internal marker for transient HTTP server responses."""


def _json_response(source_name: str, url: str, client: httpx.Client) -> Any:
    for attempt in range(_MAX_RETRIES + 1):
        try:
            response = client.get(url, timeout=_REQUEST_TIMEOUT)
            if response.status_code >= 500:
                raise _RetryableResponse()
            if response.status_code >= 400:
                raise FetchError("upstream metadata returned a non-success status")
            return response.json()
        except _RetryableResponse:
            if attempt == _MAX_RETRIES:
                raise FetchError(
                    "upstream metadata remained unavailable after retries"
                ) from None
            time.sleep(_RETRY_DELAY_SECONDS * (2**attempt))
        except httpx.TransportError:
            if attempt == _MAX_RETRIES:
                raise FetchError(
                    "upstream metadata transport failed after retries"
                ) from None
            time.sleep(_RETRY_DELAY_SECONDS * (2**attempt))
        except (json.JSONDecodeError, ValueError) as error:
            raise FetchError("upstream metadata is not valid JSON") from error
    raise AssertionError("retry loop must return or raise")


def _write_metadata(
    directory: Path,
    source: SourceDefinition,
    fetched: FetchedSource,
    age_hours: float,
    object_digests: tuple[str, ...],
) -> None:
    digest_by_path = {
        path: digest
        for path, digest in zip(_all_paths(fetched.object_paths), object_digests)
    }
    objects = {
        category: [
            {
                "path": str(path.relative_to(directory.parent)),
                "sha256": digest_by_path[path],
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
        "observed_freshness_age_hours": age_hours,
        "observed_freshness_lag_hours": fetched.observed_freshness_lag_hours,
        "resolved_revision": fetched.resolved_revision,
        "sha256": fetched.sha256,
    }
    (directory / f"{source.name.replace('/', '--')}.json").write_text(
        json.dumps(document, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _all_paths(paths: Mapping[str, tuple[Path, ...]]) -> tuple[Path, ...]:
    return tuple(path for category in paths.values() for path in category)


def _source_digest(object_digests: tuple[str, ...]) -> str:
    unique_digests = tuple(dict.fromkeys(object_digests))
    if len(unique_digests) == 1:
        return unique_digests[0]
    return hashlib.sha256("\n".join(unique_digests).encode("ascii")).hexdigest()


def _release_endpoint(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.hostname == "api.github.com" and parsed.path.endswith("/releases/latest"):
        return url
    if parsed.hostname == "github.com" and "/releases/latest/download/" in parsed.path:
        owner, repository = _github_repository(url)
        return f"https://api.github.com/repos/{owner}/{repository}/releases/latest"
    return None


def _github_repository(url: str) -> tuple[str, str]:
    parts = [part for part in urlparse(url).path.split("/") if part]
    if len(parts) < 3 or parts[0] != "repos":
        if len(parts) < 2:
            raise FetchError("GitHub URL does not identify a repository")
        return parts[0], parts[1]
    return parts[1], parts[2]


def _required_string(document: Mapping[str, Any], field: str) -> str:
    value = document.get(field)
    if not isinstance(value, str) or not value:
        raise FetchError("upstream metadata is incomplete")
    return value


def _required_datetime(document: Mapping[str, Any], field: str) -> datetime:
    value = _required_string(document, field)
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            timezone.utc
        )
    except ValueError as error:
        raise FetchError("upstream timestamp is invalid") from error


def _commit_datetime(document: Mapping[str, Any]) -> datetime:
    commit = document.get("commit")
    if not isinstance(commit, dict):
        raise FetchError("upstream commit metadata is incomplete")
    author = commit.get("author")
    if not isinstance(author, dict):
        raise FetchError("upstream commit metadata is incomplete")
    return _required_datetime(author, "date")


def _parse_digest(value: str) -> str:
    algorithm, separator, digest = value.partition(":")
    if algorithm != "sha256" or not separator or not _SHA256.fullmatch(digest):
        raise FetchError("release asset checksum is invalid")
    return digest


def _age_hours(timestamp: datetime) -> float:
    return round(
        max(0.0, (datetime.now(timezone.utc) - timestamp).total_seconds() / 3600), 6
    )


def _replace_directory(staging: Path, destination: Path) -> None:
    if not destination.exists():
        os.replace(staging, destination)
        return
    backup = Path(
        tempfile.mkdtemp(
            prefix=f".{destination.name}.previous-", dir=destination.parent
        )
    )
    backup.rmdir()
    try:
        os.replace(destination, backup)
        os.replace(staging, destination)
    except OSError:
        if backup.exists() and not destination.exists():
            os.replace(backup, destination)
        raise
    shutil.rmtree(backup)
