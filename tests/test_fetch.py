import hashlib
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import pytest

import ru_routing.fetch as fetch_module
from ru_routing.config import (
    FreshnessRule,
    LicenseMetadata,
    SourceDefinition,
    SourceRegistry,
)
from ru_routing.fetch import DegradedSource, FetchError, fetch_all


def source(
    name="example/source",
    url="https://raw.githubusercontent.com/example/source/0123456789abcdef/file.txt",
    *,
    layout="per_category_urls",
    location="https://raw.githubusercontent.com/example/source/0123456789abcdef/file.txt",
    freshness=FreshnessRule(max_age_hours=48),
):
    return SourceDefinition(
        name=name,
        url=url,
        input_type="plain_text",
        layout=layout,
        required=True,
        expected_categories=("rules",),
        category_locations={"rules": (location,)},
        attribution="Example contributors",
        license=LicenseMetadata("MIT", True),
        freshness=freshness,
    )


def local_source(location="config/overlays/universities-ru.txt"):
    return SourceDefinition(
        name="local/universities-ru-overlay",
        url=(
            "https://github.com/akent4000/ru-routing/blob/main/"
            "config/overlays/universities-ru.txt"
        ),
        input_type="local_text",
        layout="repository_file",
        required=True,
        expected_categories=("ru",),
        category_locations={"ru": (location,)},
        attribution="ru-routing maintainers",
        license=LicenseMetadata("NOASSERTION", True),
        freshness=FreshnessRule(max_age_hours=8760),
    )


def client(handler):
    return httpx.Client(transport=httpx.MockTransport(handler))


def test_fetches_local_text_into_content_addressed_metadata_without_http(
    tmp_path, monkeypatch
):
    repository_root = tmp_path / "repository"
    location = "config/overlays/universities-ru.txt"
    body = b"sso.example.edu\n"
    overlay = repository_root / location
    overlay.parent.mkdir(parents=True)
    overlay.write_bytes(body)
    monkeypatch.setattr(fetch_module, "_REPOSITORY_ROOT", repository_root)
    requests = []

    def handler(request):
        requests.append(request)
        pytest.fail(f"local source must not request HTTP: {request.url}")

    fetched = fetch_all(
        SourceRegistry((local_source(location),)), tmp_path / "inputs", client(handler)
    )

    digest = hashlib.sha256(body).hexdigest()
    item = fetched.sources[0]
    assert item.object_paths["ru"][0].read_text(encoding="utf-8") == "sso.example.edu\n"
    assert item.resolved_revision == digest
    assert item.sha256 == digest
    assert requests == []
    metadata_path = (
        tmp_path / "inputs" / "metadata" / "local--universities-ru-overlay.json"
    )
    assert json.loads(
        metadata_path.read_text(encoding="utf-8")
    ) == {
        "attribution": "ru-routing maintainers",
        "license": {"redistribution_reviewed": True, "spdx": "NOASSERTION"},
        "name": "local/universities-ru-overlay",
        "objects": {"ru": [{"path": f"objects/{digest}", "sha256": digest}]},
        "observed_freshness_lag_hours": None,
        "observed_freshness_age_hours": 0.0,
        "resolved_revision": digest,
        "sha256": digest,
    }


@pytest.mark.parametrize("location", ["/tmp/universities-ru.txt", "../overlay.txt"])
def test_local_text_locations_cannot_escape_the_repository_root(tmp_path, location):
    with pytest.raises(
        FetchError,
        match=r"local/universities-ru-overlay.*repository-relative location",
    ):
        fetch_all(
            SourceRegistry((local_source(location),)),
            tmp_path / "inputs",
            client(lambda request: pytest.fail(f"unexpected request: {request.url}")),
        )


def test_missing_local_text_file_names_source_and_location(tmp_path, monkeypatch):
    repository_root = tmp_path / "repository"
    repository_root.mkdir()
    location = "config/overlays/missing.txt"
    monkeypatch.setattr(fetch_module, "_REPOSITORY_ROOT", repository_root)

    with pytest.raises(
        FetchError,
        match=r"local/universities-ru-overlay.*config/overlays/missing\.txt",
    ):
        fetch_all(
            SourceRegistry((local_source(location),)),
            tmp_path / "inputs",
            client(lambda request: pytest.fail(f"unexpected request: {request.url}")),
        )


def test_fetches_a_pinned_raw_input_to_a_content_addressed_object_and_metadata(
    tmp_path,
):
    body = b"example.test\n"
    digest = hashlib.sha256(body).hexdigest()

    def handler(request):
        if request.url.path.endswith("/commits/0123456789abcdef"):
            return httpx.Response(
                200,
                json={
                    "sha": "0123456789abcdef",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        return httpx.Response(200, content=body)

    fetched = fetch_all(
        SourceRegistry((source(),)), tmp_path / "inputs", client(handler)
    )

    assert len(fetched.sources) == 1
    item = fetched.sources[0]
    assert item.resolved_revision == "0123456789abcdef"
    assert item.sha256 == digest
    assert item.license.spdx == "MIT"
    assert item.object_paths == {"rules": (tmp_path / "inputs" / "objects" / digest,)}
    assert item.object_paths["rules"][0].read_bytes() == body
    metadata = json.loads(
        (tmp_path / "inputs" / "metadata" / "example--source.json").read_text()
    )
    assert metadata == {
        "attribution": "Example contributors",
        "license": {"redistribution_reviewed": True, "spdx": "MIT"},
        "name": "example/source",
        "objects": {"rules": [{"path": f"objects/{digest}", "sha256": digest}]},
        "observed_freshness_lag_hours": None,
        "observed_freshness_age_hours": 0.0,
        "resolved_revision": "0123456789abcdef",
        "sha256": digest,
    }


def test_retries_transient_server_errors_before_downloading_required_input(tmp_path):
    attempts = 0
    body = b"example.test\n"

    def handler(request):
        nonlocal attempts
        if request.url.path.endswith("/commits/0123456789abcdef"):
            return httpx.Response(
                200,
                json={
                    "sha": "0123456789abcdef",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        attempts += 1
        if attempts < 3:
            return httpx.Response(503, content=b"credential=must-not-leak")
        return httpx.Response(200, content=body)

    fetched = fetch_all(
        SourceRegistry((source(),)), tmp_path / "inputs", client(handler)
    )

    assert attempts == 3
    assert fetched.sources[0].object_paths["rules"][0].read_bytes() == body


@pytest.mark.parametrize("body", [b"", b"   \n"])
def test_rejects_empty_required_input_without_replacing_prior_directory(tmp_path, body):
    destination = tmp_path / "inputs"
    destination.mkdir()
    (destination / "previous.txt").write_text("preserve me", encoding="utf-8")

    def handler(request):
        if request.url.path.endswith("/commits/0123456789abcdef"):
            return httpx.Response(
                200,
                json={
                    "sha": "0123456789abcdef",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        return httpx.Response(200, content=body)

    with pytest.raises(FetchError, match="example/source"):
        fetch_all(SourceRegistry((source(),)), destination, client(handler))

    assert (destination / "previous.txt").read_text(encoding="utf-8") == "preserve me"


def test_rejects_a_release_asset_whose_declared_checksum_does_not_match(tmp_path):
    body = b"actual bytes"
    metadata = {
        "tag_name": "v1.2.3",
        "target_commitish": "main",
        "published_at": "2999-01-01T00:00:00Z",
        "assets": [
            {
                "name": "rules.txt",
                "browser_download_url": "https://downloads.example.test/rules.txt",
                "digest": "sha256:" + ("0" * 64),
            }
        ],
    }

    def handler(request):
        if request.url.path == "/repos/example/source/releases/latest":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/repos/example/source/git/ref/tags/v1.2.3":
            return httpx.Response(
                200, json={"object": {"type": "commit", "sha": "tagged-commit"}}
            )
        if request.url.path.endswith("/commits/tagged-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "abcdef",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        return httpx.Response(200, content=body)

    release_source = source(
        url="https://api.github.com/repos/example/source/releases/latest",
        layout="release_assets",
        location="https://github.com/example/source/releases/download/latest/rules.txt",
    )

    with pytest.raises(FetchError, match="example/source"):
        fetch_all(
            SourceRegistry((release_source,)), tmp_path / "inputs", client(handler)
        )


def test_follows_a_resolved_release_asset_redirect_before_hashing_it(tmp_path):
    body = b"rules.example\n"
    metadata = {
        "tag_name": "v1.2.3",
        "target_commitish": "main",
        "published_at": "2999-01-01T00:00:00Z",
        "assets": [
            {
                "name": "rules.txt",
                "browser_download_url": "https://downloads.example.test/rules.txt",
                "digest": f"sha256:{hashlib.sha256(body).hexdigest()}",
            }
        ],
    }

    def handler(request):
        if request.url.path == "/repos/example/source/releases/latest":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/repos/example/source/git/ref/tags/v1.2.3":
            return httpx.Response(
                200, json={"object": {"type": "commit", "sha": "tagged-commit"}}
            )
        if request.url.path.endswith("/commits/tagged-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "abcdef",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        if request.url.host == "downloads.example.test":
            return httpx.Response(
                302, headers={"location": "https://objects.example.test/rules.txt"}
            )
        return httpx.Response(200, content=body)

    release_source = source(
        url="https://api.github.com/repos/example/source/releases/latest",
        layout="release_assets",
        location="https://github.com/example/source/releases/download/latest/rules.txt",
    )

    fetched = fetch_all(
        SourceRegistry((release_source,)), tmp_path / "inputs", client(handler)
    )

    assert fetched.sources[0].resolved_revision == "abcdef"
    assert fetched.sources[0].object_paths["rules"][0].read_bytes() == body


@pytest.mark.parametrize(
    ("reference_type", "reference_sha"),
    [("commit", "lightweight-commit"), ("tag", "annotated-tag-object")],
)
def test_resolves_release_tag_refs_to_the_tagged_commit(
    tmp_path, reference_type, reference_sha
):
    body = b"rules.example\n"
    metadata = {
        "tag_name": "v1.2.3",
        "target_commitish": "main",
        "published_at": "2999-01-01T00:00:00Z",
        "assets": [
            {
                "name": "rules.txt",
                "browser_download_url": "https://downloads.example.test/rules.txt",
                "digest": f"sha256:{hashlib.sha256(body).hexdigest()}",
            }
        ],
    }

    def handler(request):
        if request.url.path == "/repos/example/source/releases/latest":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/repos/example/source/git/ref/tags/v1.2.3":
            return httpx.Response(
                200, json={"object": {"type": reference_type, "sha": reference_sha}}
            )
        if request.url.path == "/repos/example/source/git/tags/annotated-tag-object":
            return httpx.Response(
                200,
                json={"object": {"type": "commit", "sha": "tagged-commit"}},
            )
        if request.url.path.endswith("/commits/lightweight-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "lightweight-commit",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        if request.url.path.endswith("/commits/tagged-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "tagged-commit",
                    "commit": {"author": {"date": "2999-01-01T00:00:00Z"}},
                },
            )
        if request.url.path.endswith("/commits/main"):
            pytest.fail("release provenance must not resolve target_commitish")
        return httpx.Response(200, content=body)

    release_source = source(
        url="https://api.github.com/repos/example/source/releases/latest",
        layout="release_assets",
        location="https://github.com/example/source/releases/download/latest/rules.txt",
    )

    fetched = fetch_all(
        SourceRegistry((release_source,)), tmp_path / "inputs", client(handler)
    )

    expected = "lightweight-commit" if reference_type == "commit" else "tagged-commit"
    assert fetched.sources[0].resolved_revision == expected


def test_rejects_aireps_when_v2fly_sync_lag_exceeds_its_declared_limit(tmp_path):
    now = datetime.now(timezone.utc)
    source_commit = now - timedelta(hours=72)
    upstream_commit = now - timedelta(hours=1)
    metadata = json.loads(
        Path("tests/fixtures/http/aireps-metadata.json").read_text(encoding="utf-8")
    )
    metadata["published_at"] = now.isoformat().replace("+00:00", "Z")

    def handler(request):
        if request.url.path == "/repos/aireps/geosite/releases/latest":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/repos/aireps/geosite/git/ref/tags/v2026.08.25":
            return httpx.Response(
                200,
                json={"object": {"type": "commit", "sha": "tagged-aireps-commit"}},
            )
        if request.url.path.endswith("/commits/tagged-aireps-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "aireps-commit",
                    "commit": {"author": {"date": source_commit.isoformat()}},
                },
            )
        if request.url.path.endswith("/commits/main"):
            return httpx.Response(
                200,
                json={
                    "sha": "moving-main-commit",
                    "commit": {"author": {"date": now.isoformat()}},
                },
            )
        if request.url.path == "/repos/v2fly/domain-list-community/commits":
            return httpx.Response(
                200,
                json=[
                    {
                        "sha": "v2fly-commit",
                        "commit": {"author": {"date": upstream_commit.isoformat()}},
                    }
                ],
            )
        return httpx.Response(200, content=b"geosite")

    aireps = source(
        name="aireps/geosite",
        url="https://github.com/aireps/geosite/releases/latest/download/geosite.dat",
        layout="single_artifact",
        location="https://github.com/aireps/geosite/releases/latest/download/geosite.dat",
        freshness=FreshnessRule(max_age_hours=48, max_sync_lag_hours=48),
    )

    with pytest.raises(FetchError, match="aireps/geosite"):
        fetch_all(SourceRegistry((aireps,)), tmp_path / "inputs", client(handler))


def test_fetch_quarantines_only_a_source_whose_age_exceeds_maximum(
    tmp_path, monkeypatch
):
    now = datetime.now(timezone.utc)
    fresh_url = "https://raw.githubusercontent.com/fresh/source/0123456789abcdef/file.txt"
    stale_url = "https://raw.githubusercontent.com/stale/source/0123456789abcdef/file.txt"
    fresh_source = source(name="fresh/source", url=fresh_url, location=fresh_url)
    stale_source = source(name="stale/source", url=stale_url, location=stale_url)
    monkeypatch.setattr(
        "ru_routing.fetch._age_hours",
        lambda timestamp: 1.0 if timestamp > now - timedelta(hours=24) else 49.0,
    )

    def handler(request):
        if request.url.path.endswith("/commits/0123456789abcdef"):
            source_name = request.url.path.split("/")[2]
            age = 1 if source_name == "fresh" else 49
            return httpx.Response(
                200,
                json={
                    "sha": "0123456789abcdef",
                    "commit": {
                        "author": {"date": (now - timedelta(hours=age)).isoformat()}
                    },
                },
            )
        return httpx.Response(200, content=b"example.test\n")

    result = fetch_all(
        SourceRegistry((fresh_source, stale_source)),
        tmp_path / "inputs",
        client(handler),
    )

    assert [item.name for item in result.sources] == ["fresh/source"]
    assert result.degraded_sources == (
        DegradedSource("stale/source", "degraded", "stale", True, 49.0, 48),
    )
    assert json.loads(
        (tmp_path / "inputs/metadata/stale--source.json").read_text()
    ) == {
        "excluded_from_build": True,
        "max_age_hours": 48,
        "name": "stale/source",
        "observed_freshness_age_hours": 49.0,
        "reason": "stale",
        "status": "degraded",
    }


def test_fetch_keeps_checksum_and_sync_lag_failures_fatal(tmp_path):
    now = datetime.now(timezone.utc)
    source_commit = now - timedelta(hours=72)
    upstream_commit = now - timedelta(hours=1)
    metadata = json.loads(
        Path("tests/fixtures/http/aireps-metadata.json").read_text(encoding="utf-8")
    )
    metadata["published_at"] = now.isoformat().replace("+00:00", "Z")

    def handler(request):
        if request.url.path == "/repos/aireps/geosite/releases/latest":
            return httpx.Response(200, json=metadata)
        if request.url.path == "/repos/aireps/geosite/git/ref/tags/v2026.08.25":
            return httpx.Response(
                200,
                json={"object": {"type": "commit", "sha": "tagged-aireps-commit"}},
            )
        if request.url.path.endswith("/commits/tagged-aireps-commit"):
            return httpx.Response(
                200,
                json={
                    "sha": "aireps-commit",
                    "commit": {"author": {"date": source_commit.isoformat()}},
                },
            )
        if request.url.path == "/repos/v2fly/domain-list-community/commits":
            return httpx.Response(
                200,
                json=[
                    {
                        "sha": "v2fly-commit",
                        "commit": {"author": {"date": upstream_commit.isoformat()}},
                    }
                ],
            )
        return httpx.Response(200, content=b"geosite")

    lagging_source = source(
        name="aireps/geosite",
        url="https://github.com/aireps/geosite/releases/latest/download/geosite.dat",
        layout="single_artifact",
        location="https://github.com/aireps/geosite/releases/latest/download/geosite.dat",
        freshness=FreshnessRule(max_age_hours=48, max_sync_lag_hours=48),
    )

    with pytest.raises(FetchError, match="synchronization lag"):
        fetch_all(
            SourceRegistry((lagging_source,)), tmp_path / "inputs", client(handler)
        )


def _builtin_source(
    name="builtin/private-networks",
    *,
    expected_categories=("private",),
):
    return SourceDefinition(
        name=name,
        url="https://example.test/documentation-only",
        input_type="builtin",
        layout="per_category_urls",
        required=True,
        expected_categories=expected_categories,
        category_locations={
            category: ("https://example.test/documentation-only",)
            for category in expected_categories
        },
        attribution="Example builtin contributors",
        license=LicenseMetadata("CC0-1.0", True),
        freshness=FreshnessRule(max_age_hours=8760),
    )


def test_builtin_source_is_fetched_without_any_network_request(tmp_path):
    def handler(request):
        raise AssertionError(
            f"builtin source must not make any network request, got {request.url}"
        )

    fetched = fetch_all(
        SourceRegistry((_builtin_source(),)), tmp_path / "inputs", client(handler)
    )

    assert len(fetched.sources) == 1
    item = fetched.sources[0]
    assert item.observed_freshness_lag_hours is None
    assert set(item.object_paths) == {"private"}
    (path,) = item.object_paths["private"]
    assert path.is_file()
    assert path.read_text(encoding="utf-8").strip()


def test_builtin_source_resolved_revision_is_stable_across_fetches(tmp_path):
    def handler(request):
        raise AssertionError("builtin source must not make any network request")

    first = fetch_all(
        SourceRegistry((_builtin_source(),)), tmp_path / "inputs-1", client(handler)
    )
    second = fetch_all(
        SourceRegistry((_builtin_source(),)), tmp_path / "inputs-2", client(handler)
    )

    assert first.sources[0].resolved_revision == second.sources[0].resolved_revision
    assert first.sources[0].sha256 == second.sources[0].sha256
