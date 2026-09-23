from pathlib import Path

from ru_routing.config import load_policy, load_registry
from ru_routing.fetch import FetchedSource
from ru_routing.models import RuleKind
from ru_routing.normalize import normalize_sources
from ru_routing.resolve import resolve_datasets


def test_max_list_check_domains_remain_separate_exact_host_categories():
    registry = load_registry(Path('config/sources.yaml'))
    policy = load_policy(Path('config/categories.yaml'))
    source = registry.resolve('fatyzzz/max-list')
    root = Path('tests/fixtures/upstreams/registry')
    fetched = FetchedSource(
        name=source.name,
        resolved_revision='fixture',
        sha256='0' * 64,
        license=source.license,
        object_paths={
            category: (root / f'fatyzzz_max-list--{category}.txt',)
            for category in source.expected_categories
        },
        observed_freshness_lag_hours=None,
    )

    build = resolve_datasets(normalize_sources((fetched,), registry=registry), policy)

    for dataset in (build.lite, build.server):
        assert {
            (entry.kind, entry.value)
            for entry in dataset.categories['max-ip-check'].entries
        } == {
            (RuleKind.DOMAIN, 'api.ipify.org'),
            (RuleKind.DOMAIN, 'ip.mail.ru'),
        }
        assert {
            (entry.kind, entry.value)
            for entry in dataset.categories['max-vpndetect'].entries
        } == {
            (RuleKind.DOMAIN, 'calls.okcdn.ru'),
            (RuleKind.DOMAIN, 'gstatic.com'),
        }
        assert 'ru' not in dataset.categories
