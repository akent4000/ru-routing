# RU routing datasets

This repository builds deterministic Russian split-routing datasets for Xray,
sing-box, and Mihomo. It combines reviewed upstream domain and CIDR lists,
normalizes conflicts, validates native artifacts, and publishes auditable
`lite` and `server` releases.

## Choose a dataset

- `lite` is the compact client policy. It sends trusted RU and Russia-only
  destinations directly, sends explicitly blocked RU destinations through the
  deployment's proxy, blocks `spy`, and sends unmatched traffic through the
  proxy. `ads` and `trackers` are included but opt-in.
- `server` is a self-contained superset for an egress node. It includes the
  configured service categories and reviewed RU GeoIP category, blocks
  spy/ads, supports selected inter-node routes, and sends unmatched traffic
  directly.

For every category shared by both datasets, validation enforces
`server >= lite` after conflict resolution. Private/local IP traffic stays in
each engine's native rules, while private/local domains are published in the
generated `private` domain artifacts; both route directly in the examples.

## Engines and artifacts

The versions below are the minimum versions this project currently verifies.
Older versions may work, but are not part of the compatibility contract.

| Engine | Minimum verified version | Main artifacts |
| --- | ---: | --- |
| Xray-core | 26.3.27 | `xray/geoip-lite.dat`, `xray/geosite-lite.dat`, `xray/geoip.dat`, `xray/geosite.dat` |
| sing-box | 1.13.19 | `sing-box/{lite,server}/*.json` and `*.srs` |
| Mihomo | 1.19.30 | `mihomo/{lite,server}/*.yaml` and `*.mrs` |

Raw normalized lists are also published below `raw/{lite,server}/`, and
complete rendered configurations are published below `examples/`. The builder
image pins these engine versions and the exact `dlc`, `geoip`, Python, and Go
toolchains; see [Dockerfile](Dockerfile).

Every distribution also carries `LICENSES.md` and the applicable exact
upstream license files below `licenses/upstream/`; the manifest and
`SHA256SUMS` cover them like all other public artifacts.

The checked-in templates are:

- [Xray lite](examples/templates/xray-lite.json) and
  [Xray server](examples/templates/xray-server.json)
- [sing-box lite](examples/templates/sing-box-lite.json) and
  [sing-box server](examples/templates/sing-box-server.json)
- [Mihomo lite](examples/templates/mihomo-lite.yaml) and
  [Mihomo server](examples/templates/mihomo-server.yaml)

Replace every `proxy` or `node-example` placeholder with deployment-specific
outbounds and credentials. Xray has native BitTorrent protocol matching. The
sing-box and Mihomo examples document their weaker approximations and do not
claim protocol-detection parity.

## Download URLs and consistency

The public base URL is `https://routing.akent.site`.

The human-readable release index is available at
`https://routing.akent.site/`. It is a convenience page; use
`manifest.json` as the source of truth when a consistent release snapshot is
required.

| Purpose | URL form | Cache behavior |
| --- | --- | --- |
| Human-readable release index | `https://routing.akent.site/` | 5 minutes, revalidate |
| Current manifest pointer | `https://routing.akent.site/manifest.json` | 5 minutes, revalidate |
| Current convenience object | `https://routing.akent.site/latest/<artifact>` | 5 minutes, revalidate |
| Immutable version object | `https://routing.akent.site/releases/<version>/<artifact>` | 1 year, immutable |
| Current checksums | `https://routing.akent.site/SHA256SUMS` | 5 minutes, revalidate |

For example, the stable Xray lite geosite URL is:

```text
https://routing.akent.site/latest/xray/geosite-lite.dat
```

The same object pinned to a release is:

```text
https://routing.akent.site/releases/<version>/xray/geosite-lite.dat
```

`/latest/*` is a convenience tree, not an atomic snapshot. During an update,
different objects there can briefly come from different releases. Integrations
that need a consistent set must fetch `/manifest.json`, read
`latest_version`, and then fetch every artifact from that exact
`/releases/<version>/` prefix:

```python
import json
from urllib.request import urlopen

base = "https://routing.akent.site"
with urlopen(f"{base}/manifest.json") as response:
    version = json.load(response)["latest_version"]

geosite_url = f"{base}/releases/{version}/xray/geosite-lite.dat"
```

Verify downloaded artifacts against the manifest's `checksums` map or the
published `SHA256SUMS`. `manifest.json` is the single pointer of record.

## Category matrix

This table follows [config/categories.yaml](config/categories.yaml), which is
the policy source of truth.

| Category | Dataset | Content | Intended/default action |
| --- | --- | --- | --- |
| `ru` | lite, server | domains | DIRECT |
| `ru-global` | server | domains | trusted RU direct candidate; not in the default example |
| `blocked` | lite, server | domains and CIDRs | PROXY, before any RU DIRECT match |
| `private` | lite, server | domains and CIDRs | DIRECT |
| `ru-inside` | lite, server | domains | DIRECT |
| `ru-geoip` | lite, server | CIDRs | DIRECT |
| `spy` | lite, server | domains | BLOCK |
| `ads` | lite, server | domains | lite opt-in; server BLOCK |
| `trackers` | lite, server | domains | optional tracker policy; Mihomo uses REJECT as its BitTorrent approximation |
| `google` | server | domains | example named inter-node route |
| `youtube` | server | domains | example named inter-node route |
| `telegram` | server | domains | optional service route |
| `discord` | server | domains | optional service route |
| `meta` | server | domains | optional service route |
| `github` | server | domains | optional service route |
| `ai` | server | domains | optional service route |
| `ru-whitelist` | lite, server | domains | DIRECT; from `aireps/geosite:whitelist` and `kirilllavrov/RU-domain-list-for-whitelist:whitelist-ru` |
| `ru-direct-geoip` | lite, server | CIDRs | DIRECT; from `hydraponique/roscomvpn-geoip:direct` and `:whitelist`, covering RU-service infrastructure outside `ru-geoip` |

`itdoginfo/allow-domains`, `hydraponique/roscomvpn-geoip`, and
`kirilllavrov/RU-domain-list-for-whitelist` are included in the source
registry under an SPDX `NOASSERTION` license status: their upstreams declare
no verifiable redistribution license, so they are consumed with attribution
under a maintainer decision rather than a confirmed grant. `ru` is currently
domain-only from sources with confirmed licenses; `ru-geoip` is the
license-reviewed RU CIDR source; `ru-direct-geoip` is the
NOASSERTION direct-CIDR candidate layer; `ru-services` is not published. See
[LICENSES.md](LICENSES.md) for the evidence and re-review policy.

Policy precedence is deny (`spy`), explicit `blocked`, trusted RU direct, then
thematic categories. A blocked entry is never allowed to remain in a
conflicting lite DIRECT category.

## Local development and builds

Use Python 3.11 or later:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e . pytest ruff
pytest -q
ruff check .
python3 -m compileall -q src
```

Fast, offline checks use committed fixtures and fake native tools:

```bash
ru-routing check --config-only
ru-routing check \
  --fixtures tests/fixtures/upstreams/registry \
  --fake-native-tools
ru-routing build \
  --fixtures tests/fixtures/upstreams/registry \
  --fake-native-tools \
  --dist output/dist
```

For a release-equivalent build, use the pinned container toolchain. The
container runs as uid 10001, so make the disposable output directory writable
by that uid first.

```bash
mkdir -p output
chmod ugo+rwx output
docker compose build builder
docker compose run --rm builder \
  build \
  --fixtures tests/fixtures/upstreams/registry \
  --dist /work/output/dist
```

To fetch and build the live source snapshot without publishing it:

```bash
docker compose run --rm builder \
  fetch --destination /work/output/fetched
docker compose run --rm builder \
  build --inputs /work/output/fetched \
  --dist /work/output/dist
```

Inspect `output/fetched/metadata/` before using a new snapshot. Routine live
builds and updates should go through the protected hourly workflow, which
performs the complete fetch, native validation, change decision, and publish
sequence. A manual run is:

```bash
gh workflow run update.yml --repo "$GITHUB_REPOSITORY"
```

## Yandex Object Storage and GitHub bootstrap

Publication targets Yandex Object Storage at the public bucket/domain
`routing.akent.site`, served over the S3 endpoint
`https://storage.yandexcloud.net`. Bucket creation, DNS, static-website
hosting/public access, and the custom-domain TLS certificate are user-owned
prerequisites; this project does not automate them.

`scripts/bootstrap-yandex-storage.sh --check` is read-only: it verifies the
custom-domain manifest probe (`200` with a valid JSON object, or `404` for the
valid first-release state — every other response is blocking), confirms the
service account can reach the bucket via `aws s3api head-bucket`, and confirms
the GitHub `production` environment carries both runtime secrets. It never
creates or mutates the bucket, DNS, hosting, public access, or certificate.

Prerequisites:

1. Create (or reuse) a Yandex Cloud service account scoped to
   `storage.editor` on the `routing.akent.site` bucket only.
2. Create a static access key pair for that service account. Record the
   access-key ID and secret once.
3. Store the pair as the GitHub `production` environment secrets
   `YANDEX_S3_ACCESS_KEY_ID` and `YANDEX_S3_SECRET_ACCESS_KEY`. Existing
   secrets are not overwritten by this script; rotate them explicitly with
   `gh secret set`.
4. Authenticate `gh` as a repository administrator so `--check` can inspect
   the `production` environment and its secrets.

```bash
export GITHUB_REPOSITORY='<owner>/<repository>'
export YANDEX_S3_ACCESS_KEY_ID='<yandex-s3-access-key-id>'
export YANDEX_S3_SECRET_ACCESS_KEY='<yandex-s3-secret-access-key>'

scripts/bootstrap-yandex-storage.sh --permissions
scripts/bootstrap-yandex-storage.sh --check
```

The release workflow forwards only `YANDEX_S3_ACCESS_KEY_ID` and
`YANDEX_S3_SECRET_ACCESS_KEY` into the publish container; `GITHUB_REPOSITORY`
and the workflow's scoped `github.token` are provided by GitHub Actions.

After bootstrap, configure any required reviewers, protected deployment
branches/tags, and wait timers for the `production` environment in repository
Settings. The script does not guess an organization's approval policy.

## Update, failure recovery, and rollback

The scheduled workflow builds first and publishes only when the packaged
manifest contains a new release version. An unchanged run never invokes the
publisher and performs no Yandex Object Storage mutation.

A changed release is published in this order:

1. create a draft GitHub Release;
2. upload and read-back-verify immutable `/releases/<version>/` objects;
3. copy those bytes to `/latest/*`;
4. write root `SHA256SUMS`, then write `/manifest.json` last as the atomic
   pointer switch;
5. finalize the GitHub Release.

Object cache headers are set per-object at upload time; there is no
post-pointer CDN cache purge step.

Recovery depends on where failure occurred:

- Fetch, build, validation, or license/freshness failure: the previous public
  release is untouched.
- Yandex Object Storage failure before the manifest switch: the draft and new
  immutable tree are removed and `/latest/*` is restored from the previous
  manifest. If cleanup itself reports a problem, trust only the unchanged
  manifest-pinned version; inspect any orphan path before removing it
  manually.
- GitHub finalization failure after the pointer switch: the release is already
  live and the draft is deliberately retained. Investigate, then retry with
  `gh release edit <version> --draft=false --repo "$GITHUB_REPOSITORY"`.

Rollback never rebuilds data. Download the immutable manifest that was
published with the target version and promote its immutable tree. Do not use
the archive-internal `release/manifest.json`: that file is created before the
final archive metadata exists, so rollback rejects it as incomplete.

```bash
VERSION='<published-version>'
mkdir -p output/rollback
curl -fsSL "https://routing.akent.site/releases/$VERSION/manifest.json" \
  > output/rollback/target-manifest.json

docker compose run --rm \
  -e YANDEX_S3_ACCESS_KEY_ID -e YANDEX_S3_SECRET_ACCESS_KEY \
  -e GITHUB_REPOSITORY \
  builder rollback \
  --version "$VERSION" \
  --target-manifest /work/output/rollback/target-manifest.json \
  --repo "$GITHUB_REPOSITORY"
```

The command requires the manifest's `release_version` to match `VERSION`,
verifies every chosen `/releases/<version>/` object against that manifest,
copies the objects to `/latest/*`, replaces root `SHA256SUMS`, and writes the
complete target manifest with `latest_version` last. Confirm the target
fingerprints and checksums after completion. Keep a backup copy of the
published `/releases/<version>/manifest.json` alongside any release archive
you retain for manual recovery.

## Attribution and bad routes

Direct upstream repositories, license evidence, and unresolved license notices
are recorded in [LICENSES.md](LICENSES.md). The generated manifest records the
exact source versions, freshness, category counts, and configured license
status for each build; the release itself includes this inventory and the
applicable upstream license texts.

To report an incorrect route, open an issue in this repository and include:

- the manifest `latest_version` (or pinned version) and engine/dataset;
- category and exact domain or CIDR;
- expected action and observed action;
- which upstream appears to contain the entry, if known;
- validation output that does not contain credentials or private addresses.

Do not post API tokens, R2 keys, private proxy addresses, or full private
configuration files. Policy fixes belong in configuration or upstream data,
not in hand-edited generated artifacts.
