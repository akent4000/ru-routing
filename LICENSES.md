# Upstream attribution and license inventory

This project redistributes transformed routing data from the direct sources
listed in [config/sources.yaml](config/sources.yaml). This inventory records
what the upstream repositories themselves declare; it does not relicense their
work or replace the upstream license terms.

## Direct sources

| Source | Material used | Upstream license evidence | Attribution |
| --- | --- | --- | --- |
| [aireps/geosite](https://github.com/aireps/geosite) | global RU domain category | [MIT license](https://github.com/aireps/geosite/blob/master/LICENSE). The repository states that it synchronizes data from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community), which also publishes an [MIT license](https://github.com/v2fly/domain-list-community/blob/master/LICENSE). | aireps/geosite and v2fly/domain-list-community contributors |
| [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) | blocked, RU, RU-inside, ads, tracker, spy, and service domain categories | [GNU GPL v3.0](https://github.com/runetfreedom/russia-v2ray-rules-dat/blob/main/LICENSE), detected by GitHub as `GPL-3.0`. The registry records `GPL-3.0-only`; no separate `-or-later` grant was found in the repository. | runetfreedom/russia-v2ray-rules-dat contributors |
| [jutsu-dev/ru-route-lists](https://github.com/jutsu-dev/ru-route-lists) | blocked domain and CIDR lists | [MIT license](https://github.com/jutsu-dev/ru-route-lists/blob/main/LICENSE) | jutsu-dev/ru-route-lists contributors |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | RU GeoIP category | [GNU GPL v3.0](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/LICENSE), detected by GitHub as `GPL-3.0`. The registry records `GPL-3.0-only`; no separate `-or-later` grant was found in the repository. | Loyalsoldier/v2ray-rules-dat contributors |

## Sources included without a verified license (NOASSERTION)

The following configured sources declare no verifiable redistribution license
upstream. They are consumed with attribution under an explicit maintainer
decision, recorded here for transparency, not because a grant was found.
`config/sources.yaml` records their SPDX status as `NOASSERTION` with
`redistribution_reviewed: true`.

| Source | Material used | Upstream license evidence | Attribution |
| --- | --- | --- | --- |
| [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) | Russia-outside domain list (`ru-inside` category) | **No repository license declaration found.** The repository has no root license file and its README does not state a license. Its README also names list providers whose terms may apply. | itdoginfo/allow-domains contributors |
| [hydraponique/roscomvpn-geoip](https://github.com/hydraponique/roscomvpn-geoip) | direct and whitelist RU CIDR categories (`ru-direct-geoip`) | **No repository license declaration found.** The GitHub API reports no license and the repository has no root license file. | hydraponique/roscomvpn-geoip contributors |
| [kirilllavrov/RU-domain-list-for-whitelist](https://github.com/kirilllavrov/RU-domain-list-for-whitelist) | `whitelist-ru` domain category (`ru-whitelist`) | **No verifiable license.** The README claims an "MIT License" but the repository ships no `LICENSE` file and the GitHub API reports no detected license; treated as `NOASSERTION` until a license file is added upstream. | kirilllavrov/RU-domain-list-for-whitelist contributors |

If any of these upstreams publish a verifiable license, update this table and
the corresponding `config/sources.yaml` `license.spdx` entry to the confirmed
SPDX identifier. If instead an upstream's terms turn out to prohibit
redistribution, remove the source and its mappings and rerun the complete
validation suite. Absence of a license is not permission to redistribute; it
is a maintainer-accepted risk recorded here.

## Generated artifacts

Generated files combine or transform entries from one or more sources. Keep
this inventory and the per-release `manifest.json` with redistributed
artifacts. The manifest identifies the exact source revisions and configured
license status used for that build.

Every packaged distribution and release archive includes this inventory as
`LICENSES.md` and the exact upstream license files under
`licenses/upstream/<source>/LICENSE`. Those files are covered by the release's
`SHA256SUMS` and `manifest.json` checksums like every other public artifact.

This repository currently has no root `LICENSE` file declaring a license for
its own original code and documentation. `LICENSES.md` is an attribution and
third-party inventory only; it does not grant permission to use the repository
itself.

When an upstream changes its license or attribution requirements, remove the
affected source from new builds, record the reviewed change in
`config/sources.yaml`, update this inventory, and build a new version. Do not
silently carry an old SPDX label forward.
