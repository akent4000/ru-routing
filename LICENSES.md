# Upstream attribution and license inventory

This project redistributes transformed routing data from the direct sources
listed in [config/sources.yaml](config/sources.yaml). This inventory records
what the upstream repositories themselves declare; it does not relicense their
work or replace the upstream license terms.

## Direct sources

| Source | Material used | Upstream license evidence | Attribution |
| --- | --- | --- | --- |
| [hydraponique/roscomvpn-geoip](https://github.com/hydraponique/roscomvpn-geoip) | RU GeoIP data | **No repository license declaration found.** The repository has no root license file and its README does not state a license. The local source registry currently labels it `GPL-3.0-only`, but that label is not sufficient upstream evidence and must be confirmed with the maintainer before relying on it for redistribution. | hydraponique/roscomvpn-geoip contributors and the data providers named in its README |
| [aireps/geosite](https://github.com/aireps/geosite) | RU, deny, and thematic domain categories | [MIT license](https://github.com/aireps/geosite/blob/master/LICENSE). The repository states that it synchronizes data from [v2fly/domain-list-community](https://github.com/v2fly/domain-list-community), which also publishes an [MIT license](https://github.com/v2fly/domain-list-community/blob/master/LICENSE). | aireps/geosite and v2fly/domain-list-community contributors |
| [runetfreedom/russia-v2ray-rules-dat](https://github.com/runetfreedom/russia-v2ray-rules-dat) | blocked, RU-inside, RU-outside, and RU domain categories | [GNU GPL v3.0](https://github.com/runetfreedom/russia-v2ray-rules-dat/blob/main/LICENSE), detected by GitHub as `GPL-3.0`. The repository does not state an `-only` or `-or-later` SPDX suffix, so this inventory does not invent one. | runetfreedom/russia-v2ray-rules-dat contributors |
| [jutsu-dev/ru-route-lists](https://github.com/jutsu-dev/ru-route-lists) | blocked domain and CIDR lists | [MIT license](https://github.com/jutsu-dev/ru-route-lists/blob/main/LICENSE) | jutsu-dev/ru-route-lists contributors |
| [itdoginfo/allow-domains](https://github.com/itdoginfo/allow-domains) | Russia-inside, Russia-outside, and selected service domain lists | **No repository license declaration found.** The repository has no root license file and its README does not state a license. The local source registry currently labels it `MIT`, but that label is not sufficient upstream evidence and must be confirmed with the maintainer before relying on it for redistribution. | itdoginfo/allow-domains contributors and the list providers named in its README |
| [Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat) | RU and global GeoIP categories | [GNU GPL v3.0](https://github.com/Loyalsoldier/v2ray-rules-dat/blob/master/LICENSE), detected by GitHub as `GPL-3.0`. The repository does not state an `-only` or `-or-later` SPDX suffix, so this inventory does not invent one. | Loyalsoldier/v2ray-rules-dat contributors |

The two “no declaration found” entries are unresolved licensing risks, not a
claim that the works are public domain or free of restrictions. Their upstream
READMEs also name additional data providers whose terms can apply to the
aggregated lists. A release operator should resolve those notices and update
both this file and `config/sources.yaml` before treating redistribution as
cleared.

## Generated artifacts

Generated files combine or transform entries from one or more sources. Keep
this inventory and the per-release `manifest.json` with redistributed
artifacts. The manifest identifies the exact source revisions and configured
license status used for that build.

This repository currently has no root `LICENSE` file declaring a license for
its own original code and documentation. `LICENSES.md` is an attribution and
third-party inventory only; it does not grant permission to use the repository
itself.

When an upstream changes its license or attribution requirements, pause the
affected source, record the reviewed change in `config/sources.yaml`, update
this inventory, and build a new version. Do not silently carry an old SPDX
label forward.
