# Рекомендации по улучшению akent4000/ru-routing

Дата оценки: 2026-08-31
Обновлено: 2026-08-31 (после merge `feature/stale-source-quarantine` в main, коммит `6faf07e`)

## Резюме

Репозиторий уже имеет сильную архитектуру: deterministic build pipeline, нормализацию и конфликт-резолвинг, semantic validation, нативные артефакты для Xray/sing-box/Mihomo, versioned releases и manifest-based publication.

Основное пространство для дальнейшего улучшения:
- снижение риска ошибочного DIRECT;
- усиление semantic QA;
- улучшение наблюдаемости изменений;
- hardening supply-chain;
- повышение объяснимости каждого routing-решения.

## Приоритеты

| Приоритет | Рекомендация | Эффект |
|---|---|---|
| ~~P0~~ | ~~Убрать временное ослабление freshness для jutsu~~ — **выполнено** (`feature/stale-source-quarantine`, merge `6faf07e`) | Критично |
| ~~P0~~ | ~~Добавить minimum-remaining guard при массовом quarantine одной категории~~ — **реализовано** (configured `0.5` floor) | Критично |
| P0 | Добавить policy canary-тесты | Очень высокий |
| P1 | Ввести confidence/quorum для DIRECT | Очень высокий |
| P1 | Добавить release diff и policy transitions | Высокий |
| P1 | Pin GitHub Actions по commit SHA | Высокий |
| P1 | Pin Go image digest и Python dependencies | Высокий |
| P2 | Добавить CIDR risk analyzer | Средне-высокий |
| P2 | Добавить source contribution report | Средне-высокий |
| P2 | Добавить entry-level provenance | Средне-высокий |
| P2 | Подписывать manifest/releases | Средне-высокий |
| P3 | Расширить docs/security/operations документацию | Средний |

# P0 — критичные изменения

## 1. ~~Убрать временное ослабление freshness для jutsu~~ — выполнено

**Статус: реализовано** в `src/ru_routing/fetch.py`, `cli.py`, `package.py` (ветка `feature/stale-source-quarantine`, смержена в main коммитом `6faf07e`, 2026-08-31).

Что сделано:
- `jutsu-dev/ru-route-lists` восстановлен до строгого `max_age_hours: 48` в `config/sources.yaml`; временное исключение и его документация в README удалены.
- Fetch теперь возвращает `FetchedInputs(sources, degraded_sources)`: источники, чей возраст превышает `max_age_hours`, помечаются как `DegradedSource` и исключаются из сборки, а не роняют pipeline.
- Только просрочка freshness квалифицируется как quarantinable — sync lag, integrity, licence, parse и transport failures остаются fatal (проверено тестом `test_fetch_keeps_checksum_and_sync_lag_failures_fatal`).
- Manifest фиксирует `degraded_sources` с полями `name`, `status`, `reason`, `excluded_from_build`, `observed_freshness_age_hours`, `max_age_hours`.
- Anomaly-check в `package.py` точечно ослабляется только для category-keys, реально затронутых quarantine (`quarantined_category_keys`), остальные пороги продолжают действовать штатно.
- Atomic replace директории назначения и детерминизм сборки сохранены без изменений.

Итоговое ревью веткиа (см. ниже, новый пункт P0#2) выявило один открытый риск, требующий отдельного решения — см. следующий пункт.

## 2. ~~Добавить minimum-remaining guard при массовом quarantine одной категории~~ — реализовано

**Статус: реализовано** в `config/thresholds.yaml`, `src/ru_routing/config.py` и `src/ru_routing/package.py`.

Что сделано:
- Настроен и загружается порог minimum-remaining с floor `0.5` (50%).
- Для каждой quarantined-категории проверяется положительный предыдущий baseline: после quarantine должно остаться не менее `ceil(previous_count * 0.5)` записей.
- Ровно достигнутый минимум принимается; результат ниже floor вызывает `AnomalyError`.
- Неположительные, отсутствующие или нечисловые предыдущие baselines, а также non-finite значения (`NaN`, `+/-Inf`) считаются непригодными и пропускаются.
- Добавлены focused-тесты для нарушения floor, equality boundary, отсутствующего/неположительного baseline и non-finite baseline.

Изменение не добавляет сигналов в stdout или job summary; такие улучшения остаются отдельной рекомендацией.

## 3. Добавить policy canary-тесты

Глобальные thresholds не поймают ошибку вида:

```text
youtube.com -> DIRECT
```

если остальные категории почти не изменились.

Добавить обязательные проверки:

```yaml
policy_canaries:
  must_proxy:
    - youtube.com
    - googlevideo.com
    - discord.com
    - discord.gg

  must_direct:
    - gosuslugi.ru
    - nalog.gov.ru

  must_block:
    - <stable test entries>
```

Pipeline должен вычислять итоговое effective action после всех конфликтов и падать при неожиданном изменении.

# P1 — изменения с максимальной отдачей

## 4. Ввести confidence/quorum для DIRECT

Для DIRECT ошибка опаснее, чем лишний PROXY, потому что может привести к bypass VPN.

Пример confidence model:

```text
explicit RU-only curated list      = 100
2 independent source families      = 90
single curated source              = 75
GeoIP only                         = 50
ASN/heuristic-derived              = 40
```

Для client/lite policy:

```text
DIRECT только при confidence >= 75
иначе PROXY
```

Важно считать quorum не просто по количеству URLs, а по независимым source families.

## 5. Добавить release diff

На каждый релиз генерировать:

```text
diff.json
diff.md
policy-transitions.json
```

Особенно важны action transitions:
- DIRECT -> PROXY
- PROXY -> DIRECT
- BLOCK -> anything
- anything -> DIRECT

Пример:

```json
{
  "entry": "example.com",
  "before": "DIRECT",
  "after": "PROXY",
  "reason": "added by jutsu blocked-domains",
  "sources": ["jutsu"]
}
```

## 6. Pin GitHub Actions по commit SHA

Вместо:

```yaml
uses: actions/checkout@v4
uses: actions/setup-python@v5
```

использовать:

```yaml
uses: actions/checkout@<full-commit-sha>
uses: actions/setup-python@<full-commit-sha>
```

Обновление SHA автоматизировать Dependabot/Renovate.

## 7. Полностью pin toolchain

### Go

Не оставлять:

```dockerfile
FROM golang:1.25-bookworm
```

Использовать digest:

```dockerfile
FROM golang:1.25-bookworm@sha256:...
```

### Python

Добавить `uv.lock` или `requirements.lock` и pin:
- httpx
- PyYAML
- pytest
- ruff
- остальные build/runtime dependencies

# P2 — качество данных и наблюдаемость

## 8. CIDR risk analyzer

Для каждого CIDR определять risk class:

```text
dedicated network       -> high confidence
hosting provider        -> medium
shared CDN              -> low
hyperscaler/cloud       -> very low
```

Проверки:
- overlap с RU GeoIP;
- overlap с известными CDN ASN;
- prefix size;
- слишком широкие диапазоны;
- shared infrastructure;
- наличие эквивалентных domain rules.

Пример policy:

```text
shared CDN CIDR
+
достаточные domain rules
=
не включать CIDR в lite
```

## 9. Сделать thresholds категориальными

Пример:

```yaml
thresholds:
  blocked:
    decrease: 0.10
    increase: 0.25

  ru:
    decrease: 0.10
    increase: 0.20

  youtube:
    decrease: 0.25
    increase: 1.00

  ai:
    decrease: 0.50
    increase: 2.00
```

Дополнительно:

```yaml
min_entries:
  blocked: 100000
  ru: 1000
```

## 10. Source contribution report

Генерировать `source-stats.json`.

Пример метрик:

| Source | Raw | Unique | Conflicts lost | Final |
|---|---:|---:|---:|---:|
| RunetFreedom | 300k | 80k | 2k | 278k |
| jutsu | 250k | 25k | 5k | 245k |
| aireps | 15k | 2k | 300 | 14.7k |

## 11. Entry-level provenance

Добавить debug artifact:

```text
raw/provenance.tsv
```

Пример:

```text
example.com    blocked    runetfreedom,jutsu    explicit_blocked
1.2.3.0/24     blocked    jutsu                 explicit_blocked
```

## 12. Подписывать manifest/releases

Рекомендуемая цепочка:

```text
public key
   ↓
verify manifest signature
   ↓
manifest
   ↓
artifact hashes
   ↓
artifacts
```

Варианты:
- Sigstore/cosign;
- minisign;
- Ed25519 detached signatures.

Публиковать:
- `manifest.json`
- `manifest.json.sig`
- `SHA256SUMS`

## 13. Усилить provenance upstream asset

Вместо логики, опирающейся только на `/releases/latest/download/...`, желательно resolve latest -> immutable release.

Хранить:

```json
{
  "repo": "owner/repo",
  "tag": "release-tag",
  "release_id": 123,
  "asset_id": 456,
  "sha256": "..."
}
```

# P3 — документация и эксплуатация

## 14. Явно маркировать semantics client/server datasets

В manifest добавить:

```json
{
  "intended_role": "egress-server",
  "fallback_action": "DIRECT",
  "safe_for_client": false
}
```

Для lite/client:

```json
{
  "intended_role": "client",
  "fallback_action": "PROXY",
  "safe_for_client": true
}
```

## 15. Добавить security/operations docs

Полезные файлы:
- `SECURITY.md`
- `CONTRIBUTING.md`
- `CHANGELOG.md`
- `docs/ARCHITECTURE.md`
- `docs/POLICY.md`
- `docs/THREAT_MODEL.md`

В `THREAT_MODEL.md` описать защиту от:
- stale upstream;
- upstream disappearance;
- пустых/аномально уменьшившихся списков;
- частичного publish failure;
- inconsistent object storage;
- ошибочных конфликтов;
- malicious upstream input.

И отдельно ограничения:
- GitHub account compromise;
- compromised upstream maintainer;
- malicious but syntactically valid source;
- publisher key compromise.

# Рекомендуемый roadmap

## Этап 1
- ~~Quarantine stale jutsu вместо 720h freshness exception.~~ — выполнено (`6faf07e`).
- ~~Minimum-remaining guard при массовом quarantine одной категории.~~ — реализовано (configured `0.5` floor).
- Policy canaries.
- `diff.json` + `policy-transitions.json`.

## Этап 2
- Pin Actions по SHA.
- Pin Go image digest.
- Python lockfile.
- Per-category thresholds.

## Этап 3
- CIDR risk analyzer.
- Source contribution metrics.
- Entry-level provenance.
- Signed manifest.

## Этап 4
- Threat model.
- Security/operations docs.
- Расширенная observability и dashboard качества источников.

# Целевая модель качества

Текущий pipeline уже хорошо отвечает на вопрос:

```text
"Успешно ли были собраны валидные routing artifacts?"
```

Следующая стадия зрелости должна отвечать на вопрос:

```text
"Почему каждая критичная запись получила именно это действие,
из каких независимых источников пришло решение,
и заметим ли мы автоматически опасное изменение policy?"
```

Именно переход к explainable routing policy, confidence scoring и transition-aware QA даст проекту наибольший дальнейший прирост качества.
