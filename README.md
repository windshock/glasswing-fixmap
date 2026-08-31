# glasswing-fixmap

Anthropic CVD의 공개 finding을 `ANT → CVE/GHSA → fix commit → 최초 patched release`로 연결하는, 증거 기반의 갱신 가능한 데이터셋입니다.

현재 생성된 스냅샷은 [data/fixmap.json](data/fixmap.json)과 [data/fixmap.csv](data/fixmap.csv)에 있습니다. JSON은 브랜치별 패치 버전과 근거를 보존하고, CSV는 검색·스프레드시트용 평면 뷰입니다.

```text
Anthropic payload + public finding card
            │
            ├── GitHub Advisory Database / repository advisory
            ├── CVE List V5
            ├── upstream commit / PR / release tag
            └── reviewed manual exceptions
                         │
                         ▼
       ANT ID | CVE/GHSA | fix_commits[] | fixed_versions[]
```

## 빠른 시작

Node.js 20 이상이 필요합니다.

```bash
npm ci
npm run sync
npm run verify
npm run report
```

특정 finding만 조사할 수도 있습니다.

```bash
npm run sync -- --only ANT-2026-GEM3N3N3,ANT-2026-P23DVQM2
```

GitHub 태그에 fix commit이 실제 포함되는지도 비교하려면 토큰을 제공합니다. 이 검증은 API 호출량 때문에 선택 사항입니다.

```bash
GITHUB_TOKEN=... npm run sync -- --verify-github
```

네트워크 응답은 `.cache/http`에 ETag와 함께 저장됩니다. 완전히 캐시된 상태에서는 `--offline`으로 재현할 수 있습니다.

## 판정 원칙

이 저장소는 “패치가 존재한다”와 “정식 패치 릴리스가 존재한다”를 구분합니다.

- GitHub Advisory/OSV의 명시적 `fixed` 이벤트, CVE List V5의 affected→unaffected 전이, repository advisory의 `Patched versions`만 자동으로 `first_patched=true`가 됩니다.
- `lessThan`의 배타적 상한은 fixed boundary로 사용할 수 있지만 `lessThanOrEqual`의 다음 버전은 추측하지 않습니다.
- 여러 유지보수 브랜치는 각각 독립된 `fixed_versions[]` 항목입니다. Rocket.Chat의 `7.10.9`를 단순히 “7.10.9 이상”으로 표현하지 않습니다.
- finding 본문의 “shipped/included in” 버전은 패치 포함 보고로 저장할 수 있지만, 그 문장만으로 최초 릴리스라고 단정하지 않습니다.
- 커밋만 확인된 경우 `release_assessment.status=commit_only`, 아직 정식 릴리스가 없으면 `no_release_yet`입니다.
- 최신 보수 버전일 뿐 최초 fixed임을 증명하지 못한 값은 `role=operational_baseline`이며 `first_patched=false`입니다.

세부 방법론과 신뢰도 규칙은 [docs/METHODOLOGY.md](docs/METHODOLOGY.md), 예외 교차 검증은 [docs/CROSS_VALIDATION.md](docs/CROSS_VALIDATION.md)에 정리했습니다.

## 데이터 예시

```json
{
  "ant_id": "ANT-2026-GEM3N3N3",
  "project": "rocketchat/rocket.chat",
  "cve_ids": ["CVE-2026-29198"],
  "fix_commits": [],
  "fixed_versions": [
    {
      "version": "7.10.9",
      "branch": "7.10",
      "role": "first_patched",
      "first_patched": true
    },
    {
      "version": "8.1.2",
      "branch": "8.1",
      "role": "first_patched",
      "first_patched": true
    }
  ],
  "release_assessment": { "status": "confirmed_versions" }
}
```

실제 항목에는 confidence, source URL, JSON 필드/페이지 위치, 태그 검증 결과도 들어갑니다. 전체 모델은 [docs/DATA_MODEL.md](docs/DATA_MODEL.md)와 [schema/fixmap.schema.json](schema/fixmap.schema.json)을 참고하십시오.

## CLI

```text
glasswing-fixmap sync [options]
glasswing-fixmap report [data/fixmap.json]
glasswing-fixmap validate [data/fixmap.json]
```

`sync` 옵션은 `--output`, `--cache`, `--overrides`, `--only`, `--concurrency`, `--offline`, `--verify-github`, `--strict`입니다. `npm run sync -- --help`에서 전체 설명을 볼 수 있습니다.

## 수동 보정

기계 판독 소스가 부족한 프로젝트는 [overrides/manual.json](overrides/manual.json)에서 근거 URL과 함께 보정합니다. 보정은 다음을 지켜야 합니다.

1. ANT finding과 수정/릴리스의 1:1 관계를 설명하는 근거가 있어야 합니다.
2. branch별 최초 버전을 별도 항목으로 기록해야 합니다.
3. 최초 버전을 증명하지 못하면 `first_patched=true`를 사용하지 않아야 합니다.
4. `no_release_yet` 판정에는 최신 stable release가 fix보다 앞선다는 근거가 있어야 합니다.

새 override와 parser 변경에는 테스트를 추가해 주세요. 자세한 절차는 [CONTRIBUTING.md](CONTRIBUTING.md)에 있습니다.

## 자동 갱신

[.github/workflows/update-data.yml](.github/workflows/update-data.yml)은 매일 새 Anthropic 스냅샷과 advisory 변경을 동기화하고 변경이 있으면 PR을 만듭니다. 출력의 생성 시각은 실행 시각이 아니라 Anthropic `as_of`를 사용하므로 원본이 같으면 불필요한 diff가 생기지 않습니다.

## 범위와 한계

- Anthropic ledger에서 아직 `ant_id`와 `project`가 공개되지 않은 sealed finding은 연결할 수 없습니다.
- `patched=true`는 Anthropic이 upstream patch를 관찰했다는 뜻이며 정식 릴리스 존재를 보장하지 않습니다.
- C/C++ 프로젝트의 GHSA는 package range가 비어 있을 수 있어 repository advisory HTML과 upstream release를 추가로 확인합니다.
- 태그 이름과 제품 릴리스가 일치하지 않는 WebKit, Hermes 같은 프로젝트는 commit-only로 남길 수 있습니다.
- `data/`는 외부 원본의 정규화·인덱싱 결과입니다. 사용 시 각 항목의 `evidence`와 원본 제공자의 이용 조건을 함께 확인하십시오.

코드는 Apache-2.0으로 배포됩니다.
