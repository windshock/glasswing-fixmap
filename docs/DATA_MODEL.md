# 데이터 모델

최상위 JSON은 `metadata`와 `findings[]`로 구성됩니다.

## 핵심 필드

| 필드 | 의미 |
| --- | --- |
| `ant_id` | 공개 Anthropic finding 식별자 |
| `cve_ids[]`, `ghsa_ids[]` | ledger 및 advisory alias를 합친 현재 식별자 |
| `fix_commits[]` | 브랜치별로 여러 개일 수 있는 수정 커밋 |
| `fix_references[]` | PR, patch, changeset 등 commit 외 수정 근거 |
| `fixed_versions[]` | package/branch별 패치 릴리스 주장 |
| `release_assessment` | 정식 릴리스 판정의 현재 상태 |
| `enrichment.status` | commit/version 필드 충족도 |
| `sources[]` | 해당 finding을 구성할 때 사용한 원본 |

## `fixed_versions[]`

`version` 하나를 단순 문자열 목록으로 저장하지 않고 다음 문맥을 같이 둡니다.

- `package`, `ecosystem`: advisory의 패키지 좌표
- `branch`: 유지보수 release line
- `introduced`: 같은 advisory range의 시작점
- `role`: `first_patched`, `patched`, `nightly`, `operational_baseline`
- `first_patched`: 최초 safe boundary가 확인됐는지 여부. 근거가 부족하면 `null`입니다.
- `confidence`: `verified`, `high`, `medium`, `low`
- `commit_verification`: 알려진 fix commit이 tag의 ancestor인지 선택적으로 검증한 결과
- `evidence[]`: source URL과 원본 내 locator

`first_patched=true`는 “모든 이후 버전이 안전하다”는 뜻이 아닙니다. 동일 프로젝트의 다른 branch, prerelease, downstream package는 별도 판정 대상입니다.

## `release_assessment.status`

| 값 | 의미 |
| --- | --- |
| `confirmed_versions` | 한 개 이상의 branch별 최초 patched release가 명시적으로 확인됨 |
| `commit_only` | 수정 커밋은 있으나 정식 릴리스 경계를 확정하지 못함 |
| `no_release_yet` | 수정은 upstream에 있으나 확인 시점에 정식 fixed release가 없음 |
| `unresolved` | 공개 근거가 부족하거나 근거끼리 충돌함 |
| `not_applicable` | Anthropic 스냅샷상 아직 patched finding이 아니며 새 외부 증거도 없음 |

## Anthropic 상태와 enrichment 상태

`patched`/`patched_at`은 Anthropic 스냅샷을 그대로 보존합니다. 더 최신 upstream 릴리스 근거가 발견돼도 이 값을 덮어쓰지 않습니다. 대신 `release_assessment`가 최신 외부 판정을 표현하고, 충돌은 `enrichment.warnings[]`에 남깁니다.

## 안정성

동일 `source_as_of`와 동일한 외부 source 상태로 실행하면 정렬과 출력이 결정적입니다. HTTP fetch 시각이나 로컬 실행 시각은 데이터에 넣지 않습니다.
