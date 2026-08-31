# 수집 및 판정 방법론

## 1. Anthropic 기준 집합

`https://red.anthropic.com/2026/cvd/data/payload.json`을 기준으로 공개된 ledger entry만 선택합니다. 공개 entry는 `ant_id`와 `project`가 모두 존재해야 합니다. 아직 sealed 상태여서 두 값이 `null`인 행은 원본 해시를 보존하는 Anthropic ledger의 역할에 맡기고, 이 데이터셋에서는 추측하지 않습니다.

각 공개 finding card에서 다음을 수집합니다.

- 보고서 제목
- `UPSTREAM FIX` 섹션의 commit/PR 링크
- 보고서에서 명시적으로 commit이라 부른 해시
- “fixed/shipped/included in”처럼 버전과 직접 연결된 보수적인 3/4-part release 언급

본문의 TLS 1.2 같은 프로토콜 버전, IPv4 주소, RFC section, affected version, 다른 연도의 과거 CVE 수정 버전을 현재 finding의 release로 오인하지 않도록 자유 텍스트 추출을 제한합니다. 본문 값은 명시적으로 “first”라고 쓰인 경우가 아니면 `first_patched=null`로 남깁니다.

## 2. GitHub advisory

GHSA ID는 먼저 OSV API로 조회합니다. OSV record가 가리키는 GitHub Advisory Database 원본 JSON 경로가 있으면 그 원본을 다시 읽습니다. 여기서 `affected[].ranges[].events[].fixed`는 branch/package별 최초 safe boundary로 취급합니다.

C/C++ advisory처럼 package range가 없는 경우, finding의 fix URL에서 GitHub repository를 알아내 repository security advisory 페이지의 `Patched versions` 필드를 확인합니다.

## 3. CVE List V5

CVE ID를 `CVEProject/cvelistV5`의 정해진 bucket 경로로 변환해 원본 JSON을 읽습니다. CNA와 ADP container를 모두 순회합니다.

- `status=affected` + 구체적인 `lessThan=X`: X는 배타적 경계이므로 first patched 후보입니다.
- `lessThanOrEqual=X`: 다음 버전을 계산하지 않습니다.
- `changes[].status=unaffected`: 직전 상태가 affected일 때만 전이 지점을 사용합니다.
- `versionType=git`의 unaffected 전이는 fix commit으로 저장합니다.

## 4. 합치기와 신뢰도

같은 package/version/branch 주장은 합치고 모든 evidence를 보존합니다. package나 ecosystem이 한 소스에서 비어 있어도 다른 필드가 호환되면 같은 버전으로 병합합니다.

신뢰도는 다음 의미입니다.

- `verified`: 태그 ancestry나 직접적인 공식 release/advisory 근거를 사람이 확인함
- `high`: 구조화된 official advisory의 fixed boundary 또는 강한 공식 근거
- `medium`: finding 본문 release 언급, release batch, 간접 매핑
- `low`: 후보 탐색용 약한 근거

소스 간 충돌이 있으면 가장 낙관적인 값을 선택하지 않습니다. `unresolved` 또는 `operational_baseline`으로 낮추고 note에 충돌을 기록합니다.

## 5. GitHub tag ancestry

`--verify-github`는 버전 문자열로 `vX`와 `X` 태그를 찾아 각 known fix commit에 대해 GitHub compare API를 호출합니다. 태그가 commit과 같거나 commit보다 ahead이면 `verified_contains_fix`입니다.

이 검증은 “해당 태그가 fix를 포함한다”만 증명합니다. 바로 이전 태그가 취약했는지까지 확인하지 않으면 이것만으로 최초 릴리스라고 승격하지 않습니다.

## 6. 수동 예외

자동 소스가 release line을 표현하지 못하거나 프로젝트별 버전 체계가 특수하면 `overrides/manual.json`을 사용합니다. 모든 수동 값에는 공개 evidence URL이 필수입니다. 자동 소스가 이후 `no_release_yet`와 충돌하는 fixed boundary를 제공하면 validation이 실패하도록 설계되어 있습니다.
