# Contributing

## 개발 확인

```bash
npm ci
npm run check
npm test
npm run sync -- --only ANT-2026-P23DVQM2
npm run validate
```

전체 `data/`를 갱신할 때는 `npm run sync`를 사용합니다. `data/fixmap.json`을 직접 편집하지 마십시오.

## 수동 override 제출

`overrides/manual.json`의 모든 값에는 접근 가능한 `evidence_url`이 필요합니다. PR 설명에는 다음을 포함해 주세요.

- ANT ID와 project
- fix commit 또는 PR
- release/tag와 공개 시각
- 바로 이전 release가 fix를 포함하지 않는 근거
- 여러 maintenance branch가 있으면 branch별 결과
- 공식 source와 제3자 source가 충돌하는지 여부

확정하지 못한 최신 보수 버전은 `role=operational_baseline`, `first_patched=false`로 기록합니다. “다음 버전일 것”이라는 예상은 넣지 않습니다.

## parser 변경

HTML/JSON parser 변경에는 최소 fixture test 하나를 추가하십시오. free-text 정규식은 CVE 번호, CVSS 숫자, TLS/HTTP protocol version을 release로 오인하지 않는 테스트가 필요합니다.
