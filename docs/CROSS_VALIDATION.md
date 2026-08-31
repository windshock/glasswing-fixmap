# 교차 검증 메모

확인 기준일: 2026-09-01 (Asia/Seoul). 이 문서는 자동 소스만으로 표현하기 어려운 대표 예외를 설명합니다. 기계 판독 값은 `overrides/manual.json`에 있습니다. 최초 제공된 표는 후보 목록으로만 사용했고, 아래 판정은 upstream commit, 이전/이후 tag, 공식 release/advisory를 다시 대조한 결과입니다.

## 릴리스 없음

- `ANT-2026-Q5A1RHS0` / libssh2: fix는 upstream에 있지만 최신 정식 release는 1.11.1이고 개발 버전만 `1.11.2_DEV`입니다. 1.11.2를 released fix로 쓰지 않습니다.
- `ANT-2026-BT210RQ0` / libtomcrypt: PR 726은 development line에 merge됐지만 최신 stable은 1.18.2입니다.
- `ANT-2026-0GNNMNPS` / WABT: fix가 stable 1.0.41 뒤에 들어갔으며 후속 stable이 없습니다.
- `ANT-2026-HRZEDXBB` / Ghostscript: 10.07.1 release가 알려진 fix 작업보다 앞섭니다.

## 단일 SemVer를 쓰지 않는 항목

- `ANT-2026-YZAKBHEW` / Hermes: `cb8a9a3…` commit은 확인되지만 React Native/downstream 제품별 release mapping이 필요합니다.
- `ANT-2026-K6DHGAYS` / WebKit: `eba64ef…` commit은 확인되지만 Safari, WebKitGTK, WPE release stream을 하나의 WebKit 버전으로 합치지 않습니다.

## 브랜치별 버전

- Rocket.Chat `ANT-2026-GEM3N3N3`는 7.10, 7.11, 7.12, 7.13, 8.0, 8.1, 8.2, 8.3 release line을 별도로 유지합니다.
- Asterisk `ANT-2026-HFGGE6HR`는 일반 20/21/22/23 line과 Certified 20/22 line을 분리합니다.
- FFmpeg `ANT-2026-SC8JK49A`, NSS `ANT-2026-XKHM3P45`, util-linux `ANT-2026-ZRDQDR79`도 maintenance branch마다 별도 first patched release를 기록합니다.
- Spark `ANT-2026-PGRNAV88`는 SPARK-56463의 branch별 backport commit을 각각 확인했습니다. 각 fix는 직전 tag에는 없고 3.5.9, 4.0.3, 4.1.2 tag의 ancestor이며, main-line fix는 4.2.0에 포함됩니다.

## 근거 충돌 또는 약한 1:1 매핑

- WAMR `ANT-2026-P7DSVPH6`: 2.4.5가 보수 기준이라는 외부 정황은 있지만 repository advisory는 아직 `Patched versions: None`을 표시합니다. 따라서 `2.4.5`는 `operational_baseline`이고 first patched 확정값이 아닙니다.
- DuckDB `ANT-2026-QRPT15J8`, RDKit `ANT-2026-N7D3E5WK`, GraphicsMagick `ANT-2026-VTJ2W5KM`는 release-level security batch와 ANT sub-finding의 공식 1:1 이름이 부족해 confidence를 낮췄습니다.
- libjxl `ANT-2026-YMN2QG55`와 OpenBabel `ANT-2026-YQ12XT7Y`도 공식 release의 보안 수정 묶음은 확인되지만 재현 가능한 ANT→fix commit→직전/최초 tag 연결이 부족합니다. 따라서 표에 제시된 버전을 patched baseline으로는 보존하되 `first_patched=true`로 확정하지 않습니다.
- FFmpeg `ANT-2026-TJ0ZJHM6`는 별개 finding이므로 `ANT-2026-SC8JK49A`의 버전을 재사용하지 않습니다.
- GDAL 일부 finding은 정확한 최초 태그 대신 3.13.2를 `operational_baseline`으로만 기록합니다.

## 이전 판정에서 갱신된 항목

- LibreDWG `ANT-2026-09SNWQBT`: 과거에는 post-fix nightly만 있었지만 이후 stable 0.14가 2026-06-27 공개됐습니다. GitHub compare에서 fix `f79f9f6…`가 0.14 tag의 ancestor이고 0.13.4에는 포함되지 않으므로 현재 최초 fixed stable은 0.14로 갱신했습니다.
