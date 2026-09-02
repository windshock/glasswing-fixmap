# Worked regression examples

Each example shows a machine result and the evidence-cited adjudication it should produce.
These are the ambiguous patterns the Skill must handle; use them to check its behavior.

## 1. Vulnerable subsystem introduced after the installed version

- Machine: `check-sbom` matched `cloudflare/circl v1.3.7` (repository identity, medium) to
  a BLS signature-forgery finding fixed in `v1.6.4`. `verify-source` returned
  `TARGET_ABSENT` — `sign/bls/` does not exist at `v1.3.7`.
- Adjudication: `LIKELY_FALSE_POSITIVE`, medium. The vulnerable subsystem was added after
  `v1.3.7`, so the finding does not apply to this version.
- Evidence: `git` shows `sign/bls/bls.go` first appears after the `v1.3.7` tag; the
  `TARGET_ABSENT` observation lists both fix files absent.
- Trap avoided: `1.3.7 < 1.6.4` is *not* the reason — an older version is not vulnerable
  without introduction/range evidence.

## 2. Backported fix in an old release line

- Machine: `PATCH_NOT_FOUND` — the finding's fix commit is not an ancestor of a maintenance
  branch's `HEAD`, and the exact post-image was not matched.
- Adjudication: `LIKELY_FALSE_POSITIVE` or `INSUFFICIENT_EVIDENCE`. Check whether the fix
  was cherry-picked/rewritten into the branch under a different commit.
- Evidence: a maintenance-branch commit/release note referencing the same CVE, or the
  fixed post-image present under a moved path. If found, it is likely fixed despite the
  ancestry miss; if not found, evidence is insufficient, not "affected".

## 3. Native vs Vanir disagreement

- Machine: `VERIFIER_CONFLICT` → `UNKNOWN`. Native fingerprint reports the post-fix image;
  Vanir reports a matching vulnerable signature (or vice versa).
- Adjudication: `INSUFFICIENT_EVIDENCE` unless Git history explains it (a later partial
  revert, a refactor that moved only part of the fix). List the conflict explicitly;
  never pick a backend as the oracle.

## 4. Missing authoritative range

- Machine: `UNKNOWN` — strong component identity, but no authoritative OSV/GHSA/CVE range,
  or an ecosystem/scheme with no comparator (e.g. Maven).
- Adjudication: state the formal range is unresolved. Investigate source/history for the
  fix and introduction boundaries; produce `LIKELY_TRUE_POSITIVE` /
  `LIKELY_FALSE_POSITIVE` only from concrete evidence, and never invent the range.

## 5. Package-name false positive / PURL mismatch

- Machine: a `name_heuristic` (low) candidate — e.g. a component named `postgresql` at a
  `42.x` version matched to the PostgreSQL *server* finding.
- Adjudication: `LIKELY_FALSE_POSITIVE`, medium/high. The component is the JDBC driver
  (`org.postgresql:postgresql`, version line `42.x`), a different product from the server
  (versions `14`–`18`). Cite the version-scheme mismatch and the distinct PURL/product.

## 6. Insufficient source / provenance

- Machine: `UNKNOWN` with `SOURCE_TREE_PARTIAL`, or a `source_binding` of
  `user_asserted` / `unverified`, or a `partial` fix impact (`IMPACT_INCOMPLETE`).
- Adjudication: `INSUFFICIENT_EVIDENCE`. A file absent in a partial tree is not "not
  applicable"; an unverified source binding does not confirm the SBOM version. Say what
  is missing (full checkout, verified revision, complete impact extraction).
