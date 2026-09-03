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

## 7. Flavored or truncated version string (FIPS / distro / missing patch)

The `UNKNOWN` here is a comparator parse gap, not a genuine ambiguity — strip the build
flavor and score the base version.

- **Coverage-dominant, resolves to `high`.** `libyang 0.16_p3` vs a range `[0, 5.4.3)`.
  `_p3` is a Gentoo revision on base `0.16`; the whole `0.16` line is below `5.4.3`, so
  the suffix is irrelevant. Adjudication: `LIKELY_TRUE_POSITIVE`, `high`. Evidence: the
  range's `introduced: 0`; the sibling `libyang 0.16.46` the engine already resolved
  `AFFECTED` on the same base line. `recommended_action`: promote a distro-suffix
  normalizer into the comparator so this stops needing adjudication.
- **Orthogonal flavor + irreducible micro-gap, resolves to a sharp `medium` + evidence
  ask.** `OpenSSL 3.4-fips3.1` vs a range `[3.4.0, 3.4.6)`. Split: base `3.4` line, FIPS
  module `3.1` (orthogonal). The bug is in default-provider `PKCS7_verify`, present in
  `libcrypto` regardless of FIPS, so the FIPS flavor does not clear it. The base `3.4`
  line is affected across `3.4.0`–`3.4.5`; nothing in the string indicates `>= 3.4.6`.
  Adjudication: `LIKELY_TRUE_POSITIVE`, `medium` — not `low`, because the only open
  question is the exact base patch. `missing_evidence`/`recommended_action`: "`openssl
  version -a` on the image; `>= 3.4.6` ⇒ not_affected, else affected." The residual is an
  SBOM data-quality limit (the string never encoded the patch), not a Skill deficiency —
  the deliverable is the precise ask, never a fabricated patch level.
- Trap avoided: averaging an imprecise version to a vague `low`, or treating a strict-parse
  failure as "cannot investigate".
