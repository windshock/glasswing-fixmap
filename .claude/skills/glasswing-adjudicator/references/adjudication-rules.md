# Adjudication rules

Detailed rules for the `glasswing-adjudicator` Skill. The core contract and guardrails
live in `SKILL.md`; this file expands the per-state handling, confidence calibration, and
the (deliberately deferred) policy-integration mapping.

## Map the machine state to an investigation angle

| Machine state | Primary question | Evidence to gather |
| --- | --- | --- |
| `UNKNOWN` + missing/unsupported range | Is there any authoritative range, and does the version fall in it? | OSV/GHSA/CVE range with provenance; ecosystem/version scheme |
| `UNKNOWN` + `VERIFIER_CONFLICT` | Why do native / ancestry / Vanir disagree? | Reverts, partial backports, refactors in Git history |
| `PATCH_NOT_FOUND` | Is the vulnerable behavior actually present, or only a similar file/function? | Source at the installed version; the fix's real pre-image |
| `TARGET_ABSENT`-adjacent / feature timing | Did the vulnerable subsystem exist in this version? | Feature-introduction commit/tag vs the installed version |
| package-identity ambiguity | Is this the same upstream product as the finding? | PURL/CPE, repository identity, product vs library distinction |
| imprecise / flavored version | Can the version be placed against the range once the build flavor is stripped? | base upstream version, distro/FIPS suffix meaning, coverage of the affected window |

## Version-string normalization and build flavors

The deterministic comparators reject any version string they cannot parse strictly, so a
common `UNKNOWN` is not a genuine ambiguity — it is a **parsing gap on a flavored or
truncated version**. Resolve these deliberately; do not let a strict-parse failure
masquerade as an investigation dead-end.

1. **Split the base upstream version from the build flavor.** A flavor is an *orthogonal*
   packaging annotation, not part of the upstream version order:
   - FIPS provider/module tag — `3.4-fips3.1` → base OpenSSL `3.4` line, FIPS module `3.1`.
   - Distro revision — Gentoo `_p3`, RPM `.el8`/`-150400`, Debian `+deb12u1`/`-1ubuntu2`.
   - Build/vendor metadata after `+` or a trailing `-<tag>`.
2. **Decide whether the flavor is relevant to the vulnerability.** A FIPS build still ships
   the same `libcrypto`; a bug in a default-provider code path (e.g. `PKCS7_verify`) is not
   removed by enabling FIPS. A distro revision *may* carry a security backport — that is the
   one case where the flavor matters (see the backport angle), so check the distro changelog.
3. **Apply the authoritative range to the base version.** If the base pins the affected
   window unambiguously, resolve it (see *coverage-dominant ranges*).
4. **If the base still cannot be pinned** (a truncated `3.4` when the window splits inside
   the `3.4.x` series), do **not** average to a vague `low`. Produce the leaning verdict the
   evidence supports and record a **precise, actionable** missing-evidence request — the
   exact command or artifact that would settle it (e.g. "`openssl version -a` on the image;
   `>= 3.4.6` ⇒ not_affected"). Precision of the ask is the deliverable, not a guess.

## Coverage-dominant ranges

When the affected interval covers the component's whole base line, the exact micro-version
is irrelevant and the verdict is confident even if the string will not parse:

- `introduced: "0"` (or an introduced boundary at/below the base line) with a `fixed` far
  above the base ⇒ everything at that base is affected. Example: range `[0, 5.4.3)` and a
  component on the `0.16` line ⇒ `LIKELY_TRUE_POSITIVE`, `high`, regardless of a `_p3`
  suffix. Cite a sibling component on the same base line that the engine already resolved
  deterministically when one exists.
- Symmetrically, a base line entirely **above** every affected interval ⇒
  `LIKELY_FALSE_POSITIVE`.
- The only caveat is a downstream backport (guardrail on the distro revision); note it as
  missing evidence when the version distance makes it implausible but not impossible.

## Confidence calibration

- `high`: multiple independent, concrete evidence items agree and none contradicts; or a
  coverage-dominant range places the base line unambiguously.
- `medium`: one strong evidence item, or several weak ones agreeing, no contradiction; or
  a flavored version whose base leans clearly one way with a single unresolved micro-level
  question captured as a concrete evidence request.
- `low`: only indirect/weak evidence, or a single source.
- Any material contradiction caps confidence at `low` or forces `INSUFFICIENT_EVIDENCE`.
- An imprecise version is not automatically `low`: strip the flavor first, and if the base
  resolves, score the base. Reserve `low`/`INSUFFICIENT_EVIDENCE` for a genuine
  irreducible gap, and always pair it with the exact evidence that would close it.

## Feedback to the deterministic engine

Some `UNKNOWN`s the Skill resolves are really engine gaps, not permanent adjudication
work. When a resolution is a *deterministic, repeatable* rule — a distro/FIPS suffix
normalizer, a product-line version scheme, a coverage-dominant shortcut — say so in
`recommended_action` so it can be promoted into a comparator and stop reaching the Skill.
A pure identity problem (a name collision with no PURL/CPE, e.g. a JDBC driver vs the
server) is *not* such a case: it is fixed upstream by emitting a PURL/CPE in the SBOM, not
by a comparator.

## Verdict selection

- `CONFIRMED`: concrete evidence shows the vulnerable behavior is present in the installed
  version and not fixed (e.g. the pre-image is present and no backport applied). Rare;
  the deterministic engine usually reaches `PATCH_NOT_FOUND`/`AFFECTED` itself.
- `LIKELY_TRUE_POSITIVE`: evidence leans toward the finding applying (vulnerable subsystem
  present, version within an unofficial-but-credible range) but a proof gap remains.
- `LIKELY_FALSE_POSITIVE`: evidence leans away (subsystem introduced later, product
  mismatch, fix backported into this version) but is not conclusive.
- `INSUFFICIENT_EVIDENCE`: evidence is absent or contradictory.

## What the Skill must never do

- Never fabricate an affected range from a first patched version or from `version <
  fixed_version` ordering.
- Never treat "no Vanir finding" or "fix signature absent" as proof of fixed/affected.
- Never convert its own opinion into a CI pass, a suppression, or a deterministic
  decision change. Suppression stays explicit, human-approved, and auditable.
- Never restate machine conclusions from memory instead of quoting the artifact.

## Suggested policy integration (for the core project, not this Skill)

The project *may later* interpret the pair `(machine_decision, ai_review.verdict)`
approximately as below. This Skill does **not** implement suppression.

```text
AFFECTED                                  -> BLOCK
VERIFIED_FIXED / strongly proven absent   -> PASS
UNKNOWN + LIKELY_TRUE_POSITIVE            -> HIGH-PRIORITY REVIEW
UNKNOWN + LIKELY_FALSE_POSITIVE           -> REVIEW / suppression candidate
UNKNOWN + INSUFFICIENT_EVIDENCE           -> REVIEW
```
