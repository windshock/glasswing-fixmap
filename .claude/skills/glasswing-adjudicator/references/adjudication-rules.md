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

## Confidence calibration

- `high`: multiple independent, concrete evidence items agree and none contradicts.
- `medium`: one strong evidence item, or several weak ones agreeing, no contradiction.
- `low`: only indirect/weak evidence, or a single source.
- Any material contradiction caps confidence at `low` or forces `INSUFFICIENT_EVIDENCE`.

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
