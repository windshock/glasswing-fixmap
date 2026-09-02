---
name: glasswing-adjudicator
description: Second-opinion adjudication of unresolved glasswing-fixmap results — UNKNOWN, PATCH_NOT_FOUND, VERIFIER_CONFLICT, unsupported/missing affected range, package-identity ambiguity, or likely false positives. Investigates the long tail the deterministic engine cannot resolve, using the machine artifacts (sbom-check / source-verification / affected-ranges / fix-impacts JSON) plus public upstream evidence, and returns an evidence-cited CONFIRMED / LIKELY_TRUE_POSITIVE / LIKELY_FALSE_POSITIVE / INSUFFICIENT_EVIDENCE review. It never overwrites the deterministic decision and never auto-suppresses. Use when a glasswing result is unresolved or ambiguous and needs investigation before human triage.
---

# glasswing-adjudicator

> **Machines establish what can be proven. AI investigates what remains ambiguous.**

`glasswing-fixmap` deterministically prefers `UNKNOWN` over an unsupported security
claim. This Skill is the investigation layer for the residual cases — it does **not**
replace the deterministic engine and its output is review metadata, never a gate.

## When to use

Adjudicate a glasswing result when it is one of:
`UNKNOWN`, `PATCH_NOT_FOUND`, `VERIFIER_CONFLICT`, unsupported ecosystem/range
comparator, missing authoritative range, ambiguous feature-introduction timing, or a
possible package/product mismatch.

Do **not** overturn a deterministic `AFFECTED` or a strongly-proven `VERIFIED_FIXED` /
`TARGET_ABSENT`; you may flag contradictory evidence for a human, but you must not
silently replace the machine decision.

## Inputs (use whatever is available — do not require all)

- `sbom-check.json`, `source-verification.json`
- `affected-ranges.json` (or the candidate's relevant range records)
- `fix-impacts.json` (or the candidate's relevant impact records)
- ANT ID, CVE/GHSA IDs, SBOM component identity / PURL / version, upstream repository
  and fix commit(s)

When deterministic artifacts are insufficient, inspect public upstream evidence:
advisory pages, OSV/GHSA/CVE records, Git history, release notes/changelog,
feature-introduction commits, tags/releases, and the source paths/functions in the fix.
Missing evidence lowers confidence or yields `INSUFFICIENT_EVIDENCE` — never a guess.

## Workflow

1. Read the machine decision and its reasons/observations first; quote them, do not
   restate from memory.
2. Pick the investigation angle(s) the unresolved case needs: source/history,
   advisory/range evidence, or identity/provenance.
3. Gather concrete evidence (file, commit, tag, advisory field, release note, tool
   result). Every material factual claim must cite one.
4. Weigh supporting vs contradictory vs missing evidence and produce the structured
   review below.

## Investigation questions

1. Did the vulnerable feature/subsystem actually exist in the installed version?
2. When was the vulnerable file/function/feature introduced? Does the installed version
   predate its introduction?
3. Is the SBOM package actually the same upstream project/product as the finding
   (not merely a similar name — e.g. a JDBC driver vs the database server)?
4. Was the fix backported, cherry-picked, rewritten, or independently implemented?
5. Do release notes or Git history establish a safer introduction/fix boundary than the
   machine-readable advisory provides?
6. Does the current source contain the vulnerable *behavior*, not just a similarly named
   file/function?
7. If native and Vanir (or ancestry) disagree, why?
8. Is the finding configuration- or feature-dependent, and is that prerequisite present?
9. Is there contradictory evidence that prevents a confident conclusion?

## Output contract

Return a separate object that preserves the machine decision:

```json
{
  "machine_decision": "UNKNOWN",
  "ai_review": {
    "verdict": "LIKELY_FALSE_POSITIVE",
    "confidence": "medium",
    "summary": "The vulnerable subsystem was introduced after the installed version.",
    "reasons": ["Target file absent from the installed-version source tree"],
    "supporting_evidence": ["repo@tag: src/foo/bar.c does not exist at v1.3.7"],
    "contradictory_evidence": [],
    "missing_evidence": ["No authoritative affected range is published"],
    "recommended_action": "Review and suppress only after human approval"
  }
}
```

Verdicts (no generic `SAFE`): `CONFIRMED`, `LIKELY_TRUE_POSITIVE`,
`LIKELY_FALSE_POSITIVE`, `INSUFFICIENT_EVIDENCE`.

## Guardrails (non-negotiable)

1. AI is a second opinion, not the gate authority — never convert "likely false
   positive" into an automatic deterministic PASS or suppression.
2. Preserve machine evidence — quote/reference it; keep deterministic decision, AI
   review, supporting/contradictory/missing evidence separate.
3. No unsupported version inference — never invent an affected range from a first patched
   version; if authoritative range evidence is absent, say the formal range is unresolved.
4. Distinguish absence of proof from proof of absence (no Vanir hit ≠ fixed; missing fix
   signature ≠ affected; file absent in a partial tree ≠ not applicable; old version ≠
   vulnerable without introduction/range evidence).
5. Contradictions lower confidence — conflicting source/history/range/advisory evidence
   yields `INSUFFICIENT_EVIDENCE` or a low-confidence result with the conflict listed.
6. Evidence-first citations — every material reason points to a file, commit, tag,
   advisory field, release note, or tool result.

Detailed rules and worked regression examples:
[references/adjudication-rules.md](references/adjudication-rules.md) and
[references/examples.md](references/examples.md).
