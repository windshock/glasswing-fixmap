# AGENTS.md — glasswing-fixmap

Guidance for coding agents (Codex, and any `AGENTS.md`-aware tool) working in this repo.
This file is auto-loaded by Codex. Claude Code reads the same conventions plus the skill
under `.claude/skills/`.

## What this project is

`glasswing-fixmap` maps Anthropic CVD findings (ANT → CVE/GHSA → fix commit → release) and
verifies patch presence. It **deterministically prefers `UNKNOWN` over an unsupported
security claim**. Six decisions are never conflated: `VERIFIED_FIXED`, `TARGET_ABSENT`,
`PATCH_NOT_FOUND`, `AFFECTED`, `UNKNOWN`, `ERROR`. `AFFECTED` requires strong identity plus
an authoritative range with provenance and a supporting comparator — never inferred from a
first-patched version or release ordering.

## Build / test / conventions

- TypeScript ESM (NodeNext), `exactOptionalPropertyTypes: true` (assign optional props
  conditionally, never set them to `undefined`). Run with `tsx`; tests are `node:test`.
- `npm run check` — typecheck (`tsc --noEmit`). `npm test` — full suite. `npm run verify` —
  check + test + validate. Run all three before proposing a change.
- CLI commands: `sync` (→ `data/fixmap.json`), `sync-ranges` (→ `data/affected-ranges.json`,
  OSV + CVE List V5), `sync-impacts` (→ `data/fix-impacts.json`), `check-sbom`,
  `verify-source`. `sync*` are periodic data refreshes; scans read the committed datasets.
- Never coerce versions in security decisions: a value that fails strict parsing yields
  `unknown`, it is not forced into a scheme.
- `sample/` holds private customer SBOM inventory — it is gitignored; never commit it,
  never include it in `npm pack`.

## Glasswing CVD adjudicator (second-opinion investigation)

The deterministic engine is the gate authority. For its residual `UNKNOWN` /
`PATCH_NOT_FOUND` / `VERIFIER_CONFLICT` / unsupported-range / package-identity cases, use
the adjudicator workflow. Its output is **review metadata, never a gate**, and it must not
overturn a deterministic decision or auto-suppress.

The full, tool-neutral instructions are the single source of truth here — read them before
adjudicating:

- Workflow, guardrails, output contract:
  [`.claude/skills/glasswing-adjudicator/SKILL.md`](.claude/skills/glasswing-adjudicator/SKILL.md)
- Per-state rules, confidence calibration, version-flavor normalization, engine feedback:
  [`.claude/skills/glasswing-adjudicator/references/adjudication-rules.md`](.claude/skills/glasswing-adjudicator/references/adjudication-rules.md)
- Worked regression examples:
  [`.claude/skills/glasswing-adjudicator/references/examples.md`](.claude/skills/glasswing-adjudicator/references/examples.md)

Return the structured `{ machine_decision, ai_review { verdict, confidence, summary,
reasons, supporting_evidence, contradictory_evidence, missing_evidence,
recommended_action } }` object; every material claim cites a file/commit/tag/advisory
field/tool result. Verdicts: `CONFIRMED`, `LIKELY_TRUE_POSITIVE`, `LIKELY_FALSE_POSITIVE`,
`INSUFFICIENT_EVIDENCE` (no generic `SAFE`).

To invoke it as a Codex slash command, copy `codex/prompts/glasswing-adjudicator.md` into
`~/.codex/prompts/` and run `/glasswing-adjudicator`.
