# glasswing-fixmap

An evidence-backed, continuously updatable dataset that maps public Anthropic CVD findings along the chain `ANT → CVE/GHSA → fix commit → first patched release`.

The current generated snapshot is available as [data/fixmap.json](data/fixmap.json) and [data/fixmap.csv](data/fixmap.csv). The JSON preserves branch-specific patched versions and their evidence, while the CSV provides a flat view for search and spreadsheet use.

```text
Anthropic payload + public finding card
            │
            ├── GitHub Advisory Database / repository advisory
            ├── CVE List V5
            ├── upstream commit / PR / release tag
            └── reviewed manual exceptions
                         │
                         ▼
       ANT ID | CVE/GHSA | fix_commits[] | fixed_versions[]
```

## Quick start

Node.js 20 or later is required.

```bash
npm ci
npm run sync
npm run verify
npm run report
```

You can also investigate a selected set of findings:

```bash
npm run sync -- --only ANT-2026-GEM3N3N3,ANT-2026-P23DVQM2
```

Provide a GitHub token to verify that known fix commits are actually contained in candidate release tags. This verification is optional because it consumes additional API requests.

```bash
GITHUB_TOKEN=... npm run sync -- --verify-github
```

Network responses are cached under `.cache/http` with their ETags. Once all required responses have been cached, the same run can be reproduced with `--offline`.

## Decision policy

This repository distinguishes between the existence of an upstream patch and the existence of a formal patched release.

- Only explicit GitHub Advisory/OSV `fixed` events, affected-to-unaffected transitions in CVE List V5, and repository advisory `Patched versions` fields are automatically promoted to `first_patched=true`.
- An exclusive `lessThan` upper bound may be used as a fixed boundary. The version after a `lessThanOrEqual` boundary is never guessed.
- Maintenance branches are represented as independent `fixed_versions[]` entries. For example, Rocket.Chat `7.10.9` is not generalized to “7.10.9 or later” across unrelated release lines.
- A version described as “shipped in” or “included in” within a finding body may be recorded as containing the patch, but that statement alone does not prove it was the first patched release.
- If only a commit is known, `release_assessment.status` is `commit_only`. If the fix has not yet reached a formal release, the status is `no_release_yet`.
- A current maintenance version that has not been proven to be the first fixed release is recorded with `role=operational_baseline` and `first_patched=false`.

See [docs/METHODOLOGY.md](docs/METHODOLOGY.md) for the full methodology and confidence rules, and [docs/CROSS_VALIDATION.md](docs/CROSS_VALIDATION.md) for reviewed exceptions.

The source-level extension is documented in [docs/PATCH_PRESENCE_PLAN.md](docs/PATCH_PRESENCE_PLAN.md). Phase 2a adds evidence-backed `fix commit → file/function/patch → source` verification, and Phase 3 adds conservative SBOM candidate selection that can bridge an unambiguous candidate into that verification.

## Data example

```json
{
  "ant_id": "ANT-2026-GEM3N3N3",
  "project": "rocketchat/rocket.chat",
  "cve_ids": ["CVE-2026-29198"],
  "fix_commits": [],
  "fixed_versions": [
    {
      "version": "7.10.9",
      "branch": "7.10",
      "role": "first_patched",
      "first_patched": true
    },
    {
      "version": "8.1.2",
      "branch": "8.1",
      "role": "first_patched",
      "first_patched": true
    }
  ],
  "release_assessment": { "status": "confirmed_versions" }
}
```

Actual records also contain confidence levels, source URLs, JSON field or page locators, and tag verification results. See [docs/DATA_MODEL.md](docs/DATA_MODEL.md) and [schema/fixmap.schema.json](schema/fixmap.schema.json) for the complete model.

## CLI

```text
glasswing-fixmap sync [options]
glasswing-fixmap sync-impacts [options]
glasswing-fixmap verify-source --ant <ANT-ID> --source <dir> [options]
glasswing-fixmap check-sbom --sbom <file> [options]
glasswing-fixmap sync-ranges [options]
glasswing-fixmap report [data/fixmap.json]
glasswing-fixmap validate [data/fixmap.json]
```

The `sync` command supports `--output`, `--cache`, `--overrides`, `--only`, `--concurrency`, `--offline`, `--verify-github`, and `--strict`. Run `npm run sync -- --help` for the complete usage text.

Phase 1 of patch-presence verification can extract changed paths, diff hunk context, and normalized fingerprints for known GitHub fix commits. It writes compact metadata and hashes, not complete patch bodies:

```bash
GITHUB_TOKEN=... npm run sync:impacts -- \
  --only ANT-2026-P23DVQM2 \
  --output .cache/fix-impacts.sample.json
```

A token is required for a full run unless all responses are already cached for `--offline` use. A full run writes `data/fix-impacts.json` by default. The generated artifact follows [schema/fix-impacts.schema.json](schema/fix-impacts.schema.json). `sync-impacts` alone does not claim that a build is fixed or affected.

Phase 2a verifies one finding against a read-only source checkout or package source tree:

```bash
npm run verify:source -- \
  --ant ANT-2026-P23DVQM2 \
  --source ../wolfssl \
  --impacts data/fix-impacts.json
```

Add `--json` for machine-readable stdout or `--output result.json` to write an atomic JSON report conforming to [schema/source-verification.schema.json](schema/source-verification.schema.json). The command runs two independent evidence producers:

- `git-ancestry` validates GitHub repository identity and tests whether a known fix commit is an ancestor of `HEAD`, without fetching missing history.
- `glasswing-fingerprint` checks relevant files and normalized pre-image/post-image signatures without modifying, building, or executing the source.

The backends are not voters. Git ancestry alone cannot prove that the current tree remains fixed because a later commit may revert the patch. A strong complete native post-image match can produce `VERIFIED_FIXED`; ancestry can corroborate it. Conflicting ancestry and pre-fix evidence produce `UNKNOWN` with `VERIFIER_CONFLICT`. `PATCH_NOT_FOUND` never implies `AFFECTED`, and operational verifier failures remain distinct from inconclusive evidence.

The optional Vanir backend proposed in [GitHub issue #1](https://github.com/windshock/glasswing-fixmap/issues/1) is not a default backend. It runs only when you opt in with `--vanir-runner <path> --vanir-signatures <file>`, entirely behind the `SourceVerifier` boundary, so the core decision model stays decoupled from Vanir. When absent it is reported as `unsupported` rather than failing verification; its missing-patch findings normalize to `PATCH_NOT_FOUND` and a clean scan to `UNKNOWN`, never a standalone proof of fix.

The integration has been validated end to end against the real Vanir 1.1.0 package. Vanir ships prebuilt x86-64 ELF parsers only, so `--vanir-runner` must point at a runner that executes it on Linux (for example a small `docker run --platform linux/amd64` wrapper); it does not run natively on macOS. Real captured Vanir output under `test/fixtures/vanir/` drives a regression test, and confirmed that Vanir writes signatures under either `ecosystem_specific` or `database_specific`, both of which the backend now reads. A ready-made runner is provided at [tools/vanir-docker-runner](tools/vanir-docker-runner) (with [tools/Dockerfile.vanir](tools/Dockerfile.vanir)); build the image with `docker build -f tools/Dockerfile.vanir -t glasswing-vanir:latest tools`, then pass `--vanir-runner tools/vanir-docker-runner`.

Phase 3 reads a CycloneDX (1.4/1.5/1.6/1.7) or Syft native JSON SBOM, selects candidate components that map to Anthropic findings, and can bridge an unambiguous strong candidate into `verify-source`:

```bash
npm run check:sbom -- \
  --sbom bom.cdx.json \
  --source ./checkout \
  --impacts data/fix-impacts.json
```

CycloneDX documents are validated with the official [`@cyclonedx/cyclonedx-library`](https://github.com/CycloneDX/cyclonedx-javascript-library) strict validator; Syft documents are validated against the pinned, checksum-recorded official schema under [schema/vendor/syft](schema/vendor/syft). PURLs are canonicalized with [`packageurl-js`](https://github.com/package-url/packageurl-js) and never repaired by hand. Component matching uses the priority `exact PURL > ecosystem + package > repository identity > normalized name`, so a Maven PostgreSQL JDBC component never matches the PostgreSQL server by name, and a valid but mismatched PURL defeats a coincidental name match. Reports follow [schema/sbom-check.schema.json](schema/sbom-check.schema.json), and an SBOM with no candidate Anthropic finding is a valid clean result rather than an error. Real-world inputs are handled robustly: a file containing several concatenated CycloneDX documents (newline-delimited or pretty-printed) is parsed document by document and its components deduplicated, and a document that violates the official schema only in fields irrelevant to component identity (a non-UUID `serialNumber`, a license carrying both `id` and `name`) is processed with a warning instead of being rejected.

An SBOM only selects candidates; it never proves a component is affected. `AFFECTED` requires strong component identity, an authoritative OSV/GHSA/CVE range with provenance, and a comparator that explicitly supports the ecosystem and range type. `sync-ranges` collects those ranges from OSV/GHSA and CVE List V5 exactly as published into `data/affected-ranges.json` (preserving each CVE record's `versionType` for correct comparator dispatch), and `check-sbom --ranges data/affected-ranges.json` consumes them offline to attach a `range_assessment`:

```bash
npm run sync:ranges
npm run check:sbom -- --sbom bom.cdx.json --ranges data/affected-ranges.json --fail-on-affected
```

The SemVer comparator covers npm, Go, and crates.io, and a PEP 440 comparator (via `@renovatebot/pep440`) covers PyPI. RPM, Debian, Maven, and Composer are not hand-rolled; they are handled by an **optional** external [`univers`](https://pypi.org/project/univers/) backend (mirroring the Vanir opt-in pattern) enabled with `--univers-runner tools/univers-runner`. It is used only for CVE ranges of those schemes, degrades to `unknown` when absent, and is gated by a differential conformance check (`tools/univers-conformance.py`) against each ecosystem's authoritative implementation; without it those schemes stay `unknown`. CVE List V5 product ranges are dispatched by their authoritative `versionType`: `semver` uses SemVer, OpenSSL classic versions (letter suffix) use a dedicated comparator, and `rpm`/`debian`/`maven`/other schemes with no proven comparator stay `unknown` rather than being coerced.

Identity governs gating, not the range evidence. A weak, name-only candidate may still receive a CVE product-name `range_assessment` of `affected`, but its explicit final `candidate_decision` stays non-gating (`UNKNOWN`); only strong identity — a matching PURL or a CPE 2.3 match — is `gating_eligible`. A component CPE that is disjoint from the range's CPE excludes the range (a JDBC driver is not the database server). `--fail-on-affected` fails only on a gating-eligible `AFFECTED`, distinct from inconclusive patch evidence.

Exit codes: `0` completed analysis (any decision, or a clean SBOM); `1` invalid input or operational failure; `2` a verifier returned an operational `ERROR`; `3` `check-sbom --fail-on-affected` found an authoritative `AFFECTED`. Aggregate, non-sensitive validation results are recorded in [docs/ACCEPTANCE.md](docs/ACCEPTANCE.md).

## Manual overrides

Projects without sufficient machine-readable sources are supplemented in [overrides/manual.json](overrides/manual.json). Every override must include public evidence and follow these rules:

1. The evidence must explain the one-to-one relationship between the ANT finding and the fix or release.
2. The first fixed version for each maintenance branch must be recorded separately.
3. Do not use `first_patched=true` unless the evidence proves that the release is the first fixed version.
4. A `no_release_yet` assessment must show that the latest stable release predates the fix.

Add tests for new overrides and parser changes. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

## Automated updates

[.github/workflows/update-data.yml](.github/workflows/update-data.yml) synchronizes the latest Anthropic snapshot and advisory changes every day, then opens a pull request when the generated data changes. Output timestamps use Anthropic's `as_of` value rather than the local execution time, avoiding unnecessary diffs when the source snapshot is unchanged.

## Adjudicating the residual (agents)

The deterministic engine is the gate authority and prefers `UNKNOWN` over an unsupported
claim. A second-opinion **adjudicator** investigates the residual `UNKNOWN` /
`PATCH_NOT_FOUND` / `VERIFIER_CONFLICT` / package-identity cases and returns evidence-cited
review metadata (`CONFIRMED` / `LIKELY_TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` /
`INSUFFICIENT_EVIDENCE`). It never overturns a deterministic decision and never
auto-suppresses.

The instructions are tool-neutral markdown and shared across agents:

- **Claude Code:** the skill at [.claude/skills/glasswing-adjudicator/](.claude/skills/glasswing-adjudicator/) (invoke `/glasswing-adjudicator`).
- **Codex / other `AGENTS.md`-aware agents:** [AGENTS.md](AGENTS.md) points at the same
  rules; for a slash command, copy [codex/prompts/glasswing-adjudicator.md](codex/prompts/glasswing-adjudicator.md) into `~/.codex/prompts/`.

## Scope and limitations

- Sealed Anthropic ledger entries whose `ant_id` and `project` have not been disclosed cannot yet be mapped.
- `patched=true` means Anthropic observed an upstream patch; it does not guarantee that a formal release exists.
- GHSA records for C and C++ projects may omit package ranges, requiring additional checks against repository advisory HTML and upstream releases.
- Projects such as WebKit and Hermes, whose tags do not map cleanly to a single product release, may remain `commit_only`.
- The files under `data/` are normalized indexes of external source material. Review each record's `evidence` and the original providers' terms before use.

The code is licensed under Apache-2.0.
