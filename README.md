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

The source-level extension is documented in [docs/PATCH_PRESENCE_PLAN.md](docs/PATCH_PRESENCE_PLAN.md). Phase 2a now adds evidence-backed `fix commit → file/function/patch → source` verification. Conservative SBOM candidate selection remains the next phase.

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

The optional Vanir backend proposed in [GitHub issue #1](https://github.com/windshock/glasswing-fixmap/issues/1) is not a runtime dependency in Phase 2a. The `SourceVerifier` boundary and preserved backend metadata allow it to be evaluated later without coupling the core decision model to Vanir.

## Manual overrides

Projects without sufficient machine-readable sources are supplemented in [overrides/manual.json](overrides/manual.json). Every override must include public evidence and follow these rules:

1. The evidence must explain the one-to-one relationship between the ANT finding and the fix or release.
2. The first fixed version for each maintenance branch must be recorded separately.
3. Do not use `first_patched=true` unless the evidence proves that the release is the first fixed version.
4. A `no_release_yet` assessment must show that the latest stable release predates the fix.

Add tests for new overrides and parser changes. See [CONTRIBUTING.md](CONTRIBUTING.md) for the full process.

## Automated updates

[.github/workflows/update-data.yml](.github/workflows/update-data.yml) synchronizes the latest Anthropic snapshot and advisory changes every day, then opens a pull request when the generated data changes. Output timestamps use Anthropic's `as_of` value rather than the local execution time, avoiding unnecessary diffs when the source snapshot is unchanged.

## Scope and limitations

- Sealed Anthropic ledger entries whose `ant_id` and `project` have not been disclosed cannot yet be mapped.
- `patched=true` means Anthropic observed an upstream patch; it does not guarantee that a formal release exists.
- GHSA records for C and C++ projects may omit package ranges, requiring additional checks against repository advisory HTML and upstream releases.
- Projects such as WebKit and Hermes, whose tags do not map cleanly to a single product release, may remain `commit_only`.
- The files under `data/` are normalized indexes of external source material. Review each record's `evidence` and the original providers' terms before use.

The code is licensed under Apache-2.0.
