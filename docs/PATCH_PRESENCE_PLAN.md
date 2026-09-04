# Patch-Presence Verification Plan

Status: Phases 1, 2a, and 3 candidate selection implemented. The Phase 2b Vanir backend is opt-in behind the `SourceVerifier` interface and has been validated end to end against the real Vanir 1.1.0 package (`linux/amd64`), which fixed a real signature-location parsing bug; promotion to a documented optional dependency still needs broader coverage measurement. Phase 3 `AFFECTED` is now reachable: `sync-ranges` persists authoritative OSV/GHSA ranges to `data/affected-ranges.json` and `check-sbom --ranges` consumes them (npm/Go/crates.io/PyPI comparators enabled; see Milestone 3c). Remaining work is Milestone 4 hardening and the Maven/Debian/RPM/Packagist comparators — not blocked on an algorithm (well-maintained implementations exist), but pending evaluation of an optional `univers` backend gated behind per-scheme differential conformance (Tier 3.13).

Last updated: 2026-09-04 — issue #4 hardening: Tier 0, Tier 1, and Tier 2 complete (adjudication store + evidence hash + check-sbom reuse + `adjudicate` record/query/export-vex CLI + OpenVEX projection), plus Tier 3.15 (Vanir hardening). Pending: Tier 3.12 (distro normalization with backport uncertainty), 3.13 (optional `univers` comparator backend under differential conformance — not blocked on an algorithm), and 3.14 (UNKNOWN categorization + batch reporting). See roadmap below.

## Objective

Extend the existing evidence chain:

```text
ANT finding → CVE/GHSA → fix commit → first patched release
```

with source-level verification:

```text
fix commit → changed file/function/patch → actual component/build
```

The result should answer a narrow, defensible question: **is the upstream fix actually present in this source tree or build input?** The project must optimize for defensible conclusions and low maintenance cost for a single maintainer, not feature count.

## Hard constraints and non-goals

- Do not create another OSV/MITRE-style affected-range database.
- Use an existing OSV, GHSA, or CVE affected range when it is authoritative. Do not infer a missing range from release ordering or maintain one locally.
- An SBOM selects candidate components. It does not prove that a component is affected or fixed.
- `PATCH_NOT_FOUND` is not `AFFECTED`; `UNKNOWN` is not `ERROR`.
- A heuristic component-name match must never fail a security gate.
- Do not add broad AST support, VEX, SARIF, SPDX, binary analysis, or package-manager-specific source discovery in the initial implementation.
- Do not implement SBOM specification parsers, PackageURL parsing, or version comparison algorithms from scratch. Prefer official validators and schemas plus established, ecosystem-correct libraries.
- Keep custom SBOM code limited to projecting validated documents into `NormalizedComponent`; keep custom version code limited to selecting and invoking an appropriate comparator.
- Do not store complete upstream patches in generated datasets.
- Do not fetch, modify, build, or execute the source tree being inspected.
- Existing `sync`, `report`, `validate`, `--verify-github`, `data/fixmap.json`, and `data/fixmap.csv` behavior must remain compatible.

## Decision model

| Decision | Required evidence | Explicitly does not mean |
| --- | --- | --- |
| `VERIFIED_FIXED` | The Glasswing-native verifier establishes complete post-fix patch presence with strong evidence, optionally corroborated by matching Git ancestry | Every build made from the package name or version is fixed |
| `TARGET_ABSENT` | The component is present, but the vulnerability-relevant file or function is absent and no rename/refactor ambiguity remains | Fixed or vulnerable |
| `PATCH_NOT_FOUND` | The target file/function is present, but the fix signature is not found | Affected or exploitable |
| `AFFECTED` | An authoritative OSV/GHSA/CVE range covers the identified component version | Inferred from `PATCH_NOT_FOUND` or from being older than a known fixed release |
| `UNKNOWN` | Evidence is insufficient because of a rename, refactor, ambiguous component identity, missing source, or inconclusive signatures | A tool failure |
| `ERROR` | Parsing, I/O, network, Git, or another verification operation failed | An inconclusive security result |

Every result also records confidence, supporting evidence, and machine-readable reasons. Git ancestry alone cannot produce `VERIFIED_FIXED`, because a later commit may have reverted or partially altered the fix. A complete strong post-image match can produce `VERIFIED_FIXED`; complete moderate native evidence requires matching ancestry for corroboration. Fuzzy, moved, partial, or internally contradictory evidence remains `UNKNOWN` with reduced confidence.

## Architecture

```text
data/fixmap.json
  ANT IDs + advisories + repositories + fix commits
                      │
                      ▼
              sync-impacts (Phase 1)
                      │
                      ▼
            data/fix-impacts.json
        paths + hunk context + fingerprints
                      │
          ┌───────────┴───────────┐
          ▼                       ▼
 verify-source (Phase 2)    SBOM adapters (Phase 3)
          │                 select candidates only
          └───────────┬───────────┘
                      ▼
              verification result
       decision + confidence + evidence + reasons
```

`data/fix-impacts.json` is a separate, versioned artifact. This avoids changing the strict `fixmap.json` 1.0 schema and lets impact fingerprints evolve without destabilizing current consumers. A later schema version may link or embed summaries after the format has proven stable.

### Fit with the current codebase

| Existing area | Reuse or extension |
| --- | --- |
| `src/sync.ts` | Remains the release-map orchestrator; it is not expanded into source verification |
| `src/http.ts` | Reuse ETag caching, retries, offline mode, and GitHub authentication for commit diffs |
| `src/github-verify.ts` | Reuse repository/tag ancestry conventions; add local-checkout ancestry in a separate verifier |
| `src/sources/advisory.ts` | Reuse explicit OSV/GHSA package and range events, retaining their provenance and interval semantics |
| `src/types.ts` and `schema/fixmap.schema.json` | Keep the current `fixmap.json` 1.0 contract unchanged |
| `src/output.ts` | Follow deterministic sorting and writing conventions for the new artifact and JSON results |
| `src/cli.ts` | Add isolated subcommands without changing existing arguments or defaults |

New code should be grouped by responsibility (`impact`, `source-verification`, and `sbom`) rather than folded into the existing synchronizer. This keeps each boundary testable and avoids a repository-wide refactor.

## Proposed data model

```ts
interface FixImpactDataset {
  metadata: {
    schema_version: "1.0.0";
    generated_from: {
      fixmap_schema_version: string;
      source_as_of: string;
      source_url: string;
    };
    finding_count: number;
    impact_count: number;
    complete_count: number;
    partial_count: number;
    error_count: number;
  };
  impacts: FixImpact[];
}

interface FixImpact {
  repository: string;
  commit: string;
  ant_ids: string[];
  extraction_status: "complete" | "partial" | "error";
  files: ChangedFile[];
  evidence: Evidence[];
  warnings: string[];
}

interface ChangedFile {
  path_before?: string;
  path_after?: string;
  status: "added" | "modified" | "deleted" | "renamed";
  patch_available: boolean;
  functions?: string[];
  hunks: PatchHunk[];
}

interface PatchHunk {
  old_range: { start: number; count: number };
  new_range: { start: number; count: number };
  context?: string;
  signatures: PatchSignature[];
}

interface PatchSignature {
  algorithm: "glasswing-normalized-sha256-v1";
  kind:
    | "added"
    | "deleted"
    | "unchanged_context"
    | "preimage"
    | "postimage"
    | "combined";
  digest: string;
  line_count: number;
  normalized_length: number;
}
```

The generated artifact contains paths, ranges, function/context labels, hashes, and source evidence. It does not contain complete patch bodies. Signature algorithms are explicitly versioned so normalization can change without silently changing prior results.

Verification output is a separate object rather than persistent state in `fixmap.json`:

```ts
interface SourceVerificationReport {
  schema_version: "1.0.0";
  ant_id: string;
  source: string;
  impact_schema_version: string;
  targets: Array<{ repository: string; commit: string }>;
  backend_results: VerifierResult[];
  decision:
    | "VERIFIED_FIXED"
    | "TARGET_ABSENT"
    | "PATCH_NOT_FOUND"
    | "AFFECTED"
    | "UNKNOWN"
    | "ERROR";
  confidence: "high" | "medium" | "low";
  reasons: DecisionReason[];
}
```

## Phase 1 — Fix impact extraction

Add a dedicated command so the normal synchronization path and its generated output remain unchanged:

```bash
glasswing-fixmap sync-impacts \
  --fixmap data/fixmap.json \
  --output data/fix-impacts.json
```

Implementation steps:

1. Select findings with a repository and a supported GitHub fix commit.
2. Fetch the commit metadata and unified diff through the existing cached HTTP client.
3. Record changed paths, change status, ranges, and hunk-header function/context.
4. Normalize added, deleted, and unchanged context lines and create several SHA-256 signatures per hunk.
5. Deduplicate impacts by `(repository, commit)` while preserving all related ANT IDs and evidence.
6. Validate against a dedicated JSON schema and write deterministic output.

Normalization v1 will remove line-ending differences, normalize horizontal whitespace, and trim structurally irrelevant leading/trailing blank lines. It will retain tokens and punctuation; broad comment stripping or language-aware rewriting would create avoidable collisions. A combined signature binds content hashes to file path and function context. Multiple signatures allow a backport to match even if surrounding context changes.

The extractor will expose a small `FunctionContextExtractor` interface, but v1 will use diff hunk headers and context only. Language-specific AST parsers are deferred until real false-negative data justifies their maintenance cost.

Phase 1 is complete when extraction is deterministic, schema-validated, cache/offline compatible, and fixture-tested for modified, added, deleted, and renamed files.

Phase 1 is implemented. An unavailable or unparseable patch, an unsupported file status, or GitHub's changed-file limit produces a `partial` impact with warnings rather than a false complete result. A failed commit lookup is retained as an `error` impact in the default mode; `--strict` fails immediately. A live acceptance run for `ANT-2026-P23DVQM2` resolved one full commit, four files, and eleven hunks without persisting patch source text.

## Phase 2 — Source verification

Add:

```bash
glasswing-fixmap verify-source \
  --ant ANT-2026-XXXX \
  --source ./checkout

glasswing-fixmap verify-source \
  --ant ANT-2026-XXXX \
  --source ./checkout \
  --json
```

Phase 2a is implemented through a narrow `SourceVerifier` interface. Each backend returns its name, version, execution status, observations, evidence, and warnings. Backends are evidence producers rather than voters; the fusion layer applies one conservative decision policy after retaining their raw output.

Verification order:

1. Resolve the ANT finding and its impact records.
2. Treat the source directory as read-only and validate repository identity when Git metadata is available.
3. Run local `git merge-base --is-ancestor <fix> HEAD` when the exact repository and commit are available. Do not fetch missing history by default.
4. Independently inspect relevant current/previous paths, hunk context, and added/deleted pre-image/post-image signatures.
5. Apply the decision table without promoting an absence of evidence into an affected conclusion.

Conservative rules:

- Exact ancestry in the correct repository is corroborating evidence, not a final decision by itself.
- A strong native match requires complete post-image evidence for one fix impact and no missing, moved, pre-fix, unsupported, or failed checks for that impact.
- Complete moderate native evidence plus matching ancestry can produce `VERIFIED_FIXED` with medium confidence.
- Ancestry plus a pre-image or missing expected signature produces `UNKNOWN` with `VERIFIER_CONFLICT`; this explicitly covers later reverts.
- A fuzzy, partial, renamed, or refactored match produces `UNKNOWN`, not `VERIFIED_FIXED`.
- `TARGET_ABSENT` is used only when component identity is established and absence is not plausibly caused by a rename or incomplete source checkout.
- `PATCH_NOT_FOUND` requires the relevant path/function to be present. It does not fail an affected/vulnerable gate by itself.
- An old product version with a verified backport may still be `VERIFIED_FIXED`.

Text output summarizes backend observations, decision, confidence, and reason codes. JSON output follows `schema/source-verification.schema.json` and preserves every backend observation and evidence item so CI consumers do not need to parse terminal text. The implementation does not fetch, modify, build, or execute the inspected source.

Phase 2b evaluates Vanir as an optional backend behind the same interface. It is deliberately not a default backend: `verify-source` runs `git-ancestry` and `glasswing-fingerprint` by default and only adds Vanir when the operator supplies `--vanir-runner` and `--vanir-signatures`. Fake-runner differential fixtures now demonstrate graceful absence (an unavailable runner is `unsupported`, never `ERROR`/`AFFECTED`), missing-patch normalization to `PATCH_NOT_FOUND`, and a clean scan normalized to `UNKNOWN` rather than a proof of fix. Making Vanir a documented optional installation still requires measured differential coverage beyond the native verifier and acceptable runtime/setup cost.

## Phase 3 — SBOM candidate selection

Add:

```bash
glasswing-fixmap check-sbom \
  --sbom bom.cdx.json \
  --source ./checkout
```

Use an adapter boundary:

```ts
interface SbomAdapter {
  supports(document: unknown): boolean;
  parse(document: unknown): NormalizedComponent[];
}

interface NormalizedComponent {
  source_format: "cyclonedx" | "syft";
  type?: string;
  name: string;
  version?: string;
  purl?: string;
  cpes: string[];
  repository?: string;
  locations: string[];
}
```

### Validation and projection boundary

The adapter pipeline is deliberately small:

```text
JSON input
  → format and schema-version detection
  → official schema validation
  → thin components/artifacts projection
  → PackageURL canonicalization
  → NormalizedComponent[]
```

CycloneDX JSON is implemented first. For supported specification versions 1.5, 1.6, and 1.7, use `JsonStrictValidator` from the official [`@cyclonedx/cyclonedx-library`](https://github.com/CycloneDX/cyclonedx-javascript-library), including its required Ajv peer dependencies. After validation, use `JSON.parse()` only to project the small set of fields required by `NormalizedComponent`; do not build a second CycloneDX object model or specification parser.

Parse and canonicalize every supplied PURL with [`packageurl-js`](https://github.com/package-url/packageurl-js), using `PackageURL.fromString()` followed by `toString()` as the canonical representation. A malformed optional PURL is never eligible for exact identity matching; record the issue and fall back conservatively rather than repairing or concatenating a PURL manually.

A narrow Syft-native JSON adapter follows in the same phase because two supplied acceptance samples use that format. Validate the document against the exact versioned [official Anchore Syft JSON schema](https://oss.anchore.com/docs/reference/syft/json/) selected by the document's schema version, then project only `artifacts[]`. Pin supported schemas, their upstream URLs, and checksums locally for reproducible offline validation; do not download a schema or transmit inventory at scan time. The initial acceptance target includes schema `16.1.2` used by the supplied samples.

Generic Go or Python SBOM tooling is not added as a subprocess or runtime dependency. SPDX, VEX, SARIF, XML, and other formats remain explicitly deferred.

Component matching priority is:

```text
exact PURL
  > ecosystem + package
  > repository identity
  > normalized name heuristic
```

Additional safeguards:

- Exclude CycloneDX `type=file` entries from package candidate matching.
- A PURL mismatch overrides a coincidental name match.
- Name-only matches are candidates with low confidence; they can produce only `UNKNOWN` until stronger identity evidence is supplied.
- `AFFECTED` requires both strong component identity and an authoritative range that explicitly covers the component version.
- Consume range facts exactly as published and parsed from OSV/GHSA/CVE, including ecosystem, package, range type, events, and evidence. Do not reconstruct a range from `fixed_versions[]` alone.
- Do not infer `AFFECTED` from `version < fixed_version`.
- When an SBOM maps to several possible source components, require an exact PURL or an explicit `--component <purl>` selection rather than scanning arbitrary directories.
- Do not persist or upload a user's component inventory unless the user explicitly chooses an output path.

The SBOM command first reports candidate-selection evidence, then runs source verification for an unambiguous candidate when `--source` is supplied. A clean result with no candidate Anthropic findings is valid and must not be represented as an error.

### Version-comparison boundary

Affected-range evaluation has a separate adapter contract:

```ts
interface VersionComparator {
  supports(ecosystem: string, rangeType: string): boolean;
  evaluate(version: string, range: AuthoritativeRange):
    | "affected"
    | "not_affected"
    | "unknown";
}
```

Use [`semver`](https://github.com/npm/node-semver) for npm and sources that explicitly declare Semantic Versioning. Use strict parsing for security decisions; do not silently coerce an arbitrary version into SemVer. Maven, PyPI/PEP 440, Debian, RPM, and other ecosystems require their own well-maintained comparison implementation and conformance fixtures. A generic “semver-ish” comparator may be useful for display ordering, but it must not evaluate authoritative ranges for a different ecosystem.

Projects such as [OSV-Scanner](https://github.com/google/osv-scanner) and [univers](https://github.com/aboutcode-org/univers) provide useful ecosystem semantics and test vectors, but their Go and Python implementations are references rather than runtime dependencies for this Node CLI. Each ecosystem comparator is enabled only after its behavior is tested against authoritative examples. If the ecosystem, version scheme, or range type cannot be selected reliably, return `UNKNOWN`.

`AFFECTED` therefore requires all three conditions:

1. strong component identity;
2. an authoritative affected range with provenance; and
3. a comparator that explicitly supports that ecosystem and range type.

No comparator match may be reconstructed from release ordering alone. The CLI must not send package names or versions to an external query service by default.

## Supplied SBOM acceptance corpus

The eight local files will be used as private acceptance inputs and will not be committed:

| Sample | Format | Package components | Identity coverage | Required behavior |
| --- | --- | ---: | --- | --- |
| `logpresso-sbom-4.0.2502.1_202608201650.json` | CycloneDX 1.5 | 322 | 322 PURLs | Parse npm/Maven PURLs; reject misleading name-only matches such as an `auth` artifact |
| `logpresso-sbom-3.10.2207.0_202608201651.json` | CycloneDX 1.5 | 134 | 134 PURLs | A PostgreSQL JDBC component must not match the PostgreSQL server solely by name |
| `IRMS_SBOM.json` | CycloneDX 1.6 | 110 | No PURL/CPE | Keep name-only candidates low confidence and non-gating |
| `Mailscreen skp-sbom-syft-cdx.json` | CycloneDX 1.7 | 13 package + 1 file | 13 PURLs and CPEs | Parse Composer identities and ignore the file component |
| `splunk_7.1.3.1_bom.json` | CycloneDX 1.7 | 10,435 file entries only | No PURL/CPE | Ignore file-only inventory for package matching without failing |
| `sbom.ftrans.json` | Syft native 16.1.2 | 74 artifacts | 74 PURLs and CPEs | Parse through the narrow Syft adapter |
| `sbom.xtrans.json` | Syft native 16.1.2 | 74 artifacts | 74 PURLs and CPEs | Parse through the narrow Syft adapter |
| `정보보안포탈_SBOM.json` | CycloneDX 1.6 | 76 | No PURL/CPE | Return conservative candidate results with no heuristic gate failure |

Current inspection found no authoritative affected match in this sample set. That is an expected clean result, not a reason to weaken matching. Synthetic fixtures will exercise all security decisions.

## Test plan

Required fixture cases:

1. Exact upstream fixed source → `VERIFIED_FIXED`.
2. Pre-fix source with the target file/function → `PATCH_NOT_FOUND`.
3. Component present but vulnerability-relevant file absent → `TARGET_ABSENT`.
4. Function renamed or substantially refactored → `UNKNOWN`.
5. Source parsing, Git, or tool failure → `ERROR`.
6. Strong component identity plus an official affected range covering the version → `AFFECTED`.
7. Backported fix in an older version → `VERIFIED_FIXED` when the patch signature is strong.

Additional regression cases:

- Maven PostgreSQL JDBC must not match the PostgreSQL server.
- A PURL mismatch must defeat an equal package name.
- A name-only match must never produce `AFFECTED` or a failing exit code.
- An invalid PURL must never be repaired into an exact match.
- File-only CycloneDX documents must parse to zero package candidates.
- CycloneDX and Syft forms of the same PURL must normalize identically.
- SemVer security decisions must reject values that require coercion.
- An unsupported ecosystem or range type must produce `UNKNOWN`, not a lexical or generic-version guess.
- Partial/fuzzy signatures must remain `UNKNOWN`.
- Existing sync fixtures, schema validation, JSON/CSV output, and GitHub tag verification must remain unchanged.

Tests use small synthetic diffs and source trees checked into `test/fixtures`. The supplied production SBOMs are local acceptance inputs only, both to avoid leaking inventory and to keep tests reproducible.

## CLI and exit behavior

Commands should support human-readable output by default and structured JSON through `--json` or `--output <file>`.

Initial exit behavior:

- Exit `0` for a completed analysis regardless of `VERIFIED_FIXED`, `TARGET_ABSENT`, `PATCH_NOT_FOUND`, or `UNKNOWN`.
- Exit non-zero for `ERROR`, invalid input, or an explicit policy option that finds authoritative `AFFECTED` results.
- Do not add a default “fail when patch not found” mode.

Any future policy/gating option must distinguish authoritative `AFFECTED` from inconclusive patch evidence in both its name and output.

## Delivery sequence

### Milestone 0 — Contracts and fixtures

- Add schemas and TypeScript contracts for fix impacts and verification results.
- Prototype and pin only the validators, schemas, PURL library, and comparators needed by supported inputs; record upstream provenance and checksums for vendored schemas.
- Add compact synthetic diff/source fixtures and sanitized SBOM identity fixtures.
- Record privacy behavior and decision invariants in tests.

### Milestone 1 — `sync-impacts` (implemented)

- Extract GitHub commit impact metadata and fingerprints.
- Reuse HTTP cache, offline mode, token handling, deterministic sorting, and evidence conventions.
- Generate and validate `data/fix-impacts.json` without changing `fixmap.json`.

### Milestone 2a — `verify-source` (implemented)

- Implement safe local Git ancestry checks.
- Implement path, hunk-context, and exact/strong signature checks.
- Produce text and JSON decisions under the strict decision model.

### Milestone 2b — optional Vanir evaluation (validated against real Vanir 1.1.0)

- Vanir runs only behind `SourceVerifier` and only when `--vanir-runner`/`--vanir-signatures` are supplied; absence or unsupported languages do not break native verification.
- Native and Vanir observations are preserved separately, and explicit conflicts remain `UNKNOWN`.
- Fake-runner differential fixtures cover graceful absence, missing-patch → `PATCH_NOT_FOUND`, and clean scan → `UNKNOWN`.
- The integration was exercised against the real Vanir 1.1.0 package end to end in a `linux/amd64` container (Vanir ships prebuilt x86-64 ELF parsers only, so it does not run natively on macOS). Vanir generated Function and Line signatures from a Git fix commit and produced a real differential: the pre-fix tree reported `missing_patches`, the post-fix tree reported none. The captured signature file and both reports are checked in under `test/fixtures/vanir/` and drive a regression test.
- This surfaced a real bug the fake-runner fixtures could not: Vanir's own sign generator writes signatures under `affected.database_specific.vanir_signatures`, but the parser read only `ecosystem_specific`, so real signature files selected zero signatures and returned `BACKEND_UNSUPPORTED`. The parser now reads either location, matching Vanir's own precedence. Vanir's Git-ecosystem signature generation applies to C/C++/Java findings that carry a GitHub fix commit, so it is a genuine optional complement; making it a documented installation still requires broader coverage measurement.

### Milestone 3 — `check-sbom` (candidate selection implemented)

- Official CycloneDX 1.5/1.6/1.7 `JsonStrictValidator` validation, thin JSON projection, and `packageurl-js` canonicalization are implemented.
- Exact-version official Syft schema (16.1.2) validation and the narrow `artifacts[]` projection are implemented; the schema is vendored under `schema/vendor/syft` with its upstream URL and SHA-256 recorded in `provenance.json`.
- The SemVer comparator (npm, Go, crates.io) and a PEP 440 comparator (PyPI) are implemented behind the `VersionComparator` boundary; every other ecosystem or range type returns `UNKNOWN`. Coercion-requiring versions are rejected.
- An unambiguous strong candidate is connected to `verify-source`; multiple strong candidates require `--component <purl>`.

Remaining before `AFFECTED` is reachable from real data: the current dataset persists only collapsed `fixed_versions[]`, not an authoritative affected range with range type, `last_affected`/`limit` events, and provenance. The comparator machinery is complete and unit-tested against synthetic ranges, but `AFFECTED` will only be emitted once such ranges are persisted (a dedicated artifact) or consumed directly from OSV/GHSA/CVE. Until then, matched components remain candidate-only, never `AFFECTED`, consistent with the decision model.

### Milestone 3b — real-world SBOM robustness (planned)

Acceptance testing against real exported SBOMs surfaced two input realities the initial strict path did not handle. Both are scoped robustness fixes, not new analysis capability, and neither weakens a security gate.

- Multi-document input: several exports concatenate multiple CycloneDX BOMs in one file, either as newline-delimited JSON or as back-to-back pretty-printed documents. A single `JSON.parse` fails on the second document. Parse each document in sequence, run the adapter on each, and aggregate components and candidates while reporting the document count.
- Cosmetic-violation tolerance: real SBOMs commonly violate the official CycloneDX schema in fields irrelevant to component identity (a non-UUID `serialNumber`; a license carrying both `id` and `name`). Run the official validator, but hard-reject only when a violation touches a projected identity field (`name`, `version`, `purl`, `cpe`, `type`) or the structural shape of `components`; tolerate other violations with a warning, since projection is already type-guarded. Candidates from such a document stay conservative and non-gating.

### Milestone 3c — `AFFECTED` via authoritative-range consumption (implemented)

`AFFECTED` is now reachable without inferring ranges or maintaining a curated range database. `sync-ranges` consumes OSV/GHSA records exactly as published and writes the full authoritative ranges to a companion artifact (`data/affected-ranges.json`, mirroring the `fix-impacts.json` pattern) with ecosystem, package, range type, events, and provenance; `fixmap.json` is unchanged. A live run over 30 GHSA-bearing findings collected real ranges across Packagist, npm, crates.io, Maven, and Go (for example `twig/twig` `[3.24.0, 3.26.0)`), confirming the parser works on published data.

`check-sbom --ranges` consumes the artifact offline: for a strong-identity candidate with a version, it selects a comparator that explicitly supports the range's ecosystem and type and evaluates it, attaching a `range_assessment`. `AFFECTED` requires all three of strong identity, an authoritative range with provenance, and a supporting comparator; a name-only candidate is never evaluated, and any unresolved case stays `unknown`. The SemVer comparator covers npm, Go, and crates.io, and a PEP 440 comparator (via `@renovatebot/pep440`) covers PyPI, each with conformance vectors; Maven, Packagist, and other schemes return `unknown` until a well-maintained library is available — they are not hand-rolled. `--fail-on-affected` makes an authoritative `AFFECTED` exit non-zero, distinct from inconclusive patch evidence.

### Milestone 4 — Hardening and release (in progress)

- Done: ran 16 real acceptance SBOMs plus the real Vanir 1.1.0 backend and retained aggregate, non-sensitive notes in [ACCEPTANCE.md](ACCEPTANCE.md).
- Done: confirmed existing outputs are byte-for-byte compatible — `data/fixmap.json` and `data/fixmap.csv` re-serialize identically through the current code, and `sync`/`report`/`validate` are unchanged.
- Done: documented exit semantics (`0`/`1`/`2`/`3`) and limitations in the README and ACCEPTANCE.md.
- Done: enabled Go and crates.io comparators (genuine SemVer) and a PyPI PEP 440 comparator (via `@renovatebot/pep440`), each with conformance vectors. Maven and Packagist remain `unknown` — their schemes must not be hand-rolled, and well-maintained implementations exist (Renovate TS, the official references, `univers`); the missing piece is a permissive standalone Node drop-in, so they are pending evaluation of an optional `univers` backend under differential conformance (Tier 3.13), not blocked on an algorithm.
- Done: end-to-end `verify-source` on a real SBOM candidate (`cloudflare/circl` `v1.3.7` → `TARGET_ABSENT`); raised the rename-discovery cap 250 → 2000 so a genuinely absent target on real-world repositories resolves to `TARGET_ABSENT` instead of a truncated `UNKNOWN`.

### Next session — GitHub issues #1–#3 reflected

Priority order leads with the correctness/security bugs from issue #2, then feature and packaging work.

**Issue #1 — Phase 2 multi-verifier source verification: essentially delivered.** Phase 2a (`SourceVerifier`, `GitAncestryVerifier`, `GlasswingFingerprintVerifier`, observation/evidence model, conservative fusion, `verify-source`, and the fixed/vulnerable/backported/reverted/moved/partial differential tests) and the Phase 2b real-Vanir evaluation are implemented. Candidate to close after publishing the Vanir differential write-up.

**Issue #2 — hardening review. The P0 correctness/security bugs are fixed; P1/P2 remain.**

P0 — done this session:
- Deletion-heavy false positive (`native-fingerprint.ts`): `evaluateHunk` now checks a still-present deleted line and the pre-fix image before any post-fix match, so a pure-deletion hunk's context overlap can no longer read as `VERIFIED_FIXED`. Pure-deletion regression test added.
- Range `unknown` propagation (`check.ts assessRanges`): a `not_affected` no longer overrides an unresolved range — any applicable unresolved range keeps the result `unknown` (affected still dominates). OSV `limit` events are now preserved in the artifact. Remaining: also ingest `affected.versions[]` as exact positive evidence when range comparison is unavailable.
- SBOM ↔ source binding (`check.ts` bridge): a `source_binding` provenance (`verified` / `user_asserted` / `unverified`) is recorded; a repository-identity conflict is `unverified`, otherwise `user_asserted` (version not machine-bound), surfaced as a warning, and source evidence stays separate from the range assessment. Remaining: emit `verified` once a VCS-revision/version binding exists.
- Fail-open policy paths (`cli.ts`): `--fail-on-affected` without `--ranges`, `--source` with an unreadable fix-impact dataset, and a malformed explicit `--component` PURL all now error instead of silently degrading.

P1:
- Done: partial-impact gating — the native verifier emits an `IMPACT_INCOMPLETE` observation for a non-`complete` fix impact, and fusion treats it as inconclusive so a partial extraction can no longer reach `VERIFIED_FIXED` even when every extracted hunk matches.
- Done: CycloneDX root component — `metadata.component` and its nested structure are now projected, so the BOM's primary application is not missed.
- Remaining: multi-commit fix-set semantics (`relation: all_of | any_of`, optional `branch`). Deferred because it needs a data-model design that fixmap does not currently carry; a naive "require every commit" default would wrongly fail legitimate branch-specific fixes (e.g. Rocket.Chat 7.x vs 8.x), so it must be modeled from real relation/branch evidence rather than assumed.

P2 — done:
- Added `.github/workflows/ci.yml` running `npm ci`, `npm run check`, `npm test`, and `npm run validate` on push to `main` and on pull requests, separate from the scheduled data-refresh workflow, with read-only permissions and no untrusted input.

**Issue #3 — AI adjudicator Skill: delivered.** The reusable `glasswing-adjudicator` Skill lives at [`.claude/skills/glasswing-adjudicator`](../.claude/skills/glasswing-adjudicator) — a compact `SKILL.md` with detailed rules and six worked regression examples under `references/`. It gives an evidence-backed second opinion on unresolved results (`UNKNOWN`, `PATCH_NOT_FOUND`, `VERIFIER_CONFLICT`, unsupported comparator, missing range, package-identity ambiguity), never overwrites the deterministic decision, returns `CONFIRMED` / `LIKELY_TRUE_POSITIVE` / `LIKELY_FALSE_POSITIVE` / `INSUFFICIENT_EVIDENCE` with cited machine + upstream evidence, records contradictions and missing evidence, and never fabricates an affected range or auto-suppresses. The `cloudflare/circl` `v1.3.7` result (vulnerable subsystem introduced after the installed version → `TARGET_ABSENT`) is example 1.

**Pre-existing feature work (unchanged priority, after the P0 fixes):**
- Maven/Debian/RPM/Packagist comparators (PyPI PEP 440 is done) via an optional `univers` backend, each behind per-scheme differential conformance against the official reference implementation (Tier 3.13) — these unblock `AFFECTED` for the ranges `sync-ranges` already collects.
- Scheduled `sync-impacts`/`sync-ranges` refresh, only after rate limits and generated-diff size are measured.
- Done: reusable Docker-based Vanir runner wrapper (`tools/vanir-docker-runner` + `tools/Dockerfile.vanir`) so `verify-source --vanir-runner` drives the real Vanir detector in a `linux/amd64` container. Remaining (optional): promote Vanir to a documented optional install after broader real-Vanir coverage measurement.

## Review fixes (external review, 2026-09-03)

An external review found real defects; all are now fixed and covered by tests, in this order (each line states the defect and the fix applied):

1. P0 multi-commit fix — `fusion.ts` excluded impacts whose files are absent, so one matching commit could return `VERIFIED_FIXED` while another required commit was simply missing. With unknown relation, treat the fix set as `all_of`: every impact must be verified present and complete, otherwise `UNKNOWN`. Add optional `relation` (`all_of`/`any_of`) and `branch` to `FixImpact`.
2. P0 OSV `limit` — the comparator ignored `limit` events, so a version at/after an exclusive `limit` read as `affected`. Evaluate `limit` as an exclusive upper bound. Also preserve `affected.package.purl` and `ranges[].repo` in the range artifact (previously dropped).
3. P0 strict CLI options — unknown flags (e.g. a typo `--fail-on-affectd`) were silently accepted, which could disable a security gate. Reject unknown options per command.
4. P1 malformed multi-document — the scanner accepted arbitrary text around JSON values, and an unsupported document among several was skipped with only a warning. Reject non-whitespace outside documents; treat an unsupported document in a multi-document file as an error.
5. P1 PURL case rules — the identity key lowercased every ecosystem, so case-different Maven coordinates (case-sensitive) matched. Lowercase only case-insensitive types.
6. P1 private sample protection — `sample/` was untracked but not ignored and was included by `npm pack`. Ignore it and restrict the package file list.
7. P2 Vanir reproducibility — pin the base image digest and Vanir version, record the real Vanir version, and preserve the report's SHA-256 rather than a deleted temp path.
8. CycloneDX 1.4 input support — the official JS library already supports 1.2–1.7, so accept 1.4 (thin projection unchanged); a dedicated BOM up-conversion remains an optional future feature via `cyclonedx-cli`.

## Improvement — consume CVE List V5 ranges (2026-09-03)

Acceptance testing on name+version-only SBOMs (Palo Alto product line, IRMS)
showed the recurring pattern: a component like `openssl 3.0.7` matches an
Anthropic finding whose authoritative affected range (`introduced 3.0.0`,
`fixed 3.0.21`) already came from CVE List V5, yet the deterministic engine kept
it low-confidence because `sync-ranges` consumed only OSV, so the range never
reached `affected-ranges.json`, and the component carries no PURL. That version
math is deterministic and belongs in the engine, not the AI adjudicator.

- `sync-ranges` also consumes the CVE List V5 record for each finding's CVE and
  emits its `affected[].versions[]` ranges (`version`/`lessThan`/
  `lessThanOrEqual`) into `affected-ranges.json`, keyed by CVE product (with any
  CPEs), exactly as published — not reconstructed from `fixed_versions[]`.
- `check-sbom` applies a CVE-product range to a candidate by CPE or by component
  name and evaluates the version, attaching a `range_assessment`. A name-only
  match remains weak identity: it is surfaced for review but does not gate
  `--fail-on-affected`, which still requires strong (PURL/CPE) identity.
- The adjudicator Skill is then reserved for cases an authoritative range cannot
  resolve (feature introduced after the installed version like `circl`, product
  namesake mismatch, backport/refactor, verifier conflict).
- Scope note: glasswing is not a general SBOM-vs-CVE scanner (that is grype /
  trivy / osv-scanner). It consumes the authoritative ranges of its own
  Anthropic findings and adds the fix→source verification those tools lack.

## Improvement — OpenSSL version comparator vs. Skill routing (2026-09-03)

Classifying the residual `UNKNOWN` verdicts from the full sample sweep (12
unique component/version/finding pairs) showed they are two different problems,
and most are *not* work for the AI adjudicator:

- **11/12 are a deterministic comparator gap, not an investigation.** OpenSSL
  ships its own version scheme — `major.minor.fix` plus a letter suffix
  (`1.0.2q`, `1.1.1g`, `1.1.1zh`, `0.9.8p`) — which is not SemVer, so the SemVer
  comparator returned `unknown`. But `1.0.2q ∈ [1.0.2, 1.0.2zq)` is pure version
  math; handing it to an AI would be exactly the over-use the engine avoids.
- **1/12 is a genuine identity case for the Skill.** `postgresql 42.4.0` matched
  a PostgreSQL *server* range (`fixed 14.23 / 15.18 / 16.14`) by bare product
  name, but 42.x is the **PostgreSQL JDBC driver** — a different product. No
  comparator can fix a namesake mismatch; the Skill investigates identity and
  flags `LIKELY_FALSE_POSITIVE`.

Fix:

- Add a dedicated CVE-ecosystem version comparator that understands OpenSSL
  classic versioning (`X.Y.Z` + bijective base-26 letter suffix, where the empty
  suffix `1.1.1` precedes `1.1.1a`) and plain three-part numeric versions. It
  resolves the OpenSSL letter-suffixed and base-release cases deterministically
  (several flip to `AFFECTED`, the pre-series ones to `not_affected`).
- Deliberately do **not** guess distro/FIPS variants (`3.4-fips3.1`, Gentoo
  `0.16_p3`) or two-part product-line boundaries (`postgresql 15.18`): these fail
  strict parsing and stay `UNKNOWN`, routed to the Skill or left for a future
  distro-version normalizer — never coerced.
- Net effect on the sample: residual `UNKNOWN` drops to the genuinely
  unresolvable (FIPS/distro variants, the JDBC-driver namesake), which is the
  correct, small surface for human/AI adjudication.

## Improvement roadmap — hardening before CPE/VEX (2026-09-03, issue #4)

The pipeline now runs SBOM → component identity → authoritative range →
source/patch verification → residual `UNKNOWN` → AI adjudication → human
disposition → planned persisted decision / VEX. Before CPE-based strong identity
and a persisted VEX/adjudication store turn these results into stronger
automation, the trust-boundary issues below must close: **a weak, non-gating hint
today can become an incorrect BLOCK or suppression once CPE and VEX are wired
in.** This section is a plan only — not yet implemented. It supersedes and
reorganizes the earlier four-item roadmap; the correctness / fail-closed work
(Tier 0) now precedes CPE, VEX, and distro normalization.

Design invariant:
> Deterministic coverage should expand until only the genuinely ambiguous long
> tail reaches AI. Persist evidence and human disposition first; export VEX
> second. VEX must not become a shortcut around weak identity, stale evidence, or
> unresolved provenance.

### Tier 0 — correctness / fail-closed (highest priority) — implemented 2026-09-03

All four Tier 0 items are implemented and covered by tests; the full sample sweep
holds at `affected 42 / not_affected 72 / unknown 3`, where the residual `unknown`
is now the genuinely unresolvable long tail (FIPS variant `3.4-fips3.1`, Gentoo
`0.16_p3`, and the `postgresql 42.4.0` rpm-typed JDBC namesake).

1. **Preserve and honor CVE List V5 `versionType`.** *(done)* `parseCveRanges()` flattens
   every CVE record to `ecosystem: "cve"`, `range_type: "SEMVER"` and discards
   `versionType` (only `git` is skipped); `CveVersionComparator` then treats the
   `cve` sentinel as OpenSSL-classic / three-part ordering universally. But `cve`
   is a *provenance* category, not a version scheme. Preserve the authoritative
   `versionType` and dispatch explicitly: `semver` → node-semver; `git` → source
   verification, never string comparison; `rpm`/`debian`/`maven`/… →
   ecosystem-specific comparator when supported; OpenSSL product + compatible
   classic form → the dedicated OpenSSL comparator; unknown/custom scheme with no
   proven comparator → `UNKNOWN`. No universal "CVE comparator". (Supersedes the
   `cve`-sentinel design of the OpenSSL-comparator section above.) Ref:
   CVEProject/cve-schema `schema/docs/versions.md`.

2. **Preserve / evaluate CVE List V5 `changes[]`.** *(done)* The range-projection path
   ignores within-line status transitions (e.g. affected → unaffected at 2.5.2 →
   affected at 2.6.0 → unaffected at 2.6.3), which can flatten a non-contiguous
   range into a broad false `AFFECTED`. Preferred: preserve `changes[]` in the
   range artifact, evaluate transitions per the declared `versionType`, keep
   provenance for every boundary. Minimum fail-safe if deferred: any entry with
   `changes[]` → mark the range unsupported / `UNKNOWN`; never emit a gating
   `AFFECTED` from the simplified interval.

3. **Explicit `--source` must not fail open.** *(done)* `checkSbom()` catches
   `verifySource()` exceptions and converts them to warnings, so an explicitly
   requested source verification can exit 0 without ever completing. Required:
   `check-sbom --source …` + `verifySource()` throws / cannot execute →
   operational `ERROR` + non-zero exit. A best-effort warning is acceptable only
   when source verification was not explicitly part of the command contract.

4. **Validate external `--ranges` input before use.** *(done)* `readAffectedRangeDataset()`
   does a raw `JSON.parse(… as AffectedRangeDataset)`, so a user-supplied or
   modified ranges file reaches the decision engine unvalidated. Change the path
   to read → structural / schema / semantic validation → snapshot-compatibility
   validation → evaluate. Malformed security-decision input must fail closed.

### Tier 1 — evidence integrity — implemented 2026-09-04

All four Tier 1 items are implemented and covered by tests (78 passing).

5. **Bind fixmap / ranges / impacts to one snapshot.** *(done)* Companion datasets carry
   only partial `generated_from` (schema version, `source_as_of`, source URL).
   Propagate and validate at least `fixmap_schema_version`, `source_as_of`,
   `source_revision`, and a `source_manifest` digest. At scan time, reject or
   explicitly mark incompatible / stale companions rather than silently combining
   a newer fixmap with older ranges/impacts.

6. **Atomic scheduled refresh of all companion datasets.** *(done)*
   `.github/workflows/update-data.yml` refreshes `fixmap` only. Run `sync` +
   `sync-ranges` + `sync-impacts` + snapshot-compatibility validation + verify /
   test → one data PR. (Now unblocked: `sync-ranges` measured 27s over 93
   findings.) Prevents stale range / impact data pairing with a newer fixmap.

7. **Real CPE 2.3 matching (not string equality).** *(done)* Adapters already preserve
   CPEs and range records can carry CPEs; adding CPE as a strong identity source
   eliminates name-collision cases (JDBC driver vs database server). CPE 2.3 has
   wildcard / ANY / NA semantics, so do **not** implement `componentCpe ===
   rangeCpe`; use CPE 2.3 Well-Formed-Name matching (or an existing
   implementation) and preserve the relation. Output `match_type: "cpe_match"`,
   `identity_strength: "strong"`, `identity_evidence: { component_cpe, range_cpe,
   relation }`. Ref: usnistgov/cpe-reference-implementation.

8. **Separate range evidence from the final candidate decision.** *(done)* A weak
   name-only candidate may legitimately carry `range_assessment.verdict:
   "affected"` while the CLI refuses to gate — safe inside the CLI but easy for a
   downstream JSON consumer or VEX exporter to misuse. Add an explicit
   `candidate_decision` object (`decision`, `range_verdict`, `identity`,
   `gating_eligible`, `reason`). Treat `range_assessment` as version/range
   evidence, not the final product-level disposition.

### Tier 2 — persistence / interoperability — implemented 2026-09-04

The adjudication store, evidence hash, check-sbom reuse, `adjudicate` CLI (record / query / export-vex), and OpenVEX projection are implemented and tested.

9. **Internal adjudication store, separate from VEX (append-only / superseding).**
   *(done — store + check-sbom reuse + record/query CLI)* VEX is
   an interchange/export representation, not the canonical internal model.
   Glasswing must preserve richer states VEX does not model (`PATCH_NOT_FOUND`,
   `VERIFIER_CONFLICT`, `SOURCE_BINDING_UNVERIFIED`, `LIKELY_FALSE_POSITIVE`,
   `INSUFFICIENT_EVIDENCE`, and machine vs AI vs human disposition). Record
   `{ subject, finding, machine, source_verification, ai_review, human_review,
   validity, vex_projection }`; a later range / advisory / build change
   **supersedes** the prior review and preserves its audit history rather than
   overwriting one key.

   Decided design (proven end to end by `src/adjudication/store.ts` +
   `test/adjudication.test.ts`): a **file-based, append-only** store at
   `data/adjudications.json`, keyed by the deterministic **evidence hash**
   (Tier 2.10). `lookup` returns the latest record for a hash (latest-wins for a
   same-evidence human correction) unless it was explicitly `invalidated`; a
   *different* evidence hash returns nothing, so a version / range / snapshot /
   decision change auto-invalidates the prior review while the old subject still
   resolves. `supersedes` is a pure audit link. The store fails closed on
   malformed input. This is exactly the "do not re-run the Skill on the same
   residual" structure. Remaining wiring: attach a matched prior review to
   `check-sbom` candidates and surface a hash-miss as "re-adjudication needed"; a
   `record` / `query` CLI; and the OpenVEX projection (item 11).

10. **Stronger evidence hash + invalidation.** *(done — hash + check-sbom auto-invalidation on evidence change)* Bind the full decision context:
    ANT + CVE/GHSA IDs; canonical PURL/CPE + version + qualifiers; SBOM / document
    digest; fixmap source revision / manifest digest; affected-range record
    digest; fix-impact dataset / record digest; source-verification report digest;
    `source_binding` status; machine decision; adjudicator ruleset / Skill commit
    SHA; and the AI review's upstream evidence references. Invalidate /
    re-adjudicate when any material input changes. Suppression stays explicitly
    human-approved and auditable.

11. **Conservative VEX projection (OpenVEX first).** *(done — projectToOpenVex + `adjudicate export-vex`)* Suggested mapping: `AFFECTED`
    + strong identity → affected; `VERIFIED_FIXED` + `source_binding == verified`
    → fixed; `TARGET_ABSENT` + strong provenance → not_affected
    (`vulnerable_code_not_present`); `PATCH_NOT_FOUND` / `UNKNOWN` /
    AI `LIKELY_FALSE_POSITIVE` → under_investigation; AI `LIKELY_FALSE_POSITIVE` +
    human approval + justification → not_affected. Do **not** export `fixed`
    merely because `--source` found the patch — ordinary source input is
    `user_asserted`, not `verified`. Distinguish identity mistakes (JDBC vs server
    → fix via PURL/CPE) from exploitability dispositions. OpenVEX is the first
    export target (grype / trivy consume VEX); do not claim OSV-Scanner interop
    until verified. Ref: openvex-spec `OPENVEX-SPEC.md`.

### Tier 3 — long-tail coverage

12. **Conservative distro / vendor normalization — preserve backport
    uncertainty.** *(done)* Stripping a build flavor (`_p3`, `.el8`, `+deb12u1`,
    `-1ubuntu2`, `-fips3.1`) to the base upstream version is useful *evidence*, but
    for distro/vendor packages it is **not** the final security decision because a
    downstream revision may carry a backported patch. Separate
    `base_version_assessment: affected`, `downstream_patch_status: unknown`,
    `final: UNKNOWN` until vendor/distro backport evidence or a native
    Debian/RPM/Gentoo comparator/advisory confirms the package state.
    `UPSTREAM_RANGE_AFFECTED` must not silently become final `AFFECTED` for a
    downstream rebuild, and the adjudicator Skill must not assume a build flavor is
    orthogonal for every vulnerability without vuln- or vendor-specific evidence.
    (Corrects the earlier roadmap claim that `libyang 0.16_p3` resolves
    deterministically to `AFFECTED`.)

13. **Ecosystem comparators via an optional `univers` backend.** *Not blocked on a
    missing algorithm* — that framing was too strong. Well-maintained
    implementations exist for every target: Renovate ships TypeScript versioning
    for Maven, Debian, RPM, and Composer, and each has an official reference
    (Apache `ComparableVersion`, `dpkg --compare-versions`, `rpmvercmp`,
    `composer/semver`). The real gap is a **permissive-license, standalone
    Node/npm drop-in**: Renovate's modules are internal and `renovate` is AGPL, so
    they are good references but not clean dependencies. The best fit for
    Glasswing is [`univers`](https://pypi.org/project/univers/) — an
    actively-maintained, Apache/BSD/MIT-family **Python** library purpose-built for
    package/vulnerability version-range handling (Maven, Debian, RPM, Composer,
    npm, PyPI, Go, Gentoo, Arch, …).

    Approach — treat it exactly like Vanir: a **core Node engine + optional
    external backend**, not a port into Node.

    ```text
    VersionComparator
      ├─ SemVer   → node-semver
      ├─ PyPI     → @renovatebot/pep440
      ├─ OpenSSL  → current native
      └─ univers backend (optional): Maven | Debian | RPM | Composer
    ```

    ```text
    univers absent            → UNKNOWN
    univers run fails         → ERROR (backend error)
    univers supports scheme
      AND conformance passes  → deterministic range evaluation (gating allowed)
    ```

    Because it is a security gate, do not trust `univers` blindly: build a
    one-time **differential conformance corpus** (hundreds–thousands of version
    pairs) against each official reference — Maven ↔ `ComparableVersion`, Debian ↔
    `dpkg`, RPM ↔ `rpmvercmp`, Composer ↔ `composer/semver` — and allow `AFFECTED`
    gating **only for schemes that pass**. One Python runtime then covers all four,
    which is far simpler than wiring Java, `dpkg`, an rpm library, and PHP
    Composer separately.

    This also lets the CVE `versionType` dispatch (Tier 0.1) route directly to a
    proven comparator instead of collapsing everything through `ecosystem="cve"`:

    ```text
    versionType=semver → node-semver     versionType=maven  → univers/maven
    versionType=python → pep440          versionType=debian → univers/debian
    versionType=rpm    → univers/rpm     versionType=custom → product-specific or UNKNOWN
    ```

14. **`UNKNOWN` reason categorization + batch reporting.** *(done)* Emit the residual
    `UNKNOWN` cause (missing-comparator / non-parseable-version / name-only-identity
    / changes-unsupported) so triage routes to the adjudicator automatically, and
    add a `--dir` / summary mode for scanning many SBOMs at once.

15. **Vanir container hardening + optional-install promotion.** *(hardening done; optional-install promotion still pending)* Constrain the
    Docker wrapper to preserve read-only inspection: source and signature mounts
    `:ro`, report dir `:rw`, `--network=none`, `--read-only`, `--cap-drop=ALL`,
    `--security-opt=no-new-privileges`; consider hash-locking transitive Python
    dependencies if reproducible container builds become a release requirement.

### P2 — docs / acceptance reconciliation (after the correctness work)

Several docs now lag the implementation and should be reconciled so external users
do not infer outdated decision semantics:
- README / CLI help still say CycloneDX 1.5/1.6/1.7, but 1.4 is now supported.
- README says name-only candidates are never evaluated for `AFFECTED`, while the
  code now attaches a weak CVE product-name `range_assessment: affected` and only
  prevents gating.
- `docs/ACCEPTANCE.md` still reflects the older 16-SBOM / no-`AFFECTED` corpus,
  while the latest sweep records deterministic affected / not_affected results.

## Definition of done

The first release is complete when it can extract compact impact evidence for supported GitHub fix commits, distinguish all six decisions without conflating their meanings, verify exact and backported fixes in a source tree, use the supplied CycloneDX and Syft SBOMs only for conservative candidate selection, and preserve every existing fixmap workflow.

The following remain intentionally deferred: broad AST parsing, unsupported SBOM formats, VEX/SARIF output, binary/package-tree inspection without source, inferred affected ranges, automatic source downloads, and heuristic security gating.
