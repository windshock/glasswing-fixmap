# Acceptance notes

Aggregate, non-sensitive results from validating the source-verification and
SBOM features against real inputs. The raw SBOMs and Vanir signatures are
private acceptance inputs and are **not** committed; only the aggregate
behaviour below is recorded.

## Regression — existing outputs are unchanged

The Phase 2a/3 work touched shared modules (`output.ts`, `cli.ts`, `impact/`),
so existing behaviour was checked for byte-for-byte compatibility:

- `data/fixmap.json` re-serialized through the current code is byte-identical to
  the committed file.
- `data/fixmap.csv` regenerated with `datasetCsv` is byte-identical to the
  committed file.
- `sync` serialization, `report`, `validate` (214 findings), and `--help` are
  unchanged; the full test suite passes.

## SBOM corpus (16 real SBOMs)

> Update (2026-09-04): after `sync-ranges` began consuming CVE List V5 ranges and
> the OpenSSL/`versionType` comparator work, a larger private sweep (101 SBOMs)
> now reaches deterministic range verdicts — `affected 42 / not_affected 72 /
> unknown 3` — while still gating nothing, because every affected component in the
> corpus is name-only (weak) identity. The residual `unknown` is the genuinely
> unresolvable tail (a FIPS build variant, a Gentoo distro suffix, and the
> `postgresql 42.4.0` rpm-typed JDBC namesake). The no-incorrect-decision and
> non-gating properties below still hold; a CPE-bearing SBOM would let the engine
> gate and would exclude the JDBC namesake outright.

Formats exercised: CycloneDX 1.4, 1.5, 1.6, and 1.7, and Syft native JSON 16.1.2.
Shapes exercised: single-document, newline-delimited multi-document, and
concatenated pretty-printed multi-document (up to 83 BOMs in one file).
Component counts ranged from a handful to 10,435 (a file-only inventory that
correctly yields zero package candidates).

- No authoritative `AFFECTED` match was found in the corpus. That is the
  expected clean result, not a reason to weaken matching.
- A small number of low-confidence `name_heuristic` candidates appeared for
  SBOMs that carry no PURL/CPE. All were non-gating (exit 0). One illustrative
  case: a component named `postgresql` at a `42.x` version (the JDBC driver) was
  name-matched to a PostgreSQL *server* finding — a genuine false positive that
  the decision model correctly kept low-confidence and non-gating, and that a
  PURL-bearing SBOM avoids entirely (verified: the same class of component in a
  PURL-bearing SBOM produced zero candidates).
- Two real-world robustness gaps were surfaced and fixed (Milestone 3b):
  cosmetic schema violations outside component identity (a non-UUID
  `serialNumber`; a license carrying both `id` and `name`) are tolerated with a
  warning; multi-document files are parsed document by document.

No incorrect security decision was produced by any corpus input.

## Source verification (end-to-end on a real candidate)

One Linux agent SBOM in the corpus produced a single repository-identity
candidate: the Go library `cloudflare/circl` at `v1.3.7`, matching finding
`ANT-2026-7R9KHDAS` (a BLS signature-forgery issue fixed in `v1.6.4`). The
candidate was carried into `verify-source` against the finding's fix commit:

- `sync-impacts` extracted the fix commit's changed files (`sign/bls/bls.go`,
  `sign/bls/bls_test.go`).
- A read-only checkout of `circl` at `v1.3.7` was inspected.
- Result: `TARGET_ABSENT` — the vulnerable `sign/bls/` package does not exist in
  `v1.3.7` (it was added later), so that finding does not apply to this version.
  `git-ancestry` independently reported `FIX_COMMIT_NOT_ANCESTOR`.

This exercised the rename-discovery cap: at 250 candidates a genuinely absent
target on a 511-file repository resolved only to a truncated `UNKNOWN`. The cap
was raised to 2000 so a real absent target now resolves to `TARGET_ABSENT`,
while remaining bounded.

## Vanir backend (real Vanir 1.1.0)

The opt-in Vanir backend was validated end to end against the real Vanir 1.1.0
package in a `linux/amd64` container (Vanir ships x86-64 ELF parsers only and
does not run natively on macOS):

- Vanir generated Function and Line signatures from a Git fix commit and
  produced a real differential — the pre-fix tree reported `missing_patches`,
  the post-fix tree reported none.
- This surfaced a real parser bug (signatures under `database_specific` were
  missed) that the synthetic fake-runner fixtures could not; it is fixed and
  covered by a regression test using the captured real output.

## Exit semantics

| Exit | Meaning |
| ---: | --- |
| `0` | Analysis completed, regardless of `VERIFIED_FIXED` / `TARGET_ABSENT` / `PATCH_NOT_FOUND` / `UNKNOWN`, or a clean SBOM with no candidates |
| `1` | Invalid input or an operational failure was thrown (bad arguments, unreadable/unsupported input) |
| `2` | A verifier backend returned an operational `ERROR` decision |
| `3` | `check-sbom --fail-on-affected` found an authoritative `AFFECTED` candidate |

`PATCH_NOT_FOUND` and `UNKNOWN` never fail the process; only an explicit
`--fail-on-affected` policy turns an authoritative `AFFECTED` into a non-zero
exit, and it is distinct from the operational-error exit.
