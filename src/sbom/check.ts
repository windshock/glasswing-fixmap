import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import path from "node:path";
import type { FindingRecord } from "../types.js";
import type { FixImpactDataset } from "../impact/types.js";
import type { AffectedRangeRecord as RangeRecord } from "../ranges/types.js";
import type { AdjudicationStore } from "../adjudication/types.js";
import { evidenceKeyForCandidate } from "../adjudication/store.js";
import { computeEvidenceHash } from "../adjudication/evidence-hash.js";
import { lookupAdjudication } from "../adjudication/store.js";
import { verifySource } from "../verification/verify.js";
import type { AffectedRangeDataset, AffectedRangeRecord } from "../ranges/types.js";
import { SOURCE_VERIFICATION_SCHEMA_VERSION } from "../verification/types.js";
import type { SourceVerificationReport } from "../verification/types.js";
import { canonicalizePurl, findingIdentityKey, identityKeyForParsedPurl } from "./purl.js";
import { cpeRelation } from "./cpe.js";
import { selectComparator } from "./comparator.js";
import { CycloneDxAdapter } from "./cyclonedx.js";
import { SyftAdapter } from "./syft.js";
import { parseJsonDocuments } from "./documents.js";
import { selectCandidates } from "./matching.js";
import {
  SBOM_CHECK_SCHEMA_VERSION,
  type CandidateDecision,
  type ComponentCandidate,
  type NormalizedComponent,
  type RangeAssessment,
  type SbomAdapter,
  type SbomCheckReport,
  type SbomParseResult,
  type SourceBinding,
} from "./types.js";

/**
 * Provenance of a `--source` binding. Repository identity conflict is
 * `unverified`; otherwise the checkout is only `user_asserted`, because its
 * version is not machine-bound to the SBOM component. `verified` is reserved for
 * a future VCS-revision/version binding and is not emitted automatically.
 */
function sourceBinding(report: SourceVerificationReport): SourceBinding {
  const observations = report.backend_results.flatMap((backend) => backend.observations);
  if (observations.some((item) => item.type === "SOURCE_REPOSITORY_MISMATCH")) return "unverified";
  return "user_asserted";
}

export interface CheckSbomOptions {
  sbomFile: string;
  findings: FindingRecord[];
  /** When present, an unambiguous strong candidate is passed to verify-source. */
  sourceRoot?: string;
  impactDataset?: FixImpactDataset;
  /** Restrict source verification to the component with this canonical PURL. */
  component?: string;
  /** Authoritative affected ranges used to reach an AFFECTED verdict. */
  rangeDataset?: AffectedRangeDataset;
  /**
   * Snapshot identity of the fixmap driving this scan. When present, companion
   * datasets (`--ranges`, `--impacts`) are checked to belong to the same source
   * snapshot; a mismatch is surfaced as a warning rather than silently combined.
   */
  snapshot?: SnapshotIdentity;
  /**
   * Prior adjudications. When present, a stored review whose evidence hash matches
   * a candidate is attached (reuse without re-running the Skill); a gating-relevant
   * `UNKNOWN` with no current review is surfaced as needing adjudication.
   */
  adjudicationStore?: AdjudicationStore;
  adapters?: SbomAdapter[];
}

/** Stable digest of the applicable authoritative ranges for a candidate. */
function rangeDigest(ranges: RangeRecord[]): string {
  const projection = ranges
    .map((range) => ({ provenance: range.provenance, range_type: range.range_type, events: range.events, versions: range.versions ?? [] }))
    .sort((a, b) => (JSON.stringify(a) < JSON.stringify(b) ? -1 : 1));
  return createHash("sha256").update(JSON.stringify(projection)).digest("hex");
}

interface SnapshotIdentity {
  source_as_of?: string;
  source_revision?: number | string | null;
  source_manifest_sha3?: string | null;
}

/**
 * Whether a companion dataset was generated from a different source snapshot than
 * the fixmap. A manifest digest is authoritative when both carry one; otherwise
 * `source_as_of` and `source_revision` are compared.
 */
function companionStale(generated: SnapshotIdentity, snapshot: SnapshotIdentity): boolean {
  if (generated.source_manifest_sha3 && snapshot.source_manifest_sha3) {
    return generated.source_manifest_sha3 !== snapshot.source_manifest_sha3;
  }
  if (
    generated.source_as_of &&
    snapshot.source_as_of &&
    generated.source_as_of !== snapshot.source_as_of
  ) {
    return true;
  }
  const generatedRevision = generated.source_revision;
  const snapshotRevision = snapshot.source_revision;
  return (
    generatedRevision != null &&
    snapshotRevision != null &&
    String(generatedRevision) !== String(snapshotRevision)
  );
}

/**
 * Evaluate a strong-identity candidate's version against its authoritative
 * ranges. AFFECTED requires a comparator that explicitly supports the range's
 * ecosystem and type; anything unresolved stays `unknown`, never guessed.
 */
function assessRanges(version: string, ranges: AffectedRangeRecord[]): RangeAssessment {
  let notAffected = false;
  let unresolved = false;
  for (const range of ranges) {
    // Exact positive evidence: the version is explicitly published as affected,
    // usable even when no range comparator supports the ecosystem.
    if (range.versions && range.versions.includes(version)) {
      return {
        verdict: "affected",
        reason: `version ${version} is explicitly listed as affected (${range.advisory}, ${range.provenance})`,
      };
    }
    const comparator = selectComparator(range.ecosystem, range.range_type);
    if (!comparator) {
      // An applicable range with no supporting comparator is unresolved, not absent.
      unresolved = true;
      continue;
    }
    const verdict = comparator.evaluate(version, range);
    if (verdict === "affected") {
      return {
        verdict: "affected",
        reason: `version ${version} is within an authoritative ${range.ecosystem} range (${range.advisory}, ${range.provenance})`,
      };
    }
    if (verdict === "not_affected") notAffected = true;
    else unresolved = true;
  }
  // A not_affected result from one range must never override an unresolved range.
  if (unresolved) {
    return {
      verdict: "unknown",
      reason: "at least one applicable authoritative range is unresolved; a not_affected result does not override it",
    };
  }
  if (notAffected) {
    return { verdict: "not_affected", reason: `version ${version} is outside every authoritative affected range` };
  }
  return { verdict: "unknown", reason: "authoritative ranges did not resolve for this version" };
}

/**
 * Reduce a candidate's range evidence and source verification into one explicit,
 * final product-level decision. Kept separate from `range_assessment` so a weak,
 * name-only affected range never reads as a gating vulnerability. Only a
 * strong-identity AFFECTED, a source AFFECTED, or an operational ERROR is
 * `gating_eligible`.
 */
function decideCandidate(candidate: ComponentCandidate): CandidateDecision {
  const identity = candidate.identity_strength;
  const rangeVerdict = candidate.range_assessment?.verdict;
  const withRange = (decision: CandidateDecision): CandidateDecision =>
    rangeVerdict ? { ...decision, range_verdict: rangeVerdict } : decision;
  const verified = candidate.verification?.decision;
  if (verified === "ERROR") {
    return withRange({ decision: "ERROR", identity, gating_eligible: true, reason: "source verification could not execute" });
  }
  if (verified && verified !== "UNKNOWN") {
    // Source evidence (VERIFIED_FIXED / TARGET_ABSENT / PATCH_NOT_FOUND / AFFECTED).
    return withRange({
      decision: verified,
      identity,
      gating_eligible: verified === "AFFECTED",
      reason: `source verification: ${verified}`,
    });
  }
  if (rangeVerdict === "affected") {
    if (identity === "strong") {
      return {
        decision: "AFFECTED",
        range_verdict: "affected",
        identity,
        gating_eligible: true,
        reason: "strong identity within an authoritative affected range",
      };
    }
    return {
      decision: "UNKNOWN",
      range_verdict: "affected",
      identity,
      gating_eligible: false,
      unknown_reason: "name_only_identity",
      reason: "weak identity (product-name match only); affected range is review evidence, not a gate",
    };
  }
  if (rangeVerdict === "not_affected") {
    return {
      decision: "NOT_AFFECTED",
      range_verdict: "not_affected",
      identity,
      gating_eligible: false,
      reason: "version outside every authoritative affected range",
    };
  }
  if (rangeVerdict === "unknown") {
    return {
      decision: "UNKNOWN",
      range_verdict: "unknown",
      identity,
      gating_eligible: false,
      unknown_reason: "range_unresolved",
      reason: candidate.range_assessment?.reason ?? "authoritative range unresolved",
    };
  }
  return {
    decision: "UNKNOWN",
    identity,
    gating_eligible: false,
    unknown_reason: verified === "UNKNOWN" ? "source_inconclusive" : "no_applicable_range",
    reason:
      verified === "UNKNOWN"
        ? "source verification was inconclusive and no authoritative range applied"
        : "no authoritative range and no source verification",
  };
}

export async function readSbomDocuments(file: string): Promise<unknown[]> {
  return parseJsonDocuments(await readFile(file, "utf8"));
}

function isStrong(candidate: ComponentCandidate): boolean {
  return candidate.identity_strength === "strong" &&
    (candidate.match_type === "exact_purl" || candidate.match_type === "ecosystem_package");
}

function componentKey(component: NormalizedComponent): string {
  return [
    component.source_format,
    component.type ?? "",
    component.name,
    component.version ?? "",
    component.purl ?? "",
  ].join("|");
}

interface RangeApplicability {
  applies: boolean;
  /** Present when a CPE 2.3 match established strong identity for this range. */
  cpe?: NonNullable<ComponentCandidate["identity_evidence"]>;
}

/**
 * Whether an authoritative range applies to a candidate, and by what identity.
 * A CVE List V5 product range prefers a CPE 2.3 match (strong identity); a CPE
 * that is present on both sides but disjoint excludes the range (a namesake such
 * as a JDBC driver vs the database server). Absent CPEs fall back to a product-
 * name match (weak, non-gating). An OSV package-ecosystem range still requires
 * strong PURL identity.
 */
function rangeAppliesTo(range: AffectedRangeRecord, candidate: ComponentCandidate): RangeApplicability {
  if (range.ant_id !== candidate.ant_id) return { applies: false };
  if (range.source === "cve_list_v5") {
    const relation = cpeRelation(candidate.component.cpes ?? [], range.cpes ?? []);
    if (relation.relation === "match") {
      return {
        applies: true,
        cpe: { component_cpe: relation.component_cpe!, range_cpe: relation.range_cpe!, relation: "match" },
      };
    }
    // Both sides declare CPEs but none are compatible: a different product.
    if (relation.relation === "disjoint") return { applies: false };
    // No usable CPE on one side: fall back to a weak product-name match.
    return {
      applies:
        Boolean(range.product) && range.product!.toLowerCase() === candidate.component.name.toLowerCase(),
    };
  }
  if (candidate.identity_strength !== "strong") return { applies: false };
  const parsed = candidate.component.purl ? canonicalizePurl(candidate.component.purl) : undefined;
  const componentKey = parsed ? identityKeyForParsedPurl(parsed) : undefined;
  if (!componentKey) return { applies: false };
  return { applies: findingIdentityKey(range.ecosystem, range.package) === componentKey };
}

/**
 * Candidate selection over an SBOM, optionally bridging an unambiguous strong
 * candidate into source verification. Multiple concatenated documents in one
 * file are each parsed and their components deduplicated and aggregated. An
 * SBOM with no candidate Anthropic finding is a valid clean result, not an error.
 */
export async function checkSbom(options: CheckSbomOptions): Promise<SbomCheckReport> {
  const rawSbom = await readFile(options.sbomFile, "utf8");
  const documents = parseJsonDocuments(rawSbom);
  const sbomDigest = createHash("sha256").update(rawSbom).digest("hex");
  const adapters = options.adapters ?? [new CycloneDxAdapter(), new SyftAdapter()];
  const warnings: string[] = [];
  const parsedResults: SbomParseResult[] = [];
  for (let index = 0; index < documents.length; index += 1) {
    const adapter = adapters.find((item) => item.supports(documents[index]));
    if (!adapter) {
      // Do not silently skip part of the input; an unsupported document fails.
      const where = documents.length > 1 ? ` (document ${index + 1} of ${documents.length})` : "";
      throw new Error(
        `Unsupported SBOM${where}: expected CycloneDX JSON (1.4/1.5/1.6/1.7) or Syft native JSON (schema 16.1.2)`,
      );
    }
    const parsed = await adapter.parse(documents[index]);
    parsedResults.push(parsed);
    warnings.push(...parsed.warnings);
  }
  if (parsedResults.length === 0) {
    throw new Error(
      "Unsupported SBOM: expected CycloneDX JSON (1.5/1.6/1.7) or Syft native JSON (schema 16.1.2)",
    );
  }

  // Companion datasets must belong to the same source snapshot as the fixmap;
  // a stale range/impact artifact paired with a newer fixmap is surfaced, not
  // silently combined.
  if (options.snapshot) {
    if (options.rangeDataset && companionStale(options.rangeDataset.metadata.generated_from, options.snapshot)) {
      warnings.push(
        `--ranges dataset is from a different fixmap snapshot (ranges source_as_of ${options.rangeDataset.metadata.generated_from.source_as_of} vs fixmap ${options.snapshot.source_as_of ?? "unknown"}); re-run sync-ranges so all evidence shares one snapshot`,
      );
    }
    if (options.impactDataset && companionStale(options.impactDataset.metadata.generated_from, options.snapshot)) {
      warnings.push(
        `--impacts dataset is from a different fixmap snapshot (impacts source_as_of ${options.impactDataset.metadata.generated_from.source_as_of} vs fixmap ${options.snapshot.source_as_of ?? "unknown"}); re-run sync-impacts so all evidence shares one snapshot`,
      );
    }
  }

  const format = parsedResults[0]!.format;
  const specVersion = parsedResults[0]!.spec_version;
  const seenComponents = new Set<string>();
  const components: NormalizedComponent[] = [];
  for (const result of parsedResults) {
    for (const component of result.components) {
      const key = componentKey(component);
      if (seenComponents.has(key)) continue;
      seenComponents.add(key);
      components.push(component);
    }
  }
  const candidates = selectCandidates(components, options.findings);

  const appliedRangeDigests = new Map<ComponentCandidate, string>();
  if (options.rangeDataset) {
    const ranges = options.rangeDataset.ranges;
    for (const candidate of candidates) {
      if (!candidate.component.version) continue;
      const applicable: AffectedRangeRecord[] = [];
      for (const range of ranges) {
        const applicability = rangeAppliesTo(range, candidate);
        if (!applicability.applies) continue;
        applicable.push(range);
        // A CPE 2.3 match is strong identity: elevate the candidate so its
        // decision becomes gating-eligible, and record the CPE evidence.
        if (applicability.cpe && candidate.identity_strength !== "strong") {
          candidate.match_type = "cpe_match";
          candidate.identity_strength = "strong";
          candidate.confidence = "high";
          candidate.identity_evidence = applicability.cpe;
        }
      }
      if (applicable.length > 0) {
        candidate.range_assessment = assessRanges(candidate.component.version, applicable);
        appliedRangeDigests.set(candidate, rangeDigest(applicable));
      }
    }
  }

  const selectedComponent = options.component ? canonicalizePurl(options.component) : undefined;
  if (options.component && !selectedComponent) {
    // An explicit component selector must not silently degrade into scanning
    // every candidate.
    throw new Error(`Malformed --component PURL: ${options.component}`);
  }

  if (options.sourceRoot && options.impactDataset) {
    const impactDataset = options.impactDataset;
    const availableAnts = new Set(
      impactDataset.impacts.flatMap((impact) => impact.ant_ids),
    );
    // Verify each finding at most once; only unambiguous strong candidates and,
    // when --component is set, the explicitly selected component are eligible.
    const verifiedAnts = new Map<string, SbomCheckReport["candidates"][number]["verification"]>();
    for (const candidate of candidates) {
      if (!isStrong(candidate)) continue;
      if (!availableAnts.has(candidate.ant_id)) continue;
      if (
        selectedComponent &&
        candidate.component.purl !== selectedComponent.canonical
      ) {
        continue;
      }
      const strongForAnt = candidates.filter(
        (item) => item.ant_id === candidate.ant_id && isStrong(item),
      );
      const distinctComponents = new Set(
        strongForAnt.map((item) => item.component.purl ?? item.component.name),
      );
      if (distinctComponents.size > 1 && !selectedComponent) {
        warnings.push(
          `${candidate.ant_id}: multiple strong SBOM components match; pass --component <purl> to verify one`,
        );
        continue;
      }
      if (!verifiedAnts.has(candidate.ant_id)) {
        try {
          const report = await verifySource({
            antId: candidate.ant_id,
            sourceRoot: options.sourceRoot,
            impactDataset,
          });
          verifiedAnts.set(candidate.ant_id, report);
        } catch (error) {
          // --source is always an explicit request here, so a verification that
          // cannot execute is an operational ERROR (non-zero exit), never a
          // best-effort warning that lets the run pass. Fail closed.
          const message = error instanceof Error ? error.message : String(error);
          verifiedAnts.set(candidate.ant_id, {
            schema_version: SOURCE_VERIFICATION_SCHEMA_VERSION,
            ant_id: candidate.ant_id,
            source: options.sourceRoot,
            impact_schema_version: impactDataset.metadata.schema_version,
            targets: [],
            backend_results: [],
            decision: "ERROR",
            confidence: "low",
            reasons: [
              { code: "BACKEND_FAILURE", detail: `source verification failed: ${message}`, observation_ids: [] },
            ],
          });
          warnings.push(`${candidate.ant_id}: source verification ERROR: ${message}`);
        }
      }
      const verification = verifiedAnts.get(candidate.ant_id);
      if (verification) {
        candidate.verification = verification;
        // A failed verification carries no observations to bind; leave
        // source_binding unset so an ERROR is not read as user_asserted evidence.
        if (verification.decision !== "ERROR") {
          candidate.source_binding = sourceBinding(verification);
          // Source evidence is kept separate from range evidence and must not be
          // read as confirming the SBOM component version.
          if (candidate.source_binding !== "verified") {
            warnings.push(
              `${candidate.ant_id}: source binding is ${candidate.source_binding}; verify-source evidence does not confirm the checkout matches the SBOM component version and does not override authoritative range evidence`,
            );
          }
        }
      }
    }
  }

  // Reduce every candidate's evidence to one explicit final decision so a
  // downstream consumer never mistakes range evidence for a gating disposition,
  // then bind an evidence hash and reuse any stored adjudication for it.
  for (const candidate of candidates) {
    candidate.candidate_decision = decideCandidate(candidate);
    const key = evidenceKeyForCandidate(candidate, {
      sbom_digest: sbomDigest,
      fixmap_source_revision: options.snapshot?.source_revision ?? null,
      fixmap_source_manifest_sha3: options.snapshot?.source_manifest_sha3 ?? null,
      affected_range_digest: appliedRangeDigests.get(candidate) ?? null,
      source_verification_digest: candidate.verification
        ? createHash("sha256").update(JSON.stringify(candidate.verification)).digest("hex")
        : null,
      source_binding: candidate.source_binding ?? null,
    });
    candidate.evidence_hash = computeEvidenceHash(key);
    if (options.adjudicationStore) {
      const prior = lookupAdjudication(options.adjudicationStore, candidate.evidence_hash);
      if (prior) {
        candidate.prior_adjudication = prior;
      } else if (candidate.candidate_decision.decision === "UNKNOWN") {
        const reason = candidate.candidate_decision.unknown_reason ?? "unresolved";
        warnings.push(
          `${candidate.ant_id}: ${candidate.component.name}@${candidate.component.version ?? "?"} is UNKNOWN (${reason}) with no current adjudication (evidence ${candidate.evidence_hash.slice(0, 12)}); needs review`,
        );
      }
    }
  }

  const packageComponentCount = components.filter(
    (component) => component.type !== "file",
  ).length;

  const report: SbomCheckReport = {
    schema_version: SBOM_CHECK_SCHEMA_VERSION,
    sbom: path.resolve(options.sbomFile),
    format,
    document_count: documents.length,
    component_count: components.length,
    package_component_count: packageComponentCount,
    candidates,
    warnings: [...new Set(warnings)].sort(),
  };
  if (specVersion) report.spec_version = specVersion;
  return report;
}
