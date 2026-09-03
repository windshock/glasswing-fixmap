import { readFile } from "node:fs/promises";
import path from "node:path";
import type { FindingRecord } from "../types.js";
import type { FixImpactDataset } from "../impact/types.js";
import { verifySource } from "../verification/verify.js";
import type { AffectedRangeDataset, AffectedRangeRecord } from "../ranges/types.js";
import type { SourceVerificationReport } from "../verification/types.js";
import { canonicalizePurl, findingIdentityKey, identityKeyForParsedPurl } from "./purl.js";
import { selectComparator } from "./comparator.js";
import { CycloneDxAdapter } from "./cyclonedx.js";
import { SyftAdapter } from "./syft.js";
import { parseJsonDocuments } from "./documents.js";
import { selectCandidates } from "./matching.js";
import {
  SBOM_CHECK_SCHEMA_VERSION,
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
  adapters?: SbomAdapter[];
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

/**
 * Whether an authoritative range applies to a candidate. A CVE List V5 product
 * range matches by component name (CVE records carry no package ecosystem), so
 * it can be evaluated even for a name-only, weak-identity candidate. An OSV
 * package-ecosystem range still requires strong PURL identity.
 */
function rangeAppliesTo(range: AffectedRangeRecord, candidate: ComponentCandidate): boolean {
  if (range.ant_id !== candidate.ant_id) return false;
  if (range.source === "cve_list_v5") {
    return Boolean(range.product) &&
      range.product!.toLowerCase() === candidate.component.name.toLowerCase();
  }
  if (candidate.identity_strength !== "strong") return false;
  const parsed = candidate.component.purl ? canonicalizePurl(candidate.component.purl) : undefined;
  const componentKey = parsed ? identityKeyForParsedPurl(parsed) : undefined;
  if (!componentKey) return false;
  return findingIdentityKey(range.ecosystem, range.package) === componentKey;
}

/**
 * Candidate selection over an SBOM, optionally bridging an unambiguous strong
 * candidate into source verification. Multiple concatenated documents in one
 * file are each parsed and their components deduplicated and aggregated. An
 * SBOM with no candidate Anthropic finding is a valid clean result, not an error.
 */
export async function checkSbom(options: CheckSbomOptions): Promise<SbomCheckReport> {
  const documents = await readSbomDocuments(options.sbomFile);
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

  if (options.rangeDataset) {
    const ranges = options.rangeDataset.ranges;
    for (const candidate of candidates) {
      if (!candidate.component.version) continue;
      const applicable = ranges.filter((range) => rangeAppliesTo(range, candidate));
      if (applicable.length > 0) {
        candidate.range_assessment = assessRanges(candidate.component.version, applicable);
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
          verifiedAnts.set(candidate.ant_id, undefined);
          warnings.push(
            `${candidate.ant_id}: source verification failed: ${error instanceof Error ? error.message : String(error)}`,
          );
        }
      }
      const verification = verifiedAnts.get(candidate.ant_id);
      if (verification) {
        candidate.verification = verification;
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
