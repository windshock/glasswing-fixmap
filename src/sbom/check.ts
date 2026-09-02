import { readFile } from "node:fs/promises";
import path from "node:path";
import type { FindingRecord } from "../types.js";
import type { FixImpactDataset } from "../impact/types.js";
import { verifySource } from "../verification/verify.js";
import type { AffectedRangeDataset, AffectedRangeRecord } from "../ranges/types.js";
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
} from "./types.js";

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
      warnings.push(`Document ${index + 1} of ${documents.length} is not a supported SBOM format; skipped`);
      continue;
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
      if (candidate.identity_strength !== "strong" || !candidate.component.version) continue;
      const parsed = candidate.component.purl ? canonicalizePurl(candidate.component.purl) : undefined;
      const componentKey = parsed ? identityKeyForParsedPurl(parsed) : undefined;
      if (!componentKey) continue;
      const applicable = ranges.filter(
        (range) =>
          range.ant_id === candidate.ant_id &&
          findingIdentityKey(range.ecosystem, range.package) === componentKey,
      );
      if (applicable.length > 0) {
        candidate.range_assessment = assessRanges(candidate.component.version, applicable);
      }
    }
  }

  const selectedComponent = options.component ? canonicalizePurl(options.component) : undefined;
  if (options.component && !selectedComponent) {
    warnings.push(`Ignoring malformed --component PURL: ${options.component}`);
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
      if (verification) candidate.verification = verification;
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
