import { readFile } from "node:fs/promises";
import path from "node:path";
import type { FindingRecord } from "../types.js";
import type { FixImpactDataset } from "../impact/types.js";
import { verifySource } from "../verification/verify.js";
import { canonicalizePurl } from "./purl.js";
import { CycloneDxAdapter } from "./cyclonedx.js";
import { SyftAdapter } from "./syft.js";
import { selectCandidates } from "./matching.js";
import {
  SBOM_CHECK_SCHEMA_VERSION,
  type ComponentCandidate,
  type SbomAdapter,
  type SbomCheckReport,
} from "./types.js";

export interface CheckSbomOptions {
  sbomFile: string;
  findings: FindingRecord[];
  /** When present, an unambiguous strong candidate is passed to verify-source. */
  sourceRoot?: string;
  impactDataset?: FixImpactDataset;
  /** Restrict source verification to the component with this canonical PURL. */
  component?: string;
  adapters?: SbomAdapter[];
}

export async function readSbomDocument(file: string): Promise<unknown> {
  return JSON.parse(await readFile(file, "utf8")) as unknown;
}

function isStrong(candidate: ComponentCandidate): boolean {
  return candidate.identity_strength === "strong" &&
    (candidate.match_type === "exact_purl" || candidate.match_type === "ecosystem_package");
}

/**
 * Candidate selection over an SBOM, optionally bridging an unambiguous strong
 * candidate into source verification. An SBOM with no candidate Anthropic
 * finding is a valid clean result, not an error.
 */
export async function checkSbom(options: CheckSbomOptions): Promise<SbomCheckReport> {
  const document = await readSbomDocument(options.sbomFile);
  const adapters = options.adapters ?? [new CycloneDxAdapter(), new SyftAdapter()];
  const adapter = adapters.find((item) => item.supports(document));
  if (!adapter) {
    throw new Error(
      "Unsupported SBOM: expected CycloneDX JSON (1.5/1.6/1.7) or Syft native JSON (schema 16.1.2)",
    );
  }

  const parsed = await adapter.parse(document);
  const warnings = [...parsed.warnings];
  const candidates = selectCandidates(parsed.components, options.findings);

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

  const packageComponentCount = parsed.components.filter(
    (component) => component.type !== "file",
  ).length;

  const report: SbomCheckReport = {
    schema_version: SBOM_CHECK_SCHEMA_VERSION,
    sbom: path.resolve(options.sbomFile),
    format: parsed.format,
    component_count: parsed.components.length,
    package_component_count: packageComponentCount,
    candidates,
    warnings: [...new Set(warnings)].sort(),
  };
  if (parsed.spec_version) report.spec_version = parsed.spec_version;
  return report;
}
