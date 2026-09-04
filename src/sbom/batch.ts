import { readdir } from "node:fs/promises";
import path from "node:path";
import { checkSbom, type CheckSbomOptions } from "./check.js";

export const SBOM_BATCH_SCHEMA_VERSION = "1.0.0" as const;

export interface SbomBatchSummary {
  schema_version: typeof SBOM_BATCH_SCHEMA_VERSION;
  directory: string;
  file_count: number;
  processed: number;
  unsupported: number;
  errors: Array<{ file: string; error: string }>;
  totals: {
    candidates: number;
    affected: number;
    not_affected: number;
    unknown: number;
    none: number;
    gating: number;
  };
  unknown_by_reason: Record<string, number>;
  gating_candidates: Array<{ file: string; ant_id: string; component: string; decision: string }>;
}

async function jsonFiles(directory: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) out.push(...(await jsonFiles(full)));
    else if (entry.isFile() && entry.name.endsWith(".json")) out.push(full);
  }
  return out.sort();
}

/**
 * Run `check-sbom` over every JSON SBOM under a directory and aggregate the
 * results. A file that is not a supported SBOM is counted as `unsupported`
 * rather than failing the batch; any other error is recorded per file. Coverage
 * is never silently dropped — the counts reconcile file_count = processed +
 * unsupported + errors.
 */
export async function checkSbomDir(
  options: Omit<CheckSbomOptions, "sbomFile"> & { directory: string },
): Promise<SbomBatchSummary> {
  const { directory, ...checkOptions } = options;
  const files = await jsonFiles(directory);
  const summary: SbomBatchSummary = {
    schema_version: SBOM_BATCH_SCHEMA_VERSION,
    directory: path.resolve(directory),
    file_count: files.length,
    processed: 0,
    unsupported: 0,
    errors: [],
    totals: { candidates: 0, affected: 0, not_affected: 0, unknown: 0, none: 0, gating: 0 },
    unknown_by_reason: {},
    gating_candidates: [],
  };
  for (const file of files) {
    let report;
    try {
      report = await checkSbom({ ...checkOptions, sbomFile: file });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (/Unsupported SBOM/.test(message)) summary.unsupported += 1;
      else summary.errors.push({ file: path.relative(directory, file), error: message.slice(0, 200) });
      continue;
    }
    summary.processed += 1;
    for (const candidate of report.candidates) {
      summary.totals.candidates += 1;
      const verdict = candidate.range_assessment?.verdict;
      if (verdict === "affected") summary.totals.affected += 1;
      else if (verdict === "not_affected") summary.totals.not_affected += 1;
      else if (verdict === "unknown") summary.totals.unknown += 1;
      else summary.totals.none += 1;
      const decision = candidate.candidate_decision;
      if (decision?.decision === "UNKNOWN" && decision.unknown_reason) {
        summary.unknown_by_reason[decision.unknown_reason] =
          (summary.unknown_by_reason[decision.unknown_reason] ?? 0) + 1;
      }
      if (decision?.gating_eligible && decision.decision === "AFFECTED") {
        summary.totals.gating += 1;
        summary.gating_candidates.push({
          file: path.relative(directory, file),
          ant_id: candidate.ant_id,
          component: `${candidate.component.name}@${candidate.component.version ?? "?"}`,
          decision: decision.decision,
        });
      }
    }
  }
  return summary;
}

export function formatSbomBatch(summary: SbomBatchSummary): string {
  const lines = [
    `Directory: ${summary.directory}`,
    `SBOMs: ${summary.processed} processed, ${summary.unsupported} unsupported, ${summary.errors.length} errored (of ${summary.file_count} JSON files)`,
    `Candidates: ${summary.totals.candidates}`,
    `Range verdicts: affected ${summary.totals.affected} | not_affected ${summary.totals.not_affected} | unknown ${summary.totals.unknown} | no-assessment ${summary.totals.none}`,
    `Gating AFFECTED: ${summary.totals.gating}`,
  ];
  const reasons = Object.entries(summary.unknown_by_reason).sort();
  if (reasons.length > 0) {
    lines.push(`UNKNOWN by reason: ${reasons.map(([reason, count]) => `${reason} ${count}`).join(" | ")}`);
  }
  for (const gating of summary.gating_candidates) {
    lines.push(`  GATING ${gating.ant_id}  ${gating.component}  (${gating.file})`);
  }
  for (const failure of summary.errors) {
    lines.push(`  ERROR ${failure.file}: ${failure.error}`);
  }
  return `${lines.join("\n")}\n`;
}
