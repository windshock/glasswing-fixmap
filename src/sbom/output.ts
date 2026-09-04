import { atomicWrite } from "../output.js";
import type { SbomCheckReport } from "./types.js";

export function formatSbomCheck(report: SbomCheckReport): string {
  const lines = [
    `SBOM: ${report.sbom}`,
    `Format: ${report.format}${report.spec_version ? ` ${report.spec_version}` : ""}${report.document_count > 1 ? ` (${report.document_count} documents)` : ""}`,
    `Components: ${report.component_count} (${report.package_component_count} package)`,
    "",
  ];
  if (report.candidates.length === 0) {
    lines.push("No candidate Anthropic findings matched this SBOM.");
  } else {
    lines.push(`Candidates: ${report.candidates.length}`);
    for (const candidate of report.candidates) {
      const component = candidate.component;
      const identity = component.purl ?? `${component.name}${component.version ? `@${component.version}` : ""}`;
      lines.push(
        `  ${candidate.ant_id}  ${candidate.match_type} (${candidate.confidence})  ${identity}`,
      );
      if (candidate.candidate_decision) {
        const decision = candidate.candidate_decision;
        lines.push(
          `    decision: ${decision.decision}${decision.gating_eligible ? " (gating)" : ""} — ${decision.reason}`,
        );
      }
      if (candidate.prior_adjudication) {
        const prior = candidate.prior_adjudication;
        const review = prior.human_review
          ? `human: ${prior.human_review.disposition} (${prior.human_review.approved_by})`
          : prior.ai_review
            ? `ai: ${prior.ai_review.verdict} (${prior.ai_review.confidence})`
            : "recorded";
        lines.push(`    adjudication: ${review} [reused ${prior.evidence_hash.slice(0, 12)}]`);
      }
      if (candidate.range_assessment) {
        lines.push(
          `    range: ${candidate.range_assessment.verdict.toUpperCase()} — ${candidate.range_assessment.reason}`,
        );
      }
      if (candidate.verification) {
        lines.push(
          `    verify-source: ${candidate.verification.decision} (${candidate.verification.confidence}, source binding: ${candidate.source_binding ?? "user_asserted"})`,
        );
      }
    }
  }
  if (report.warnings.length > 0) {
    lines.push("", "Warnings:");
    for (const warning of report.warnings) lines.push(`  ${warning}`);
  }
  return `${lines.join("\n")}\n`;
}

export async function writeSbomCheck(report: SbomCheckReport, file: string): Promise<void> {
  await atomicWrite(file, `${JSON.stringify(report, null, 2)}\n`);
}
