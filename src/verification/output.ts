import { atomicWrite } from "../output.js";
import type { SourceVerificationReport } from "./types.js";

export function formatSourceVerification(report: SourceVerificationReport): string {
  const lines = [
    report.ant_id,
    `Source: ${report.source}`,
    "",
  ];
  for (const backend of report.backend_results) {
    lines.push(
      `Backend: ${backend.backend.name} (${backend.backend.version})  ${backend.execution_status.toUpperCase()}`,
    );
    for (const item of backend.observations) {
      const location = item.actual_file ?? item.target_file;
      lines.push(`  ${item.type}${location ? `  ${location}` : ""}: ${item.detail}`);
    }
  }
  lines.push("", `Decision: ${report.decision}`, `Confidence: ${report.confidence}`);
  for (const item of report.reasons) lines.push(`Reason: ${item.code} — ${item.detail}`);
  return `${lines.join("\n")}\n`;
}

export async function writeSourceVerification(
  report: SourceVerificationReport,
  file: string,
): Promise<void> {
  await atomicWrite(file, `${JSON.stringify(report, null, 2)}\n`);
}
