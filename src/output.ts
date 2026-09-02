import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { FixmapDataset } from "./types.js";

function csvCell(value: unknown): string {
  const text = value === null || value === undefined ? "" : String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function datasetCsv(dataset: FixmapDataset): string {
  const columns = [
    "ant_id",
    "project",
    "cve_ids",
    "ghsa_ids",
    "status",
    "patched",
    "patched_at",
    "fix_commits",
    "fixed_versions",
    "release_assessment",
    "enrichment_status",
    "finding_url",
  ];
  const rows = dataset.findings.map((finding) => [
    finding.ant_id,
    finding.project,
    finding.cve_ids.join(";"),
    finding.ghsa_ids.join(";"),
    finding.status,
    finding.patched,
    finding.patched_at,
    finding.fix_commits.map((commit) => `${commit.repository ?? ""}@${commit.sha}`).join(";"),
    finding.fixed_versions
      .map(
        (version) =>
          `${version.package ? `${version.package}@` : ""}${version.version}${version.first_patched ? " [first]" : ""}`,
      )
      .join(";"),
    finding.release_assessment.status,
    finding.enrichment.status,
    `https://red.anthropic.com/2026/cvd/findings/${finding.ant_id}`,
  ]);
  return [columns, ...rows].map((row) => row.map(csvCell).join(",")).join("\n") + "\n";
}

export async function atomicWrite(file: string, contents: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  await writeFile(temporary, contents, "utf8");
  await rename(temporary, file);
}

export async function writeDataset(dataset: FixmapDataset, outputDirectory: string): Promise<void> {
  await Promise.all([
    atomicWrite(path.join(outputDirectory, "fixmap.json"), `${JSON.stringify(dataset, null, 2)}\n`),
    atomicWrite(path.join(outputDirectory, "fixmap.csv"), datasetCsv(dataset)),
  ]);
}

export async function readDataset(file: string): Promise<FixmapDataset> {
  return JSON.parse(await readFile(file, "utf8")) as FixmapDataset;
}
