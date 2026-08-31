import type { FixmapDataset } from "./types.js";

export function validateDataset(dataset: FixmapDataset): string[] {
  const errors: string[] = [];
  if (!dataset || typeof dataset !== "object" || !Array.isArray(dataset.findings)) {
    return ["Dataset must contain a findings array"];
  }
  const ids = new Set<string>();
  let previous = "";
  for (const finding of dataset.findings) {
    const prefix = finding.ant_id || "<missing ANT ID>";
    if (!/^ANT-\d{4}-[A-Z0-9]+$/.test(finding.ant_id)) {
      errors.push(`${prefix}: invalid ANT ID`);
    }
    if (ids.has(finding.ant_id)) errors.push(`${prefix}: duplicate ANT ID`);
    ids.add(finding.ant_id);
    if (previous && previous.localeCompare(finding.ant_id) > 0) {
      errors.push(`${prefix}: findings are not sorted by ANT ID`);
    }
    previous = finding.ant_id;
    for (const id of finding.cve_ids) {
      if (!/^CVE-\d{4}-\d+$/.test(id)) errors.push(`${prefix}: invalid CVE ID ${id}`);
    }
    for (const id of finding.ghsa_ids) {
      if (!/^GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}$/i.test(id)) {
        errors.push(`${prefix}: invalid GHSA ID ${id}`);
      }
    }
    for (const commit of finding.fix_commits) {
      if (!/^[0-9a-f]{7,64}$/.test(commit.sha)) {
        errors.push(`${prefix}: invalid fix SHA ${commit.sha}`);
      }
      if (!/^https?:\/\//.test(commit.url)) errors.push(`${prefix}: invalid commit URL`);
    }
    for (const version of finding.fixed_versions) {
      if (!version.version.trim()) errors.push(`${prefix}: empty fixed version`);
      if (version.first_patched && version.role !== "first_patched") {
        errors.push(`${prefix}: first_patched version ${version.version} has role ${version.role}`);
      }
      if (version.role === "first_patched" && version.first_patched !== true) {
        errors.push(`${prefix}: first_patched role ${version.version} must set first_patched=true`);
      }
      if (version.role === "operational_baseline" && version.first_patched !== false) {
        errors.push(`${prefix}: operational baseline ${version.version} must set first_patched=false`);
      }
      if (version.evidence.length === 0) errors.push(`${prefix}: ${version.version} has no evidence`);
    }
    if (
      finding.release_assessment.status === "no_release_yet" &&
      finding.fixed_versions.some((version) => version.first_patched)
    ) {
      errors.push(`${prefix}: no_release_yet conflicts with a first patched version`);
    }
    if (
      finding.release_assessment.status === "confirmed_versions" &&
      !finding.fixed_versions.some((version) => version.first_patched)
    ) {
      errors.push(`${prefix}: confirmed_versions requires a first patched version`);
    }
  }

  const metadataChecks: Array<[number, number, string]> = [
    [dataset.metadata.finding_count, dataset.findings.length, "finding_count"],
    [dataset.metadata.patched_count, dataset.findings.filter((item) => item.patched).length, "patched_count"],
    [
      dataset.metadata.with_fix_commit,
      dataset.findings.filter((item) => item.fix_commits.length > 0).length,
      "with_fix_commit",
    ],
    [
      dataset.metadata.with_fixed_version,
      dataset.findings.filter((item) => item.fixed_versions.length > 0).length,
      "with_fixed_version",
    ],
    [
      dataset.metadata.complete_count,
      dataset.findings.filter((item) => item.enrichment.status === "complete").length,
      "complete_count",
    ],
    [
      dataset.metadata.partial_count,
      dataset.findings.filter((item) => item.enrichment.status === "partial").length,
      "partial_count",
    ],
    [
      dataset.metadata.unresolved_count,
      dataset.findings.filter((item) => item.enrichment.status === "unresolved").length,
      "unresolved_count",
    ],
  ];
  for (const [actual, expected, name] of metadataChecks) {
    if (actual !== expected) errors.push(`metadata.${name}: expected ${expected}, got ${actual}`);
  }
  return errors;
}
