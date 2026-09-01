import type { ChangedFile, FixImpactDataset } from "./types.js";
import { FIX_IMPACT_SCHEMA_VERSION, PATCH_SIGNATURE_ALGORITHM } from "./types.js";

function filePath(file: ChangedFile): string {
  return file.path_after ?? file.path_before ?? "";
}

export function validateImpactDataset(dataset: FixImpactDataset): string[] {
  const errors: string[] = [];
  if (!dataset || typeof dataset !== "object" || !Array.isArray(dataset.impacts)) {
    return ["Impact dataset must contain an impacts array"];
  }
  if (dataset.metadata?.schema_version !== FIX_IMPACT_SCHEMA_VERSION) {
    errors.push(`metadata.schema_version must be ${FIX_IMPACT_SCHEMA_VERSION}`);
  }

  let previousImpact = "";
  const impactKeys = new Set<string>();
  for (const impact of dataset.impacts) {
    const prefix = `${impact.repository || "<missing repository>"}@${impact.commit || "<missing commit>"}`;
    const key = `${impact.repository.toLowerCase()}@${impact.commit}`;
    if (impactKeys.has(key)) errors.push(`${prefix}: duplicate impact`);
    impactKeys.add(key);
    if (previousImpact && previousImpact.localeCompare(key) > 0) {
      errors.push(`${prefix}: impacts are not sorted`);
    }
    previousImpact = key;
    if (!/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(impact.repository)) {
      errors.push(`${prefix}: invalid GitHub repository`);
    }
    if (!/^[0-9a-f]{7,64}$/.test(impact.commit)) errors.push(`${prefix}: invalid commit SHA`);
    if (impact.evidence.length === 0) errors.push(`${prefix}: missing evidence`);
    if (impact.extraction_status === "complete" && impact.warnings.length > 0) {
      errors.push(`${prefix}: complete extraction has warnings`);
    }
    if (impact.extraction_status === "complete" && impact.files.length === 0) {
      errors.push(`${prefix}: complete extraction has no files`);
    }
    if (impact.extraction_status === "error" && impact.files.length > 0) {
      errors.push(`${prefix}: error extraction contains files`);
    }
    if (impact.extraction_status === "error" && impact.warnings.length === 0) {
      errors.push(`${prefix}: error extraction has no warning`);
    }
    const sortedAntIds = [...impact.ant_ids].sort();
    if (new Set(impact.ant_ids).size !== impact.ant_ids.length || sortedAntIds.join() !== impact.ant_ids.join()) {
      errors.push(`${prefix}: ANT IDs must be unique and sorted`);
    }
    for (const antId of impact.ant_ids) {
      if (!/^ANT-\d{4}-[A-Z0-9]+$/.test(antId)) errors.push(`${prefix}: invalid ANT ID ${antId}`);
    }

    let previousFile = "";
    for (const file of impact.files) {
      const currentFile = filePath(file);
      if (!currentFile) errors.push(`${prefix}: changed file has no path`);
      if (previousFile && previousFile.localeCompare(currentFile) > 0) {
        errors.push(`${prefix}: changed files are not sorted`);
      }
      previousFile = currentFile;
      if (file.status === "added" && !file.path_after) errors.push(`${prefix}: added file has no path_after`);
      if (file.status === "deleted" && !file.path_before) errors.push(`${prefix}: deleted file has no path_before`);
      if (file.status === "renamed" && (!file.path_before || !file.path_after)) {
        errors.push(`${prefix}: renamed file requires both paths`);
      }
      if (!file.patch_available && file.hunks.length > 0) {
        errors.push(`${prefix}: unavailable patch contains hunks for ${currentFile}`);
      }
      for (const hunk of file.hunks) {
        if (hunk.old_range.start < 0 || hunk.old_range.count < 0 || hunk.new_range.start < 0 || hunk.new_range.count < 0) {
          errors.push(`${prefix}: invalid hunk range for ${currentFile}`);
        }
        for (const signature of hunk.signatures) {
          if (signature.algorithm !== PATCH_SIGNATURE_ALGORITHM) {
            errors.push(`${prefix}: unknown signature algorithm for ${currentFile}`);
          }
          if (!/^[0-9a-f]{64}$/.test(signature.digest)) {
            errors.push(`${prefix}: invalid signature digest for ${currentFile}`);
          }
          if (signature.line_count < 0 || signature.normalized_length < 0) {
            errors.push(`${prefix}: invalid signature size for ${currentFile}`);
          }
        }
      }
    }
  }

  const counts: Array<[number, number, string]> = [
    [dataset.metadata.impact_count, dataset.impacts.length, "impact_count"],
    [dataset.metadata.complete_count, dataset.impacts.filter((item) => item.extraction_status === "complete").length, "complete_count"],
    [dataset.metadata.partial_count, dataset.impacts.filter((item) => item.extraction_status === "partial").length, "partial_count"],
    [dataset.metadata.error_count, dataset.impacts.filter((item) => item.extraction_status === "error").length, "error_count"],
  ];
  for (const [actual, expected, name] of counts) {
    if (actual !== expected) errors.push(`metadata.${name}: expected ${expected}, got ${actual}`);
  }
  const findingCount = new Set(dataset.impacts.flatMap((impact) => impact.ant_ids)).size;
  if (dataset.metadata.finding_count !== findingCount) {
    errors.push(`metadata.finding_count: expected ${findingCount}, got ${dataset.metadata.finding_count}`);
  }
  return errors;
}
