import { readFile } from "node:fs/promises";
import {
  AFFECTED_RANGE_SCHEMA_VERSION,
  type AffectedRangeDataset,
  type AffectedRangeRecord,
} from "./types.js";

export async function readAffectedRangeDataset(file: string): Promise<AffectedRangeDataset> {
  return JSON.parse(await readFile(file, "utf8")) as AffectedRangeDataset;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Structural validation of an authoritative-range dataset. Kept deliberately
 * small; the JSON schema is the full contract for generated output.
 */
export function validateAffectedRangeDataset(dataset: AffectedRangeDataset): string[] {
  const errors: string[] = [];
  if (!dataset || typeof dataset !== "object" || !Array.isArray(dataset.ranges)) {
    return ["Affected-range dataset must contain a ranges array"];
  }
  if (dataset.metadata?.schema_version !== AFFECTED_RANGE_SCHEMA_VERSION) {
    errors.push(`metadata.schema_version must be ${AFFECTED_RANGE_SCHEMA_VERSION}`);
  }
  dataset.ranges.forEach((range: AffectedRangeRecord, index) => {
    const prefix = `ranges[${index}]`;
    if (!isRecord(range)) {
      errors.push(`${prefix}: not an object`);
      return;
    }
    if (!/^ANT-\d{4}-[A-Z0-9]+$/.test(range.ant_id)) errors.push(`${prefix}: invalid ant_id`);
    for (const field of ["advisory", "ecosystem", "package", "range_type", "provenance"] as const) {
      if (typeof range[field] !== "string" || range[field].length === 0) {
        errors.push(`${prefix}: missing ${field}`);
      }
    }
    if (!Array.isArray(range.events)) {
      errors.push(`${prefix}: events must be an array`);
    } else if (
      range.events.length === 0 &&
      (!Array.isArray(range.versions) || range.versions.length === 0)
    ) {
      errors.push(`${prefix}: must have at least one event or exact version`);
    }
  });
  if (dataset.metadata?.record_count !== dataset.ranges.length) {
    errors.push(`metadata.record_count: expected ${dataset.ranges.length}, got ${dataset.metadata?.record_count}`);
  }
  return errors;
}
