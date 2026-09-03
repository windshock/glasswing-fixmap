export const AFFECTED_RANGE_SCHEMA_VERSION = "1.0.0" as const;

export interface AffectedRangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

/**
 * An authoritative affected range consumed exactly as published and parsed from
 * an OSV/GHSA record. It is never reconstructed from `fixed_versions[]` or from
 * release ordering. `range_type` and every event are preserved so a comparator
 * can decide whether it supports the ecosystem/scheme.
 */
export interface AffectedRangeRecord {
  ant_id: string;
  advisory: string;
  ecosystem: string;
  package: string;
  /** Canonical PURL from OSV `affected.package.purl`, when published. */
  purl?: string;
  range_type: string;
  /** OSV `ranges[].repo`, when published (notably for GIT ranges). */
  repo?: string;
  events: AffectedRangeEvent[];
  /** Exact affected versions published in OSV `affected.versions[]`, if any. */
  versions?: string[];
  provenance: string;
}

export interface AffectedRangeDataset {
  metadata: {
    schema_version: typeof AFFECTED_RANGE_SCHEMA_VERSION;
    generated_from: {
      fixmap_schema_version: string;
      source_as_of: string;
      source_url: string;
    };
    finding_count: number;
    record_count: number;
  };
  ranges: AffectedRangeRecord[];
}
