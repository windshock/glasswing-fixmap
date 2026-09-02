import type { HttpClient } from "../http.js";
import { atomicWrite } from "../output.js";
import type { FixmapDataset } from "../types.js";
import { parseAuthoritativeRanges, type OsvRangeRecord } from "./extract.js";
import { validateAffectedRangeDataset } from "./read.js";
import {
  AFFECTED_RANGE_SCHEMA_VERSION,
  type AffectedRangeDataset,
  type AffectedRangeRecord,
} from "./types.js";

export interface SyncRangesOptions {
  client: HttpClient;
  fixmap: FixmapDataset;
  outputFile: string;
  only?: Set<string>;
  concurrency?: number;
  onProgress?: (message: string) => void;
}

function rangeKey(record: AffectedRangeRecord): string {
  return [
    record.ant_id,
    record.advisory,
    record.ecosystem,
    record.package,
    record.range_type,
    JSON.stringify(record.events),
    JSON.stringify(record.versions ?? []),
  ].join("|");
}

async function mapPool<T, R>(items: T[], limit: number, worker: (item: T) => Promise<R>): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let next = 0;
  const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await worker(items[index]!);
    }
  });
  await Promise.all(runners);
  return results;
}

/**
 * Collect authoritative affected ranges for findings that carry an advisory ID,
 * consuming OSV records exactly as published. Ranges are never inferred from
 * `fixed_versions[]` or release ordering. The result is a versioned companion
 * artifact; `fixmap.json` is unchanged.
 */
export async function syncAffectedRanges(options: SyncRangesOptions): Promise<AffectedRangeDataset> {
  const concurrency = options.concurrency ?? 4;
  const findings = options.fixmap.findings.filter(
    (finding) => !options.only || options.only.has(finding.ant_id),
  );
  const targets = findings.filter(
    (finding) => finding.ghsa_ids.length > 0 || finding.cve_ids.length > 0,
  );

  const collected = await mapPool(targets, concurrency, async (finding) => {
    const records: AffectedRangeRecord[] = [];
    const advisoryIds = [...new Set([...finding.ghsa_ids, ...finding.cve_ids])];
    for (const advisoryId of advisoryIds) {
      const url = `https://api.osv.dev/v1/vulns/${encodeURIComponent(advisoryId)}`;
      const osv = await options.client.getOptionalJson<OsvRangeRecord>(url);
      if (osv) records.push(...parseAuthoritativeRanges(osv, finding.ant_id, url));
    }
    options.onProgress?.(`${finding.ant_id}: ${records.length} authoritative range(s)`);
    return records;
  });

  const deduped = new Map<string, AffectedRangeRecord>();
  for (const record of collected.flat()) {
    if (!deduped.has(rangeKey(record))) deduped.set(rangeKey(record), record);
  }
  const ranges = [...deduped.values()].sort(
    (a, b) =>
      a.ant_id.localeCompare(b.ant_id) ||
      a.ecosystem.localeCompare(b.ecosystem) ||
      a.package.localeCompare(b.package) ||
      a.advisory.localeCompare(b.advisory) ||
      rangeKey(a).localeCompare(rangeKey(b)),
  );

  const dataset: AffectedRangeDataset = {
    metadata: {
      schema_version: AFFECTED_RANGE_SCHEMA_VERSION,
      generated_from: {
        fixmap_schema_version: options.fixmap.metadata.schema_version,
        source_as_of: options.fixmap.metadata.source_as_of,
        source_url: options.fixmap.metadata.source_url,
      },
      finding_count: new Set(ranges.map((range) => range.ant_id)).size,
      record_count: ranges.length,
    },
    ranges,
  };

  const errors = validateAffectedRangeDataset(dataset);
  if (errors.length > 0) throw new Error(`Invalid affected-range dataset:\n${errors.join("\n")}`);
  await atomicWrite(options.outputFile, `${JSON.stringify(dataset, null, 2)}\n`);
  return dataset;
}
