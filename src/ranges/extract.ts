import type { AffectedRangeEvent, AffectedRangeRecord } from "./types.js";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type?: string;
  events?: OsvEvent[];
}

interface OsvAffected {
  package?: { ecosystem?: string; name?: string };
  ranges?: OsvRange[];
  versions?: unknown;
}

export interface OsvRangeRecord {
  id?: string;
  aliases?: string[];
  affected?: OsvAffected[];
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

function pickEvent(event: OsvEvent): AffectedRangeEvent | undefined {
  const picked: AffectedRangeEvent = {};
  if (typeof event.introduced === "string") picked.introduced = event.introduced;
  if (typeof event.fixed === "string") picked.fixed = event.fixed;
  if (typeof event.last_affected === "string") picked.last_affected = event.last_affected;
  // `limit` is a housekeeping bound rather than an affected boundary, but it is
  // preserved so the published range is not projected away.
  if (typeof event.limit === "string") picked.limit = event.limit;
  return Object.keys(picked).length > 0 ? picked : undefined;
}

/**
 * Project the authoritative affected ranges from a single OSV record for one
 * finding. Only entries with a resolvable ecosystem and package are kept;
 * `affected.versions[]` is preserved as exact positive evidence, including for
 * entries that publish versions but no usable range.
 */
export function parseAuthoritativeRanges(
  record: OsvRangeRecord,
  antId: string,
  provenance: string,
): AffectedRangeRecord[] {
  const advisory = typeof record.id === "string" ? record.id : "unknown";
  const results: AffectedRangeRecord[] = [];
  for (const affected of record.affected ?? []) {
    const ecosystem = affected.package?.ecosystem;
    const packageName = affected.package?.name;
    if (!ecosystem || !packageName) continue;
    const versions = stringArray(affected.versions);

    let emitted = 0;
    for (const range of affected.ranges ?? []) {
      const events = (range.events ?? [])
        .map(pickEvent)
        .filter((event): event is AffectedRangeEvent => event !== undefined);
      if (events.length === 0) continue;
      const rangeRecord: AffectedRangeRecord = {
        ant_id: antId,
        advisory,
        ecosystem,
        package: packageName,
        range_type: range.type ?? "UNSPECIFIED",
        events,
        provenance,
      };
      if (versions.length > 0) rangeRecord.versions = versions;
      results.push(rangeRecord);
      emitted += 1;
    }

    // Exact affected versions with no usable range are still positive evidence.
    if (emitted === 0 && versions.length > 0) {
      results.push({
        ant_id: antId,
        advisory,
        ecosystem,
        package: packageName,
        range_type: "EXACT",
        events: [],
        versions,
        provenance,
      });
    }
  }
  return results;
}
