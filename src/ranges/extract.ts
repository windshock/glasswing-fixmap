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
}

export interface OsvRangeRecord {
  id?: string;
  aliases?: string[];
  affected?: OsvAffected[];
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
 * finding. Only ranges with a resolvable ecosystem, package, and at least one
 * usable event are kept; identity-less or empty ranges are skipped rather than
 * guessed.
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
    for (const range of affected.ranges ?? []) {
      const events = (range.events ?? [])
        .map(pickEvent)
        .filter((event): event is AffectedRangeEvent => event !== undefined);
      if (events.length === 0) continue;
      results.push({
        ant_id: antId,
        advisory,
        ecosystem,
        package: packageName,
        range_type: range.type ?? "UNSPECIFIED",
        events,
        provenance,
      });
    }
  }
  return results;
}
