import type { AffectedRangeEvent, AffectedRangeRecord } from "./types.js";

interface OsvEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

interface OsvRange {
  type?: string;
  repo?: string;
  events?: OsvEvent[];
}

interface OsvAffected {
  package?: { ecosystem?: string; name?: string; purl?: string };
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
    const purl = typeof affected.package?.purl === "string" ? affected.package.purl : undefined;

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
      if (purl) rangeRecord.purl = purl;
      if (typeof range.repo === "string") rangeRecord.repo = range.repo;
      if (versions.length > 0) rangeRecord.versions = versions;
      results.push(rangeRecord);
      emitted += 1;
    }

    // Exact affected versions with no usable range are still positive evidence.
    if (emitted === 0 && versions.length > 0) {
      const versionsRecord: AffectedRangeRecord = {
        ant_id: antId,
        advisory,
        ecosystem,
        package: packageName,
        range_type: "EXACT",
        events: [],
        versions,
        provenance,
        source: "osv",
      };
      if (purl) versionsRecord.purl = purl;
      results.push(versionsRecord);
    }
  }
  for (const record of results) record.source = "osv";
  return results;
}

interface CveVersion {
  version?: string;
  versionType?: string;
  status?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
}

interface CveAffected {
  vendor?: string;
  product?: string;
  packageName?: string;
  cpes?: unknown;
  versions?: CveVersion[];
}

export interface CveRangeRecord {
  cveMetadata?: { cveId?: string };
  containers?: { cna?: { affected?: CveAffected[] }; adp?: Array<{ affected?: CveAffected[] }> };
}

/**
 * Project authoritative affected ranges from a CVE List V5 record. Ranges are
 * keyed by CVE product (with any CPEs) since CVE records carry no package
 * ecosystem; versions are consumed exactly as published (`version`/`lessThan`/
 * `lessThanOrEqual`), never reconstructed. GIT version types are skipped.
 */
export function parseCveRanges(
  record: CveRangeRecord,
  antId: string,
  provenance: string,
): AffectedRangeRecord[] {
  const advisory = record.cveMetadata?.cveId ?? "unknown";
  const affectedEntries = [
    ...(record.containers?.cna?.affected ?? []),
    ...(record.containers?.adp ?? []).flatMap((container) => container.affected ?? []),
  ];
  const results: AffectedRangeRecord[] = [];
  const seen = new Set<string>();
  for (const affected of affectedEntries) {
    const product = affected.packageName ?? affected.product;
    if (!product) continue;
    const cpes = stringArray(affected.cpes);
    for (const entry of affected.versions ?? []) {
      if (entry.status !== "affected") continue;
      if (entry.versionType?.toLowerCase() === "git") continue;
      if (typeof entry.version !== "string") continue;
      const events: AffectedRangeEvent[] = [];
      const versions: string[] = [];
      if (typeof entry.lessThan === "string" && !entry.lessThan.includes("*")) {
        events.push({ introduced: entry.version }, { fixed: entry.lessThan });
      } else if (typeof entry.lessThanOrEqual === "string" && !entry.lessThanOrEqual.includes("*")) {
        events.push({ introduced: entry.version }, { last_affected: entry.lessThanOrEqual });
      } else {
        versions.push(entry.version);
      }
      const rangeRecord: AffectedRangeRecord = {
        ant_id: antId,
        advisory,
        source: "cve_list_v5",
        ecosystem: "cve",
        package: product,
        product,
        range_type: "SEMVER",
        events,
        provenance,
      };
      if (cpes.length > 0) rangeRecord.cpes = cpes;
      if (versions.length > 0) rangeRecord.versions = versions;
      const key = `${product}|${JSON.stringify(events)}|${JSON.stringify(versions)}`;
      if (seen.has(key)) continue;
      seen.add(key);
      results.push(rangeRecord);
    }
  }
  return results;
}
