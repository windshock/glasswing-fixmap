import type {
  Confidence,
  Evidence,
  FixCommit,
  FixedVersion,
  FixReference,
} from "./types.js";

const CONFIDENCE_RANK: Record<Confidence, number> = {
  low: 0,
  medium: 1,
  high: 2,
  verified: 3,
};

function bestConfidence(a: Confidence, b: Confidence): Confidence {
  return CONFIDENCE_RANK[a] >= CONFIDENCE_RANK[b] ? a : b;
}

function mergeEvidence(left: Evidence[], right: Evidence[]): Evidence[] {
  const map = new Map<string, Evidence>();
  for (const item of [...left, ...right]) {
    const key = `${item.source}\u0000${item.url}\u0000${item.locator ?? ""}\u0000${item.note ?? ""}`;
    map.set(key, item);
  }
  return [...map.values()].sort((a, b) =>
    `${a.source}:${a.url}:${a.locator ?? ""}`.localeCompare(
      `${b.source}:${b.url}:${b.locator ?? ""}`,
    ),
  );
}

export function mergeCommits(items: FixCommit[]): FixCommit[] {
  const map = new Map<string, FixCommit>();
  for (const item of items) {
    const key = `${item.repository?.toLowerCase() ?? ""}:${item.sha.toLowerCase()}`;
    const previous = map.get(key);
    if (!previous) {
      map.set(key, { ...item, evidence: mergeEvidence([], item.evidence) });
      continue;
    }
    previous.confidence = bestConfidence(previous.confidence, item.confidence);
    previous.evidence = mergeEvidence(previous.evidence, item.evidence);
    if (!previous.repository && item.repository) previous.repository = item.repository;
    if (item.url.length > previous.url.length) previous.url = item.url;
  }
  return [...map.values()].sort((a, b) =>
    `${a.repository ?? ""}:${a.sha}`.localeCompare(`${b.repository ?? ""}:${b.sha}`),
  );
}

export function mergeReferences(items: FixReference[]): FixReference[] {
  const map = new Map<string, FixReference>();
  for (const item of items) {
    const key = `${item.kind}:${item.url}`;
    const previous = map.get(key);
    if (!previous) {
      map.set(key, { ...item, evidence: mergeEvidence([], item.evidence) });
      continue;
    }
    previous.confidence = bestConfidence(previous.confidence, item.confidence);
    previous.evidence = mergeEvidence(previous.evidence, item.evidence);
  }
  return [...map.values()].sort((a, b) => a.url.localeCompare(b.url));
}

export function mergeVersions(items: FixedVersion[]): FixedVersion[] {
  const merged: FixedVersion[] = [];
  for (const item of items) {
    const previous = merged.find(
      (candidate) =>
        candidate.version.toLowerCase() === item.version.toLowerCase() &&
        (candidate.branch?.toLowerCase() ?? "") === (item.branch?.toLowerCase() ?? "") &&
        (!candidate.package ||
          !item.package ||
          candidate.package.toLowerCase() === item.package.toLowerCase()) &&
        (!candidate.ecosystem ||
          !item.ecosystem ||
          candidate.ecosystem.toLowerCase() === item.ecosystem.toLowerCase()),
    );
    if (!previous) {
      merged.push({ ...item, evidence: mergeEvidence([], item.evidence) });
      continue;
    }
    previous.confidence = bestConfidence(previous.confidence, item.confidence);
    previous.evidence = mergeEvidence(previous.evidence, item.evidence);
    previous.first_patched =
      previous.first_patched === true || item.first_patched === true
        ? true
        : previous.first_patched ?? item.first_patched;
    if (previous.first_patched === true) {
      previous.role = "first_patched";
    } else if (previous.role === "operational_baseline" && item.role !== "operational_baseline") {
      previous.role = item.role;
    }
    if (!previous.introduced && item.introduced) previous.introduced = item.introduced;
    if (!previous.package && item.package) previous.package = item.package;
    if (!previous.ecosystem && item.ecosystem) previous.ecosystem = item.ecosystem;
  }
  return merged.sort((a, b) => {
    const packageCompare = `${a.ecosystem ?? ""}:${a.package ?? ""}`.localeCompare(
      `${b.ecosystem ?? ""}:${b.package ?? ""}`,
    );
    return packageCompare || a.version.localeCompare(b.version, undefined, { numeric: true });
  });
}

export function uniqueStrings(values: Array<string | null | undefined>): string[] {
  return [...new Set(values.filter((value): value is string => Boolean(value)))].sort();
}

export function uniqueEvidence(items: Evidence[]): Evidence[] {
  return mergeEvidence([], items);
}
