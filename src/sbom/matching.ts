import type { FindingRecord } from "../types.js";
import {
  canonicalizePurl,
  findingIdentityKey,
  identityKeyForParsedPurl,
  type ParsedPurl,
} from "./purl.js";
import type {
  CandidateConfidence,
  ComponentCandidate,
  IdentityStrength,
  MatchType,
  NormalizedComponent,
} from "./types.js";

interface FindingIndex {
  byIdentity: Map<string, FindingRecord[]>;
  byRepository: Map<string, FindingRecord[]>;
  byName: Map<string, FindingRecord[]>;
  findingIdentity: Map<string, { ecosystem?: string; package?: string }>;
}

function addTo(map: Map<string, FindingRecord[]>, key: string, finding: FindingRecord): void {
  const existing = map.get(key);
  if (existing) existing.push(finding);
  else map.set(key, [finding]);
}

function repositoryName(project: string): string | undefined {
  const parts = project.split("/");
  return parts.length === 2 ? parts[1] : undefined;
}

function buildIndex(findings: FindingRecord[]): FindingIndex {
  const index: FindingIndex = {
    byIdentity: new Map(),
    byRepository: new Map(),
    byName: new Map(),
    findingIdentity: new Map(),
  };
  for (const finding of findings) {
    if (finding.project) addTo(index.byRepository, finding.project.toLowerCase(), finding);
    const repoName = finding.project ? repositoryName(finding.project) : undefined;
    if (repoName) addTo(index.byName, repoName.toLowerCase(), finding);
    for (const fixedVersion of finding.fixed_versions) {
      if (!fixedVersion.package) continue;
      const packageName = fixedVersion.package;
      addTo(index.byName, packageName.toLowerCase(), finding);
      const artifact = packageName.includes(":") ? packageName.slice(packageName.indexOf(":") + 1) : packageName;
      addTo(index.byName, artifact.toLowerCase(), finding);
      if (!fixedVersion.ecosystem) continue;
      const key = findingIdentityKey(fixedVersion.ecosystem, packageName);
      if (!key) continue;
      addTo(index.byIdentity, key, finding);
      if (!index.findingIdentity.has(`${finding.ant_id}:${key}`)) {
        index.findingIdentity.set(`${finding.ant_id}:${key}`, {
          ecosystem: fixedVersion.ecosystem,
          package: packageName,
        });
      }
    }
  }
  return index;
}

function repositoryFromPurl(parsed: ParsedPurl): string | undefined {
  if (parsed.type === "github" && parsed.namespace) return `${parsed.namespace}/${parsed.name}`;
  if (parsed.type === "golang" && parsed.namespace?.toLowerCase().startsWith("github.com/")) {
    return `${parsed.namespace.slice("github.com/".length)}/${parsed.name}`;
  }
  return undefined;
}

function confidenceFor(matchType: MatchType): {
  strength: IdentityStrength;
  confidence: CandidateConfidence;
} {
  switch (matchType) {
    case "exact_purl":
    case "ecosystem_package":
      return { strength: "strong", confidence: "high" };
    case "repository":
      return { strength: "strong", confidence: "medium" };
    case "name_heuristic":
      return { strength: "weak", confidence: "low" };
  }
}

function candidate(
  finding: FindingRecord,
  component: NormalizedComponent,
  matchType: MatchType,
  identity: { ecosystem?: string; package?: string },
): ComponentCandidate {
  const { strength, confidence } = confidenceFor(matchType);
  const componentView: ComponentCandidate["component"] = {
    source_format: component.source_format,
    name: component.name,
    locations: component.locations,
  };
  if (component.version) componentView.version = component.version;
  if (component.purl) componentView.purl = component.purl;
  if (component.repository) componentView.repository = component.repository;
  const findingIdentity: ComponentCandidate["finding_identity"] = {};
  if (identity.ecosystem) findingIdentity.ecosystem = identity.ecosystem;
  if (identity.package) findingIdentity.package = identity.package;
  return {
    ant_id: finding.ant_id,
    project: finding.project,
    match_type: matchType,
    identity_strength: strength,
    confidence,
    component: componentView,
    finding_identity: findingIdentity,
  };
}

/**
 * Select candidate `(finding, component)` pairs using the priority
 * `exact PURL > ecosystem + package > repository identity > normalized name`.
 * A component carrying a valid PURL that does not identity-match a finding can
 * never fall back to a coincidental name match against it.
 */
export function selectCandidates(
  components: NormalizedComponent[],
  findings: FindingRecord[],
): ComponentCandidate[] {
  const index = buildIndex(findings);
  const candidates: ComponentCandidate[] = [];
  const seen = new Set<string>();

  for (const component of components) {
    if (component.type === "file") continue;
    const parsed = component.purl ? canonicalizePurl(component.purl) : undefined;
    const identityKey = parsed ? identityKeyForParsedPurl(parsed) : undefined;
    const repository = component.repository ?? (parsed ? repositoryFromPurl(parsed) : undefined);
    const matchedFindings = new Set<string>();

    const emit = (finding: FindingRecord, matchType: MatchType): void => {
      const dedupe = `${finding.ant_id}::${component.name}::${component.version ?? ""}::${component.purl ?? ""}::${matchType}`;
      if (seen.has(dedupe)) return;
      seen.add(dedupe);
      matchedFindings.add(finding.ant_id);
      const identity = identityKey
        ? index.findingIdentity.get(`${finding.ant_id}:${identityKey}`) ?? {}
        : {};
      candidates.push(candidate(finding, component, matchType, identity));
    };

    if (identityKey) {
      for (const finding of index.byIdentity.get(identityKey) ?? []) emit(finding, "exact_purl");
    }
    if (repository) {
      for (const finding of index.byRepository.get(repository.toLowerCase()) ?? []) {
        if (!matchedFindings.has(finding.ant_id)) emit(finding, "repository");
      }
    }
    // A valid but non-matching PURL positively identifies a different package,
    // so a coincidental name match must not be produced for it.
    if (!parsed) {
      for (const finding of index.byName.get(component.name.toLowerCase()) ?? []) {
        if (!matchedFindings.has(finding.ant_id)) emit(finding, "name_heuristic");
      }
    }
  }

  candidates.sort(
    (a, b) =>
      a.ant_id.localeCompare(b.ant_id) ||
      a.component.name.localeCompare(b.component.name) ||
      a.match_type.localeCompare(b.match_type),
  );
  return candidates;
}
