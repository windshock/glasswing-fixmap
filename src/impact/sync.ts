import type { HttpClient } from "../http.js";
import { mapConcurrent } from "../http.js";
import { uniqueEvidence, uniqueStrings } from "../merge.js";
import type { Evidence, FixmapDataset } from "../types.js";
import { validateDataset } from "../validate.js";
import { extractGitHubImpact, type GitHubImpactRequest } from "./github.js";
import { writeImpactDataset } from "./output.js";
import type { FixImpact, FixImpactDataset } from "./types.js";
import { FIX_IMPACT_SCHEMA_VERSION } from "./types.js";
import { validateImpactDataset } from "./validate.js";

export interface SyncImpactOptions {
  client: HttpClient;
  fixmap: FixmapDataset;
  outputFile: string;
  concurrency: number;
  only?: Set<string>;
  strict?: boolean;
  onProgress?: (message: string) => void;
}

interface ImpactCandidate extends GitHubImpactRequest {
  commitUrl: string;
}

function isGitHubCommitUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return parsed.hostname.toLowerCase() === "github.com" && parsed.pathname.includes("/commit/");
  } catch {
    return false;
  }
}

function mergePrefixCandidates(candidates: ImpactCandidate[]): ImpactCandidate[] {
  const merged: ImpactCandidate[] = [];
  for (const candidate of [...candidates].sort((a, b) =>
    a.repository.toLowerCase().localeCompare(b.repository.toLowerCase()) ||
    b.commit.length - a.commit.length ||
    a.commit.localeCompare(b.commit),
  )) {
    const existing = merged.find(
      (item) =>
        item.repository.toLowerCase() === candidate.repository.toLowerCase() &&
        (item.commit.startsWith(candidate.commit) || candidate.commit.startsWith(item.commit)),
    );
    if (!existing) {
      merged.push({
        ...candidate,
        antIds: uniqueStrings(candidate.antIds),
        evidence: uniqueEvidence(candidate.evidence),
      });
      continue;
    }
    if (candidate.commit.length > existing.commit.length) {
      existing.commit = candidate.commit;
      existing.commitUrl = candidate.commitUrl;
    }
    existing.antIds = uniqueStrings([...existing.antIds, ...candidate.antIds]);
    existing.evidence = uniqueEvidence([...existing.evidence, ...candidate.evidence]);
  }
  return merged;
}

function candidatesFromFixmap(
  fixmap: FixmapDataset,
  only: Set<string> | undefined,
): ImpactCandidate[] {
  const candidates: ImpactCandidate[] = [];
  for (const finding of fixmap.findings) {
    if (only && !only.has(finding.ant_id)) continue;
    for (const commit of finding.fix_commits) {
      if (!commit.repository || !isGitHubCommitUrl(commit.url)) continue;
      candidates.push({
        repository: commit.repository,
        commit: commit.sha,
        commitUrl: commit.url,
        antIds: [finding.ant_id],
        evidence: commit.evidence,
      });
    }
  }
  return mergePrefixCandidates(candidates);
}

function errorImpact(candidate: ImpactCandidate, error: unknown): FixImpact {
  return {
    repository: candidate.repository,
    commit: candidate.commit,
    ant_ids: uniqueStrings(candidate.antIds),
    extraction_status: "error",
    files: [],
    evidence: uniqueEvidence([
      ...candidate.evidence,
      {
        source: "github_repository",
        url: candidate.commitUrl,
        locator: "commit impact extraction failed",
      } satisfies Evidence,
    ]),
    warnings: [`Unable to extract GitHub commit impact: ${String(error)}`],
  };
}

function mergeResolvedImpacts(impacts: FixImpact[]): FixImpact[] {
  const merged = new Map<string, FixImpact>();
  for (const impact of impacts) {
    const key = `${impact.repository.toLowerCase()}@${impact.commit}`;
    const existing = merged.get(key);
    if (!existing) {
      merged.set(key, impact);
      continue;
    }
    existing.ant_ids = uniqueStrings([...existing.ant_ids, ...impact.ant_ids]);
    existing.evidence = uniqueEvidence([...existing.evidence, ...impact.evidence]);
    existing.warnings = uniqueStrings([...existing.warnings, ...impact.warnings]);
    if (existing.extraction_status === "error" && impact.extraction_status !== "error") {
      existing.extraction_status = impact.extraction_status;
      existing.files = impact.files;
    } else if (existing.extraction_status === "complete" && impact.extraction_status === "partial") {
      existing.extraction_status = "partial";
    }
  }
  return [...merged.values()].sort((a, b) =>
    a.repository.toLowerCase().localeCompare(b.repository.toLowerCase()) ||
    a.commit.localeCompare(b.commit),
  );
}

export async function syncImpactDataset(options: SyncImpactOptions): Promise<FixImpactDataset> {
  const fixmapErrors = validateDataset(options.fixmap);
  if (fixmapErrors.length > 0) {
    throw new Error(`Input fixmap failed validation:\n${fixmapErrors.join("\n")}`);
  }
  const progress = options.onProgress ?? (() => undefined);
  const candidates = candidatesFromFixmap(options.fixmap, options.only);
  progress(`Extracting ${candidates.length} unique GitHub fix commits`);
  const results = await mapConcurrent(candidates, options.concurrency, async (candidate, index) => {
    progress(`[${index + 1}/${candidates.length}] ${candidate.repository}@${candidate.commit}`);
    try {
      return await extractGitHubImpact(options.client, candidate);
    } catch (error) {
      if (options.strict) throw error;
      return errorImpact(candidate, error);
    }
  });
  const impacts = mergeResolvedImpacts(results);
  const dataset: FixImpactDataset = {
    metadata: {
      schema_version: FIX_IMPACT_SCHEMA_VERSION,
      generated_from: {
        fixmap_schema_version: options.fixmap.metadata.schema_version,
        source_as_of: options.fixmap.metadata.source_as_of,
        source_revision: options.fixmap.metadata.source_revision,
        source_manifest_sha3: options.fixmap.metadata.source_manifest_sha3,
        source_url: options.fixmap.metadata.source_url,
      },
      finding_count: new Set(impacts.flatMap((impact) => impact.ant_ids)).size,
      impact_count: impacts.length,
      complete_count: impacts.filter((impact) => impact.extraction_status === "complete").length,
      partial_count: impacts.filter((impact) => impact.extraction_status === "partial").length,
      error_count: impacts.filter((impact) => impact.extraction_status === "error").length,
    },
    impacts,
  };
  const errors = validateImpactDataset(dataset);
  if (errors.length > 0) {
    throw new Error(`Generated impact dataset failed validation:\n${errors.join("\n")}`);
  }
  await writeImpactDataset(dataset, options.outputFile);
  return dataset;
}
