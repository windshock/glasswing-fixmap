import path from "node:path";
import type { HttpClient } from "./http.js";
import { mapConcurrent } from "./http.js";
import { verifyFindingTags } from "./github-verify.js";
import {
  loadManualOverrides,
  manualEnrichment,
  manualReleaseAssessment,
} from "./manual.js";
import {
  mergeCommits,
  mergeReferences,
  mergeVersions,
  uniqueEvidence,
  uniqueStrings,
} from "./merge.js";
import { writeDataset } from "./output.js";
import {
  ANTHROPIC_PAYLOAD_URL,
  anthropicFindingUrl,
  fetchAnthropicFindingPage,
  fetchAnthropicPayload,
  titleMapFromPayload,
} from "./sources/anthropic.js";
import { fetchGithubAdvisoryEnrichment } from "./sources/advisory.js";
import { fetchCveEnrichment } from "./sources/cve.js";
import type {
  AnthropicLedgerEntry,
  EnrichmentFragment,
  FindingRecord,
  FixmapDataset,
  ManualOverrides,
  ParsedFindingPage,
  ReleaseAssessment,
} from "./types.js";
import { OUTPUT_SCHEMA_VERSION } from "./types.js";
import { validateDataset } from "./validate.js";

export interface SyncOptions {
  client: HttpClient;
  outputDirectory: string;
  overridesFile: string;
  concurrency: number;
  only?: Set<string>;
  verifyGithub?: boolean;
  strict?: boolean;
  onProgress?: (message: string) => void;
}

const EMPTY_FRAGMENT: EnrichmentFragment = {
  fix_commits: [],
  fix_references: [],
  fixed_versions: [],
  sources: [],
  warnings: [],
};

async function safeFetch<T>(
  description: string,
  operation: () => Promise<T>,
  fallback: T,
  warnings: string[],
  strict: boolean,
): Promise<T> {
  try {
    return await operation();
  } catch (error) {
    const message = `${description}: ${String(error)}`;
    warnings.push(message);
    if (strict) throw new Error(message, { cause: error });
    return fallback;
  }
}

function automaticAssessment(finding: Pick<FindingRecord, "patched" | "fix_commits" | "fixed_versions">): ReleaseAssessment {
  if (!finding.patched) return { status: "not_applicable", evidence: [] };
  const firstPatched = finding.fixed_versions.filter((version) => version.first_patched);
  if (firstPatched.length > 0) {
    return {
      status: "confirmed_versions",
      evidence: uniqueEvidence(firstPatched.flatMap((version) => version.evidence)),
    };
  }
  if (finding.fix_commits.length > 0) {
    return {
      status: "commit_only",
      note: "A fix commit is known, but no authoritative first patched release boundary was found",
      evidence: uniqueEvidence(finding.fix_commits.flatMap((commit) => commit.evidence)),
    };
  }
  return {
    status: "unresolved",
    note: "Anthropic marks the finding patched, but no fix commit or first patched release was resolved",
    evidence: [],
  };
}

function fragmentsForFinding(
  ledger: AnthropicLedgerEntry,
  ghsaFragments: Map<string, EnrichmentFragment>,
  cveFragments: Map<string, EnrichmentFragment>,
): EnrichmentFragment[] {
  const fragments: EnrichmentFragment[] = [];
  const cveIds = [...ledger.cve_ids];
  for (const ghsaId of ledger.ghsa_ids) {
    const fragment = ghsaFragments.get(ghsaId);
    if (!fragment) continue;
    fragments.push(fragment);
    cveIds.push(...(fragment.cve_ids ?? []));
  }
  for (const cveId of uniqueStrings(cveIds)) {
    const fragment = cveFragments.get(cveId);
    if (fragment) fragments.push(fragment);
  }
  return fragments;
}

export async function syncFixmap(options: SyncOptions): Promise<FixmapDataset> {
  const progress = options.onProgress ?? (() => undefined);
  progress("Fetching Anthropic CVD ledger");
  const payload = await fetchAnthropicPayload(options.client);
  const titleMap = titleMapFromPayload(payload);
  const allPublicEntries = payload.ledger.filter(
    (entry): entry is AnthropicLedgerEntry & { ant_id: string; project: string } =>
      Boolean(entry.ant_id && entry.project),
  );
  const entries = allPublicEntries
    .filter((entry) => !options.only || options.only.has(entry.ant_id))
    .sort((a, b) => a.ant_id.localeCompare(b.ant_id));
  const globalWarnings: string[] = [];
  const strict = options.strict ?? false;

  progress(`Fetching ${entries.length} public finding cards`);
  const pages = new Map<string, ParsedFindingPage>();
  const pageResults = await mapConcurrent(entries, options.concurrency, async (entry) => {
    const warnings: string[] = [];
    const page = await safeFetch(
      `Unable to fetch Anthropic finding ${entry.ant_id}`,
      () => fetchAnthropicFindingPage(options.client, entry.ant_id, entry.project),
      { title: null, fix_commits: [], fix_references: [], fixed_versions: [], links: [] },
      warnings,
      strict,
    );
    return { antId: entry.ant_id, page, warnings };
  });
  const pageWarnings = new Map<string, string[]>();
  for (const result of pageResults) {
    pages.set(result.antId, result.page);
    pageWarnings.set(result.antId, result.warnings);
  }

  const ghsaIds = uniqueStrings(entries.flatMap((entry) => entry.ghsa_ids));
  progress(`Enriching ${ghsaIds.length} GitHub advisories`);
  const ghsaFragments = new Map<string, EnrichmentFragment>();
  const ghsaResults = await mapConcurrent(ghsaIds, options.concurrency, async (ghsaId) => {
    const warnings: string[] = [];
    const repositories = uniqueStrings(
      entries
        .filter((entry) => entry.ghsa_ids.includes(ghsaId))
        .flatMap((entry) => {
          const page = pages.get(entry.ant_id);
          return [
            ...(page?.fix_commits.map((commit) => commit.repository) ?? []),
            ...(page?.fix_references.map((reference) => reference.repository) ?? []),
            ...(entry.project.includes("/") ? [entry.project] : []),
          ];
        }),
    );
    const fragment = await safeFetch(
      `Unable to enrich ${ghsaId}`,
      () => fetchGithubAdvisoryEnrichment(options.client, ghsaId, repositories),
      { ...EMPTY_FRAGMENT, warnings: [] },
      warnings,
      strict,
    );
    fragment.warnings.push(...warnings);
    return { ghsaId, fragment };
  });
  for (const result of ghsaResults) ghsaFragments.set(result.ghsaId, result.fragment);

  const cveIds = uniqueStrings([
    ...entries.flatMap((entry) => entry.cve_ids),
    ...[...ghsaFragments.values()].flatMap((fragment) => fragment.cve_ids ?? []),
  ]);
  progress(`Enriching ${cveIds.length} CVE records`);
  const cveFragments = new Map<string, EnrichmentFragment>();
  const cveResults = await mapConcurrent(cveIds, options.concurrency, async (cveId) => {
    const warnings: string[] = [];
    const fragment = await safeFetch(
      `Unable to enrich ${cveId}`,
      () => fetchCveEnrichment(options.client, cveId),
      { ...EMPTY_FRAGMENT, warnings: [] },
      warnings,
      strict,
    );
    fragment.warnings.push(...warnings);
    return { cveId, fragment };
  });
  for (const result of cveResults) cveFragments.set(result.cveId, result.fragment);

  const overrides: ManualOverrides = await loadManualOverrides(options.overridesFile);
  for (const antId of Object.keys(overrides)) {
    if (!allPublicEntries.some((entry) => entry.ant_id === antId)) {
      globalWarnings.push(`Manual override ${antId} is not present in the public Anthropic ledger`);
    }
  }

  const findings: FindingRecord[] = entries.map((entry) => {
    const page = pages.get(entry.ant_id)!;
    const fragments = fragmentsForFinding(entry, ghsaFragments, cveFragments);
    const override = overrides[entry.ant_id];
    if (override) fragments.push(manualEnrichment(entry.ant_id, override));
    const cveIdsForFinding = uniqueStrings([
      ...entry.cve_ids,
      ...fragments.flatMap((fragment) => fragment.cve_ids ?? []),
      ...(override?.cve_ids ?? []),
    ]);
    const ghsaIdsForFinding = uniqueStrings([
      ...entry.ghsa_ids,
      ...fragments.flatMap((fragment) => fragment.ghsa_ids ?? []),
      ...(override?.ghsa_ids ?? []),
    ]);
    const fixCommits = mergeCommits([
      ...page.fix_commits,
      ...fragments.flatMap((fragment) => fragment.fix_commits),
    ]);
    const fixReferences = mergeReferences([
      ...page.fix_references,
      ...fragments.flatMap((fragment) => fragment.fix_references),
    ]);
    const fixedVersions = mergeVersions([
      ...page.fixed_versions,
      ...fragments.flatMap((fragment) => fragment.fixed_versions),
    ]);
    const hasCommit = fixCommits.length > 0;
    const hasVersion = fixedVersions.length > 0;
    const enrichmentStatus = hasCommit && hasVersion
      ? "complete"
      : hasCommit || hasVersion
        ? "partial"
        : entry.patched
          ? "unresolved"
          : "not_patched";
    const record: FindingRecord = {
      schema_version: OUTPUT_SCHEMA_VERSION,
      ant_id: entry.ant_id,
      project: override?.project ?? entry.project,
      title: override?.title ?? page.title ?? titleMap.get(entry.ant_id) ?? null,
      bug_class: entry.bug_class,
      severity: {
        claude: entry.claude_severity,
        firm: entry.vendor_severity,
        maintainer: entry.maintainer_severity,
      },
      status: entry.status,
      patched: entry.patched,
      patched_at: entry.patched_at,
      discovered_on: entry.discovered_on,
      revealed_at: entry.revealed_at,
      withdrawn: entry.withdrawn,
      cve_ids: cveIdsForFinding,
      ghsa_ids: ghsaIdsForFinding,
      fix_commits: fixCommits,
      fix_references: fixReferences,
      fixed_versions: fixedVersions,
      release_assessment: { status: "unresolved", evidence: [] },
      enrichment: {
        status: enrichmentStatus,
        warnings: uniqueStrings([
          ...(pageWarnings.get(entry.ant_id) ?? []),
          ...fragments.flatMap((fragment) => fragment.warnings),
        ]),
      },
      sources: uniqueEvidence([
        { source: "anthropic_ledger", url: ANTHROPIC_PAYLOAD_URL, locator: entry.ant_id },
        { source: "anthropic_finding", url: anthropicFindingUrl(entry.ant_id) },
        ...fragments.flatMap((fragment) => fragment.sources),
      ]),
    };
    record.release_assessment =
      (override && manualReleaseAssessment(entry.ant_id, override)) ?? automaticAssessment(record);
    if (!entry.patched && record.release_assessment.status === "confirmed_versions") {
      record.enrichment.warnings.push(
        "External release evidence is newer than or conflicts with the Anthropic snapshot patched flag",
      );
      record.enrichment.warnings.sort();
    }
    return record;
  });

  if (options.verifyGithub) {
    progress("Verifying release tags contain known fix commits");
    await mapConcurrent(findings, Math.min(options.concurrency, 4), async (finding) => {
      await verifyFindingTags(options.client, finding);
      return finding;
    });
  }

  const dataset: FixmapDataset = {
    metadata: {
      schema_version: OUTPUT_SCHEMA_VERSION,
      source_as_of: payload.as_of,
      source_revision: payload.revision,
      source_manifest_sha3: payload.manifest_sha3 ?? null,
      source_url: ANTHROPIC_PAYLOAD_URL,
      finding_count: findings.length,
      patched_count: findings.filter((finding) => finding.patched).length,
      with_fix_commit: findings.filter((finding) => finding.fix_commits.length > 0).length,
      with_fixed_version: findings.filter((finding) => finding.fixed_versions.length > 0).length,
      complete_count: findings.filter((finding) => finding.enrichment.status === "complete").length,
      partial_count: findings.filter((finding) => finding.enrichment.status === "partial").length,
      unresolved_count: findings.filter((finding) => finding.enrichment.status === "unresolved").length,
    },
    findings,
  };
  const validationErrors = validateDataset(dataset);
  if (validationErrors.length > 0) {
    throw new Error(`Generated dataset failed validation:\n${validationErrors.join("\n")}`);
  }
  if (globalWarnings.length > 0) {
    progress(globalWarnings.join("\n"));
  }
  await writeDataset(dataset, path.resolve(options.outputDirectory));
  return dataset;
}
