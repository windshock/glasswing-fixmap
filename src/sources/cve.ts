import type { HttpClient } from "../http.js";
import { mergeCommits, mergeReferences, mergeVersions } from "../merge.js";
import type {
  EnrichmentFragment,
  Evidence,
  FixCommit,
  FixedVersion,
} from "../types.js";
import {
  cveRecordRawUrl,
  isVersionToken,
  parseCommitUrl,
  parseFixReferenceUrl,
} from "../urls.js";

interface CveVersionChange {
  at?: string;
  status?: string;
}

interface CveVersion {
  version?: string;
  versionType?: string;
  status?: string;
  lessThan?: string;
  lessThanOrEqual?: string;
  repo?: string;
  changes?: CveVersionChange[];
}

interface CveAffected {
  vendor?: string;
  product?: string;
  packageName?: string;
  collectionURL?: string;
  defaultStatus?: string;
  versions?: CveVersion[];
}

interface CveContainer {
  affected?: CveAffected[];
  references?: Array<{ url?: string; tags?: string[] }>;
}

interface CveRecord {
  cveMetadata?: { cveId?: string; state?: string };
  containers?: { cna?: CveContainer; adp?: CveContainer[] };
}

function cveContainers(record: CveRecord): CveContainer[] {
  const containers: CveContainer[] = [];
  if (record.containers?.cna) containers.push(record.containers.cna);
  containers.push(...(record.containers?.adp ?? []));
  return containers;
}

function fixedVersion(
  version: string,
  affected: CveAffected,
  sourceUrl: string,
  locator: string,
  introduced?: string,
): FixedVersion {
  const result: FixedVersion = {
    version,
    role: "first_patched",
    first_patched: true,
    confidence: "high",
    evidence: [
      {
        source: "cve_list_v5",
        url: sourceUrl,
        locator,
        note: "CVE version-status transition to unaffected",
      },
    ],
    commit_verification: { status: "not_run" },
  };
  const packageName = affected.packageName ?? affected.product;
  if (packageName) result.package = packageName;
  if (introduced) result.introduced = introduced;
  return result;
}

export function parseCveRecord(record: CveRecord, cveId: string, sourceUrl: string): EnrichmentFragment {
  const commits: FixCommit[] = [];
  const references = [];
  const versions: FixedVersion[] = [];
  const evidence: Evidence = { source: "cve_list_v5", url: sourceUrl };

  for (const container of cveContainers(record)) {
    for (const reference of container.references ?? []) {
      if (!reference.url) continue;
      const commit = parseCommitUrl(reference.url, "medium", {
        ...evidence,
        locator: "containers.*.references",
      });
      if (commit) commits.push(commit);
      const fixReference = parseFixReferenceUrl(reference.url, "medium", {
        ...evidence,
        locator: "containers.*.references",
      });
      if (fixReference) references.push(fixReference);
    }

    for (const affected of container.affected ?? []) {
      for (const entry of affected.versions ?? []) {
        const versionType = entry.versionType?.toLowerCase();
        if (
          entry.status === "affected" &&
          entry.lessThan &&
          isVersionToken(entry.lessThan) &&
          !entry.lessThan.includes("*")
        ) {
          versions.push(
            fixedVersion(
              entry.lessThan,
              affected,
              sourceUrl,
              "containers.*.affected[].versions[].lessThan",
              entry.version,
            ),
          );
        }

        let currentStatus = entry.status;
        for (const change of entry.changes ?? []) {
          if (!change.at || !change.status) continue;
          if (currentStatus === "affected" && change.status === "unaffected") {
            if (versionType === "git" && /^[0-9a-f]{7,64}$/i.test(change.at)) {
              const repositoryUrl = entry.repo ?? affected.collectionURL;
              const commitUrl = repositoryUrl
                ? `${repositoryUrl.replace(/\/$/, "")}/commit/${change.at}`
                : sourceUrl;
              const commit: FixCommit = {
                sha: change.at.toLowerCase(),
                url: commitUrl,
                confidence: "high",
                evidence: [
                  {
                    ...evidence,
                    locator: "containers.*.affected[].versions[].changes[].at",
                    note: "CVE git version-status transition to unaffected",
                  },
                ],
              };
              if (repositoryUrl) {
                const match = repositoryUrl.match(/github\.com\/([^/]+\/[^/]+?)(?:\.git)?$/i);
                if (match) commit.repository = match[1]!;
              }
              commits.push(commit);
            } else if (isVersionToken(change.at)) {
              versions.push(
                fixedVersion(
                  change.at,
                  affected,
                  sourceUrl,
                  "containers.*.affected[].versions[].changes[].at",
                  entry.version,
                ),
              );
            }
          }
          currentStatus = change.status;
        }

        if (
          affected.defaultStatus === "affected" &&
          entry.status === "unaffected" &&
          entry.version &&
          isVersionToken(entry.version)
        ) {
          versions.push(
            fixedVersion(
              entry.version,
              affected,
              sourceUrl,
              "containers.*.affected[].versions[].version",
            ),
          );
        }
      }
    }
  }

  const warnings: string[] = [];
  if (record.cveMetadata?.state && record.cveMetadata.state !== "PUBLISHED") {
    warnings.push(`${cveId} state is ${record.cveMetadata.state}`);
  }
  return {
    cve_ids: [record.cveMetadata?.cveId ?? cveId],
    fix_commits: mergeCommits(commits),
    fix_references: mergeReferences(references),
    fixed_versions: mergeVersions(versions),
    sources: [evidence],
    warnings,
  };
}

export async function fetchCveEnrichment(
  client: HttpClient,
  cveId: string,
): Promise<EnrichmentFragment> {
  const sourceUrl = cveRecordRawUrl(cveId);
  const record = await client.getOptionalJson<CveRecord>(sourceUrl);
  if (!record) {
    return {
      fix_commits: [],
      fix_references: [],
      fixed_versions: [],
      sources: [],
      warnings: [`No CVE List V5 record found for ${cveId}`],
    };
  }
  return parseCveRecord(record, cveId, sourceUrl);
}
