import * as cheerio from "cheerio";
import type { HttpClient } from "../http.js";
import { mergeCommits, mergeReferences, mergeVersions, uniqueStrings } from "../merge.js";
import type {
  EnrichmentFragment,
  Evidence,
  FixedVersion,
} from "../types.js";
import {
  githubAdvisoryRawUrl,
  parseCommitUrl,
  parseFixReferenceUrl,
} from "../urls.js";

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
  package?: { ecosystem?: string; name?: string };
  ranges?: OsvRange[];
  database_specific?: { source?: string | string[] };
}

interface OsvRecord {
  id?: string;
  aliases?: string[];
  affected?: OsvAffected[];
  references?: Array<{ type?: string; url?: string }>;
  database_specific?: { source?: string | string[] };
}

function mergeFragments(fragments: EnrichmentFragment[]): EnrichmentFragment {
  return {
    cve_ids: uniqueStrings(fragments.flatMap((fragment) => fragment.cve_ids ?? [])),
    ghsa_ids: uniqueStrings(fragments.flatMap((fragment) => fragment.ghsa_ids ?? [])),
    fix_commits: mergeCommits(fragments.flatMap((fragment) => fragment.fix_commits)),
    fix_references: mergeReferences(fragments.flatMap((fragment) => fragment.fix_references)),
    fixed_versions: mergeVersions(fragments.flatMap((fragment) => fragment.fixed_versions)),
    sources: fragments.flatMap((fragment) => fragment.sources),
    warnings: fragments.flatMap((fragment) => fragment.warnings),
  };
}

function sourceUrls(record: OsvRecord): string[] {
  const values: string[] = [];
  const add = (source: string | string[] | undefined): void => {
    if (typeof source === "string") values.push(source);
    if (Array.isArray(source)) values.push(...source);
  };
  add(record.database_specific?.source);
  for (const affected of record.affected ?? []) add(affected.database_specific?.source);
  return uniqueStrings(values);
}

export function parseAdvisoryRecord(record: OsvRecord, sourceUrl: string): EnrichmentFragment {
  const evidenceSource = sourceUrl.includes("github/advisory-database")
    ? "github_advisory_database"
    : "osv";
  const commits = [];
  const references = [];
  const fixedVersions: FixedVersion[] = [];
  const evidence: Evidence = { source: evidenceSource, url: sourceUrl };

  for (const reference of record.references ?? []) {
    if (!reference.url) continue;
    const commit = parseCommitUrl(reference.url, "high", {
      ...evidence,
      locator: "references",
    });
    if (commit) commits.push(commit);
    const fixReference = parseFixReferenceUrl(reference.url, "high", {
      ...evidence,
      locator: "references",
    });
    if (fixReference) references.push(fixReference);
  }

  for (const affected of record.affected ?? []) {
    for (const range of affected.ranges ?? []) {
      let introduced: string | undefined;
      for (const event of range.events ?? []) {
        if (event.introduced !== undefined) introduced = event.introduced;
        if (event.fixed === undefined) continue;
        const item: FixedVersion = {
          version: event.fixed,
          role: "first_patched",
          first_patched: true,
          confidence: "high",
          evidence: [
            {
              ...evidence,
              locator: `affected.ranges[${range.type ?? "unknown"}].events.fixed`,
              note: "Explicit fixed boundary in the advisory record",
            },
          ],
          commit_verification: { status: "not_run" },
        };
        if (affected.package?.name) item.package = affected.package.name;
        if (affected.package?.ecosystem) item.ecosystem = affected.package.ecosystem;
        if (introduced !== undefined) item.introduced = introduced;
        fixedVersions.push(item);
      }
    }
  }

  return {
    cve_ids: uniqueStrings(
      [record.id, ...(record.aliases ?? [])].filter((id) => /^CVE-\d{4}-\d+$/i.test(id ?? "")),
    ),
    ghsa_ids: uniqueStrings(
      [record.id, ...(record.aliases ?? [])].filter((id) => /^GHSA-/i.test(id ?? "")),
    ),
    fix_commits: mergeCommits(commits),
    fix_references: mergeReferences(references),
    fixed_versions: mergeVersions(fixedVersions),
    sources: [evidence],
    warnings: [],
  };
}

export function parseRepositoryAdvisoryPage(
  html: string,
  ghsaId: string,
  sourceUrl: string,
): EnrichmentFragment {
  const $ = cheerio.load(html);
  const versions: FixedVersion[] = [];
  $("h2")
    .filter((_, element) => $(element).text().trim().toLowerCase() === "patched versions")
    .each((_, element) => {
      const container = $(element).parent();
      const text = container.find(".f4").first().text().trim();
      const packageContainer = container.closest(".Box-body");
      const packageName = packageContainer
        .find("h2")
        .filter((__, heading) => $(heading).text().trim().toLowerCase() === "package")
        .first()
        .parent()
        .find(".f4")
        .first()
        .text()
        .trim();
      for (const match of text.matchAll(/\bv?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?\b/g)) {
        const item: FixedVersion = {
          version: match[0],
          role: "first_patched",
          first_patched: true,
          confidence: "high",
          evidence: [
            {
              source: "github_advisory_database",
              url: sourceUrl,
              locator: "Patched versions",
              note: "Explicit patched version on the repository security advisory",
            },
          ],
          commit_verification: { status: "not_run" },
        };
        if (packageName) item.package = packageName;
        versions.push(item);
      }
    });

  const cveIds = new Set<string>();
  const pageText = $("main").text();
  for (const match of pageText.matchAll(/\bCVE-\d{4}-\d+\b/g)) cveIds.add(match[0]);
  return {
    cve_ids: [...cveIds].sort(),
    ghsa_ids: [ghsaId],
    fix_commits: [],
    fix_references: [],
    fixed_versions: mergeVersions(versions),
    sources: [{ source: "github_advisory_database", url: sourceUrl }],
    warnings: [],
  };
}

export async function fetchGithubAdvisoryEnrichment(
  client: HttpClient,
  ghsaId: string,
  repositories: string[] = [],
): Promise<EnrichmentFragment> {
  const osvUrl = `https://api.osv.dev/v1/vulns/${encodeURIComponent(ghsaId)}`;
  const osv = await client.getOptionalJson<OsvRecord>(osvUrl);
  const fragments: EnrichmentFragment[] = [];
  if (osv) {
    const githubSource = sourceUrls(osv).find((url) =>
      url.includes("github.com/github/advisory-database/blob/main/"),
    );
    const rawUrl = githubSource ? githubAdvisoryRawUrl(githubSource) : undefined;
    const raw = rawUrl ? await client.getOptionalJson<OsvRecord>(rawUrl) : undefined;
    if (raw && githubSource) {
      const parsed = parseAdvisoryRecord(raw, githubSource);
      parsed.sources.push({ source: "osv", url: osvUrl, locator: "source discovery" });
      fragments.push(parsed);
    } else {
      const parsed = parseAdvisoryRecord(osv, osvUrl);
      parsed.warnings.push(
        `${ghsaId} was enriched from OSV because a raw GitHub Advisory Database record was not discoverable`,
      );
      fragments.push(parsed);
    }
  }

  for (const repository of uniqueStrings(repositories)) {
    const sourceUrl = `https://github.com/${repository}/security/advisories/${ghsaId}`;
    try {
      const html = await client.getText(sourceUrl);
      const parsed = parseRepositoryAdvisoryPage(html, ghsaId, sourceUrl);
      if (parsed.fixed_versions.length > 0) fragments.push(parsed);
      break;
    } catch {
      // The advisory may belong to a fork or an organization not inferable from the ledger.
    }
  }

  if (fragments.length === 0) {
    return {
      fix_commits: [],
      fix_references: [],
      fixed_versions: [],
      sources: [],
      warnings: [`No OSV or GitHub Advisory Database record found for ${ghsaId}`],
    };
  }
  return mergeFragments(fragments);
}
