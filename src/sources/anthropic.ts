import * as cheerio from "cheerio";
import type { AnyNode } from "domhandler";
import { extractBareCommitClaims, extractReportedVersions } from "../extract.js";
import { mergeCommits, mergeReferences, mergeVersions, uniqueStrings } from "../merge.js";
import type {
  AnthropicPayload,
  Evidence,
  ParsedFindingPage,
} from "../types.js";
import {
  githubRepositoryFromUrl,
  normalizeUrl,
  parseCommitUrl,
  parseFixReferenceUrl,
} from "../urls.js";
import type { HttpClient } from "../http.js";

export const ANTHROPIC_PAYLOAD_URL =
  "https://red.anthropic.com/2026/cvd/data/payload.json";

export function anthropicFindingUrl(antId: string): string {
  return `https://red.anthropic.com/2026/cvd/findings/${antId}`;
}

export async function fetchAnthropicPayload(client: HttpClient): Promise<AnthropicPayload> {
  const payload = await client.getJson<AnthropicPayload>(ANTHROPIC_PAYLOAD_URL);
  if (!payload || !Array.isArray(payload.ledger) || typeof payload.as_of !== "string") {
    throw new Error("Anthropic payload does not match the expected ledger shape");
  }
  return payload;
}

export function titleMapFromPayload(payload: AnthropicPayload): Map<string, string> {
  const result = new Map<string, string>();
  for (const group of [payload.cve_records ?? [], payload.ghsa_records ?? []]) {
    for (const record of group) {
      for (const finding of record.findings ?? []) {
        if (finding.ant_id && finding.title && !result.has(finding.ant_id)) {
          result.set(finding.ant_id, finding.title);
        }
      }
    }
  }
  return result;
}

function siblingsUntilMarker($: cheerio.CheerioAPI, marker: AnyNode): cheerio.Cheerio<AnyNode> {
  let current = $(marker).next();
  let result = $([]) as cheerio.Cheerio<AnyNode>;
  while (current.length && !current.hasClass("marker")) {
    result = result.add(current);
    current = current.next();
  }
  return result;
}

export function parseAnthropicFindingPage(
  html: string,
  antId: string,
  project?: string,
): ParsedFindingPage {
  const sourceUrl = anthropicFindingUrl(antId);
  const $ = cheerio.load(html);
  const report = $(".report-body");
  const reportText = report.text().replace(/\s+/g, " ").trim();
  const reportBlocks = report
    .find("p, li, td")
    .map((_, element) => $(element).text().replace(/\s+/g, " ").trim())
    .get()
    .filter(Boolean)
    .join("\n");
  const title = report.find("h1").first().text().trim() || null;

  const upstreamMarker = $(".marker")
    .filter((_, element) => $(element).text().trim().toUpperCase() === "UPSTREAM FIX")
    .first();
  const upstream = upstreamMarker.length
    ? siblingsUntilMarker($, upstreamMarker.get(0)!)
    : ($([]) as cheerio.Cheerio<AnyNode>);

  const links = uniqueStrings(
    $("a[href]")
      .map((_, element) => normalizeUrl($(element).attr("href") ?? ""))
      .get()
      .filter((url) => /^https?:\/\//.test(url)),
  );
  const upstreamLinks = upstream
    .find("a[href]")
    .map((_, element) => normalizeUrl($(element).attr("href") ?? ""))
    .get()
    .filter((url) => /^https?:\/\//.test(url));

  const pageRepository =
    upstreamLinks.map(githubRepositoryFromUrl).find(Boolean) ??
    links.map(githubRepositoryFromUrl).find(Boolean) ??
    (project?.includes("/") ? project : undefined);

  const commits = [];
  const references = [];
  for (const url of uniqueStrings([...upstreamLinks, ...links])) {
    const inUpstreamSection = upstreamLinks.includes(url);
    const evidence: Evidence = {
      source: "anthropic_finding",
      url: sourceUrl,
      locator: inUpstreamSection ? "UPSTREAM FIX" : "linked reference",
    };
    const commit = parseCommitUrl(url, inUpstreamSection ? "high" : "medium", evidence);
    if (commit) commits.push(commit);
    const reference = parseFixReferenceUrl(
      url,
      inUpstreamSection ? "high" : "medium",
      evidence,
    );
    if (reference) references.push(reference);
  }

  commits.push(...extractBareCommitClaims(reportText, sourceUrl, pageRepository));

  return {
    title,
    fix_commits: mergeCommits(commits),
    fix_references: mergeReferences(references),
    fixed_versions: mergeVersions(extractReportedVersions(reportBlocks, sourceUrl)),
    links,
  };
}

export async function fetchAnthropicFindingPage(
  client: HttpClient,
  antId: string,
  project?: string,
): Promise<ParsedFindingPage> {
  return parseAnthropicFindingPage(await client.getText(anthropicFindingUrl(antId)), antId, project);
}
