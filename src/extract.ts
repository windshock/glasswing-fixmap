import type { Evidence, FixCommit, FixedVersion } from "./types.js";
import { isVersionToken, normalizeVersion } from "./urls.js";

// Narrative text contains protocol versions (TLS 1.2, HTTP 1.1) far more often
// than two-component release claims. Keep free-text extraction conservative;
// authoritative advisory fields still accept two-component release versions.
const VERSION_TOKEN = /\bv?\d+(?:\.\d+){2,3}(?:[-+][0-9A-Za-z.-]+)?\b/g;
const RELEASE_CLAIM_BEFORE_VERSION =
  /\b(?:fixed|patched|resolved|shipped|included|released|available)\b[\s\S]{0,100}\b(?:in|with|as|version|release|starting)\b[\s\S]{0,80}$/i;
const RELEASE_CLAIM_AFTER_VERSION =
  /^[\s\S]{0,40}\b(?:is|was|becomes?|became)?\s*(?:the\s+)?(?:first\s+)?(?:fixed|patched|safe)\b/i;
const NEGATIVE_VERSION_CONTEXT =
  /\b(?:affected|vulnerable|unfixed|not\s+(?:fixed|patched|included|contain)|does\s+not\s+contain|before|prior\s+to)\b/i;

function isIpv4OrDottedSection(value: string): boolean {
  const parts = value.replace(/^v/, "").split(".");
  return parts.length === 4 && parts.every((part) => /^\d+$/.test(part) && Number(part) <= 255);
}

function sentences(text: string): string[] {
  return text
    .split(/\s*[\r\n]+\s*/)
    .flatMap((block) => block.replace(/\s+/g, " ").split(/(?<=[.!?])\s+(?=[A-Z(])/))
    .flatMap((sentence) => sentence.split(/\s*;\s*/))
    .map((value) => value.replace(/\s+/g, " ").trim())
    .filter(Boolean);
}

export function extractReportedVersions(text: string, sourceUrl: string): FixedVersion[] {
  const found: FixedVersion[] = [];
  for (const sentence of sentences(text)) {
    const antYear = sourceUrl.match(/ANT-(\d{4})-/)?.[1];
    const mentionedCveYears = [...sentence.matchAll(/\bCVE-(\d{4})-\d+\b/gi)].map(
      (match) => match[1],
    );
    if (antYear && mentionedCveYears.length > 0 && !mentionedCveYears.includes(antYear)) continue;
    for (const match of sentence.matchAll(VERSION_TOKEN)) {
      const raw = match[0];
      const index = match.index;
      const before = sentence.slice(Math.max(0, index - 180), index);
      const after = sentence.slice(index + raw.length, index + raw.length + 80);
      if (
        !RELEASE_CLAIM_BEFORE_VERSION.test(before) &&
        !RELEASE_CLAIM_AFTER_VERSION.test(after)
      ) {
        continue;
      }
      if (NEGATIVE_VERSION_CONTEXT.test(`${before.slice(-60)} ${after.slice(0, 60)}`)) continue;
      const version = normalizeVersion(raw);
      if (!isVersionToken(version)) continue;
      // IP literals and RFC section numbers such as 169.254.169.254 and
      // 6.2.3.2 often occur next to words like "fix" in vulnerability prose.
      if (isIpv4OrDottedSection(version)) continue;
      const numeric = version.replace(/^v/, "");
      if (/^(?:19|20)\d{2}\.\d{1,2}(?:\.\d{1,2})?$/.test(numeric)) continue;
      const firstPatched = /\bfirst\s+(?:fixed|patched|safe|shipped|released)\b/i.test(
        `${before} ${after}`,
      );
      found.push({
        version,
        role: firstPatched ? "first_patched" : "patched",
        first_patched: firstPatched ? true : null,
        confidence: "medium",
        evidence: [
          {
            source: "anthropic_finding",
            url: sourceUrl,
            locator: "REPORT release statement",
            note: "Release version reported in the public finding body",
          },
        ],
        commit_verification: { status: "not_run" },
      });
    }
  }
  return found;
}

export function extractBareCommitClaims(
  text: string,
  sourceUrl: string,
  repository?: string,
): FixCommit[] {
  const found: FixCommit[] = [];
  const pattern = /\b(?:commit|revision|changeset)\s+[`'"(]*([0-9a-f]{7,40})\b/gi;
  for (const match of text.matchAll(pattern)) {
    const sha = match[1]!.toLowerCase();
    const evidence: Evidence = {
      source: "anthropic_finding",
      url: sourceUrl,
      locator: "REPORT fix statement",
      note: "Commit identifier reported in the public finding body",
    };
    const item: FixCommit = {
      sha,
      url: repository ? `https://github.com/${repository}/commit/${sha}` : sourceUrl,
      confidence: "medium",
      evidence: [evidence],
    };
    if (repository) item.repository = repository;
    found.push(item);
  }
  return found;
}
