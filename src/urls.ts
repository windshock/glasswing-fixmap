import type { FixCommit, FixReference, Confidence, Evidence } from "./types.js";

const GITHUB_REPOSITORY = /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/;

export function normalizeUrl(input: string): string {
  try {
    const url = new URL(input.trim().replace(/[),.;]+$/, ""));
    url.hash = "";
    for (const key of [...url.searchParams.keys()]) {
      if (key.toLowerCase().startsWith("utm_")) url.searchParams.delete(key);
    }
    return url.toString().replace(/\/$/, "");
  } catch {
    return input.trim().replace(/[),.;]+$/, "");
  }
}

export function githubRepositoryFromUrl(input: string): string | undefined {
  try {
    const url = new URL(input);
    if (url.hostname.toLowerCase() !== "github.com") return undefined;
    const parts = url.pathname.split("/").filter(Boolean);
    if (parts.length < 2) return undefined;
    const repository = `${parts[0]}/${parts[1]?.replace(/\.git$/, "")}`;
    return GITHUB_REPOSITORY.test(repository) ? repository : undefined;
  } catch {
    return undefined;
  }
}

export function parseCommitUrl(
  input: string,
  confidence: Confidence,
  evidence: Evidence,
): FixCommit | undefined {
  const url = normalizeUrl(input);
  const patterns = [
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/commit\/([0-9a-f]{7,64})(?:\/|$)/i,
    /^https?:\/\/gitlab\.com\/([^/]+)\/([^/]+)\/-\/commit\/([0-9a-f]{7,64})(?:\/|$)/i,
    /^https?:\/\/[^/]+\/.*\/commit\/?(?:\?[^#]*&)?id=([0-9a-f]{7,64})(?:&|$)/i,
    /^https?:\/\/[^/]+\/.*\/commit\/([0-9a-f]{7,64})(?:\/|$)/i,
  ];

  const github = url.match(patterns[0]!);
  if (github) {
    return {
      sha: github[3]!.toLowerCase(),
      url,
      repository: `${github[1]}/${github[2]}`,
      confidence,
      evidence: [evidence],
    };
  }

  const gitlab = url.match(patterns[1]!);
  if (gitlab) {
    return {
      sha: gitlab[3]!.toLowerCase(),
      url,
      repository: `${gitlab[1]}/${gitlab[2]}`,
      confidence,
      evidence: [evidence],
    };
  }

  for (const pattern of patterns.slice(2)) {
    const match = url.match(pattern);
    if (match) {
      return {
        sha: match[1]!.toLowerCase(),
        url,
        confidence,
        evidence: [evidence],
      };
    }
  }
  return undefined;
}

export function parseFixReferenceUrl(
  input: string,
  confidence: Confidence,
  evidence: Evidence,
): FixReference | undefined {
  const url = normalizeUrl(input);
  const githubPull = url.match(
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+)\/(?:pull|pulls)\/(\d+)(?:\/|$)/i,
  );
  if (githubPull) {
    return {
      kind: "pull_request",
      url,
      repository: `${githubPull[1]}/${githubPull[2]}`,
      number: Number(githubPull[3]),
      confidence,
      evidence: [evidence],
    };
  }

  const gitlabMerge = url.match(
    /^https?:\/\/gitlab\.com\/([^/]+)\/([^/]+)\/-\/merge_requests\/(\d+)(?:\/|$)/i,
  );
  if (gitlabMerge) {
    return {
      kind: "pull_request",
      url,
      repository: `${gitlabMerge[1]}/${gitlabMerge[2]}`,
      number: Number(gitlabMerge[3]),
      confidence,
      evidence: [evidence],
    };
  }

  if (/\.(?:patch|diff)(?:\?|$)/i.test(url)) {
    return { kind: "patch", url, confidence, evidence: [evidence] };
  }
  return undefined;
}

export function cveRecordRawUrl(cveId: string): string {
  const match = cveId.toUpperCase().match(/^CVE-(\d{4})-(\d{4,})$/);
  if (!match) throw new Error(`Invalid CVE identifier: ${cveId}`);
  const year = match[1]!;
  const sequence = match[2]!;
  const bucket = `${sequence.slice(0, -3)}xxx`;
  return `https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/${year}/${bucket}/${cveId.toUpperCase()}.json`;
}

export function githubAdvisoryRawUrl(sourceUrl: string): string | undefined {
  const match = sourceUrl.match(
    /^https:\/\/github\.com\/github\/advisory-database\/blob\/main\/(.+)$/,
  );
  if (!match) return undefined;
  return `https://raw.githubusercontent.com/github/advisory-database/main/${match[1]}`;
}

export function isVersionToken(input: string): boolean {
  return /^v?\d+(?:\.\d+){1,3}(?:[-+][0-9A-Za-z.-]+)?$/.test(input.trim());
}

export function normalizeVersion(input: string): string {
  return input.trim().replace(/^version\s+/i, "").replace(/[),.;:]+$/, "");
}
