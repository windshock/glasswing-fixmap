import type { HttpClient } from "../http.js";
import { uniqueEvidence, uniqueStrings } from "../merge.js";
import type { Evidence } from "../types.js";
import { fingerprintPatch } from "./fingerprint.js";
import type { ChangedFile, ChangedFileStatus, FixImpact } from "./types.js";

interface GitHubCommitFile {
  filename?: string;
  previous_filename?: string;
  status?: string;
  changes?: number;
  patch?: string;
}

interface GitHubCommitResponse {
  sha?: string;
  html_url?: string;
  files?: GitHubCommitFile[];
}

export interface GitHubImpactRequest {
  repository: string;
  commit: string;
  antIds: string[];
  evidence: Evidence[];
}

const FILES_PER_PAGE = 100;
const MAX_FILE_PAGES = 30;

function repositoryParts(repository: string): [string, string] {
  const parts = repository.split("/");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    throw new Error(`Unsupported GitHub repository identity: ${repository}`);
  }
  return [parts[0], parts[1]];
}

function changedFileStatus(status: string | undefined): ChangedFileStatus | undefined {
  if (status === "added" || status === "modified" || status === "renamed") return status;
  if (status === "removed") return "deleted";
  return undefined;
}

function fileKey(file: GitHubCommitFile): string {
  return [file.status ?? "", file.previous_filename ?? "", file.filename ?? ""].join("\0");
}

async function fetchCommitFiles(
  client: HttpClient,
  repository: string,
  commit: string,
): Promise<{ sha: string; htmlUrl: string; files: GitHubCommitFile[]; pageLimitReached: boolean }> {
  const [owner, repo] = repositoryParts(repository);
  const files = new Map<string, GitHubCommitFile>();
  let resolvedSha: string | undefined;
  let htmlUrl: string | undefined;
  let pageLimitReached = false;

  for (let page = 1; page <= MAX_FILE_PAGES; page += 1) {
    const url = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/commits/${encodeURIComponent(commit)}?per_page=${FILES_PER_PAGE}&page=${page}`;
    const response = await client.getJson<GitHubCommitResponse>(url);
    if (!response.sha || !/^[0-9a-f]{7,64}$/i.test(response.sha)) {
      throw new Error(`GitHub returned no valid commit SHA for ${repository}@${commit}`);
    }
    if (resolvedSha && resolvedSha.toLowerCase() !== response.sha.toLowerCase()) {
      throw new Error(`GitHub returned inconsistent commit pages for ${repository}@${commit}`);
    }
    resolvedSha = response.sha.toLowerCase();
    htmlUrl = response.html_url ?? `https://github.com/${repository}/commit/${resolvedSha}`;
    if (!Array.isArray(response.files)) {
      throw new Error(`GitHub returned no changed-file list for ${repository}@${commit}`);
    }
    for (const file of response.files) files.set(fileKey(file), file);
    if (response.files.length < FILES_PER_PAGE) break;
    if (page === MAX_FILE_PAGES) pageLimitReached = true;
  }

  if (!resolvedSha || !htmlUrl) {
    throw new Error(`GitHub returned an empty commit response for ${repository}@${commit}`);
  }
  return { sha: resolvedSha, htmlUrl, files: [...files.values()], pageLimitReached };
}

function projectChangedFile(
  input: GitHubCommitFile,
): { file?: ChangedFile; warnings: string[] } {
  const warnings: string[] = [];
  const status = changedFileStatus(input.status);
  if (!status) {
    return {
      warnings: [`Skipped a file with unsupported GitHub status ${JSON.stringify(input.status)}`],
    };
  }
  if (!input.filename) {
    return { warnings: [`Skipped a ${status} file without a filename`] };
  }

  let pathBefore: string | undefined;
  let pathAfter: string | undefined;
  if (status === "added") {
    pathAfter = input.filename;
  } else if (status === "deleted") {
    pathBefore = input.filename;
  } else if (status === "renamed") {
    pathBefore = input.previous_filename;
    pathAfter = input.filename;
    if (!pathBefore) {
      return { warnings: [`Skipped renamed file ${input.filename} without previous_filename`] };
    }
  } else {
    pathBefore = input.filename;
    pathAfter = input.filename;
  }

  const patchAvailable = typeof input.patch === "string" && input.patch.length > 0;
  const fingerprint = patchAvailable
    ? fingerprintPatch(input.patch!, pathBefore, pathAfter)
    : { hunks: [], functions: [] };
  const changes = input.changes ?? 0;
  if (!patchAvailable && changes > 0) {
    warnings.push(`Patch text was unavailable for ${input.filename} (${changes} changed lines)`);
  } else if (patchAvailable && fingerprint.hunks.length === 0) {
    warnings.push(`Patch text for ${input.filename} contained no parseable unified-diff hunks`);
  } else if (fingerprint.hunks.some((hunk) => hunk.signatures.length === 0)) {
    warnings.push(`A patch hunk for ${input.filename} contained no fingerprintable content`);
  }

  const file: ChangedFile = {
    status,
    patch_available: patchAvailable,
    hunks: fingerprint.hunks,
  };
  if (pathBefore) file.path_before = pathBefore;
  if (pathAfter) file.path_after = pathAfter;
  if (fingerprint.functions.length > 0) file.functions = fingerprint.functions;
  return { file, warnings };
}

export async function extractGitHubImpact(
  client: HttpClient,
  request: GitHubImpactRequest,
): Promise<FixImpact> {
  const response = await fetchCommitFiles(client, request.repository, request.commit);
  const warnings: string[] = [];
  if (response.pageLimitReached) {
    warnings.push(`GitHub's ${MAX_FILE_PAGES * FILES_PER_PAGE}-file commit limit was reached`);
  }
  const files: ChangedFile[] = [];
  for (const input of response.files) {
    const projected = projectChangedFile(input);
    warnings.push(...projected.warnings);
    if (projected.file) files.push(projected.file);
  }
  if (response.files.length === 0) warnings.push("GitHub returned no changed files for the commit");
  if (files.length === 0) warnings.push("No supported changed files could be projected");
  files.sort((a, b) =>
    (a.path_after ?? a.path_before ?? "").localeCompare(b.path_after ?? b.path_before ?? ""),
  );

  return {
    repository: request.repository,
    commit: response.sha,
    ant_ids: uniqueStrings(request.antIds),
    extraction_status: warnings.length > 0 ? "partial" : "complete",
    files,
    evidence: uniqueEvidence([
      ...request.evidence,
      {
        source: "github_repository",
        url: response.htmlUrl,
        locator: "commit files and patch hunks",
      },
    ]),
    warnings: uniqueStrings(warnings),
  };
}
