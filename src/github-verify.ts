import type { HttpClient } from "./http.js";
import type { FindingRecord, FixedVersion } from "./types.js";

interface GitReference {
  object?: { type?: string; sha?: string; url?: string };
}

interface GitTag {
  object?: { type?: string; sha?: string; url?: string };
}

interface CompareResult {
  status?: string;
  html_url?: string;
}

function tagCandidates(version: string): string[] {
  if (version.startsWith("v")) return [version, version.slice(1)];
  return [`v${version}`, version];
}

async function resolveTag(
  client: HttpClient,
  repository: string,
  candidates: string[],
): Promise<{ tag: string; sha: string } | undefined> {
  for (const tag of candidates) {
    const url = `https://api.github.com/repos/${repository}/git/ref/tags/${encodeURIComponent(tag)}`;
    const reference = await client.getOptionalJson<GitReference>(url);
    if (!reference?.object?.sha) continue;
    let object = reference.object;
    for (let depth = 0; object.type === "tag" && depth < 3; depth += 1) {
      const tagObject = await client.getOptionalJson<GitTag>(
        `https://api.github.com/repos/${repository}/git/tags/${object.sha}`,
      );
      if (!tagObject?.object?.sha) break;
      object = tagObject.object;
    }
    if (object.sha) return { tag, sha: object.sha };
  }
  return undefined;
}

async function verifyVersion(
  client: HttpClient,
  finding: FindingRecord,
  version: FixedVersion,
): Promise<void> {
  const repositories = [
    ...new Set(
      finding.fix_commits
        .map((commit) => commit.repository)
        .filter((repository): repository is string => Boolean(repository)),
    ),
  ];
  if (repositories.length === 0 && finding.project.includes("/")) {
    repositories.push(finding.project);
  }
  if (repositories.length === 0) {
    version.commit_verification = { status: "repository_unknown" };
    return;
  }

  let foundTag = false;
  for (const repository of repositories) {
    const tag = await resolveTag(client, repository, tagCandidates(version.version));
    if (!tag) continue;
    foundTag = true;
    const matchingCommits = finding.fix_commits.filter(
      (commit) => !commit.repository || commit.repository.toLowerCase() === repository.toLowerCase(),
    );
    for (const commit of matchingCommits) {
      const compareUrl = `https://api.github.com/repos/${repository}/compare/${encodeURIComponent(commit.sha)}...${encodeURIComponent(tag.sha)}`;
      const comparison = await client.getOptionalJson<CompareResult>(compareUrl);
      if (comparison?.status === "ahead" || comparison?.status === "identical") {
        version.commit_verification = {
          status: "verified_contains_fix",
          repository,
          tag: tag.tag,
          fix_sha: commit.sha,
          url: comparison.html_url ?? compareUrl,
        };
        version.confidence = "verified";
        version.evidence.push({
          source: "github_repository",
          url: comparison.html_url ?? compareUrl,
          locator: `${commit.sha} is an ancestor of ${tag.tag}`,
        });
        return;
      }
    }
    version.commit_verification = {
      status: "fix_not_in_tag",
      repository,
      tag: tag.tag,
      detail: "No known fix commit was an ancestor of this tag",
    };
  }
  if (!foundTag) {
    version.commit_verification = {
      status: "tag_not_found",
      detail: `Tried ${tagCandidates(version.version).join(", ")}`,
    };
  }
}

export async function verifyFindingTags(
  client: HttpClient,
  finding: FindingRecord,
): Promise<void> {
  for (const version of finding.fixed_versions) {
    if (version.role === "nightly") continue;
    try {
      await verifyVersion(client, finding, version);
    } catch (error) {
      version.commit_verification = { status: "error", detail: String(error) };
      finding.enrichment.warnings.push(
        `GitHub tag verification failed for ${version.version}: ${String(error)}`,
      );
    }
  }
}
