import { execFile } from "node:child_process";
import type { FixImpact } from "../impact/types.js";
import { observation, sortObservations } from "./observations.js";
import type {
  SourceVerifier,
  VerificationContext,
  VerificationObservation,
  VerifierResult,
} from "./types.js";

interface CommandResult {
  code: number | null;
  stdout: string;
  stderr: string;
  failedToStart: boolean;
}

function runCommand(command: string, args: string[], cwd?: string): Promise<CommandResult> {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      {
        ...(cwd ? { cwd } : {}),
        encoding: "utf8",
        timeout: 10_000,
        maxBuffer: 1024 * 1024,
      },
      (error, stdout, stderr) => {
        const rawCode = error && "code" in error ? error.code : 0;
        resolve({
          code: typeof rawCode === "number" ? rawCode : error ? null : 0,
          stdout,
          stderr,
          failedToStart: Boolean(error && typeof rawCode === "string"),
        });
      },
    );
  });
}

export function githubRepositoryFromRemote(remote: string): string | undefined {
  const trimmed = remote.trim();
  const patterns = [
    /^https?:\/\/github\.com\/([^/]+)\/([^/]+)$/i,
    /^git@github\.com:([^/]+)\/([^/]+)$/i,
    /^ssh:\/\/(?:git@)?github\.com\/([^/]+)\/([^/]+)$/i,
  ];
  for (const pattern of patterns) {
    const match = trimmed.match(pattern);
    if (match?.[1] && match[2]) return `${match[1]}/${match[2].replace(/\.git$/i, "")}`;
  }
  return undefined;
}

function impactEvidence(
  backend: string,
  impact: FixImpact,
  type: "FIX_COMMIT_ANCESTOR" | "FIX_COMMIT_NOT_ANCESTOR" | "BACKEND_UNSUPPORTED" | "BACKEND_ERROR",
  strength: "strong" | "informational",
  detail: string,
): VerificationObservation {
  return observation({
    backend,
    type,
    strength,
    repository: impact.repository,
    commit: impact.commit,
    detail,
    evidence: [
      {
        kind: "git",
        locator: `git merge-base --is-ancestor ${impact.commit} HEAD`,
      },
    ],
  });
}

export class GitAncestryVerifier implements SourceVerifier {
  readonly name = "git-ancestry";

  async verify(context: VerificationContext): Promise<VerifierResult> {
    const observations: VerificationObservation[] = [];
    const warnings: string[] = [];
    const versionResult = await runCommand("git", ["--version"]);
    const version = versionResult.code === 0 ? versionResult.stdout.trim() : "unavailable";
    if (versionResult.failedToStart) {
      observations.push(
        observation({
          backend: this.name,
          type: "BACKEND_UNSUPPORTED",
          strength: "informational",
          detail: "git executable is unavailable",
        }),
      );
      return {
        backend: { name: this.name, version },
        execution_status: "unsupported",
        observations,
        warnings: [],
      };
    }

    const inside = await runCommand("git", ["rev-parse", "--is-inside-work-tree"], context.sourceRoot);
    if (inside.code !== 0 || inside.stdout.trim() !== "true") {
      observations.push(
        observation({
          backend: this.name,
          type: "BACKEND_UNSUPPORTED",
          strength: "informational",
          detail: "source is not a Git work tree",
          evidence: [{ kind: "git", locator: "git rev-parse --is-inside-work-tree" }],
        }),
      );
      return {
        backend: { name: this.name, version },
        execution_status: "unsupported",
        observations,
        warnings: [],
      };
    }

    const remoteResult = await runCommand("git", ["remote", "get-url", "origin"], context.sourceRoot);
    const sourceRepository = remoteResult.code === 0
      ? githubRepositoryFromRemote(remoteResult.stdout)
      : undefined;
    if (!sourceRepository) {
      observations.push(
        observation({
          backend: this.name,
          type: "BACKEND_UNSUPPORTED",
          strength: "informational",
          detail: "Git origin is missing or is not a recognized GitHub repository",
          evidence: [{ kind: "git", locator: "git remote get-url origin" }],
        }),
      );
      return {
        backend: { name: this.name, version },
        execution_status: "unsupported",
        observations,
        warnings: [],
      };
    }

    const matchingImpacts = context.impacts.filter(
      (impact) => impact.repository.toLowerCase() === sourceRepository.toLowerCase(),
    );
    observations.push(
      observation({
        backend: this.name,
        type: matchingImpacts.length > 0 ? "SOURCE_REPOSITORY_MATCH" : "SOURCE_REPOSITORY_MISMATCH",
        strength: matchingImpacts.length > 0 ? "strong" : "informational",
        repository: sourceRepository,
        detail: matchingImpacts.length > 0
          ? `Git origin matches ${sourceRepository}`
          : `Git origin ${sourceRepository} does not match any fix-impact repository`,
        evidence: [
          { kind: "git", locator: "git remote get-url origin", value: remoteResult.stdout.trim() },
        ],
      }),
    );
    if (matchingImpacts.length === 0) {
      return {
        backend: { name: this.name, version },
        execution_status: "unsupported",
        observations: sortObservations(observations),
        warnings: [],
      };
    }

    const [sparse, shallow] = await Promise.all([
      runCommand("git", ["config", "--bool", "core.sparseCheckout"], context.sourceRoot),
      runCommand("git", ["rev-parse", "--is-shallow-repository"], context.sourceRoot),
    ]);
    if (sparse.stdout.trim() === "true") {
      observations.push(
        observation({
          backend: this.name,
          type: "SOURCE_TREE_PARTIAL",
          strength: "informational",
          repository: sourceRepository,
          detail: "Git sparse checkout is enabled",
          evidence: [{ kind: "configuration", locator: "core.sparseCheckout", value: "true" }],
        }),
      );
    }
    if (shallow.stdout.trim() === "true") {
      observations.push(
        observation({
          backend: this.name,
          type: "SOURCE_TREE_PARTIAL",
          strength: "informational",
          repository: sourceRepository,
          detail: "Git history is shallow",
          evidence: [{ kind: "git", locator: "git rev-parse --is-shallow-repository", value: "true" }],
        }),
      );
    }

    let completedChecks = 0;
    let backendErrors = 0;
    for (const impact of matchingImpacts) {
      const object = await runCommand(
        "git",
        ["cat-file", "-e", `${impact.commit}^{commit}`],
        context.sourceRoot,
      );
      if (object.code !== 0) {
        observations.push(
          impactEvidence(
            this.name,
            impact,
            "BACKEND_UNSUPPORTED",
            "informational",
            "fix commit is unavailable in local Git history",
          ),
        );
        continue;
      }
      const ancestor = await runCommand(
        "git",
        ["merge-base", "--is-ancestor", impact.commit, "HEAD"],
        context.sourceRoot,
      );
      if (ancestor.code === 0) {
        completedChecks += 1;
        observations.push(
          impactEvidence(
            this.name,
            impact,
            "FIX_COMMIT_ANCESTOR",
            "strong",
            "fix commit is an ancestor of HEAD",
          ),
        );
      } else if (ancestor.code === 1) {
        completedChecks += 1;
        observations.push(
          impactEvidence(
            this.name,
            impact,
            "FIX_COMMIT_NOT_ANCESTOR",
            "informational",
            "fix commit is not an ancestor of HEAD",
          ),
        );
      } else {
        backendErrors += 1;
        const detail = ancestor.stderr.trim() || "git merge-base failed";
        warnings.push(`${impact.repository}@${impact.commit}: ${detail}`);
        observations.push(
          impactEvidence(this.name, impact, "BACKEND_ERROR", "informational", detail),
        );
      }
    }

    const executionStatus = completedChecks > 0
      ? "completed"
      : backendErrors > 0
        ? "error"
        : "unsupported";
    return {
      backend: { name: this.name, version },
      execution_status: executionStatus,
      observations: sortObservations(observations),
      warnings: [...new Set(warnings)].sort(),
    };
  }
}
