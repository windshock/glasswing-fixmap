import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import { fingerprintPatch } from "../src/impact/fingerprint.js";
import type { FixImpactDataset } from "../src/impact/types.js";
import { githubRepositoryFromRemote } from "../src/verification/git-ancestry.js";
import type { SourceVerificationReport } from "../src/verification/types.js";
import { verifySource } from "../src/verification/verify.js";

const execFileAsync = promisify(execFile);
const ANT_ID = "ANT-2026-EXAMPLE";
const VULNERABLE_SOURCE = `int parse_packet(const char *packet) {
  if (packet == 0) {
    return -1;
  }
  return decode(packet);
}
`;
const FIXED_SOURCE = `int parse_packet(const char *packet) {
  if (packet == 0) {
    return -1;
  }
  return decode_checked(packet);
}
`;

async function git(repository: string, ...args: string[]): Promise<string> {
  const result = await execFileAsync("git", args, { cwd: repository, encoding: "utf8" });
  return result.stdout.trim();
}

async function writeSource(repository: string, source: string | Uint8Array): Promise<void> {
  await mkdir(path.join(repository, "src"), { recursive: true });
  await writeFile(path.join(repository, "src/parser.c"), source);
}

async function commitAll(repository: string, message: string): Promise<string> {
  await git(repository, "add", "-A");
  await git(repository, "commit", "-m", message);
  return git(repository, "rev-parse", "HEAD");
}

function impactDataset(commit: string, patch: string): FixImpactDataset {
  const fingerprint = fingerprintPatch(patch, "src/parser.c", "src/parser.c");
  return {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-02T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: 1,
      impact_count: 1,
      complete_count: 1,
      partial_count: 0,
      error_count: 0,
    },
    impacts: [
      {
        repository: "example/project",
        commit,
        ant_ids: [ANT_ID],
        extraction_status: "complete",
        files: [
          {
            path_before: "src/parser.c",
            path_after: "src/parser.c",
            status: "modified",
            patch_available: true,
            ...(fingerprint.functions.length > 0 ? { functions: fingerprint.functions } : {}),
            hunks: fingerprint.hunks,
          },
        ],
        evidence: [
          {
            source: "github_repository",
            url: `https://github.com/example/project/commit/${commit}`,
          },
        ],
        warnings: [],
      },
    ],
  };
}

async function check(
  repository: string,
  dataset: FixImpactDataset,
  decision: SourceVerificationReport["decision"],
): Promise<SourceVerificationReport> {
  const report = await verifySource({ antId: ANT_ID, sourceRoot: repository, impactDataset: dataset });
  assert.equal(report.decision, decision, JSON.stringify(report, null, 2));
  assert.notEqual(report.decision, "AFFECTED");
  return report;
}

test("normalizes common GitHub remote URL forms", () => {
  assert.equal(githubRepositoryFromRemote("https://github.com/example/project.git"), "example/project");
  assert.equal(githubRepositoryFromRemote("git@github.com:example/project.git"), "example/project");
  assert.equal(githubRepositoryFromRemote("ssh://git@github.com/example/project"), "example/project");
  assert.equal(githubRepositoryFromRemote("https://gitlab.com/example/project.git"), undefined);
});

test("differentially verifies fixed, vulnerable, backported, reverted, and ambiguous sources", async (context) => {
  const repository = await mkdtemp(path.join(os.tmpdir(), "glasswing-source-test-"));
  context.after(async () => rm(repository, { recursive: true, force: true }));
  await git(repository, "init", "-b", "main");
  await git(repository, "config", "user.name", "glasswing test");
  await git(repository, "config", "user.email", "glasswing@example.invalid");
  await git(repository, "remote", "add", "origin", "https://github.com/example/project.git");

  await writeSource(repository, VULNERABLE_SOURCE);
  const vulnerableCommit = await commitAll(repository, "vulnerable fixture");
  await writeSource(repository, FIXED_SOURCE);
  const fixCommit = await commitAll(repository, "fix parser");
  const patch = await git(repository, "diff", vulnerableCommit, fixCommit, "--", "src/parser.c");
  const dataset = impactDataset(fixCommit, patch);

  const fixed = await check(repository, dataset, "VERIFIED_FIXED");
  assert.equal(fixed.confidence, "high");
  assert.ok(fixed.reasons.some((item) => item.code === "ANCESTRY_CORROBORATED"));

  await git(repository, "checkout", "--detach", vulnerableCommit);
  const vulnerable = await check(repository, dataset, "PATCH_NOT_FOUND");
  assert.ok(vulnerable.reasons.some((item) => item.code === "PREIMAGE_PRESENT"));

  await git(repository, "checkout", "-B", "backport", vulnerableCommit);
  await writeSource(repository, FIXED_SOURCE);
  const backportCommit = await commitAll(repository, "backport parser fix");
  const backport = await check(repository, dataset, "VERIFIED_FIXED");
  assert.ok(backport.backend_results.flatMap((item) => item.observations).some(
    (item) => item.type === "FIX_COMMIT_NOT_ANCESTOR",
  ));

  await git(repository, "checkout", "-B", "reverted", fixCommit);
  await writeSource(repository, VULNERABLE_SOURCE);
  await commitAll(repository, "revert parser fix");
  const reverted = await check(repository, dataset, "UNKNOWN");
  assert.ok(reverted.reasons.some((item) => item.code === "VERIFIER_CONFLICT"));

  await git(repository, "checkout", "--detach", fixCommit);
  await writeSource(repository, new Uint8Array([0, 1, 2, 3]));
  const ancestryOnly = await check(repository, dataset, "UNKNOWN");
  assert.ok(ancestryOnly.reasons.some((item) => item.code === "INSUFFICIENT_EVIDENCE"));
  await git(repository, "checkout", "--", "src/parser.c");

  await git(repository, "checkout", "-B", "whitespace-backport", vulnerableCommit);
  await writeSource(
    repository,
    FIXED_SOURCE.replace(/^  /gm, "\t").replace("return decode_checked", "return     decode_checked"),
  );
  await commitAll(repository, "whitespace backport");
  await check(repository, dataset, "VERIFIED_FIXED");

  await git(repository, "checkout", "-B", "nearby-change", vulnerableCommit);
  await writeSource(
    repository,
    FIXED_SOURCE.replace("packet == 0", "packet == NULL").replace("return -1", "return ERROR_INVALID"),
  );
  await commitAll(repository, "backport with nearby changes");
  await check(repository, dataset, "UNKNOWN");

  await git(repository, "checkout", "-B", "moved", backportCommit);
  await mkdir(path.join(repository, "lib"), { recursive: true });
  await git(repository, "mv", "src/parser.c", "lib/parser.c");
  await commitAll(repository, "move parser");
  const moved = await check(repository, dataset, "UNKNOWN");
  assert.ok(moved.backend_results.flatMap((item) => item.observations).some(
    (item) => item.type === "TARGET_PATH_MOVED",
  ));

  await git(repository, "checkout", "-B", "target-absent", vulnerableCommit);
  await git(repository, "rm", "src/parser.c");
  await commitAll(repository, "source tree omits parser");
  await check(repository, dataset, "TARGET_ABSENT");

  await git(repository, "checkout", "-B", "partial", vulnerableCommit);
  await git(repository, "rm", "src/parser.c");
  await commitAll(repository, "partial source omits parser");
  await git(repository, "config", "core.sparseCheckout", "true");
  const partial = await check(repository, dataset, "UNKNOWN");
  assert.ok(partial.backend_results.flatMap((item) => item.observations).some(
    (item) => item.type === "SOURCE_TREE_PARTIAL",
  ));
  await git(repository, "config", "core.sparseCheckout", "false");

  await git(repository, "checkout", "-B", "unsupported-source", vulnerableCommit);
  await writeSource(repository, new Uint8Array([0, 255, 1, 254]));
  await commitAll(repository, "binary source fixture");
  await check(repository, dataset, "UNKNOWN");

  await git(repository, "checkout", "-B", "mismatched-source", backportCommit);
  await git(repository, "remote", "set-url", "origin", "https://github.com/other/project.git");
  const mismatch = await check(repository, dataset, "UNKNOWN");
  assert.ok(mismatch.reasons.some((item) => item.code === "VERIFIER_CONFLICT"));

  const schemaText = await readFile(
    new URL("../schema/source-verification.schema.json", import.meta.url),
    "utf8",
  );
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    JSON.parse(schemaText) as object,
  );
  assert.equal(validate(fixed), true, JSON.stringify(validate.errors, null, 2));

  const failed = await verifySource({
    antId: ANT_ID,
    sourceRoot: repository,
    impactDataset: dataset,
    verifiers: [
      {
        name: "failing-fixture",
        async verify() {
          throw new Error("fixture verifier failed");
        },
      },
    ],
  });
  assert.equal(failed.decision, "ERROR");
  assert.ok(failed.reasons.some((item) => item.code === "BACKEND_FAILURE"));
  assert.equal(validate(failed), true, JSON.stringify(validate.errors, null, 2));

  const thirdPartyOnly = await verifySource({
    antId: ANT_ID,
    sourceRoot: repository,
    impactDataset: dataset,
    verifiers: [
      {
        name: "third-party-fixture",
        async verify() {
          return {
            backend: { name: "third-party-fixture", version: "1.0.0" },
            execution_status: "completed" as const,
            observations: [
              {
                id: `third-party-fixture:FIX_POSTIMAGE_PRESENT:example/project@${fixCommit}`,
                type: "FIX_POSTIMAGE_PRESENT" as const,
                strength: "strong" as const,
                repository: "example/project",
                commit: fixCommit,
                detail: "fixture third-party backend reports a match",
                evidence: [{ kind: "signature" as const, locator: "fixture" }],
              },
            ],
            warnings: [],
          };
        },
      },
    ],
  });
  assert.equal(thirdPartyOnly.decision, "UNKNOWN");
});

test("a pure-deletion fix is not VERIFIED_FIXED while the removed line remains", async (context) => {
  const repository = await mkdtemp(path.join(os.tmpdir(), "glasswing-deletion-test-"));
  context.after(async () => rm(repository, { recursive: true, force: true }));
  await git(repository, "init", "-b", "main");
  await git(repository, "config", "user.name", "glasswing test");
  await git(repository, "config", "user.email", "glasswing@example.invalid");
  await git(repository, "remote", "add", "origin", "https://github.com/example/project.git");

  // The fix is a pure deletion of one dangerous line; the post-fix image is
  // entirely unchanged context that already exists in the vulnerable source.
  const vulnerable = `int process(const char *input) {
  validate_length_of_incoming_request(input);
  dangerous_unchecked_call_with_user_input(input, 0);
  return finalize_processing(input);
}
`;
  const fixed = `int process(const char *input) {
  validate_length_of_incoming_request(input);
  return finalize_processing(input);
}
`;
  await writeSource(repository, vulnerable);
  const vulnerableCommit = await commitAll(repository, "vulnerable fixture");
  await writeSource(repository, fixed);
  const fixCommit = await commitAll(repository, "fix: remove dangerous call");
  const patch = await git(repository, "diff", vulnerableCommit, fixCommit, "--", "src/parser.c");
  const dataset = impactDataset(fixCommit, patch);

  // The removed line is still present in the vulnerable tree: the post-fix
  // context match alone must not read as fixed.
  await git(repository, "checkout", "--detach", vulnerableCommit);
  const stillVulnerable = await check(repository, dataset, "PATCH_NOT_FOUND");
  assert.ok(
    stillVulnerable.backend_results
      .flatMap((item) => item.observations)
      .some((item) => item.type === "VULNERABLE_PATTERN_PRESENT"),
    JSON.stringify(stillVulnerable, null, 2),
  );

  // The removed line is gone and the context remains in the fixed tree.
  await git(repository, "checkout", "--detach", fixCommit);
  await check(repository, dataset, "VERIFIED_FIXED");
});

test("a partial fix impact never yields VERIFIED_FIXED even when every hunk matches", async (context) => {
  const repository = await mkdtemp(path.join(os.tmpdir(), "glasswing-partial-test-"));
  context.after(async () => rm(repository, { recursive: true, force: true }));
  await git(repository, "init", "-b", "main");
  await git(repository, "config", "user.name", "glasswing test");
  await git(repository, "config", "user.email", "glasswing@example.invalid");
  await git(repository, "remote", "add", "origin", "https://github.com/example/project.git");

  await writeSource(repository, VULNERABLE_SOURCE);
  const vulnerableCommit = await commitAll(repository, "vulnerable fixture");
  await writeSource(repository, FIXED_SOURCE);
  const fixCommit = await commitAll(repository, "fix parser");
  const patch = await git(repository, "diff", vulnerableCommit, fixCommit, "--", "src/parser.c");
  const dataset = impactDataset(fixCommit, patch);
  // The extraction was incomplete: the full fix is not proven even if every
  // extracted hunk matches.
  dataset.impacts[0]!.extraction_status = "partial";
  dataset.impacts[0]!.warnings = ["patch extraction was truncated"];
  dataset.metadata.complete_count = 0;
  dataset.metadata.partial_count = 1;

  await git(repository, "checkout", "--detach", fixCommit);
  const report = await check(repository, dataset, "UNKNOWN");
  assert.ok(
    report.backend_results
      .flatMap((item) => item.observations)
      .some((item) => item.type === "IMPACT_INCOMPLETE"),
    JSON.stringify(report, null, 2),
  );
});

test("a multi-commit fix requires every applicable commit to be present", async (context) => {
  const repository = await mkdtemp(path.join(os.tmpdir(), "glasswing-multi-test-"));
  context.after(async () => rm(repository, { recursive: true, force: true }));
  await git(repository, "init", "-b", "main");
  await git(repository, "config", "user.name", "glasswing test");
  await git(repository, "config", "user.email", "glasswing@example.invalid");
  await git(repository, "remote", "add", "origin", "https://github.com/example/project.git");

  const alphaVulnerable = "int alpha(const char *p){ return process_alpha_input_unchecked(p); }\n";
  const alphaFixed = "int alpha(const char *p){ return process_alpha_input_checked_safely(p); }\n";
  const betaVulnerable = "int beta(const char *p){ return process_beta_input_unchecked(p); }\n";
  const betaFixed = "int beta(const char *p){ return process_beta_input_checked_safely(p); }\n";
  const writeFiles = async (alpha: string, beta: string): Promise<void> => {
    await mkdir(path.join(repository, "src"), { recursive: true });
    await writeFile(path.join(repository, "src/alpha.c"), alpha);
    await writeFile(path.join(repository, "src/beta.c"), beta);
  };

  await writeFiles(alphaVulnerable, betaVulnerable);
  const base = await commitAll(repository, "vulnerable");
  await writeFiles(alphaFixed, betaVulnerable);
  const commitA = await commitAll(repository, "fix alpha");
  await writeFiles(alphaFixed, betaFixed);
  const commitB = await commitAll(repository, "fix beta");
  const fingerprintA = fingerprintPatch(
    await git(repository, "diff", base, commitA, "--", "src/alpha.c"),
    "src/alpha.c",
    "src/alpha.c",
  );
  const fingerprintB = fingerprintPatch(
    await git(repository, "diff", commitA, commitB, "--", "src/beta.c"),
    "src/beta.c",
    "src/beta.c",
  );
  const impact = (commit: string, file: string, fingerprint: ReturnType<typeof fingerprintPatch>) => ({
    repository: "example/project",
    commit,
    ant_ids: [ANT_ID],
    extraction_status: "complete" as const,
    files: [
      { path_before: file, path_after: file, status: "modified" as const, patch_available: true, hunks: fingerprint.hunks },
    ],
    evidence: [{ source: "github_repository" as const, url: `https://github.com/example/project/commit/${commit}` }],
    warnings: [],
  });
  const dataset: FixImpactDataset = {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-02T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: 1,
      impact_count: 2,
      complete_count: 2,
      partial_count: 0,
      error_count: 0,
    },
    impacts: [impact(commitA, "src/alpha.c", fingerprintA), impact(commitB, "src/beta.c", fingerprintB)].sort(
      (a, b) => `${a.repository}@${a.commit}`.localeCompare(`${b.repository}@${b.commit}`),
    ),
  };

  // Both fix commits are applied in the checkout.
  await git(repository, "checkout", "--detach", commitB);
  await check(repository, dataset, "VERIFIED_FIXED");

  // One required commit is reverted: a single matching commit is not proof.
  await git(repository, "checkout", "-B", "partial-fix", commitB);
  await writeFile(path.join(repository, "src/beta.c"), betaVulnerable);
  await commitAll(repository, "revert beta fix");
  await check(repository, dataset, "UNKNOWN");
});
