import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import type { HttpClient } from "../src/http.js";
import { fingerprintPatch } from "../src/impact/fingerprint.js";
import { extractGitHubImpact } from "../src/impact/github.js";
import { syncImpactDataset } from "../src/impact/sync.js";
import type { FixImpactDataset } from "../src/impact/types.js";
import type { FixmapDataset } from "../src/types.js";

const PATCH = `@@ -10,4 +10,5 @@ static int parse_packet(struct packet *packet)
 if (packet == NULL) {
+  return ERROR_INVALID_PACKET;
 }
-return decode(packet);
+return decode_checked(packet);
`;

test("extracts hunk context and several code-free patch fingerprints", () => {
  const result = fingerprintPatch(PATCH, "src/parser.c", "src/parser.c");
  assert.deepEqual(result.functions, ["static int parse_packet(struct packet *packet)"]);
  assert.equal(result.hunks.length, 1);
  assert.deepEqual(result.hunks[0]?.old_range, { start: 10, count: 4 });
  assert.deepEqual(result.hunks[0]?.new_range, { start: 10, count: 5 });
  assert.deepEqual(
    [...new Set(result.hunks[0]?.signatures.map((signature) => signature.kind))].sort(),
    ["added", "combined", "deleted", "postimage", "preimage", "unchanged_context"],
  );
  for (const signature of result.hunks[0]?.signatures ?? []) {
    assert.match(signature.digest, /^[0-9a-f]{64}$/);
    assert.equal(signature.algorithm, "glasswing-normalized-sha256-v1");
  }
  const serialized = JSON.stringify(result);
  assert.equal(serialized.includes("decode_checked"), false);
  assert.equal(serialized.includes("ERROR_INVALID_PACKET"), false);
});

test("normalizes horizontal whitespace before hashing", () => {
  const withTabs = PATCH.replace("  return ERROR_INVALID_PACKET;", "\treturn   ERROR_INVALID_PACKET;");
  const first = fingerprintPatch(PATCH, "src/parser.c", "src/parser.c");
  const second = fingerprintPatch(withTabs, "src/parser.c", "src/parser.c");
  assert.deepEqual(first, second);
});

test("projects GitHub commit metadata and marks unavailable patch text partial", async () => {
  const client = {
    async getJson() {
      return {
        sha: "a".repeat(40),
        html_url: `https://github.com/example/project/commit/${"a".repeat(40)}`,
        files: [
          {
            filename: "src/parser.c",
            status: "modified",
            changes: 3,
            patch: PATCH,
          },
          {
            filename: "assets/table.bin",
            status: "modified",
            changes: 8,
          },
        ],
      };
    },
  } as unknown as HttpClient;
  const impact = await extractGitHubImpact(client, {
    repository: "example/project",
    commit: "abcdef0",
    antIds: ["ANT-2026-EXAMPLE"],
    evidence: [
      {
        source: "anthropic_finding",
        url: "https://red.anthropic.com/2026/cvd/findings/ANT-2026-EXAMPLE",
      },
    ],
  });
  assert.equal(impact.commit, "a".repeat(40));
  assert.equal(impact.extraction_status, "partial");
  assert.deepEqual(
    impact.files.map((file) => file.path_after),
    ["assets/table.bin", "src/parser.c"],
  );
  assert.equal(impact.files[0]?.patch_available, false);
  assert.match(impact.warnings[0] ?? "", /Patch text was unavailable/);
});

test("maps added, removed, and renamed GitHub files without inventing patch text", async () => {
  const client = {
    async getJson() {
      return {
        sha: "b".repeat(40),
        files: [
          {
            filename: "src/new.c",
            status: "added",
            changes: 1,
            patch: "@@ -0,0 +1 @@\n+int safe_value = 1;",
          },
          {
            filename: "src/old.c",
            status: "removed",
            changes: 1,
            patch: "@@ -1 +0,0 @@\n-int unsafe_value = 1;",
          },
          {
            filename: "src/renamed.c",
            previous_filename: "src/original.c",
            status: "renamed",
            changes: 0,
          },
        ],
      };
    },
  } as unknown as HttpClient;
  const impact = await extractGitHubImpact(client, {
    repository: "example/project",
    commit: "bcdef01",
    antIds: ["ANT-2026-EXAMPLE"],
    evidence: [
      {
        source: "github_repository",
        url: "https://github.com/example/project/commit/bcdef01",
      },
    ],
  });
  assert.equal(impact.extraction_status, "complete");
  assert.deepEqual(
    impact.files.map(({ status, path_before, path_after, patch_available }) => ({
      status,
      path_before,
      path_after,
      patch_available,
    })),
    [
      { status: "added", path_before: undefined, path_after: "src/new.c", patch_available: true },
      { status: "deleted", path_before: "src/old.c", path_after: undefined, patch_available: true },
      {
        status: "renamed",
        path_before: "src/original.c",
        path_after: "src/renamed.c",
        patch_available: false,
      },
    ],
  );
});

test("deduplicates short and full SHAs and retains extraction errors", async (context) => {
  const temporary = await mkdtemp(path.join(os.tmpdir(), "glasswing-impact-test-"));
  context.after(async () => rm(temporary, { recursive: true }));
  let requests = 0;
  const client = {
    async getJson() {
      requests += 1;
      throw new Error("fixture lookup failed");
    },
  } as unknown as HttpClient;
  const fullSha = "c".repeat(40);
  const evidence = {
    source: "anthropic_finding" as const,
    url: "https://red.anthropic.com/2026/cvd/findings/ANT-2026-EXAMPLE",
  };
  const fixmap: FixmapDataset = {
    metadata: {
      schema_version: "1.0.0",
      source_as_of: "2026-09-01T00:00:00Z",
      source_revision: 1,
      source_manifest_sha3: null,
      source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      finding_count: 1,
      patched_count: 1,
      with_fix_commit: 1,
      with_fixed_version: 0,
      complete_count: 0,
      partial_count: 1,
      unresolved_count: 0,
    },
    findings: [
      {
        schema_version: "1.0.0",
        ant_id: "ANT-2026-EXAMPLE",
        project: "example/project",
        title: "Fixture",
        bug_class: null,
        severity: { claude: null, firm: null, maintainer: null },
        status: "fixed",
        patched: true,
        patched_at: null,
        discovered_on: null,
        revealed_at: null,
        withdrawn: false,
        cve_ids: [],
        ghsa_ids: [],
        fix_commits: [
          {
            sha: fullSha.slice(0, 8),
            url: `https://github.com/example/project/commit/${fullSha.slice(0, 8)}`,
            repository: "example/project",
            confidence: "high",
            evidence: [evidence],
          },
          {
            sha: fullSha,
            url: `https://github.com/example/project/commit/${fullSha}`,
            repository: "example/project",
            confidence: "high",
            evidence: [evidence],
          },
        ],
        fix_references: [],
        fixed_versions: [],
        release_assessment: { status: "commit_only", evidence: [evidence] },
        enrichment: { status: "partial", warnings: [] },
        sources: [evidence],
      },
    ],
  };
  const outputFile = path.join(temporary, "fix-impacts.json");
  const dataset = await syncImpactDataset({
    client,
    fixmap,
    outputFile,
    concurrency: 1,
  });
  assert.equal(requests, 1);
  assert.equal(dataset.impacts.length, 1);
  assert.equal(dataset.impacts[0]?.commit, fullSha);
  assert.equal(dataset.impacts[0]?.extraction_status, "error");
  assert.match(dataset.impacts[0]?.warnings[0] ?? "", /fixture lookup failed/);
  assert.deepEqual(JSON.parse(await readFile(outputFile, "utf8")), dataset);
});

test("the fix-impact contract conforms to its published JSON schema", async () => {
  const schemaText = await readFile(
    new URL("../schema/fix-impacts.schema.json", import.meta.url),
    "utf8",
  );
  const fingerprint = fingerprintPatch(PATCH, "src/parser.c", "src/parser.c");
  const dataset: FixImpactDataset = {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-01T00:00:00Z",
        source_url: "https://red.anthropic.com/data/payload.json",
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
        commit: "a".repeat(40),
        ant_ids: ["ANT-2026-EXAMPLE"],
        extraction_status: "complete",
        files: [
          {
            path_before: "src/parser.c",
            path_after: "src/parser.c",
            status: "modified",
            patch_available: true,
            functions: fingerprint.functions,
            hunks: fingerprint.hunks,
          },
        ],
        evidence: [
          {
            source: "github_repository",
            url: `https://github.com/example/project/commit/${"a".repeat(40)}`,
          },
        ],
        warnings: [],
      },
    ],
  };
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    JSON.parse(schemaText) as object,
  );
  assert.equal(validate(dataset), true, JSON.stringify(validate.errors, null, 2));
});
