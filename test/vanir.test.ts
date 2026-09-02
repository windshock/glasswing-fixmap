import assert from "node:assert/strict";
import { chmod, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";
import type { FixImpactDataset } from "../src/impact/types.js";
import type { SourceVerificationReport } from "../src/verification/types.js";
import { VanirVerifier } from "../src/verification/vanir.js";
import { verifySource } from "../src/verification/verify.js";

const ANT_ID = "ANT-2026-VANIR01";

function impactDataset(): FixImpactDataset {
  // Vanir ignores impacts, but verify-source still requires a valid dataset
  // that carries an impact for the finding under test.
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
      complete_count: 0,
      partial_count: 1,
      error_count: 0,
    },
    impacts: [
      {
        repository: "example/project",
        commit: "abcdef1",
        ant_ids: [ANT_ID],
        extraction_status: "partial",
        files: [],
        evidence: [
          { source: "github_repository", url: "https://github.com/example/project/commit/abcdef1" },
        ],
        warnings: ["vanir differential fixture"],
      },
    ],
  };
}

async function writeSignatures(directory: string): Promise<string> {
  const file = path.join(directory, "signatures.json");
  await writeFile(
    file,
    JSON.stringify([
      {
        id: ANT_ID,
        affected: [
          {
            ecosystem_specific: {
              vanir_signatures: [{ id: "sig-1", target: { file: "src/parser.c" } }],
            },
          },
        ],
      },
    ]),
  );
  return file;
}

async function writeRunner(directory: string, report: unknown): Promise<string> {
  const file = path.join(directory, "fake-vanir.mjs");
  await writeFile(
    file,
    [
      "#!/usr/bin/env node",
      'import { writeFileSync } from "node:fs";',
      'const match = process.argv.map((a) => /^--report_file_name_prefix=(.*)$/.exec(a)).find(Boolean);',
      "if (!match) process.exit(3);",
      `writeFileSync(match[1] + ".json", ${JSON.stringify(JSON.stringify(report))});`,
      "process.exit(0);",
    ].join("\n"),
  );
  await chmod(file, 0o755);
  return file;
}

async function runVanir(
  directory: string,
  runner: string,
  signatureFile: string,
): Promise<SourceVerificationReport> {
  return verifySource({
    antId: ANT_ID,
    sourceRoot: directory,
    impactDataset: impactDataset(),
    verifiers: [new VanirVerifier({ runner, signatureFiles: [signatureFile] })],
  });
}

test("Vanir absence is graceful: an unavailable runner is unsupported, not an error", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "glasswing-vanir-"));
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const signatureFile = await writeSignatures(directory);
  const report = await runVanir(directory, path.join(directory, "does-not-exist"), signatureFile);
  const vanir = report.backend_results.find((backend) => backend.backend.name === "vanir");
  assert.ok(vanir);
  assert.equal(vanir!.execution_status, "unsupported");
  assert.ok(vanir!.observations.some((item) => item.type === "BACKEND_UNSUPPORTED"));
  // A missing optional backend never manufactures an AFFECTED or ERROR result.
  assert.equal(report.decision, "UNKNOWN");
  assert.notEqual(report.decision, "AFFECTED");
});

test("Vanir missing-patch match yields PATCH_NOT_FOUND, never AFFECTED", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "glasswing-vanir-"));
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const signatureFile = await writeSignatures(directory);
  const runner = await writeRunner(directory, {
    missing_patches: [
      {
        ID: ANT_ID,
        details: [{ unpatched_code: "src/parser.c::parse", matched_signature: "sig-1" }],
      },
    ],
  });
  const report = await runVanir(directory, runner, signatureFile);
  const vanir = report.backend_results.find((backend) => backend.backend.name === "vanir");
  assert.equal(vanir!.execution_status, "completed");
  assert.ok(vanir!.observations.some((item) => item.type === "VULNERABLE_PATTERN_PRESENT"));
  assert.equal(report.decision, "PATCH_NOT_FOUND");
  assert.ok(report.reasons.some((item) => item.code === "PREIMAGE_PRESENT"));

  const schemaText = await readFile(
    new URL("../schema/source-verification.schema.json", import.meta.url),
    "utf8",
  );
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    JSON.parse(schemaText) as object,
  );
  assert.equal(validate(report), true, JSON.stringify(validate.errors, null, 2));
});

test("Vanir clean scan is inconclusive, not proof of a fix", async (context) => {
  const directory = await mkdtemp(path.join(os.tmpdir(), "glasswing-vanir-"));
  context.after(async () => rm(directory, { recursive: true, force: true }));
  const signatureFile = await writeSignatures(directory);
  const runner = await writeRunner(directory, { missing_patches: [] });
  const report = await runVanir(directory, runner, signatureFile);
  const vanir = report.backend_results.find((backend) => backend.backend.name === "vanir");
  assert.equal(vanir!.execution_status, "completed");
  assert.ok(vanir!.observations.some((item) => item.type === "VULNERABLE_PATTERN_ABSENT"));
  assert.equal(report.decision, "UNKNOWN");
  assert.ok(report.reasons.some((item) => item.code === "INSUFFICIENT_EVIDENCE"));
});
