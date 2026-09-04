#!/usr/bin/env node
import { readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { HttpClient } from "./http.js";
import { syncImpactDataset } from "./impact/sync.js";
import type { FixImpactDataset } from "./impact/types.js";
import { readDataset } from "./output.js";
import { syncFixmap } from "./sync.js";
import { validateDataset } from "./validate.js";
import { formatSourceVerification, writeSourceVerification } from "./verification/output.js";
import { readImpactDataset, verifySource } from "./verification/verify.js";
import { GitAncestryVerifier } from "./verification/git-ancestry.js";
import { GlasswingFingerprintVerifier } from "./verification/native-fingerprint.js";
import { VanirVerifier } from "./verification/vanir.js";
import type { SourceVerifier } from "./verification/types.js";
import { checkSbom } from "./sbom/check.js";
import { formatSbomCheck, writeSbomCheck } from "./sbom/output.js";
import { syncAffectedRanges } from "./ranges/sync.js";
import { readAffectedRangeDataset } from "./ranges/read.js";
import {
  appendAdjudication,
  lookupAdjudication,
  readAdjudicationStore,
  readOrEmptyAdjudicationStore,
  validateAdjudicationRecord,
  writeAdjudicationStore,
} from "./adjudication/store.js";
import type { AdjudicationRecord } from "./adjudication/types.js";

const HELP = `glasswing-fixmap

Usage:
  glasswing-fixmap sync [options]
  glasswing-fixmap sync-impacts [options]
  glasswing-fixmap report [data/fixmap.json]
  glasswing-fixmap validate [data/fixmap.json]
  glasswing-fixmap verify-source --ant <ANT-ID> --source <dir> [options]
  glasswing-fixmap check-sbom --sbom <file> [options]
  glasswing-fixmap sync-ranges [options]
  glasswing-fixmap adjudicate record --store <file> [--input <review.json>]
  glasswing-fixmap adjudicate query --store <file> --evidence-hash <hash>

Sync options:
  --output <dir>          Output directory (default: data)
  --cache <dir>           HTTP cache directory (default: .cache/http)
  --overrides <file>      Manual override file (default: overrides/manual.json)
  --only <ANT,...>        Sync only selected public ANT IDs
  --concurrency <n>       Concurrent requests (default: 8)
  --offline               Use cached responses only
  --verify-github         Verify candidate tags contain a known fix commit
  --strict                Fail instead of recording a source-fetch warning
  -h, --help              Show this help

Impact sync options:
  --fixmap <file>         Input fixmap (default: data/fixmap.json)
  --output <file>         Output file (default: data/fix-impacts.json)
  --cache <dir>           HTTP cache directory (default: .cache/http)
  --only <ANT,...>        Extract only selected ANT IDs
  --concurrency <n>       Concurrent requests (default: 4)
  --offline               Use cached responses only
  --strict                Fail on the first extraction error

Source verification options:
  --ant <ANT-ID>          Anthropic finding to verify (required)
  --source <dir>          Source checkout or package tree (required)
  --impacts <file>        Fix-impact input (default: data/fix-impacts.json)
  --json                  Print the complete machine-readable report
  --output <file>         Also write the JSON report atomically
  --vanir-runner <path>   Opt in to the Vanir backend with this runner
  --vanir-signatures <f>  Vanir OSV signature file(s), comma-separated
  --vanir-vuln <id,...>   Extra vulnerability IDs to select Vanir signatures

Check SBOM options:
  --sbom <file>           CycloneDX (1.5/1.6/1.7) or Syft JSON SBOM (required)
  --fixmap <file>         Findings input (default: data/fixmap.json)
  --source <dir>          Verify an unambiguous strong candidate against a tree
  --impacts <file>        Fix-impact input for --source (default: data/fix-impacts.json)
  --component <purl>      Restrict source verification to one canonical PURL
  --ranges <file>         Authoritative ranges for AFFECTED (data/affected-ranges.json)
  --adjudications <file>  Prior adjudications to reuse (data/adjudications.json)
  --fail-on-affected      Exit non-zero when an authoritative AFFECTED is found
  --json                  Print the complete machine-readable report
  --output <file>         Also write the JSON report atomically

Range sync options:
  --fixmap <file>         Input fixmap (default: data/fixmap.json)
  --output <file>         Output file (default: data/affected-ranges.json)
  --cache <dir>           HTTP cache directory (default: .cache/http)
  --only <ANT,...>        Collect ranges only for selected ANT IDs
  --concurrency <n>       Concurrent requests (default: 4)
  --offline               Use cached responses only

Environment:
  GITHUB_TOKEN or GH_TOKEN is required for practical --verify-github and full
  sync-impacts runs.
`;

interface ParsedArguments {
  command: string;
  positional: string[];
  values: Map<string, string>;
  flags: Set<string>;
}

const COMMON_OPTIONS = ["--help", "-h"] as const;

// Per-command option allowlist. An unknown option (e.g. a typo like
// `--fail-on-affectd`) is rejected rather than silently accepted, so a
// misspelled security gate cannot quietly disable a check.
const COMMAND_OPTIONS: Record<string, readonly string[]> = {
  sync: ["--output", "--cache", "--overrides", "--only", "--concurrency", "--offline", "--verify-github", "--strict", ...COMMON_OPTIONS],
  "sync-impacts": ["--fixmap", "--output", "--cache", "--only", "--concurrency", "--offline", "--strict", ...COMMON_OPTIONS],
  "sync-ranges": ["--fixmap", "--output", "--cache", "--only", "--concurrency", "--offline", ...COMMON_OPTIONS],
  "verify-source": ["--ant", "--source", "--impacts", "--json", "--output", "--vanir-runner", "--vanir-signatures", "--vanir-vuln", ...COMMON_OPTIONS],
  "check-sbom": ["--sbom", "--fixmap", "--source", "--impacts", "--component", "--ranges", "--adjudications", "--fail-on-affected", "--json", "--output", ...COMMON_OPTIONS],
  adjudicate: ["--store", "--input", "--evidence-hash", ...COMMON_OPTIONS],
  report: [...COMMON_OPTIONS],
  validate: [...COMMON_OPTIONS],
  help: [...COMMON_OPTIONS],
};

function parseArguments(argv: string[]): ParsedArguments {
  const command = argv[0] && !argv[0].startsWith("-") ? argv[0] : "sync";
  const rest = command === argv[0] ? argv.slice(1) : argv;
  const values = new Map<string, string>();
  const flags = new Set<string>();
  const positional: string[] = [];
  const valueOptions = new Set([
    "--output",
    "--cache",
    "--overrides",
    "--only",
    "--concurrency",
    "--fixmap",
    "--ant",
    "--source",
    "--impacts",
    "--sbom",
    "--component",
    "--ranges",
    "--adjudications",
    "--store",
    "--input",
    "--evidence-hash",
    "--vanir-runner",
    "--vanir-signatures",
    "--vanir-vuln",
  ]);
  for (let index = 0; index < rest.length; index += 1) {
    const argument = rest[index]!;
    if (valueOptions.has(argument)) {
      const value = rest[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      values.set(argument, value);
      index += 1;
    } else if (argument.startsWith("-")) {
      flags.add(argument);
    } else {
      positional.push(argument);
    }
  }
  const allowed = COMMAND_OPTIONS[command];
  if (allowed) {
    const allowedSet = new Set(allowed);
    for (const option of [...values.keys(), ...flags]) {
      if (!allowedSet.has(option)) {
        throw new Error(`Unknown option ${option} for command '${command}'`);
      }
    }
  }
  return { command, positional, values, flags };
}

async function readStdin(): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(chunk as Buffer);
  return Buffer.concat(chunks).toString("utf8");
}

function printReport(dataset: Awaited<ReturnType<typeof readDataset>>): void {
  const metadata = dataset.metadata;
  process.stdout.write(
    [
      `Source snapshot: ${metadata.source_as_of} (revision ${metadata.source_revision ?? "unknown"})`,
      `Public findings: ${metadata.finding_count}`,
      `Patched: ${metadata.patched_count}`,
      `Fix commit known: ${metadata.with_fix_commit}`,
      `Fixed version known: ${metadata.with_fixed_version}`,
      `Complete / partial / unresolved: ${metadata.complete_count} / ${metadata.partial_count} / ${metadata.unresolved_count}`,
    ].join("\n") + "\n",
  );
}

function printImpactReport(dataset: FixImpactDataset): void {
  const metadata = dataset.metadata;
  process.stdout.write(
    [
      `Source snapshot: ${metadata.generated_from.source_as_of}`,
      `Findings with GitHub fix commits: ${metadata.finding_count}`,
      `Unique fix impacts: ${metadata.impact_count}`,
      `Complete / partial / error: ${metadata.complete_count} / ${metadata.partial_count} / ${metadata.error_count}`,
    ].join("\n") + "\n",
  );
}

async function main(): Promise<void> {
  const args = parseArguments(process.argv.slice(2));
  if (args.flags.has("--help") || args.flags.has("-h") || args.command === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (args.command === "report" || args.command === "validate") {
    const file = path.resolve(args.positional[0] ?? "data/fixmap.json");
    const dataset = await readDataset(file);
    const errors = validateDataset(dataset);
    if (args.command === "validate") {
      if (errors.length > 0) throw new Error(errors.join("\n"));
      process.stdout.write(`Valid: ${file} (${dataset.findings.length} findings)\n`);
    } else {
      printReport(dataset);
      if (errors.length > 0) process.stderr.write(`Validation errors:\n${errors.join("\n")}\n`);
    }
    return;
  }
  if (args.command === "sync-impacts") {
    const concurrency = Number(args.values.get("--concurrency") ?? "4");
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
      throw new Error("--concurrency must be an integer between 1 and 16");
    }
    const githubToken = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
    const onlyValue = args.values.get("--only");
    if (!githubToken && !args.flags.has("--offline") && !onlyValue) {
      throw new Error(
        "A full sync-impacts run requires GITHUB_TOKEN or GH_TOKEN; use --only for a small unauthenticated run",
      );
    }
    const client = new HttpClient({
      cacheDirectory: path.resolve(args.values.get("--cache") ?? ".cache/http"),
      offline: args.flags.has("--offline"),
      ...(githubToken ? { githubToken } : {}),
    });
    const fixmap = await readDataset(path.resolve(args.values.get("--fixmap") ?? "data/fixmap.json"));
    const dataset = await syncImpactDataset({
      client,
      fixmap,
      outputFile: path.resolve(args.values.get("--output") ?? "data/fix-impacts.json"),
      concurrency,
      ...(onlyValue
        ? { only: new Set(onlyValue.split(",").map((value) => value.trim()).filter(Boolean)) }
        : {}),
      strict: args.flags.has("--strict"),
      onProgress: (message) => process.stderr.write(`${message}\n`),
    });
    printImpactReport(dataset);
    return;
  }
  if (args.command === "verify-source") {
    const antId = args.values.get("--ant");
    const source = args.values.get("--source");
    if (!antId) throw new Error("verify-source requires --ant <ANT-ID>");
    if (!source) throw new Error("verify-source requires --source <dir>");
    const impactDataset = await readImpactDataset(
      path.resolve(args.values.get("--impacts") ?? "data/fix-impacts.json"),
    );
    const verifiers: SourceVerifier[] = [
      new GitAncestryVerifier(),
      new GlasswingFingerprintVerifier(),
    ];
    const vanirRunner = args.values.get("--vanir-runner");
    const vanirSignatures = args.values.get("--vanir-signatures");
    if (vanirRunner || vanirSignatures) {
      if (!vanirRunner || !vanirSignatures) {
        throw new Error("Vanir requires both --vanir-runner and --vanir-signatures");
      }
      const signatureFiles = vanirSignatures
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean)
        .map((file) => path.resolve(file));
      const vulnerabilityIds = (args.values.get("--vanir-vuln") ?? "")
        .split(",")
        .map((value) => value.trim())
        .filter(Boolean);
      verifiers.push(
        new VanirVerifier({
          runner: path.resolve(vanirRunner),
          signatureFiles,
          ...(vulnerabilityIds.length > 0 ? { vulnerabilityIds } : {}),
        }),
      );
    }
    const report = await verifySource({
      antId,
      sourceRoot: path.resolve(source),
      impactDataset,
      verifiers,
    });
    const output = args.values.get("--output");
    if (output) await writeSourceVerification(report, path.resolve(output));
    process.stdout.write(
      args.flags.has("--json")
        ? `${JSON.stringify(report, null, 2)}\n`
        : formatSourceVerification(report),
    );
    if (report.decision === "ERROR") process.exitCode = 2;
    return;
  }
  if (args.command === "check-sbom") {
    const sbom = args.values.get("--sbom");
    if (!sbom) throw new Error("check-sbom requires --sbom <file>");
    const rangesFile = args.values.get("--ranges");
    // Explicit security-policy requests must fail fast rather than silently
    // degrade into a partial analysis.
    if (args.flags.has("--fail-on-affected") && !rangesFile) {
      throw new Error(
        "--fail-on-affected requires --ranges <file>; authoritative AFFECTED cannot be evaluated without ranges",
      );
    }
    const fixmap = await readDataset(path.resolve(args.values.get("--fixmap") ?? "data/fixmap.json"));
    const source = args.values.get("--source");
    let impactDataset: FixImpactDataset | undefined;
    if (source) {
      // An explicit --source requires readable fix impacts; do not silently skip.
      impactDataset = await readImpactDataset(
        path.resolve(args.values.get("--impacts") ?? "data/fix-impacts.json"),
      );
    }
    const component = args.values.get("--component");
    const rangeDataset = rangesFile
      ? await readAffectedRangeDataset(path.resolve(rangesFile))
      : undefined;
    const adjudicationsFile = args.values.get("--adjudications");
    const adjudicationStore = adjudicationsFile
      ? await readAdjudicationStore(path.resolve(adjudicationsFile))
      : undefined;
    const report = await checkSbom({
      sbomFile: path.resolve(sbom),
      findings: fixmap.findings,
      snapshot: {
        source_as_of: fixmap.metadata.source_as_of,
        source_revision: fixmap.metadata.source_revision,
        source_manifest_sha3: fixmap.metadata.source_manifest_sha3,
      },
      ...(source ? { sourceRoot: path.resolve(source) } : {}),
      ...(impactDataset ? { impactDataset } : {}),
      ...(component ? { component } : {}),
      ...(rangeDataset ? { rangeDataset } : {}),
      ...(adjudicationStore ? { adjudicationStore } : {}),
    });
    const output = args.values.get("--output");
    if (output) await writeSbomCheck(report, path.resolve(output));
    process.stdout.write(
      args.flags.has("--json")
        ? `${JSON.stringify(report, null, 2)}\n`
        : formatSbomCheck(report),
    );
    // Gating is driven by the explicit final candidate_decision, not by raw range
    // evidence: only a gating-eligible AFFECTED (strong identity or source) fails.
    const errored = report.candidates.some(
      (candidate) => candidate.candidate_decision?.decision === "ERROR",
    );
    const affected = report.candidates.some(
      (candidate) =>
        candidate.candidate_decision?.gating_eligible === true &&
        candidate.candidate_decision.decision === "AFFECTED",
    );
    if (errored) {
      process.exitCode = 2;
    } else if (affected && args.flags.has("--fail-on-affected")) {
      process.exitCode = 3;
    }
    return;
  }
  if (args.command === "adjudicate") {
    const subcommand = args.positional[0];
    const storeFile = args.values.get("--store");
    if (!storeFile) throw new Error("adjudicate requires --store <file>");
    const storePath = path.resolve(storeFile);
    if (subcommand === "record") {
      // A review is produced by the adjudicator (e.g. the Skill) as a JSON record
      // and appended; the store is validated on read and write (fail closed).
      const inputFile = args.values.get("--input");
      const raw = inputFile ? await readFile(path.resolve(inputFile), "utf8") : await readStdin();
      let record: AdjudicationRecord;
      try {
        record = JSON.parse(raw) as AdjudicationRecord;
      } catch (error) {
        throw new Error(`Malformed adjudication record: ${error instanceof Error ? error.message : String(error)}`);
      }
      const recordErrors = validateAdjudicationRecord(record);
      if (recordErrors.length > 0) throw new Error(`Invalid adjudication record:\n${recordErrors.join("\n")}`);
      const store = await readOrEmptyAdjudicationStore(storePath);
      const updated = appendAdjudication(store, record);
      await writeAdjudicationStore(updated, storePath);
      process.stdout.write(
        `Recorded adjudication for ${record.subject.ant_id} (evidence ${record.evidence_hash.slice(0, 12)}); ${updated.records.length} record(s)\n`,
      );
      return;
    }
    if (subcommand === "query") {
      const evidenceHash = args.values.get("--evidence-hash");
      if (!evidenceHash) throw new Error("adjudicate query requires --evidence-hash <hash>");
      const store = await readAdjudicationStore(storePath);
      const record = lookupAdjudication(store, evidenceHash);
      process.stdout.write(record ? `${JSON.stringify(record, null, 2)}\n` : "No current adjudication for that evidence hash\n");
      if (!record) process.exitCode = 1;
      return;
    }
    throw new Error("adjudicate requires a subcommand: 'record' or 'query'");
  }
  if (args.command === "sync-ranges") {
    const concurrency = Number(args.values.get("--concurrency") ?? "4");
    if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 16) {
      throw new Error("--concurrency must be an integer between 1 and 16");
    }
    const client = new HttpClient({
      cacheDirectory: path.resolve(args.values.get("--cache") ?? ".cache/http"),
      offline: args.flags.has("--offline"),
    });
    const fixmap = await readDataset(path.resolve(args.values.get("--fixmap") ?? "data/fixmap.json"));
    const onlyValue = args.values.get("--only");
    const dataset = await syncAffectedRanges({
      client,
      fixmap,
      outputFile: path.resolve(args.values.get("--output") ?? "data/affected-ranges.json"),
      concurrency,
      ...(onlyValue
        ? { only: new Set(onlyValue.split(",").map((value) => value.trim()).filter(Boolean)) }
        : {}),
      onProgress: (message) => process.stderr.write(`${message}\n`),
    });
    process.stdout.write(
      `Authoritative ranges: ${dataset.metadata.record_count} across ${dataset.metadata.finding_count} findings\n`,
    );
    return;
  }
  if (args.command !== "sync") throw new Error(`Unknown command: ${args.command}`);

  const concurrency = Number(args.values.get("--concurrency") ?? "8");
  if (!Number.isInteger(concurrency) || concurrency < 1 || concurrency > 32) {
    throw new Error("--concurrency must be an integer between 1 and 32");
  }
  const verifyGithub = args.flags.has("--verify-github");
  const githubToken = process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN;
  if (verifyGithub && !githubToken) {
    throw new Error("--verify-github requires GITHUB_TOKEN or GH_TOKEN to avoid API rate limits");
  }
  const client = new HttpClient({
    cacheDirectory: path.resolve(args.values.get("--cache") ?? ".cache/http"),
    offline: args.flags.has("--offline"),
    ...(githubToken ? { githubToken } : {}),
  });
  const onlyValue = args.values.get("--only");
  const dataset = await syncFixmap({
    client,
    outputDirectory: args.values.get("--output") ?? "data",
    overridesFile: path.resolve(args.values.get("--overrides") ?? "overrides/manual.json"),
    concurrency,
    ...(onlyValue
      ? { only: new Set(onlyValue.split(",").map((value) => value.trim()).filter(Boolean)) }
      : {}),
    verifyGithub,
    strict: args.flags.has("--strict"),
    onProgress: (message) => process.stderr.write(`${message}\n`),
  });
  printReport(dataset);
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
  process.exitCode = 1;
});
