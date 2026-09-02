#!/usr/bin/env node
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

const HELP = `glasswing-fixmap

Usage:
  glasswing-fixmap sync [options]
  glasswing-fixmap sync-impacts [options]
  glasswing-fixmap report [data/fixmap.json]
  glasswing-fixmap validate [data/fixmap.json]
  glasswing-fixmap verify-source --ant <ANT-ID> --source <dir> [options]

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
  return { command, positional, values, flags };
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
    const report = await verifySource({
      antId,
      sourceRoot: path.resolve(source),
      impactDataset,
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
