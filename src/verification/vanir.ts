import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { access, lstat, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { constants } from "node:fs";
import { observation, sortObservations } from "./observations.js";
import type {
  SourceVerifier,
  VerificationContext,
  VerificationEvidence,
  VerificationObservation,
  VerifierResult,
} from "./types.js";

const DEFAULT_TIMEOUT_MS = 5 * 60 * 1000;
const MAX_SIGNATURE_FILE_BYTES = 100 * 1024 * 1024;
const MAX_REPORT_FILE_BYTES = 50 * 1024 * 1024;
const MAX_PROCESS_OUTPUT_BYTES = 10 * 1024 * 1024;
const SUPPORTED_EXTENSIONS = new Set([
  ".c", ".h", ".cc", ".hh", ".cpp", ".hpp", ".cxx", ".hxx", ".java",
]);

interface JsonRecord {
  [key: string]: unknown;
}

interface TargetSignatureSet {
  ids: Set<string>;
  targetFiles: Set<string>;
  evidence: VerificationEvidence[];
}

interface ProcessResult {
  code: number | null;
  stdout: string;
  stderr: string;
  failedToStart: boolean;
  timedOut: boolean;
}

export interface VanirVerifierOptions {
  runner: string;
  signatureFiles: string[];
  vulnerabilityIds?: string[];
  timeoutMs?: number;
}

function isRecord(value: unknown): value is JsonRecord {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.filter((item): item is string => typeof item === "string")
    : [];
}

async function sha256File(file: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const hash = createHash("sha256");
    const input = createReadStream(file);
    input.on("error", reject);
    input.on("data", (chunk) => hash.update(chunk));
    input.on("end", () => resolve(hash.digest("hex")));
  });
}

async function readLimitedJson(file: string, maximumBytes: number): Promise<unknown> {
  const metadata = await lstat(file);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error(`${file} is not a regular non-symlink file`);
  }
  if (metadata.size > maximumBytes) {
    throw new Error(`${file} exceeds the ${maximumBytes}-byte input limit`);
  }
  return JSON.parse(await readFile(file, "utf8")) as unknown;
}

function collectSignatures(document: unknown, targetIds: Set<string>): {
  ids: Set<string>;
  targetFiles: Set<string>;
} {
  if (!Array.isArray(document)) throw new Error("Vanir signature input must be an OSV JSON array");
  const ids = new Set<string>();
  const targetFiles = new Set<string>();
  for (const item of document) {
    if (!isRecord(item)) continue;
    const identifiers = new Set([
      ...(typeof item.id === "string" ? [item.id] : []),
      ...stringArray(item.aliases),
    ]);
    if (![...identifiers].some((identifier) => targetIds.has(identifier))) continue;
    if (!Array.isArray(item.affected)) continue;
    for (const affected of item.affected) {
      if (!isRecord(affected)) continue;
      // Vanir stores signatures under database_specific (the sign generator's
      // own output) or ecosystem_specific; its loader prefers database_specific.
      const fromDatabase = isRecord(affected.database_specific)
        ? affected.database_specific.vanir_signatures
        : undefined;
      const fromEcosystem = isRecord(affected.ecosystem_specific)
        ? affected.ecosystem_specific.vanir_signatures
        : undefined;
      const signatures = Array.isArray(fromDatabase)
        ? fromDatabase
        : Array.isArray(fromEcosystem)
          ? fromEcosystem
          : undefined;
      if (!signatures) continue;
      for (const signature of signatures) {
        if (!isRecord(signature) || signature.deprecated === true || typeof signature.id !== "string") {
          continue;
        }
        ids.add(signature.id);
        if (isRecord(signature.target) && typeof signature.target.file === "string") {
          targetFiles.add(signature.target.file);
        }
      }
    }
  }
  return { ids, targetFiles };
}

async function loadTargetSignatures(
  signatureFiles: string[],
  targetIds: Set<string>,
): Promise<TargetSignatureSet> {
  const ids = new Set<string>();
  const targetFiles = new Set<string>();
  const evidence: VerificationEvidence[] = [];
  for (const configuredFile of signatureFiles) {
    const file = path.resolve(configuredFile);
    const document = await readLimitedJson(file, MAX_SIGNATURE_FILE_BYTES);
    const selected = collectSignatures(document, targetIds);
    selected.ids.forEach((id) => ids.add(id));
    selected.targetFiles.forEach((targetFile) => targetFiles.add(targetFile));
    evidence.push({
      kind: "configuration",
      locator: file,
      value: `sha256:${await sha256File(file)}`,
    });
  }
  return { ids, targetFiles, evidence };
}

function runVanir(
  runner: string,
  args: string[],
  timeoutMs: number,
): Promise<ProcessResult> {
  return new Promise((resolve) => {
    execFile(
      runner,
      args,
      {
        encoding: "utf8",
        timeout: timeoutMs,
        maxBuffer: MAX_PROCESS_OUTPUT_BYTES,
        windowsHide: true,
      },
      (error, stdout, stderr) => {
        const rawCode = error && "code" in error ? error.code : 0;
        const signal = error && "signal" in error ? error.signal : undefined;
        resolve({
          code: typeof rawCode === "number" ? rawCode : error ? null : 0,
          stdout,
          stderr,
          failedToStart: Boolean(error && typeof rawCode === "string"),
          timedOut: Boolean(error && signal && typeof rawCode !== "number"),
        });
      },
    );
  });
}

function missingPatchEntries(report: JsonRecord): JsonRecord[] {
  if (!Array.isArray(report.missing_patches)) {
    throw new Error("Vanir JSON report has no missing_patches array");
  }
  return report.missing_patches.filter(isRecord);
}

function reportMatchesTarget(
  entry: JsonRecord,
  targetIds: Set<string>,
  signatureIds: Set<string>,
): boolean {
  if (typeof entry.ID === "string" && targetIds.has(entry.ID)) return true;
  if (stringArray(entry.CVE).some((identifier) => targetIds.has(identifier))) return true;
  if (!Array.isArray(entry.details)) return false;
  return entry.details.some(
    (detail) => isRecord(detail) &&
      typeof detail.matched_signature === "string" &&
      signatureIds.has(detail.matched_signature),
  );
}

function missingPatchObservations(
  backend: string,
  entries: JsonRecord[],
  reportFile: string,
  signatureEvidence: VerificationEvidence[],
): VerificationObservation[] {
  const observations: VerificationObservation[] = [];
  for (const entry of entries) {
    const details = Array.isArray(entry.details) ? entry.details.filter(isRecord) : [];
    if (details.length === 0) {
      observations.push(
        observation({
          backend,
          type: "VULNERABLE_PATTERN_PRESENT",
          strength: "moderate",
          detail: `Vanir reported a missing patch for ${String(entry.ID ?? "the selected vulnerability")}`,
          evidence: [{ kind: "file", locator: reportFile }, ...signatureEvidence],
        }),
      );
      continue;
    }
    for (const detail of details) {
      const unpatchedCode = typeof detail.unpatched_code === "string"
        ? detail.unpatched_code
        : "<unknown>";
      const [targetFile] = unpatchedCode.split("::", 1);
      const signatureId = typeof detail.matched_signature === "string"
        ? detail.matched_signature
        : "unknown";
      observations.push(
        observation({
          backend,
          type: "VULNERABLE_PATTERN_PRESENT",
          strength: "moderate",
          ...(targetFile && targetFile !== "<unknown>" ? { targetFile, actualFile: targetFile } : {}),
          detail: `Vanir matched vulnerable signature ${signatureId}`,
          evidence: [
            { kind: "signature", locator: reportFile, value: signatureId },
            ...signatureEvidence,
          ],
        }),
      );
    }
  }
  return observations;
}

export class VanirVerifier implements SourceVerifier {
  readonly name = "vanir";
  private readonly runner: string;
  private readonly signatureFiles: string[];
  private readonly vulnerabilityIds: string[];
  private readonly timeoutMs: number;

  constructor(options: VanirVerifierOptions) {
    this.runner = path.resolve(options.runner);
    this.signatureFiles = [...new Set(options.signatureFiles.map((file) => path.resolve(file)))].sort();
    this.vulnerabilityIds = [...new Set(options.vulnerabilityIds ?? [])].sort();
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    if (this.signatureFiles.length === 0) throw new Error("Vanir requires at least one signature file");
    if (!Number.isInteger(this.timeoutMs) || this.timeoutMs < 1000 || this.timeoutMs > 30 * 60 * 1000) {
      throw new Error("Vanir timeout must be between 1 second and 30 minutes");
    }
  }

  async verify(context: VerificationContext): Promise<VerifierResult> {
    const warnings: string[] = [];
    const targetIds = new Set([context.antId, ...this.vulnerabilityIds]);
    let runnerVersion = "unavailable";
    try {
      await access(this.runner, constants.X_OK);
      const resolvedRunner = await realpath(this.runner);
      runnerVersion = `sha256:${await sha256File(resolvedRunner)}`;
    } catch (error) {
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "unsupported",
        observations: [
          observation({
            backend: this.name,
            type: "BACKEND_UNSUPPORTED",
            strength: "informational",
            detail: `Vanir runner is unavailable or not executable: ${String(error)}`,
            evidence: [{ kind: "configuration", locator: this.runner }],
          }),
        ],
        warnings,
      };
    }

    let selected: TargetSignatureSet;
    try {
      selected = await loadTargetSignatures(this.signatureFiles, targetIds);
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "error",
        observations: [
          observation({
            backend: this.name,
            type: "BACKEND_ERROR",
            strength: "informational",
            detail: `Unable to load Vanir signatures: ${detail}`,
          }),
        ],
        warnings: [detail],
      };
    }
    if (selected.ids.size === 0) {
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "unsupported",
        observations: [
          observation({
            backend: this.name,
            type: "BACKEND_UNSUPPORTED",
            strength: "informational",
            detail: `No non-deprecated Vanir signatures cover ${[...targetIds].sort().join(", ")}`,
            evidence: selected.evidence,
          }),
        ],
        warnings,
      };
    }
    if (
      selected.targetFiles.size === 0 ||
      ![...selected.targetFiles].some((file) => SUPPORTED_EXTENSIONS.has(path.extname(file)))
    ) {
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "unsupported",
        observations: [
          observation({
            backend: this.name,
            type: "BACKEND_UNSUPPORTED",
            strength: "informational",
            detail: "Selected signatures do not target a Vanir-supported C, C++, or Java file",
            evidence: selected.evidence,
          }),
        ],
        warnings,
      };
    }

    const temporary = await mkdtemp(path.join(os.tmpdir(), "glasswing-vanir-"));
    const reportPrefix = path.join(temporary, "report");
    const reportFile = `${reportPrefix}.json`;
    try {
      const args = [
        ...this.signatureFiles.map((file) => `--vulnerability_file_name=${file}`),
        `--report_file_name_prefix=${reportPrefix}`,
        "--verbosity=-1",
        "offline_directory_scanner",
        context.sourceRoot,
      ];
      const completed = await runVanir(this.runner, args, this.timeoutMs);
      if (completed.failedToStart) {
        return {
          backend: { name: this.name, version: runnerVersion },
          execution_status: "unsupported",
          observations: [
            observation({
              backend: this.name,
              type: "BACKEND_UNSUPPORTED",
              strength: "informational",
              detail: "Vanir runner could not be started",
              evidence: [{ kind: "configuration", locator: this.runner }],
            }),
          ],
          warnings,
        };
      }
      if (completed.timedOut || completed.code !== 0) {
        const detail = completed.timedOut
          ? `Vanir exceeded the ${this.timeoutMs}-millisecond timeout`
          : `Vanir exited with code ${completed.code ?? "unknown"}`;
        const stderr = completed.stderr.trim();
        return {
          backend: { name: this.name, version: runnerVersion },
          execution_status: "error",
          observations: [
            observation({
              backend: this.name,
              type: "BACKEND_ERROR",
              strength: "informational",
              detail,
              evidence: [{ kind: "configuration", locator: this.runner }],
            }),
          ],
          warnings: stderr ? [stderr.slice(-4000)] : [detail],
        };
      }
      if (/contains only 0 file\(s\) supported by Vanir/i.test(`${completed.stdout}\n${completed.stderr}`)) {
        return {
          backend: { name: this.name, version: runnerVersion },
          execution_status: "unsupported",
          observations: [
            observation({
              backend: this.name,
              type: "BACKEND_UNSUPPORTED",
              strength: "informational",
              detail: "Vanir found no supported source files in the target tree",
              evidence: selected.evidence,
            }),
          ],
          warnings,
        };
      }
      const report = await readLimitedJson(reportFile, MAX_REPORT_FILE_BYTES);
      if (!isRecord(report)) throw new Error("Vanir JSON report must be an object");
      const missing = missingPatchEntries(report).filter((entry) =>
        reportMatchesTarget(entry, targetIds, selected.ids),
      );
      const observations = missing.length > 0
        ? missingPatchObservations(this.name, missing, reportFile, selected.evidence)
        : [
            observation({
              backend: this.name,
              type: "VULNERABLE_PATTERN_ABSENT",
              strength: "informational",
              detail: "Vanir completed with selected signatures and reported no matching vulnerable pattern; this is not proof of a fix",
              evidence: [{ kind: "file", locator: reportFile }, ...selected.evidence],
            }),
          ];
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "completed",
        observations: sortObservations(observations),
        warnings,
      };
    } catch (error) {
      const detail = error instanceof Error ? error.message : String(error);
      return {
        backend: { name: this.name, version: runnerVersion },
        execution_status: "error",
        observations: [
          observation({
            backend: this.name,
            type: "BACKEND_ERROR",
            strength: "informational",
            detail: `Unable to parse Vanir output: ${detail}`,
          }),
        ],
        warnings: [detail],
      };
    } finally {
      await rm(temporary, { recursive: true, force: true });
    }
  }
}
