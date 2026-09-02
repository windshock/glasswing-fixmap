import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import path from "node:path";
import { sourceContainsSignature } from "../impact/fingerprint.js";
import {
  PATCH_SIGNATURE_ALGORITHM,
  type ChangedFile,
  type FixImpact,
  type PatchHunk,
  type PatchSignature,
} from "../impact/types.js";
import { observation, sortObservations } from "./observations.js";
import type {
  ObservationStrength,
  SourceVerifier,
  VerificationContext,
  VerificationObservation,
  VerifierResult,
} from "./types.js";

const MAX_SOURCE_FILE_BYTES = 5 * 1024 * 1024;
const MAX_DISCOVERY_FILES = 5000;
const MAX_RENAME_CANDIDATES = 250;
const MIN_MEANINGFUL_LENGTH = 16;

interface SourceFile {
  relativePath: string;
  text?: string;
  status: "readable" | "absent" | "unsupported" | "error";
  detail?: string;
}

interface DiscoveryResult {
  files: string[];
  truncated: boolean;
  warnings: string[];
}

function safeSourcePath(root: string, relativePath: string): string | undefined {
  if (!relativePath || path.posix.isAbsolute(relativePath)) return undefined;
  const segments = relativePath.split("/");
  if (segments.some((segment) => !segment || segment === "." || segment === "..")) return undefined;
  const resolvedRoot = path.resolve(root);
  const resolved = path.resolve(resolvedRoot, ...segments);
  if (resolved !== resolvedRoot && !resolved.startsWith(`${resolvedRoot}${path.sep}`)) return undefined;
  return resolved;
}

function isWithinRoot(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." && !path.isAbsolute(relative));
}

async function inspectSourceFile(
  root: string,
  realRoot: string,
  relativePath: string,
): Promise<SourceFile> {
  const resolved = safeSourcePath(root, relativePath);
  if (!resolved) {
    return {
      relativePath,
      status: "error",
      detail: "target path is not a safe repository-relative path",
    };
  }
  try {
    const realTarget = await realpath(resolved);
    if (!isWithinRoot(realRoot, realTarget)) {
      return {
        relativePath,
        status: "unsupported",
        detail: "target resolves outside the source root",
      };
    }
    const metadata = await lstat(resolved);
    if (!metadata.isFile() || metadata.isSymbolicLink()) {
      return {
        relativePath,
        status: "unsupported",
        detail: "target is not a regular non-symlink file",
      };
    }
    if (metadata.size > MAX_SOURCE_FILE_BYTES) {
      return {
        relativePath,
        status: "unsupported",
        detail: `target exceeds ${MAX_SOURCE_FILE_BYTES} bytes`,
      };
    }
    const content = await readFile(resolved);
    if (content.includes(0)) {
      return { relativePath, status: "unsupported", detail: "target appears to be binary" };
    }
    try {
      const text = new TextDecoder("utf-8", { fatal: true }).decode(content);
      return { relativePath, text, status: "readable" };
    } catch {
      return { relativePath, status: "unsupported", detail: "target is not valid UTF-8 text" };
    }
  } catch (error) {
    if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
      return { relativePath, status: "absent" };
    }
    return { relativePath, status: "error", detail: String(error) };
  }
}

async function discoverSourceFiles(root: string): Promise<DiscoveryResult> {
  const files: string[] = [];
  const warnings: string[] = [];
  const pending: Array<{ absolute: string; relative: string }> = [{ absolute: path.resolve(root), relative: "" }];
  let truncated = false;
  while (pending.length > 0 && !truncated) {
    const directory = pending.pop()!;
    let entries;
    try {
      entries = await readdir(directory.absolute, { withFileTypes: true });
    } catch (error) {
      warnings.push(`Unable to inspect ${directory.relative || "."}: ${String(error)}`);
      continue;
    }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const entry of entries) {
      if (entry.name === ".git") continue;
      const relative = directory.relative ? `${directory.relative}/${entry.name}` : entry.name;
      const absolute = path.join(directory.absolute, entry.name);
      if (entry.isDirectory()) {
        pending.push({ absolute, relative });
      } else if (entry.isFile()) {
        files.push(relative);
        if (files.length >= MAX_DISCOVERY_FILES) {
          truncated = true;
          break;
        }
      }
    }
  }
  return { files: files.sort(), truncated, warnings: [...new Set(warnings)].sort() };
}

function signatures(hunk: PatchHunk, kind: PatchSignature["kind"]): PatchSignature[] {
  return hunk.signatures.filter(
    (signature) => signature.kind === kind && signature.normalized_length >= MIN_MEANINGFUL_LENGTH,
  );
}

function signatureEvidence(
  signature: PatchSignature,
  actualFile: string,
  hunkIndex: number,
) {
  return [
    {
      kind: "signature" as const,
      locator: `${actualFile}#hunk-${hunkIndex}`,
      value: `${signature.kind}:${signature.digest}`,
    },
  ];
}

function signatureStrength(signature: PatchSignature, hunk: PatchHunk): ObservationStrength {
  return signature.normalized_length >= 24 && (signature.line_count >= 2 || Boolean(hunk.context))
    ? "strong"
    : "moderate";
}

function targetPaths(file: ChangedFile): string[] {
  return [...new Set([file.path_after, file.path_before].filter((value): value is string => Boolean(value)))];
}

function evaluateHunk(
  backend: string,
  impact: FixImpact,
  targetFile: string,
  actualFile: string,
  hunk: PatchHunk,
  hunkIndex: number,
  source: string,
  moved: boolean,
): VerificationObservation {
  const postimages = signatures(hunk, "postimage");
  const preimages = signatures(hunk, "preimage");
  const additions = signatures(hunk, "added");
  const deletions = signatures(hunk, "deleted");
  const postimage = postimages.find((signature) => sourceContainsSignature(source, signature));
  if (postimage) {
    return observation({
      backend,
      type: "FIX_POSTIMAGE_PRESENT",
      strength: moved ? "moderate" : signatureStrength(postimage, hunk),
      repository: impact.repository,
      commit: impact.commit,
      targetFile,
      actualFile,
      hunkIndex,
      detail: moved
        ? "post-fix hunk image is present under a different path"
        : "post-fix hunk image is present",
      evidence: signatureEvidence(postimage, actualFile, hunkIndex),
    });
  }

  const matchingAdditions = additions.filter((signature) => sourceContainsSignature(source, signature));
  const matchingDeletions = deletions.filter((signature) => sourceContainsSignature(source, signature));
  if (additions.length > 0 && matchingAdditions.length === additions.length && matchingDeletions.length === 0) {
    return observation({
      backend,
      type: "FIX_POSTIMAGE_PRESENT",
      strength: "moderate",
      repository: impact.repository,
      commit: impact.commit,
      targetFile,
      actualFile,
      hunkIndex,
      detail: "all meaningful added-line signatures are present and deleted-line signatures are absent",
      evidence: matchingAdditions.flatMap((signature) =>
        signatureEvidence(signature, actualFile, hunkIndex),
      ),
    });
  }

  const preimage = preimages.find((signature) => sourceContainsSignature(source, signature));
  if (preimage) {
    return observation({
      backend,
      type: "FIX_PREIMAGE_PRESENT",
      strength: moved ? "moderate" : signatureStrength(preimage, hunk),
      repository: impact.repository,
      commit: impact.commit,
      targetFile,
      actualFile,
      hunkIndex,
      detail: moved
        ? "pre-fix hunk image is present under a different path"
        : "pre-fix hunk image is present",
      evidence: signatureEvidence(preimage, actualFile, hunkIndex),
    });
  }
  if (matchingDeletions.length > 0) {
    return observation({
      backend,
      type: "VULNERABLE_PATTERN_PRESENT",
      strength: "moderate",
      repository: impact.repository,
      commit: impact.commit,
      targetFile,
      actualFile,
      hunkIndex,
      detail: "one or more meaningful deleted-line signatures remain present",
      evidence: matchingDeletions.flatMap((signature) =>
        signatureEvidence(signature, actualFile, hunkIndex),
      ),
    });
  }
  return observation({
    backend,
    type: "PATCH_SIGNATURE_ABSENT",
    strength: "moderate",
    repository: impact.repository,
    commit: impact.commit,
    targetFile,
    actualFile,
    hunkIndex,
    detail: "neither a meaningful post-fix nor pre-fix signature was found",
    evidence: [{ kind: "file", locator: actualFile }],
  });
}

function usableHunks(file: ChangedFile): boolean {
  return file.hunks.some((hunk) =>
    hunk.signatures.some(
      (signature) => signature.kind !== "combined" && signature.normalized_length >= MIN_MEANINGFUL_LENGTH,
    ),
  );
}

export class GlasswingFingerprintVerifier implements SourceVerifier {
  readonly name = "glasswing-fingerprint";

  async verify(context: VerificationContext): Promise<VerifierResult> {
    const observations: VerificationObservation[] = [];
    const warnings: string[] = [];
    const fileCache = new Map<string, Promise<SourceFile>>();
    let discovery: Promise<DiscoveryResult> | undefined;
    let completedOperations = 0;
    let backendErrors = 0;
    let unsupportedOperations = 0;
    const realSourceRoot = await realpath(context.sourceRoot);

    const inspect = (relativePath: string): Promise<SourceFile> => {
      let pending = fileCache.get(relativePath);
      if (!pending) {
        pending = inspectSourceFile(context.sourceRoot, realSourceRoot, relativePath);
        fileCache.set(relativePath, pending);
      }
      return pending;
    };

    for (const impact of context.impacts) {
      warnings.push(...impact.warnings.map((warning) => `${impact.repository}@${impact.commit}: ${warning}`));
      if (impact.extraction_status === "error" || impact.files.length === 0) {
        unsupportedOperations += 1;
        observations.push(
          observation({
            backend: this.name,
            type: "BACKEND_UNSUPPORTED",
            strength: "informational",
            repository: impact.repository,
            commit: impact.commit,
            detail: "fix impact contains no usable changed files",
          }),
        );
        continue;
      }
      for (const file of impact.files) {
        const paths = targetPaths(file);
        const targetFile = file.path_after ?? file.path_before ?? "<unknown>";
        if (paths.length === 0 || !usableHunks(file)) {
          unsupportedOperations += 1;
          observations.push(
            observation({
              backend: this.name,
              type: "BACKEND_UNSUPPORTED",
              strength: "informational",
              repository: impact.repository,
              commit: impact.commit,
              targetFile,
              detail: "changed file has no usable patch signatures",
            }),
          );
          continue;
        }

        let selected: SourceFile | undefined;
        for (const candidate of paths) {
          const inspected = await inspect(candidate);
          if (inspected.status === "readable") {
            selected = inspected;
            break;
          }
          if (inspected.status === "error") {
            backendErrors += 1;
            observations.push(
              observation({
                backend: this.name,
                type: "BACKEND_ERROR",
                strength: "informational",
                repository: impact.repository,
                commit: impact.commit,
                targetFile: candidate,
                detail: inspected.detail ?? "source file inspection failed",
              }),
            );
          } else if (inspected.status === "unsupported") {
            unsupportedOperations += 1;
            observations.push(
              observation({
                backend: this.name,
                type: "BACKEND_UNSUPPORTED",
                strength: "informational",
                repository: impact.repository,
                commit: impact.commit,
                targetFile: candidate,
                detail: inspected.detail ?? "source file cannot be inspected",
              }),
            );
          }
        }

        if (selected?.text !== undefined) {
          completedOperations += 1;
          file.hunks.forEach((hunk, hunkIndex) => {
            if (!hunk.signatures.some(
              (signature) => signature.kind !== "combined" &&
                signature.normalized_length >= MIN_MEANINGFUL_LENGTH,
            )) {
              unsupportedOperations += 1;
              observations.push(
                observation({
                  backend: this.name,
                  type: "BACKEND_UNSUPPORTED",
                  strength: "informational",
                  repository: impact.repository,
                  commit: impact.commit,
                  targetFile,
                  hunkIndex,
                  detail: "patch hunk has no meaningful source-search signature",
                }),
              );
              return;
            }
            observations.push(
              evaluateHunk(
                this.name,
                impact,
                targetFile,
                selected!.relativePath,
                hunk,
                hunkIndex,
                selected!.text!,
                selected!.relativePath !== targetFile,
              ),
            );
          });
          continue;
        }

        if (file.status === "added") {
          completedOperations += 1;
          observations.push(
            observation({
              backend: this.name,
              type: "PATCH_SIGNATURE_ABSENT",
              strength: "moderate",
              repository: impact.repository,
              commit: impact.commit,
              targetFile,
              detail: "file added by the fix is absent",
              evidence: [{ kind: "file", locator: targetFile }],
            }),
          );
          continue;
        }

        discovery ??= discoverSourceFiles(context.sourceRoot);
        const discovered = await discovery;
        warnings.push(...discovered.warnings);
        const extension = path.posix.extname(targetFile).toLowerCase();
        const allAlternatives = discovered.files.filter(
          (candidate) => !paths.includes(candidate) &&
            (!extension || path.posix.extname(candidate).toLowerCase() === extension),
        );
        const alternatives = allAlternatives.slice(0, MAX_RENAME_CANDIDATES);
        let movedMatch: { file: SourceFile; observation: VerificationObservation } | undefined;
        for (const alternative of alternatives) {
          const inspected = await inspect(alternative);
          if (inspected.status !== "readable" || inspected.text === undefined) continue;
          for (let hunkIndex = 0; hunkIndex < file.hunks.length; hunkIndex += 1) {
            const hunk = file.hunks[hunkIndex]!;
            const evaluated = evaluateHunk(
              this.name,
              impact,
              targetFile,
              alternative,
              hunk,
              hunkIndex,
              inspected.text,
              true,
            );
            if (evaluated.type === "FIX_POSTIMAGE_PRESENT" || evaluated.type === "FIX_PREIMAGE_PRESENT") {
              movedMatch = { file: inspected, observation: evaluated };
              break;
            }
          }
          if (movedMatch) break;
        }

        completedOperations += 1;
        if (movedMatch) {
          observations.push(
            observation({
              backend: this.name,
              type: "TARGET_PATH_MOVED",
              strength: "informational",
              repository: impact.repository,
              commit: impact.commit,
              targetFile,
              actualFile: movedMatch.file.relativePath,
              detail: "a patch image matched under a different file path",
              evidence: [{ kind: "file", locator: movedMatch.file.relativePath }],
            }),
            movedMatch.observation,
          );
        } else {
          observations.push(
            observation({
              backend: this.name,
              type: "TARGET_FILE_ABSENT",
              strength: "informational",
              repository: impact.repository,
              commit: impact.commit,
              targetFile,
              detail: "no target path or recognizable patch image was found",
              evidence: [{ kind: "file", locator: targetFile }],
            }),
          );
          if (
            discovered.truncated ||
            discovered.warnings.length > 0 ||
            allAlternatives.length > MAX_RENAME_CANDIDATES
          ) {
            unsupportedOperations += 1;
            observations.push(
              observation({
                backend: this.name,
                type: "BACKEND_UNSUPPORTED",
                strength: "informational",
                repository: impact.repository,
                commit: impact.commit,
                targetFile,
                detail: discovered.truncated
                  ? `rename discovery stopped after ${MAX_DISCOVERY_FILES} files`
                  : discovered.warnings.length > 0
                    ? "rename discovery could not read every source directory"
                    : `rename discovery inspected only the first ${MAX_RENAME_CANDIDATES} candidate files`,
              }),
            );
          }
        }
      }
    }

    const executionStatus = completedOperations > 0
      ? "completed"
      : backendErrors > 0
        ? "error"
        : "unsupported";
    if (completedOperations === 0 && backendErrors === 0 && unsupportedOperations === 0) {
      observations.push(
        observation({
          backend: this.name,
          type: "BACKEND_UNSUPPORTED",
          strength: "informational",
          detail: "no fix impacts were available for native verification",
        }),
      );
    }
    return {
      backend: { name: this.name, version: PATCH_SIGNATURE_ALGORITHM },
      execution_status: executionStatus,
      observations: sortObservations(observations),
      warnings: [...new Set(warnings)].sort(),
    };
  }
}
