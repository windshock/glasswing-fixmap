import { createHash } from "node:crypto";
import {
  PATCH_SIGNATURE_ALGORITHM,
  type LineRange,
  type PatchHunk,
  type PatchSignature,
  type PatchSignatureKind,
} from "./types.js";

interface DiffLine {
  kind: "added" | "deleted" | "unchanged_context";
  value: string;
}

interface ParsedHunk {
  oldRange: LineRange;
  newRange: LineRange;
  context?: string;
  lines: DiffLine[];
}

const HUNK_HEADER = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@(?:\s?(.*))?$/;

export function normalizePatchLine(line: string): string {
  return line.trim().replace(/[\t ]+/g, " ");
}

function normalizeLines(lines: string[]): string[] {
  const normalized = lines.map(normalizePatchLine);
  let start = 0;
  let end = normalized.length;
  while (start < end && normalized[start] === "") start += 1;
  while (end > start && normalized[end - 1] === "") end -= 1;
  return normalized.slice(start, end);
}

function digest(kind: PatchSignatureKind, normalized: string): string {
  return createHash("sha256")
    .update(`${PATCH_SIGNATURE_ALGORITHM}\0${kind}\0${normalized}`, "utf8")
    .digest("hex");
}

function contentSignature(
  kind: Exclude<PatchSignatureKind, "combined">,
  lines: string[],
): PatchSignature | undefined {
  const normalizedLines = normalizeLines(lines);
  if (normalizedLines.length === 0) return undefined;
  const normalized = normalizedLines.join("\n");
  return {
    algorithm: PATCH_SIGNATURE_ALGORITHM,
    kind,
    digest: digest(kind, normalized),
    line_count: normalizedLines.length,
    normalized_length: Buffer.byteLength(normalized, "utf8"),
  };
}

function parseHunks(patch: string): ParsedHunk[] {
  const hunks: ParsedHunk[] = [];
  let current: ParsedHunk | undefined;
  for (const rawLine of patch.replace(/\r\n?/g, "\n").split("\n")) {
    const header = rawLine.match(HUNK_HEADER);
    if (header) {
      current = {
        oldRange: { start: Number(header[1]), count: Number(header[2] ?? "1") },
        newRange: { start: Number(header[3]), count: Number(header[4] ?? "1") },
        lines: [],
      };
      const context = header[5]?.trim();
      if (context) current.context = context;
      hunks.push(current);
      continue;
    }
    if (!current || rawLine.startsWith("\\ No newline at end of file")) continue;
    if (rawLine.startsWith("+")) {
      current.lines.push({ kind: "added", value: rawLine.slice(1) });
    } else if (rawLine.startsWith("-")) {
      current.lines.push({ kind: "deleted", value: rawLine.slice(1) });
    } else if (rawLine.startsWith(" ")) {
      current.lines.push({ kind: "unchanged_context", value: rawLine.slice(1) });
    }
  }
  return hunks;
}

function runSignatures(lines: DiffLine[]): PatchSignature[] {
  const signatures: PatchSignature[] = [];
  let runKind: DiffLine["kind"] | undefined;
  let runLines: string[] = [];
  const flush = (): void => {
    if (!runKind) return;
    const signature = contentSignature(runKind, runLines);
    if (signature) signatures.push(signature);
    runKind = undefined;
    runLines = [];
  };
  for (const line of lines) {
    if (line.kind !== runKind) {
      flush();
      runKind = line.kind;
    }
    runLines.push(line.value);
  }
  flush();
  return signatures;
}

function hunkSignatures(
  hunk: ParsedHunk,
  pathBefore: string | undefined,
  pathAfter: string | undefined,
): PatchSignature[] {
  const signatures = runSignatures(hunk.lines);
  const preimage = contentSignature(
    "preimage",
    hunk.lines
      .filter((line) => line.kind !== "added")
      .map((line) => line.value),
  );
  const postimage = contentSignature(
    "postimage",
    hunk.lines
      .filter((line) => line.kind !== "deleted")
      .map((line) => line.value),
  );
  if (preimage) signatures.push(preimage);
  if (postimage) signatures.push(postimage);
  signatures.sort((a, b) => a.kind.localeCompare(b.kind) || a.digest.localeCompare(b.digest));

  const combinedInput = [
    pathBefore ?? "",
    pathAfter ?? "",
    hunk.context ?? "",
    ...signatures.map((signature) => `${signature.kind}:${signature.digest}`),
  ].join("\0");
  if (signatures.length > 0) {
    signatures.push({
      algorithm: PATCH_SIGNATURE_ALGORITHM,
      kind: "combined",
      digest: digest("combined", combinedInput),
      line_count: Math.max(preimage?.line_count ?? 0, postimage?.line_count ?? 0),
      normalized_length: Buffer.byteLength(combinedInput, "utf8"),
    });
  }
  return signatures;
}

export function fingerprintPatch(
  patch: string,
  pathBefore?: string,
  pathAfter?: string,
): { hunks: PatchHunk[]; functions: string[] } {
  const parsed = parseHunks(patch);
  const hunks = parsed.map((hunk): PatchHunk => {
    const result: PatchHunk = {
      old_range: hunk.oldRange,
      new_range: hunk.newRange,
      signatures: hunkSignatures(hunk, pathBefore, pathAfter),
    };
    if (hunk.context) result.context = hunk.context;
    return result;
  });
  const functions = [
    ...new Set(parsed.map((hunk) => hunk.context).filter((value): value is string => Boolean(value))),
  ].sort();
  return { hunks, functions };
}
