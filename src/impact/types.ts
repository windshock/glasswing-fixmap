import type { Evidence } from "../types.js";

export const FIX_IMPACT_SCHEMA_VERSION = "1.0.0" as const;
export const PATCH_SIGNATURE_ALGORITHM = "glasswing-normalized-sha256-v1" as const;

export type ChangedFileStatus = "added" | "modified" | "deleted" | "renamed";

export type PatchSignatureKind =
  | "added"
  | "deleted"
  | "unchanged_context"
  | "preimage"
  | "postimage"
  | "combined";

export interface PatchSignature {
  algorithm: typeof PATCH_SIGNATURE_ALGORITHM;
  kind: PatchSignatureKind;
  digest: string;
  line_count: number;
  normalized_length: number;
}

export interface LineRange {
  start: number;
  count: number;
}

export interface PatchHunk {
  old_range: LineRange;
  new_range: LineRange;
  context?: string;
  signatures: PatchSignature[];
}

export interface ChangedFile {
  path_before?: string;
  path_after?: string;
  status: ChangedFileStatus;
  patch_available: boolean;
  functions?: string[];
  hunks: PatchHunk[];
}

export type ImpactExtractionStatus = "complete" | "partial" | "error";

export interface FixImpact {
  repository: string;
  commit: string;
  ant_ids: string[];
  extraction_status: ImpactExtractionStatus;
  files: ChangedFile[];
  evidence: Evidence[];
  warnings: string[];
}

export interface FixImpactMetadata {
  schema_version: typeof FIX_IMPACT_SCHEMA_VERSION;
  generated_from: {
    fixmap_schema_version: string;
    source_as_of: string;
    source_url: string;
  };
  finding_count: number;
  impact_count: number;
  complete_count: number;
  partial_count: number;
  error_count: number;
}

export interface FixImpactDataset {
  metadata: FixImpactMetadata;
  impacts: FixImpact[];
}
