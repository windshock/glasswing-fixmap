import type { FixImpact } from "../impact/types.js";

export const SOURCE_VERIFICATION_SCHEMA_VERSION = "1.0.0" as const;

export type VerificationDecision =
  | "VERIFIED_FIXED"
  | "TARGET_ABSENT"
  | "PATCH_NOT_FOUND"
  | "AFFECTED"
  | "UNKNOWN"
  | "ERROR";

export type VerificationConfidence = "high" | "medium" | "low";

export type BackendExecutionStatus = "completed" | "unsupported" | "error";

export type ObservationStrength = "strong" | "moderate" | "weak" | "informational";

export type ObservationType =
  | "SOURCE_REPOSITORY_MATCH"
  | "SOURCE_REPOSITORY_MISMATCH"
  | "SOURCE_TREE_PARTIAL"
  | "FIX_COMMIT_ANCESTOR"
  | "FIX_COMMIT_NOT_ANCESTOR"
  | "FIX_POSTIMAGE_PRESENT"
  | "FIX_PREIMAGE_PRESENT"
  | "VULNERABLE_PATTERN_PRESENT"
  | "VULNERABLE_PATTERN_ABSENT"
  | "PATCH_SIGNATURE_ABSENT"
  | "TARGET_FILE_ABSENT"
  | "TARGET_PATH_MOVED"
  | "IMPACT_INCOMPLETE"
  | "BACKEND_UNSUPPORTED"
  | "BACKEND_ERROR";

export interface VerificationEvidence {
  kind: "git" | "file" | "signature" | "configuration";
  locator: string;
  value?: string;
}

export interface VerificationObservation {
  id: string;
  type: ObservationType;
  strength: ObservationStrength;
  repository?: string;
  commit?: string;
  target_file?: string;
  actual_file?: string;
  hunk_index?: number;
  detail: string;
  evidence: VerificationEvidence[];
}

export interface VerifierBackend {
  name: string;
  version: string;
}

export interface VerifierResult {
  backend: VerifierBackend;
  execution_status: BackendExecutionStatus;
  observations: VerificationObservation[];
  warnings: string[];
}

export interface VerificationContext {
  antId: string;
  sourceRoot: string;
  impacts: FixImpact[];
}

export interface SourceVerifier {
  readonly name: string;
  verify(context: VerificationContext): Promise<VerifierResult>;
}

export type DecisionReasonCode =
  | "NATIVE_POSTIMAGE_MATCH"
  | "ANCESTRY_CORROBORATED"
  | "PREIMAGE_PRESENT"
  | "PATCH_SIGNATURE_ABSENT"
  | "TARGET_ABSENT"
  | "VERIFIER_CONFLICT"
  | "INSUFFICIENT_EVIDENCE"
  | "BACKEND_FAILURE";

export interface DecisionReason {
  code: DecisionReasonCode;
  detail: string;
  observation_ids: string[];
}

export interface SourceVerificationReport {
  schema_version: typeof SOURCE_VERIFICATION_SCHEMA_VERSION;
  ant_id: string;
  source: string;
  impact_schema_version: string;
  targets: Array<{ repository: string; commit: string }>;
  backend_results: VerifierResult[];
  decision: VerificationDecision;
  confidence: VerificationConfidence;
  reasons: DecisionReason[];
}
