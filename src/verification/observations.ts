import type {
  ObservationStrength,
  ObservationType,
  VerificationEvidence,
  VerificationObservation,
} from "./types.js";

export interface ObservationInput {
  backend: string;
  type: ObservationType;
  strength: ObservationStrength;
  repository?: string;
  commit?: string;
  targetFile?: string;
  actualFile?: string;
  hunkIndex?: number;
  detail: string;
  evidence?: VerificationEvidence[];
}

export function observation(input: ObservationInput): VerificationObservation {
  const location = [
    input.repository && input.commit ? `${input.repository}@${input.commit}` : undefined,
    input.targetFile,
    input.actualFile && input.actualFile !== input.targetFile ? input.actualFile : undefined,
    input.hunkIndex === undefined ? undefined : `hunk-${input.hunkIndex}`,
  ].filter(Boolean).join(":");
  const result: VerificationObservation = {
    id: `${input.backend}:${input.type}${location ? `:${location}` : ""}`,
    type: input.type,
    strength: input.strength,
    detail: input.detail,
    evidence: input.evidence ?? [],
  };
  if (input.repository) result.repository = input.repository;
  if (input.commit) result.commit = input.commit;
  if (input.targetFile) result.target_file = input.targetFile;
  if (input.actualFile) result.actual_file = input.actualFile;
  if (input.hunkIndex !== undefined) result.hunk_index = input.hunkIndex;
  return result;
}

export function sortObservations(
  observations: VerificationObservation[],
): VerificationObservation[] {
  return observations.sort((a, b) => a.id.localeCompare(b.id) || a.detail.localeCompare(b.detail));
}
