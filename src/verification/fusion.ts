import type { FixImpact } from "../impact/types.js";
import type {
  DecisionReason,
  SourceVerificationReport,
  VerificationConfidence,
  VerificationDecision,
  VerificationObservation,
  VerifierResult,
} from "./types.js";

type FusionResult = Pick<SourceVerificationReport, "decision" | "confidence" | "reasons">;

const VULNERABLE_TYPES = new Set([
  "FIX_PREIMAGE_PRESENT",
  "VULNERABLE_PATTERN_PRESENT",
]);

const INCONCLUSIVE_TYPES = new Set([
  "PATCH_SIGNATURE_ABSENT",
  "TARGET_FILE_ABSENT",
  "TARGET_PATH_MOVED",
  "BACKEND_UNSUPPORTED",
  "BACKEND_ERROR",
]);

function observationIds(observations: VerificationObservation[]): string[] {
  return [...new Set(observations.map((item) => item.id))].sort();
}

function reason(
  code: DecisionReason["code"],
  detail: string,
  observations: VerificationObservation[],
): DecisionReason {
  return { code, detail, observation_ids: observationIds(observations) };
}

function result(
  decision: VerificationDecision,
  confidence: VerificationConfidence,
  reasons: DecisionReason[],
): FusionResult {
  return { decision, confidence, reasons };
}

function impactKey(repository: string | undefined, commit: string | undefined): string | undefined {
  return repository && commit ? `${repository.toLowerCase()}@${commit.toLowerCase()}` : undefined;
}

function forImpact(
  observations: VerificationObservation[],
  impact: FixImpact,
): VerificationObservation[] {
  const key = impactKey(impact.repository, impact.commit);
  return observations.filter((item) => impactKey(item.repository, item.commit) === key);
}

function hasType(observations: VerificationObservation[], type: string): boolean {
  return observations.some((item) => item.type === type);
}

function candidateIsNativelyComplete(observations: VerificationObservation[]): boolean {
  return hasType(observations, "FIX_POSTIMAGE_PRESENT") &&
    !observations.some((item) => INCONCLUSIVE_TYPES.has(item.type)) &&
    !observations.some((item) => VULNERABLE_TYPES.has(item.type));
}

/**
 * Combine evidence conservatively. Verifier backends produce observations; they
 * are not voters, and backend count never increases confidence by itself.
 */
export function fuseVerificationEvidence(
  impacts: FixImpact[],
  backendResults: VerifierResult[],
): FusionResult {
  const observations = backendResults.flatMap((backend) => backend.observations);
  const fingerprintObservations = backendResults
    .filter((backend) => backend.backend.name === "glasswing-fingerprint")
    .flatMap((backend) => backend.observations);
  const fixed = observations.filter((item) => item.type === "FIX_POSTIMAGE_PRESENT");
  const vulnerable = observations.filter((item) => VULNERABLE_TYPES.has(item.type));
  const ancestry = observations.filter((item) => item.type === "FIX_COMMIT_ANCESTOR");
  const repositoryMismatch = observations.filter(
    (item) => item.type === "SOURCE_REPOSITORY_MISMATCH",
  );
  const partialTree = observations.filter((item) => item.type === "SOURCE_TREE_PARTIAL");
  const signatureAbsent = observations.filter((item) => item.type === "PATCH_SIGNATURE_ABSENT");

  if (
    repositoryMismatch.length > 0 ||
    (fixed.length > 0 && vulnerable.length > 0) ||
    (fixed.length > 0 && signatureAbsent.length > 0) ||
    (ancestry.length > 0 && vulnerable.length > 0)
  ) {
    const conflicts = [
      ...repositoryMismatch,
      ...fixed,
      ...vulnerable,
      ...signatureAbsent,
      ...ancestry,
    ];
    return result("UNKNOWN", "low", [
      reason(
        "VERIFIER_CONFLICT",
        repositoryMismatch.length > 0
          ? "The source repository identity conflicts with the selected fix impact."
          : "Fixed, pre-fix, or missing-signature evidence conflicts; a revert, partial backport, or refactor is possible.",
        conflicts,
      ),
    ]);
  }

  for (const impact of impacts) {
    const nativeCandidate = forImpact(fingerprintObservations, impact);
    if (!candidateIsNativelyComplete(nativeCandidate)) continue;
    const postimages = nativeCandidate.filter((item) => item.type === "FIX_POSTIMAGE_PRESENT");
    const strong = postimages.some((item) => item.strength === "strong");
    const candidateAncestry = forImpact(ancestry, impact);
    if (strong || candidateAncestry.length > 0) {
      const reasons = [
        reason(
          "NATIVE_POSTIMAGE_MATCH",
          "All inspectable patch hunks reported by glasswing-fingerprint match the post-fix source image.",
          postimages,
        ),
      ];
      if (candidateAncestry.length > 0) {
        reasons.push(
          reason(
            "ANCESTRY_CORROBORATED",
            "Git ancestry independently corroborates the native patch match.",
            candidateAncestry,
          ),
        );
      }
      return result("VERIFIED_FIXED", strong ? "high" : "medium", reasons);
    }
  }

  if (ancestry.length > 0 && signatureAbsent.length > 0) {
    return result("UNKNOWN", "low", [
      reason(
        "VERIFIER_CONFLICT",
        "The fix commit is in history, but its expected source signature is not present at HEAD.",
        [...ancestry, ...signatureAbsent],
      ),
    ]);
  }

  if (vulnerable.length > 0) {
    const confidence = vulnerable.some((item) => item.strength === "strong")
      ? "high"
      : "medium";
    return result("PATCH_NOT_FOUND", confidence, [
      reason(
        "PREIMAGE_PRESENT",
        "A pre-fix source image or deleted-line pattern remains present; this does not by itself prove AFFECTED.",
        vulnerable,
      ),
    ]);
  }

  if (signatureAbsent.length > 0) {
    return result("PATCH_NOT_FOUND", "medium", [
      reason(
        "PATCH_SIGNATURE_ABSENT",
        "The relevant file was inspected, but the expected fix signature was not found; this does not prove AFFECTED.",
        signatureAbsent,
      ),
    ]);
  }

  const absent = observations.filter((item) => item.type === "TARGET_FILE_ABSENT");
  const repositoryMatch = observations.filter((item) => item.type === "SOURCE_REPOSITORY_MATCH");
  const ambiguity = fingerprintObservations.filter(
    (item) => item.type === "TARGET_PATH_MOVED" ||
      item.type === "BACKEND_UNSUPPORTED" ||
      item.type === "BACKEND_ERROR",
  );
  if (
    absent.length > 0 &&
    repositoryMatch.length > 0 &&
    partialTree.length === 0 &&
    ambiguity.length === 0 &&
    impacts.every((impact) => {
      const native = forImpact(fingerprintObservations, impact);
      return native.length > 0 && native.every((item) => item.type === "TARGET_FILE_ABSENT");
    })
  ) {
    return result("TARGET_ABSENT", "medium", [
      reason(
        "TARGET_ABSENT",
        "Repository identity is established and every relevant target file is absent from a complete source tree.",
        [...repositoryMatch, ...absent],
      ),
    ]);
  }

  const backendErrors = backendResults.filter((backend) => backend.execution_status === "error");
  const completed = backendResults.filter((backend) => backend.execution_status === "completed");
  if (backendErrors.length > 0 && completed.length === 0) {
    const errors = observations.filter((item) => item.type === "BACKEND_ERROR");
    return result("ERROR", "low", [
      reason("BACKEND_FAILURE", "Every usable verifier backend failed.", errors),
    ]);
  }

  const inconclusive = observations.filter(
    (item) => item.type === "TARGET_PATH_MOVED" ||
      item.type === "TARGET_FILE_ABSENT" ||
      item.type === "SOURCE_TREE_PARTIAL" ||
      item.type === "BACKEND_UNSUPPORTED" ||
      item.type === "BACKEND_ERROR" ||
      item.type === "FIX_COMMIT_ANCESTOR" ||
      item.type === "FIX_COMMIT_NOT_ANCESTOR" ||
      item.type === "FIX_POSTIMAGE_PRESENT" ||
      item.type === "VULNERABLE_PATTERN_ABSENT",
  );
  return result("UNKNOWN", "low", [
    reason(
      "INSUFFICIENT_EVIDENCE",
      "Available observations are incomplete or ambiguous and do not support a stronger conclusion.",
      inconclusive,
    ),
  ]);
}
