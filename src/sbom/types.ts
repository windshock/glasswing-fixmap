import type { SourceVerificationReport } from "../verification/types.js";

export const SBOM_CHECK_SCHEMA_VERSION = "1.0.0" as const;

export type SbomFormat = "cyclonedx" | "syft";

/**
 * A thin projection of a validated SBOM component. Only the fields needed for
 * conservative candidate selection are retained; no second CycloneDX/Syft
 * object model is constructed.
 */
export interface NormalizedComponent {
  source_format: SbomFormat;
  type?: string;
  name: string;
  version?: string;
  /** Canonical PackageURL (packageurl-js round-trip). Absent when unparseable. */
  purl?: string;
  cpes: string[];
  repository?: string;
  locations: string[];
}

export interface SbomParseResult {
  format: SbomFormat;
  spec_version?: string;
  components: NormalizedComponent[];
  warnings: string[];
}

export interface SbomAdapter {
  readonly format: SbomFormat;
  supports(document: unknown): boolean;
  parse(document: unknown): Promise<SbomParseResult>;
}

export type MatchType = "exact_purl" | "cpe_match" | "ecosystem_package" | "repository" | "name_heuristic";

export type IdentityStrength = "strong" | "weak";

export type CandidateConfidence = "high" | "medium" | "low";

/** Result of evaluating an authoritative affected range against a version. */
export type RangeVerdict = "affected" | "not_affected" | "unknown";

/**
 * How strongly the inspected `--source` tree is bound to the SBOM component.
 * `verified` requires machine-confirmed repository AND version correspondence;
 * `user_asserted` means the operator pointed `--source` at a tree without that
 * confirmation; `unverified` means the checkout's repository identity conflicts.
 */
export type SourceBinding = "verified" | "user_asserted" | "unverified";

export interface RangeAssessment {
  verdict: RangeVerdict;
  /** Why the verdict was reached — always explains an `unknown` conservatively. */
  reason: string;
}

/** Final, product-level disposition of a candidate. */
export type CandidateDecisionValue =
  | "AFFECTED"
  | "NOT_AFFECTED"
  | "VERIFIED_FIXED"
  | "TARGET_ABSENT"
  | "PATCH_NOT_FOUND"
  | "UNKNOWN"
  | "ERROR";

/**
 * The explicit, final candidate decision, kept separate from `range_assessment`
 * (which is only version/range evidence). A weak, name-only candidate can carry
 * `range_assessment.verdict = "affected"` yet a `decision = "UNKNOWN"` with
 * `gating_eligible = false`, so a downstream consumer or VEX exporter cannot
 * mistake range evidence for a gating vulnerability disposition.
 */
export interface CandidateDecision {
  decision: CandidateDecisionValue;
  /** The underlying authoritative-range verdict, when one was evaluated. */
  range_verdict?: RangeVerdict;
  identity: IdentityStrength;
  /** Whether this decision may fail a security gate (`--fail-on-affected`). */
  gating_eligible: boolean;
  reason: string;
}

export interface ComponentCandidate {
  ant_id: string;
  project: string;
  match_type: MatchType;
  identity_strength: IdentityStrength;
  confidence: CandidateConfidence;
  component: {
    source_format: SbomFormat;
    name: string;
    version?: string;
    purl?: string;
    cpes?: string[];
    repository?: string;
    locations: string[];
  };
  finding_identity: {
    ecosystem?: string;
    package?: string;
  };
  /** Present when identity was established or refuted by a CPE 2.3 match. */
  identity_evidence?: {
    component_cpe: string;
    range_cpe: string;
    relation: "match";
  };
  /** Present only when an authoritative range and a supporting comparator exist. */
  range_assessment?: RangeAssessment;
  /** Present only when `--source` resolves an unambiguous candidate. */
  verification?: SourceVerificationReport;
  /** Provenance of the `--source` binding; present whenever `verification` is. */
  source_binding?: SourceBinding;
  /**
   * Final product-level disposition, distinct from `range_assessment` evidence.
   * Always populated by `checkSbom` for every candidate it returns.
   */
  candidate_decision?: CandidateDecision;
}

export interface SbomCheckReport {
  schema_version: typeof SBOM_CHECK_SCHEMA_VERSION;
  sbom: string;
  format: SbomFormat;
  spec_version?: string;
  document_count: number;
  component_count: number;
  package_component_count: number;
  candidates: ComponentCandidate[];
  warnings: string[];
}
