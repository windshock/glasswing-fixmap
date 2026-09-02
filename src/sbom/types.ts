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

export type MatchType = "exact_purl" | "ecosystem_package" | "repository" | "name_heuristic";

export type IdentityStrength = "strong" | "weak";

export type CandidateConfidence = "high" | "medium" | "low";

/** Result of evaluating an authoritative affected range against a version. */
export type RangeVerdict = "affected" | "not_affected" | "unknown";

export interface RangeAssessment {
  verdict: RangeVerdict;
  /** Why the verdict was reached — always explains an `unknown` conservatively. */
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
    repository?: string;
    locations: string[];
  };
  finding_identity: {
    ecosystem?: string;
    package?: string;
  };
  /** Present only when an authoritative range and a supporting comparator exist. */
  range_assessment?: RangeAssessment;
  /** Present only when `--source` resolves an unambiguous candidate. */
  verification?: SourceVerificationReport;
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
