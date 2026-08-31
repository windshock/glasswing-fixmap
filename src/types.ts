export const OUTPUT_SCHEMA_VERSION = "1.0.0" as const;

export type Confidence = "verified" | "high" | "medium" | "low";

export type EvidenceSource =
  | "anthropic_ledger"
  | "anthropic_finding"
  | "github_advisory_database"
  | "cve_list_v5"
  | "osv"
  | "github_repository"
  | "manual_override";

export interface Evidence {
  source: EvidenceSource;
  url: string;
  locator?: string;
  note?: string;
}

export interface FixCommit {
  sha: string;
  url: string;
  repository?: string;
  confidence: Confidence;
  evidence: Evidence[];
}

export interface FixReference {
  kind: "pull_request" | "patch" | "changeset";
  url: string;
  repository?: string;
  number?: number;
  confidence: Confidence;
  evidence: Evidence[];
}

export type CommitVerificationStatus =
  | "not_run"
  | "verified_contains_fix"
  | "tag_not_found"
  | "fix_not_in_tag"
  | "repository_unknown"
  | "error";

export interface CommitVerification {
  status: CommitVerificationStatus;
  repository?: string;
  tag?: string;
  fix_sha?: string;
  url?: string;
  detail?: string;
}

export interface FixedVersion {
  version: string;
  package?: string;
  ecosystem?: string;
  branch?: string;
  introduced?: string;
  role: "first_patched" | "patched" | "nightly" | "operational_baseline";
  first_patched: boolean | null;
  confidence: Confidence;
  evidence: Evidence[];
  commit_verification: CommitVerification;
}

export interface ReleaseAssessment {
  status:
    | "confirmed_versions"
    | "commit_only"
    | "no_release_yet"
    | "unresolved"
    | "not_applicable";
  note?: string;
  evidence: Evidence[];
}

export interface FindingRecord {
  schema_version: typeof OUTPUT_SCHEMA_VERSION;
  ant_id: string;
  project: string;
  title: string | null;
  bug_class: string | null;
  severity: {
    claude: string | null;
    firm: string | null;
    maintainer: string | null;
  };
  status: string;
  patched: boolean;
  patched_at: string | null;
  discovered_on: string | null;
  revealed_at: string | null;
  withdrawn: boolean;
  cve_ids: string[];
  ghsa_ids: string[];
  fix_commits: FixCommit[];
  fix_references: FixReference[];
  fixed_versions: FixedVersion[];
  release_assessment: ReleaseAssessment;
  enrichment: {
    status: "complete" | "partial" | "unresolved" | "not_patched";
    warnings: string[];
  };
  sources: Evidence[];
}

export interface DatasetMetadata {
  schema_version: typeof OUTPUT_SCHEMA_VERSION;
  source_as_of: string;
  source_revision: number | string | null;
  source_manifest_sha3: string | null;
  source_url: string;
  finding_count: number;
  patched_count: number;
  with_fix_commit: number;
  with_fixed_version: number;
  complete_count: number;
  partial_count: number;
  unresolved_count: number;
}

export interface FixmapDataset {
  metadata: DatasetMetadata;
  findings: FindingRecord[];
}

export interface AnthropicLedgerEntry {
  ant_id: string | null;
  project: string | null;
  bug_class: string | null;
  claude_severity: string | null;
  vendor_severity: string | null;
  maintainer_severity: string | null;
  status: string;
  patched: boolean;
  patched_at: string | null;
  discovered_on: string | null;
  revealed_at: string | null;
  withdrawn: boolean;
  cve_ids: string[];
  ghsa_ids: string[];
  corrected_cve_ids?: string[];
  corrected_ghsa_ids?: string[];
}

export interface AnthropicIdentifierFinding {
  ant_id: string;
  title?: string;
  project?: string;
  bug_class?: string;
}

export interface AnthropicPayload {
  as_of: string;
  revision: number | string | null;
  manifest_sha3?: string | null;
  ledger: AnthropicLedgerEntry[];
  cve_records?: Array<{ findings?: AnthropicIdentifierFinding[] }>;
  ghsa_records?: Array<{ findings?: AnthropicIdentifierFinding[] }>;
}

export interface ParsedFindingPage {
  title: string | null;
  fix_commits: FixCommit[];
  fix_references: FixReference[];
  fixed_versions: FixedVersion[];
  links: string[];
}

export interface EnrichmentFragment {
  cve_ids?: string[];
  ghsa_ids?: string[];
  fix_commits: FixCommit[];
  fix_references: FixReference[];
  fixed_versions: FixedVersion[];
  sources: Evidence[];
  warnings: string[];
}

export interface ManualOverride {
  project?: string;
  title?: string;
  cve_ids?: string[];
  ghsa_ids?: string[];
  release_assessment?: {
    status: ReleaseAssessment["status"];
    evidence_url: string;
    note?: string;
  };
  fix_commits?: Array<{
    sha: string;
    url: string;
    repository?: string;
    evidence_url: string;
    note?: string;
  }>;
  fix_references?: Array<{
    kind: "pull_request" | "patch" | "changeset";
    url: string;
    repository?: string;
    number?: number;
    evidence_url: string;
    note?: string;
  }>;
  fixed_versions?: Array<{
    version: string;
    package?: string;
    ecosystem?: string;
    branch?: string;
    introduced?: string;
    role?: FixedVersion["role"];
    first_patched: boolean | null;
    confidence?: Confidence;
    evidence_url: string;
    note?: string;
  }>;
}

export type ManualOverrides = Record<string, ManualOverride>;
