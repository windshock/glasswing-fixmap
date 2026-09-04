export const ADJUDICATION_SCHEMA_VERSION = "1.0.0" as const;

/** The machine, AI, and human layers of one adjudication, kept separate. */
export interface AdjudicationRecord {
  /** Deterministic key binding this record to its full decision context. */
  evidence_hash: string;
  /** When the record was written (caller-supplied; kept out of the hash). */
  recorded_at: string;
  subject: {
    ant_id: string;
    component: { name: string; version?: string; purl?: string; cpes?: string[] };
  };
  /** The deterministic engine decision this adjudication is attached to. */
  machine_decision: string;
  /** AI second opinion (verdict is review metadata, never a gate). */
  ai_review?: {
    verdict: "CONFIRMED" | "LIKELY_TRUE_POSITIVE" | "LIKELY_FALSE_POSITIVE" | "INSUFFICIENT_EVIDENCE";
    confidence: "high" | "medium" | "low";
    summary: string;
  };
  /** Human disposition — the only thing that may authorize a suppression. */
  human_review?: {
    disposition: "affected" | "not_affected" | "under_investigation";
    approved_by: string;
    justification?: string;
  };
  /** evidence_hash of a prior record this one replaces (audit chain). */
  supersedes?: string;
  /** Explicitly retired without a replacement. */
  invalidated?: boolean;
}

export interface AdjudicationStore {
  metadata: { schema_version: typeof ADJUDICATION_SCHEMA_VERSION };
  /** Append-only: a newer record supersedes an older one, never overwrites it. */
  records: AdjudicationRecord[];
}
