import type { AdjudicationRecord } from "./types.js";

/**
 * Minimal OpenVEX (v0.2.0) projection. VEX is an *export* representation, not the
 * canonical internal model: the richer internal states (PATCH_NOT_FOUND,
 * VERIFIER_CONFLICT, UNKNOWN, INSUFFICIENT_EVIDENCE, …) collapse conservatively so
 * VEX is never a shortcut around weak identity or unresolved provenance. Only a
 * human disposition, a strong-identity AFFECTED, or absent vulnerable code becomes
 * a definite status; everything else is `under_investigation`.
 */
export type OpenVexStatus = "affected" | "fixed" | "not_affected" | "under_investigation";

export interface OpenVexStatement {
  vulnerability: { name: string };
  products: Array<{ "@id": string }>;
  status: OpenVexStatus;
  justification?: string;
  impact_statement?: string;
  action_statement?: string;
}

export interface OpenVexDocument {
  "@context": "https://openvex.dev/ns/v0.2.0";
  "@id": string;
  author: string;
  timestamp: string;
  version: number;
  statements: OpenVexStatement[];
}

export interface OpenVexMeta {
  author: string;
  timestamp: string;
  id: string;
}

function productId(record: AdjudicationRecord): string {
  const component = record.subject.component;
  if (component.purl) return component.purl;
  return `${component.name}${component.version ? `@${component.version}` : ""}`;
}

function statusFor(record: AdjudicationRecord): Omit<OpenVexStatement, "vulnerability" | "products"> {
  // A human disposition is authoritative.
  if (record.human_review) {
    switch (record.human_review.disposition) {
      case "affected":
        return { status: "affected" };
      case "not_affected":
        return record.human_review.justification
          ? { status: "not_affected", impact_statement: record.human_review.justification }
          : { status: "not_affected", impact_statement: "human review: not affected" };
      case "under_investigation":
        return { status: "under_investigation" };
    }
  }
  // Otherwise the deterministic machine decision, collapsed conservatively.
  switch (record.machine_decision) {
    case "AFFECTED":
      // candidate_decision only yields AFFECTED for strong identity.
      return { status: "affected", action_statement: "update to a fixed release" };
    case "TARGET_ABSENT":
      return { status: "not_affected", justification: "vulnerable_code_not_present" };
    case "NOT_AFFECTED":
      return { status: "not_affected", impact_statement: "installed version is outside every authoritative affected range" };
    // VERIFIED_FIXED is not exported as `fixed`: ordinary --source is user_asserted,
    // not a machine-confirmed build/version binding.
    default:
      return { status: "under_investigation" };
  }
}

export function projectRecordToOpenVex(record: AdjudicationRecord): OpenVexStatement[] {
  const vulnerabilities = record.finding?.vulnerability_ids?.length
    ? record.finding.vulnerability_ids
    : [record.subject.ant_id];
  const product = productId(record);
  const base = statusFor(record);
  return vulnerabilities.map((name) => ({ vulnerability: { name }, products: [{ "@id": product }], ...base }));
}

export function projectToOpenVex(records: AdjudicationRecord[], meta: OpenVexMeta): OpenVexDocument {
  return {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": meta.id,
    author: meta.author,
    timestamp: meta.timestamp,
    version: 1,
    statements: records.flatMap(projectRecordToOpenVex),
  };
}
