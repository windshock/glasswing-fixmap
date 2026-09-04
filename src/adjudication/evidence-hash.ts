import { createHash } from "node:crypto";

/**
 * The full decision context an adjudication is bound to. Every material input
 * that could change the correct disposition is included, so a stored review is
 * reused only while the evidence is unchanged and is invalidated the moment any
 * of it moves (issue #4, Tier 2.10). This is a deterministic key, not a store.
 */
export interface EvidenceKey {
  /** Anthropic finding identity. */
  ant_id: string;
  cve_ids?: string[];
  ghsa_ids?: string[];
  /** Component identity: canonical PURL and/or CPE, plus version. */
  component_purl?: string | null;
  component_cpes?: string[];
  component_version?: string | null;
  /** Digest of the SBOM document the component came from. */
  sbom_digest?: string | null;
  /** Fixmap snapshot the deterministic evidence was produced from. */
  fixmap_source_revision?: number | string | null;
  fixmap_source_manifest_sha3?: string | null;
  /** Digest of the specific affected-range record(s) applied. */
  affected_range_digest?: string | null;
  /** Digest of the fix-impact dataset/record used, if any. */
  fix_impact_digest?: string | null;
  /** Digest of the source-verification report, if any. */
  source_verification_digest?: string | null;
  /** How strongly the inspected source was bound to the component. */
  source_binding?: string | null;
  /** The deterministic machine decision being adjudicated. */
  machine_decision: string;
  /** The adjudicator ruleset / Skill commit the review was produced under. */
  adjudicator_ruleset?: string | null;
}

/** Recursively sort object keys so serialization is order-independent. */
function canonicalize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalize);
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return Object.fromEntries(entries.map(([k, v]) => [k, canonicalize(v)]));
  }
  return value;
}

/**
 * A stable SHA-256 over the canonicalized evidence key. Independent of property
 * order and of absent/undefined fields; sensitive to every present value. Arrays
 * whose order is not semantically meaningful (IDs, CPEs) are sorted first so an
 * ordering difference does not spuriously invalidate a prior review.
 */
export function computeEvidenceHash(key: EvidenceKey): string {
  const normalized: EvidenceKey = {
    ...key,
    ...(key.cve_ids ? { cve_ids: [...key.cve_ids].sort() } : {}),
    ...(key.ghsa_ids ? { ghsa_ids: [...key.ghsa_ids].sort() } : {}),
    ...(key.component_cpes ? { component_cpes: [...key.component_cpes].sort() } : {}),
  };
  const canonical = JSON.stringify(canonicalize(normalized));
  return createHash("sha256").update(canonical).digest("hex");
}
