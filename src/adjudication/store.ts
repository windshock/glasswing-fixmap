import { readFile } from "node:fs/promises";
import { atomicWrite } from "../output.js";
import type { ComponentCandidate } from "../sbom/types.js";
import { computeEvidenceHash, type EvidenceKey } from "./evidence-hash.js";
import {
  ADJUDICATION_SCHEMA_VERSION,
  type AdjudicationRecord,
  type AdjudicationStore,
} from "./types.js";

export function emptyStore(): AdjudicationStore {
  return { metadata: { schema_version: ADJUDICATION_SCHEMA_VERSION }, records: [] };
}

export function validateAdjudicationStore(store: AdjudicationStore): string[] {
  const errors: string[] = [];
  if (!store || typeof store !== "object" || !Array.isArray(store.records)) {
    return ["Adjudication store must contain a records array"];
  }
  if (store.metadata?.schema_version !== ADJUDICATION_SCHEMA_VERSION) {
    errors.push(`metadata.schema_version must be ${ADJUDICATION_SCHEMA_VERSION}`);
  }
  store.records.forEach((record, index) => {
    if (typeof record.evidence_hash !== "string" || !/^[0-9a-f]{64}$/.test(record.evidence_hash)) {
      errors.push(`records[${index}]: evidence_hash must be a sha256 hex digest`);
    }
    if (typeof record.machine_decision !== "string" || record.machine_decision.length === 0) {
      errors.push(`records[${index}]: missing machine_decision`);
    }
    if (!record.subject?.ant_id) errors.push(`records[${index}]: missing subject.ant_id`);
  });
  return errors;
}

export async function readAdjudicationStore(file: string): Promise<AdjudicationStore> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    throw new Error(`Malformed adjudication store ${file}: ${error instanceof Error ? error.message : String(error)}`);
  }
  const store = parsed as AdjudicationStore;
  const errors = validateAdjudicationStore(store);
  if (errors.length > 0) throw new Error(`Invalid adjudication store ${file}:\n${errors.join("\n")}`);
  return store;
}

/** Append a record without mutating the input store (append-only history). */
export function appendAdjudication(store: AdjudicationStore, record: AdjudicationRecord): AdjudicationStore {
  return { metadata: store.metadata, records: [...store.records, record] };
}

export async function writeAdjudicationStore(store: AdjudicationStore, file: string): Promise<void> {
  const errors = validateAdjudicationStore(store);
  if (errors.length > 0) throw new Error(`Invalid adjudication store:\n${errors.join("\n")}`);
  await atomicWrite(file, `${JSON.stringify(store, null, 2)}\n`);
}

/**
 * The current review for an evidence hash: the latest appended record for that
 * hash (append-only, so latest-wins for a same-evidence correction), unless that
 * latest record was explicitly `invalidated`. A different evidence hash returns
 * nothing — that is the automatic invalidation: when the version, applied range,
 * fixmap snapshot, or machine decision moves, the hash moves and the prior
 * review no longer applies. `supersedes` is a pure audit link to the prior
 * record and does not affect lookup.
 */
export function lookupAdjudication(store: AdjudicationStore, evidenceHash: string): AdjudicationRecord | undefined {
  let latest: AdjudicationRecord | undefined;
  for (const record of store.records) {
    if (record.evidence_hash === evidenceHash) latest = record;
  }
  if (!latest || latest.invalidated) return undefined;
  return latest;
}

/**
 * Build the evidence key for a candidate. Binds component identity and the
 * machine decision; the caller supplies the surrounding snapshot/digests so the
 * hash also moves when the fixmap snapshot or applied range moves.
 */
export function evidenceKeyForCandidate(
  candidate: ComponentCandidate,
  context: Omit<EvidenceKey, "ant_id" | "component_purl" | "component_cpes" | "component_version" | "machine_decision"> = {},
): EvidenceKey {
  return {
    ...context,
    ant_id: candidate.ant_id,
    component_purl: candidate.component.purl ?? null,
    component_cpes: candidate.component.cpes ?? [],
    component_version: candidate.component.version ?? null,
    machine_decision: candidate.candidate_decision?.decision ?? "UNKNOWN",
  };
}

export function evidenceHashForCandidate(
  candidate: ComponentCandidate,
  context?: Parameters<typeof evidenceKeyForCandidate>[1],
): string {
  return computeEvidenceHash(evidenceKeyForCandidate(candidate, context));
}
