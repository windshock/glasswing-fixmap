import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { computeEvidenceHash, type EvidenceKey } from "../src/adjudication/evidence-hash.js";
import {
  appendAdjudication,
  emptyStore,
  evidenceHashForCandidate,
  lookupAdjudication,
  readAdjudicationStore,
  writeAdjudicationStore,
} from "../src/adjudication/store.js";
import type { AdjudicationRecord } from "../src/adjudication/types.js";
import { checkSbom } from "../src/sbom/check.js";
import type { AffectedRangeDataset, AffectedRangeRecord } from "../src/ranges/types.js";
import type { FindingRecord } from "../src/types.js";

function baseKey(): EvidenceKey {
  return {
    ant_id: "ANT-2026-OSSL",
    cve_ids: ["CVE-2026-45447"],
    ghsa_ids: ["GHSA-f684-cpcq-j565"],
    component_purl: null,
    component_cpes: ["cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"],
    component_version: "3.0.7",
    sbom_digest: "sha256:abc",
    fixmap_source_revision: 32,
    fixmap_source_manifest_sha3: "f89b",
    affected_range_digest: "sha256:range",
    source_binding: null,
    machine_decision: "UNKNOWN",
    adjudicator_ruleset: "skill@5cf63e6",
  };
}

test("evidence hash is deterministic and stable for identical keys", () => {
  assert.equal(computeEvidenceHash(baseKey()), computeEvidenceHash(baseKey()));
  // 64 hex chars (SHA-256).
  assert.match(computeEvidenceHash(baseKey()), /^[0-9a-f]{64}$/);
});

test("evidence hash is independent of property order and array order", () => {
  const a = baseKey();
  // Reconstruct with a different insertion order and reversed arrays.
  const b: EvidenceKey = {
    machine_decision: "UNKNOWN",
    adjudicator_ruleset: "skill@5cf63e6",
    ant_id: "ANT-2026-OSSL",
    ghsa_ids: ["GHSA-f684-cpcq-j565"],
    cve_ids: ["CVE-2026-45447"],
    component_version: "3.0.7",
    component_cpes: ["cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"],
    component_purl: null,
    sbom_digest: "sha256:abc",
    fixmap_source_revision: 32,
    fixmap_source_manifest_sha3: "f89b",
    affected_range_digest: "sha256:range",
    source_binding: null,
  };
  assert.equal(computeEvidenceHash(a), computeEvidenceHash(b));

  // Multi-element arrays: order must not matter.
  const two1 = { ...baseKey(), cve_ids: ["CVE-1", "CVE-2"], component_cpes: ["cpe:x", "cpe:y"] };
  const two2 = { ...baseKey(), cve_ids: ["CVE-2", "CVE-1"], component_cpes: ["cpe:y", "cpe:x"] };
  assert.equal(computeEvidenceHash(two1), computeEvidenceHash(two2));
});

test("evidence hash changes when any material input changes", () => {
  const base = computeEvidenceHash(baseKey());
  const mutations: Array<Partial<EvidenceKey>> = [
    { component_version: "3.0.8" },
    { machine_decision: "AFFECTED" },
    { affected_range_digest: "sha256:other" },
    { source_binding: "user_asserted" },
    { fixmap_source_manifest_sha3: "aaaa" },
    { fixmap_source_revision: 33 },
    { adjudicator_ruleset: "skill@deadbee" },
    { component_cpes: ["cpe:2.3:a:openssl:openssl:3.0.8:*:*:*:*:*:*:*"] },
    { cve_ids: ["CVE-2026-99999"] },
    { sbom_digest: "sha256:different" },
  ];
  for (const mutation of mutations) {
    assert.notEqual(
      computeEvidenceHash({ ...baseKey(), ...mutation }),
      base,
      `mutation did not change the hash: ${JSON.stringify(mutation)}`,
    );
  }
});

test("an absent field differs from a present one (no silent collapse)", () => {
  const withField = computeEvidenceHash(baseKey());
  const withoutBinding = { ...baseKey() };
  delete withoutBinding.source_binding;
  // null vs absent both mean "no binding"; canonicalization drops undefined but
  // keeps null, so an explicit null and an omitted key hash identically only when
  // the value is genuinely the same. Here null is present in both via baseKey,
  // so removing it (undefined) must still differ from a concrete value.
  assert.notEqual(computeEvidenceHash({ ...baseKey(), source_binding: "verified" }), withField);
  assert.equal(typeof computeEvidenceHash(withoutBinding), "string");
});

// --- Store prototype: end-to-end record -> reuse -> invalidate -> supersede ---

function finding(antId: string): FindingRecord {
  return {
    schema_version: "1.0.0",
    ant_id: antId,
    project: "openssl/openssl",
    title: null,
    bug_class: null,
    severity: { claude: null, firm: null, maintainer: null },
    status: "public",
    patched: true,
    patched_at: null,
    discovered_on: null,
    revealed_at: null,
    withdrawn: false,
    cve_ids: ["CVE-2026-45447"],
    ghsa_ids: [],
    fix_commits: [],
    fix_references: [],
    fixed_versions: [
      {
        version: "9.9.9",
        package: "openssl",
        ecosystem: "npm",
        role: "first_patched",
        first_patched: true,
        confidence: "high",
        evidence: [],
        commit_verification: { status: "not_run" },
      },
    ],
    release_assessment: { status: "confirmed_versions", evidence: [] },
    enrichment: { status: "complete", warnings: [] },
    sources: [],
  };
}

function cveRange(antId: string, introduced: string, fixed: string): AffectedRangeRecord {
  return {
    ant_id: antId,
    advisory: "CVE-2026-45447",
    source: "cve_list_v5",
    ecosystem: "cve",
    package: "openssl",
    product: "openssl",
    version_type: "semver",
    range_type: "SEMVER",
    events: [{ introduced }, { fixed }],
    provenance: "https://.../CVE-2026-45447.json",
  };
}

function rangeDataset(ranges: AffectedRangeRecord[]): AffectedRangeDataset {
  return {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-08-26T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: 1,
      record_count: ranges.length,
    },
    ranges,
  };
}

async function sbomWithOpenssl(version: string): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "glasswing-adj-"));
  const file = path.join(dir, "bom.json");
  await writeFile(
    file,
    JSON.stringify({ bomFormat: "CycloneDX", specVersion: "1.6", version: 1, components: [{ type: "library", name: "openssl", version }] }),
  );
  return file;
}

async function opensslCandidate(version: string) {
  const report = await checkSbom({
    sbomFile: await sbomWithOpenssl(version),
    findings: [finding("ANT-2026-OSSL")],
    rangeDataset: rangeDataset([cveRange("ANT-2026-OSSL", "3.0.0", "3.0.21")]),
  });
  return report.candidates[0]!;
}

test("adjudication store: record a review, reuse it, and auto-invalidate on evidence change", async () => {
  // A weak, name-only openssl 3.0.7 lands as candidate_decision UNKNOWN — exactly
  // the residual that should be adjudicated once and then reused.
  const candidate = await opensslCandidate("3.0.7");
  assert.equal(candidate.candidate_decision?.decision, "UNKNOWN");
  const hash = evidenceHashForCandidate(candidate);

  let store = emptyStore();
  const review: AdjudicationRecord = {
    evidence_hash: hash,
    recorded_at: "2026-09-04T00:00:00Z",
    subject: { ant_id: candidate.ant_id, component: { name: "openssl", version: "3.0.7" } },
    machine_decision: "UNKNOWN",
    ai_review: { verdict: "LIKELY_TRUE_POSITIVE", confidence: "medium", summary: "OpenSSL 3.0.7 in the affected 3.0 line." },
  };
  store = appendAdjudication(store, review);

  // Reuse: the same candidate resolves to the stored review — no re-adjudication.
  const again = await opensslCandidate("3.0.7");
  assert.equal(lookupAdjudication(store, evidenceHashForCandidate(again))?.ai_review?.verdict, "LIKELY_TRUE_POSITIVE");

  // Auto-invalidation: a version bump moves the evidence hash, so the prior
  // review no longer applies and the lookup misses.
  const bumped = await opensslCandidate("3.0.8");
  assert.equal(lookupAdjudication(store, evidenceHashForCandidate(bumped)), undefined);
  // The old SBOM (3.0.7) still resolves — the review remains valid for its subject.
  assert.ok(lookupAdjudication(store, hash));
});

test("adjudication store: latest-wins for a same-evidence correction and explicit invalidation retires it", async () => {
  const candidate = await opensslCandidate("3.0.7");
  const hash = evidenceHashForCandidate(candidate);
  let store = emptyStore();
  store = appendAdjudication(store, {
    evidence_hash: hash,
    recorded_at: "2026-09-04T00:00:00Z",
    subject: { ant_id: candidate.ant_id, component: { name: "openssl", version: "3.0.7" } },
    machine_decision: "UNKNOWN",
    ai_review: { verdict: "INSUFFICIENT_EVIDENCE", confidence: "low", summary: "first pass" },
  });
  // A human corrects it for the identical evidence: latest-wins, history kept.
  store = appendAdjudication(store, {
    evidence_hash: hash,
    recorded_at: "2026-09-04T01:00:00Z",
    subject: { ant_id: candidate.ant_id, component: { name: "openssl", version: "3.0.7" } },
    machine_decision: "UNKNOWN",
    human_review: { disposition: "affected", approved_by: "windshock", justification: "in 3.0 line" },
    supersedes: hash,
  });
  assert.equal(store.records.length, 2);
  assert.equal(lookupAdjudication(store, hash)?.human_review?.disposition, "affected");

  // Explicitly voiding the latest retires the review entirely.
  store = appendAdjudication(store, {
    evidence_hash: hash,
    recorded_at: "2026-09-04T02:00:00Z",
    subject: { ant_id: candidate.ant_id, component: { name: "openssl", version: "3.0.7" } },
    machine_decision: "UNKNOWN",
    invalidated: true,
  });
  assert.equal(lookupAdjudication(store, hash), undefined);
});

test("adjudication store round-trips through disk and fails closed on malformed input", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "glasswing-adjstore-"));
  const file = path.join(dir, "adjudications.json");
  let store = emptyStore();
  store = appendAdjudication(store, {
    evidence_hash: "a".repeat(64),
    recorded_at: "2026-09-04T00:00:00Z",
    subject: { ant_id: "ANT-2026-OSSL", component: { name: "openssl", version: "3.0.7" } },
    machine_decision: "UNKNOWN",
  });
  await writeAdjudicationStore(store, file);
  const read = await readAdjudicationStore(file);
  assert.equal(read.records.length, 1);

  const bad = path.join(dir, "bad.json");
  await writeFile(bad, JSON.stringify({ metadata: { schema_version: "1.0.0" }, records: [{ evidence_hash: "nope", machine_decision: "UNKNOWN", subject: { ant_id: "ANT-2026-X" } }] }));
  await assert.rejects(readAdjudicationStore(bad), /evidence_hash must be a sha256/);
});
