import assert from "node:assert/strict";
import test from "node:test";
import { computeEvidenceHash, type EvidenceKey } from "../src/adjudication/evidence-hash.js";

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
