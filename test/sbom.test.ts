import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { promisify } from "node:util";
import Ajv2020 from "ajv/dist/2020.js";
import { fingerprintPatch } from "../src/impact/fingerprint.js";
import type { FixImpactDataset } from "../src/impact/types.js";
import type { FindingRecord } from "../src/types.js";
import { checkSbom } from "../src/sbom/check.js";
import { CveVersionComparator, Pep440Comparator, SemverComparator } from "../src/sbom/comparator.js";
import { canonicalizePurl } from "../src/sbom/purl.js";
import { cpeRelation } from "../src/sbom/cpe.js";
import type { SbomCheckReport } from "../src/sbom/types.js";
import { parseAuthoritativeRanges, parseCveRanges } from "../src/ranges/extract.js";
import { readAffectedRangeDataset, validateAffectedRangeDataset } from "../src/ranges/read.js";
import type { AffectedRangeDataset, AffectedRangeRecord } from "../src/ranges/types.js";

function rangeDataset(ranges: AffectedRangeRecord[]): AffectedRangeDataset {
  return {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-02T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: new Set(ranges.map((range) => range.ant_id)).size,
      record_count: ranges.length,
    },
    ranges,
  };
}

function npmRange(antId: string, packageName: string, introduced: string, fixed: string): AffectedRangeRecord {
  return {
    ant_id: antId,
    advisory: "GHSA-test-0001",
    source: "osv",
    ecosystem: "npm",
    package: packageName,
    range_type: "ECOSYSTEM",
    events: [{ introduced }, { fixed }],
    provenance: "https://osv.dev/vulnerability/GHSA-test-0001",
  };
}

const CVE_PROVENANCE =
  "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/CVE-2026-45447.json";

function cveRange(antId: string, product: string, introduced: string, fixed: string): AffectedRangeRecord {
  return {
    ant_id: antId,
    advisory: "CVE-2026-45447",
    source: "cve_list_v5",
    ecosystem: "cve",
    package: product,
    product,
    range_type: "SEMVER",
    events: [{ introduced }, { fixed }],
    provenance: CVE_PROVENANCE,
  };
}

const execFileAsync = promisify(execFile);

function finding(partial: Partial<FindingRecord> & Pick<FindingRecord, "ant_id" | "project">): FindingRecord {
  return {
    schema_version: "1.0.0",
    title: null,
    bug_class: null,
    severity: { claude: null, firm: null, maintainer: null },
    status: "public",
    patched: true,
    patched_at: null,
    discovered_on: null,
    revealed_at: null,
    withdrawn: false,
    cve_ids: [],
    ghsa_ids: [],
    fix_commits: [],
    fix_references: [],
    fixed_versions: [],
    release_assessment: { status: "confirmed_versions", evidence: [] },
    enrichment: { status: "complete", warnings: [] },
    sources: [],
    ...partial,
  };
}

function packageFinding(
  antId: string,
  project: string,
  ecosystem: string,
  packageName: string,
): FindingRecord {
  return finding({
    ant_id: antId,
    project,
    fixed_versions: [
      {
        version: "9.9.9",
        package: packageName,
        ecosystem,
        role: "first_patched",
        first_patched: true,
        confidence: "high",
        evidence: [],
        commit_verification: { status: "not_run" },
      },
    ],
  });
}

async function writeSbom(document: unknown): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "glasswing-sbom-"));
  const file = path.join(directory, "bom.json");
  await writeFile(file, JSON.stringify(document));
  return file;
}

function cyclonedx(components: unknown[], specVersion = "1.6"): Record<string, unknown> {
  return { bomFormat: "CycloneDX", specVersion, version: 1, components };
}

function syft(artifacts: unknown[]): Record<string, unknown> {
  return {
    artifacts,
    artifactRelationships: [],
    source: { id: "s", name: "src", version: "", type: "directory", metadata: {} },
    distro: {},
    descriptor: { name: "syft", version: "1.0.0" },
    schema: {
      version: "16.1.2",
      url: "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-16.1.2.json",
    },
  };
}

test("selects a PURL identity candidate with strong, high confidence", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-LEFTPAD", "stevemao/left-pad", "npm", "left-pad")],
  });
  assert.equal(report.candidates.length, 1);
  // Findings carry no PURL, so the honest strongest label is ecosystem_package.
  assert.equal(report.candidates[0]!.match_type, "ecosystem_package");
  assert.equal(report.candidates[0]!.identity_strength, "strong");
  assert.equal(report.candidates[0]!.confidence, "high");
  assert.equal(report.package_component_count, 1);
});

test("Maven identity is case-sensitive; case-different coordinates do not match", async () => {
  const file = await writeSbom(
    cyclonedx([
      { type: "library", name: "PostgreSQL", version: "42.7.3", purl: "pkg:maven/org.PostgreSQL/PostgreSQL@42.7.3" },
    ]),
  );
  // The finding uses the canonical lowercase Maven coordinate; Maven groupId/
  // artifactId are case-sensitive, so this must not match.
  const mismatched = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-MVNCASE", "org/pg", "Maven", "org.postgresql:postgresql")],
  });
  assert.ok(!mismatched.candidates.some((candidate) => candidate.identity_strength === "strong"));
  // The same coordinate with matching case is a strong identity match.
  const matched = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-MVNCASE", "org/pg", "Maven", "org.PostgreSQL:PostgreSQL")],
  });
  assert.equal(matched.candidates[0]!.match_type, "ecosystem_package");
});

test("accepts CycloneDX 1.4 input", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }], "1.4"),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-CDX14", "stevemao/left-pad", "npm", "left-pad")],
  });
  assert.equal(report.spec_version, "1.4");
  assert.equal(report.candidates[0]!.match_type, "ecosystem_package");
});

test("a Maven PostgreSQL JDBC component does not match the PostgreSQL server by name", async () => {
  const file = await writeSbom(
    cyclonedx([
      {
        type: "library",
        name: "postgresql",
        version: "42.7.3",
        purl: "pkg:maven/org.postgresql/postgresql@42.7.3",
      },
    ]),
  );
  // Finding is for the PostgreSQL server project, not the JDBC driver.
  const report = await checkSbom({
    sbomFile: file,
    findings: [finding({ ant_id: "ANT-2026-PGSERVER", project: "postgres/postgres" })],
  });
  assert.equal(report.candidates.length, 0);
});

test("a valid but mismatched PURL defeats a coincidental equal package name", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "auth", version: "1.0.0", purl: "pkg:npm/auth@1.0.0" }]),
  );
  // A finding whose package name is 'auth' but in a different ecosystem.
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-AUTH", "someorg/auth-server", "Maven", "com.example:auth")],
  });
  assert.equal(report.candidates.length, 0);
});

test("a name-only match stays low confidence and never AFFECTED", async () => {
  // Component has no PURL, so only a name heuristic is possible.
  const file = await writeSbom(cyclonedx([{ type: "library", name: "widget", version: "2.0.0" }]));
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-WIDGET", "acme/widget", "npm", "widget")],
  });
  assert.equal(report.candidates.length, 1);
  assert.equal(report.candidates[0]!.match_type, "name_heuristic");
  assert.equal(report.candidates[0]!.confidence, "low");
  assert.equal(report.candidates[0]!.identity_strength, "weak");
  assert.ok(!report.candidates.some((candidate) => candidate.verification));
});

test("a malformed PURL is never repaired into an exact match", async () => {
  assert.equal(canonicalizePurl("not a purl"), undefined);
  assert.equal(canonicalizePurl("pkg:"), undefined);
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:::@@bad" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-BADPURL", "stevemao/left-pad", "npm", "left-pad")],
  });
  // No valid PURL and the name still matches, so at most a weak heuristic — never
  // a strong identity match.
  assert.ok(!report.candidates.some((candidate) => candidate.identity_strength === "strong"));
  assert.ok(!report.candidates.some((candidate) => candidate.match_type === "exact_purl"));
  assert.ok(!report.candidates.some((candidate) => candidate.match_type === "ecosystem_package"));
});

test("a file-only CycloneDX document produces zero package candidates", async () => {
  const file = await writeSbom(
    cyclonedx([
      { type: "file", name: "src/index.js" },
      { type: "file", name: "README.md" },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-FILE", "acme/index.js", "npm", "index.js")],
  });
  assert.equal(report.candidates.length, 0);
  assert.equal(report.package_component_count, 0);
  assert.equal(report.component_count, 2);
});

test("CycloneDX and Syft forms of the same PURL normalize to the same candidate identity", async () => {
  const findings = [packageFinding("ANT-2026-SAME", "expressjs/express", "npm", "express")];
  const cdxFile = await writeSbom(
    cyclonedx([{ type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" }]),
  );
  const syftFile = await writeSbom(
    syft([
      {
        id: "a1",
        name: "express",
        version: "4.19.2",
        type: "npm",
        foundBy: "javascript-cataloger",
        locations: [],
        licenses: [],
        language: "javascript",
        cpes: [],
        purl: "pkg:npm/express@4.19.2",
      },
    ]),
  );
  const cdx = await checkSbom({ sbomFile: cdxFile, findings });
  const syftReport = await checkSbom({ sbomFile: syftFile, findings });
  assert.equal(cdx.candidates.length, 1);
  assert.equal(syftReport.candidates.length, 1);
  assert.equal(cdx.candidates[0]!.component.purl, syftReport.candidates[0]!.component.purl);
  assert.equal(cdx.candidates[0]!.match_type, "ecosystem_package");
  assert.equal(syftReport.candidates[0]!.match_type, "ecosystem_package");
});

test("an unsupported SBOM format is rejected", async () => {
  const file = await writeSbom({ spdxVersion: "SPDX-2.3", packages: [] });
  await assert.rejects(() => checkSbom({ sbomFile: file, findings: [] }), /Unsupported SBOM/);
});

test("a malformed explicit --component PURL is a hard error, not a silent scan", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  await assert.rejects(
    () => checkSbom({ sbomFile: file, findings: [], component: "not a purl" }),
    /Malformed --component/,
  );
});

async function writeRaw(text: string): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "glasswing-sbom-"));
  const file = path.join(directory, "multi.json");
  await writeFile(file, text);
  return file;
}

test("aggregates multiple newline-delimited CycloneDX documents", async () => {
  const doc1 = cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]);
  const doc2 = cyclonedx([{ type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" }]);
  const file = await writeRaw(`${JSON.stringify(doc1)}\n${JSON.stringify(doc2)}\n`);
  const report = await checkSbom({
    sbomFile: file,
    findings: [
      packageFinding("ANT-2026-LP", "stevemao/left-pad", "npm", "left-pad"),
      packageFinding("ANT-2026-EX", "expressjs/express", "npm", "express"),
    ],
  });
  assert.equal(report.document_count, 2);
  assert.equal(report.component_count, 2);
  assert.equal(report.candidates.length, 2);
});

test("aggregates concatenated pretty-printed documents and dedupes components", async () => {
  const doc = cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]);
  const file = await writeRaw(`${JSON.stringify(doc, null, 2)}\n${JSON.stringify(doc, null, 2)}\n`);
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-LP", "stevemao/left-pad", "npm", "left-pad")],
  });
  assert.equal(report.document_count, 2);
  assert.equal(report.component_count, 1); // the identical component is deduplicated
  assert.equal(report.candidates.length, 1);
});

test("rejects non-whitespace outside JSON documents", async () => {
  const file = await writeRaw(
    'garbage {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[]} tail',
  );
  await assert.rejects(
    () => checkSbom({ sbomFile: file, findings: [] }),
    /Unexpected non-whitespace|Unsupported SBOM/,
  );
});

test("accepts comma-separated documents (array elements without brackets)", async () => {
  const doc1 = JSON.stringify(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  const doc2 = JSON.stringify(
    cyclonedx([{ type: "library", name: "express", version: "4.19.2", purl: "pkg:npm/express@4.19.2" }]),
  );
  const file = await writeRaw(`${doc1},\n${doc2}`);
  const report = await checkSbom({
    sbomFile: file,
    findings: [
      packageFinding("ANT-2026-CS1", "stevemao/left-pad", "npm", "left-pad"),
      packageFinding("ANT-2026-CS2", "expressjs/express", "npm", "express"),
    ],
  });
  assert.equal(report.document_count, 2);
  assert.equal(report.candidates.length, 2);
});

test("an unsupported document among several is a hard error, not a silent skip", async () => {
  const cdx = JSON.stringify(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  const spdx = JSON.stringify({ spdxVersion: "SPDX-2.3", packages: [] });
  const file = await writeRaw(`${cdx}\n${spdx}\n`);
  await assert.rejects(() => checkSbom({ sbomFile: file, findings: [] }), /Unsupported SBOM/);
});

test("reaches AFFECTED for strong identity and an authoritative range covering the version", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.5.0", purl: "pkg:npm/left-pad@1.5.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-AFF", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-AFF", "left-pad", "1.0.0", "2.0.0")]),
  });
  const candidate = report.candidates[0]!;
  assert.equal(candidate.identity_strength, "strong");
  assert.equal(candidate.range_assessment?.verdict, "affected");
});

test("a version outside the authoritative range is not_affected, never AFFECTED", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "2.1.0", purl: "pkg:npm/left-pad@2.1.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-NAF", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-NAF", "left-pad", "1.0.0", "2.0.0")]),
  });
  assert.equal(report.candidates[0]!.range_assessment?.verdict, "not_affected");
});

test("an unresolved authoritative range keeps the result unknown despite a not_affected range", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "2.1.0", purl: "pkg:npm/left-pad@2.1.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-UNR", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([
      // Range A resolves to not_affected (2.1.0 is >= the fixed boundary).
      npmRange("ANT-2026-UNR", "left-pad", "1.0.0", "2.0.0"),
      // Range B is applicable (same npm identity) but its boundary is not valid
      // SemVer, so the comparator cannot resolve it -> unresolved.
      {
        ant_id: "ANT-2026-UNR",
        advisory: "GHSA-unresolved",
        ecosystem: "npm",
        package: "left-pad",
        range_type: "SEMVER",
        events: [{ introduced: "1.0" }, { fixed: "2.0" }],
        provenance: "https://osv.dev/vulnerability/GHSA-unresolved",
      },
    ]),
  });
  assert.equal(report.candidates[0]!.range_assessment?.verdict, "unknown");
});

test("an unsupported ecosystem range stays unknown, never AFFECTED", async () => {
  const file = await writeSbom(
    cyclonedx([
      { type: "library", name: "guava", version: "31.0", purl: "pkg:maven/com.google.guava/guava@31.0" },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-MVN", "google/guava", "Maven", "com.google.guava:guava")],
    rangeDataset: rangeDataset([
      {
        ant_id: "ANT-2026-MVN",
        advisory: "GHSA-maven",
        ecosystem: "Maven",
        package: "com.google.guava:guava",
        range_type: "MAVEN",
        events: [{ introduced: "30.0" }, { fixed: "32.0" }],
        provenance: "https://osv.dev/vulnerability/GHSA-maven",
      },
    ]),
  });
  const candidate = report.candidates.find((item) => item.identity_strength === "strong");
  assert.ok(candidate);
  assert.equal(candidate!.range_assessment?.verdict, "unknown");
});

test("a name-only candidate is never AFFECTED even with an authoritative range", async () => {
  // No PURL -> name heuristic only -> weak identity -> no range assessment at all.
  const file = await writeSbom(cyclonedx([{ type: "library", name: "left-pad", version: "1.5.0" }]));
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-WNM", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-WNM", "left-pad", "1.0.0", "2.0.0")]),
  });
  const candidate = report.candidates[0]!;
  assert.equal(candidate.match_type, "name_heuristic");
  assert.equal(candidate.range_assessment, undefined);
});

test("a CVE List V5 product range reaches AFFECTED for a name-only component", async () => {
  // openssl 3.0.7 carries no PURL: name_heuristic, weak identity. A CVE List V5
  // range is keyed by product (CVE records have no package ecosystem), so it
  // still applies by name and resolves deterministically via the SemVer comparator.
  const file = await writeSbom(cyclonedx([{ type: "library", name: "openssl", version: "3.0.7" }]));
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-OSSL", "openssl/openssl", "npm", "openssl")],
    rangeDataset: rangeDataset([cveRange("ANT-2026-OSSL", "openssl", "3.0.0", "3.0.21")]),
  });
  const candidate = report.candidates[0]!;
  assert.equal(candidate.match_type, "name_heuristic");
  assert.equal(candidate.identity_strength, "weak");
  assert.equal(candidate.range_assessment?.verdict, "affected");
});

test("a CVE List V5 product range is not_affected for an already-patched name-only component", async () => {
  // 3.0.21 is the fixed boundary (exclusive): outside the affected range.
  const file = await writeSbom(cyclonedx([{ type: "library", name: "openssl", version: "3.0.21" }]));
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-OSSL", "openssl/openssl", "npm", "openssl")],
    rangeDataset: rangeDataset([cveRange("ANT-2026-OSSL", "openssl", "3.0.0", "3.0.21")]),
  });
  assert.equal(report.candidates[0]!.range_assessment?.verdict, "not_affected");
});

test("cpeRelation matches on part/vendor/product, excludes namesakes, defers without CPEs", () => {
  const server = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*";
  assert.equal(cpeRelation(["cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*"], [server]).relation, "match");
  // JDBC driver vs the OpenSSL... use the postgresql namesake: different product token.
  assert.equal(
    cpeRelation(
      ["cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.4.0:*:*:*:*:*:*:*"],
      ["cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*"],
    ).relation,
    "disjoint",
  );
  // A different vendor is also disjoint even when the product token matches.
  assert.equal(cpeRelation(["cpe:2.3:a:acme:openssl:*:*:*:*:*:*:*:*"], [server]).relation, "disjoint");
  // No parseable CPE on one side -> defer to a weaker signal.
  assert.equal(cpeRelation([], [server]).relation, "unknown");
  assert.equal(cpeRelation(["not-a-cpe"], [server]).relation, "unknown");
  // The legacy 2.2 URI binding is accepted.
  assert.equal(cpeRelation(["cpe:/a:openssl:openssl:1.1.1"], [server]).relation, "match");
});

function cveRangeWithCpe(
  antId: string,
  product: string,
  cpe: string,
  events: unknown[],
  rangeType = "SEMVER",
  versionType = "semver",
): AffectedRangeRecord {
  return {
    ant_id: antId,
    advisory: "CVE-2026-00000",
    source: "cve_list_v5",
    ecosystem: "cve",
    package: product,
    product,
    version_type: versionType,
    range_type: rangeType,
    cpes: [cpe],
    events: events as AffectedRangeRecord["events"],
    provenance: CVE_PROVENANCE,
  };
}

test("a CPE 2.3 match elevates a CVE range to strong identity and gates", async () => {
  const file = await writeSbom(
    cyclonedx([
      { type: "library", name: "openssl", version: "3.0.7", cpe: "cpe:2.3:a:openssl:openssl:3.0.7:*:*:*:*:*:*:*" },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-OSSL", "openssl/openssl", "npm", "openssl")],
    rangeDataset: rangeDataset([
      cveRangeWithCpe(
        "ANT-2026-OSSL",
        "openssl",
        "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*",
        [{ introduced: "3.0.0" }, { fixed: "3.0.21" }],
      ),
    ]),
  });
  const candidate = report.candidates[0]!;
  assert.equal(candidate.match_type, "cpe_match");
  assert.equal(candidate.identity_strength, "strong");
  assert.equal(candidate.identity_evidence?.relation, "match");
  assert.equal(candidate.candidate_decision?.decision, "AFFECTED");
  assert.equal(candidate.candidate_decision?.gating_eligible, true);
});

test("a disjoint CPE excludes a namesake CVE range (JDBC driver vs server)", async () => {
  const file = await writeSbom(
    cyclonedx([
      {
        type: "library",
        name: "postgresql",
        version: "42.4.0",
        cpe: "cpe:2.3:a:postgresql:postgresql_jdbc_driver:42.4.0:*:*:*:*:*:*:*",
      },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-PG", "postgres/postgres", "npm", "postgresql")],
    rangeDataset: rangeDataset([
      cveRangeWithCpe(
        "ANT-2026-PG",
        "PostgreSQL",
        "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
        [{ introduced: "0" }, { fixed: "14.23" }],
        "RPM",
        "rpm",
      ),
    ]),
  });
  const candidate = report.candidates[0]!;
  // The range does not apply: the component CPE is a different product.
  assert.equal(candidate.range_assessment, undefined);
  assert.equal(candidate.match_type, "name_heuristic");
  assert.equal(candidate.candidate_decision?.decision, "UNKNOWN");
  assert.equal(candidate.candidate_decision?.gating_eligible, false);
});

test("candidate_decision separates the gating decision from weak range evidence", async () => {
  // Weak, name-only openssl affected by a CVE product range: the evidence is
  // affected, but the final decision is UNKNOWN and not gating-eligible.
  const weakFile = await writeSbom(cyclonedx([{ type: "library", name: "openssl", version: "3.0.7" }]));
  const weak = await checkSbom({
    sbomFile: weakFile,
    findings: [packageFinding("ANT-2026-OSSL", "openssl/openssl", "npm", "openssl")],
    rangeDataset: rangeDataset([cveRange("ANT-2026-OSSL", "openssl", "3.0.0", "3.0.21")]),
  });
  const wc = weak.candidates[0]!;
  assert.equal(wc.range_assessment?.verdict, "affected");
  assert.equal(wc.candidate_decision?.decision, "UNKNOWN");
  assert.equal(wc.candidate_decision?.range_verdict, "affected");
  assert.equal(wc.candidate_decision?.gating_eligible, false);

  // Strong identity (PURL) inside the range: AFFECTED and gating-eligible.
  const strongFile = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.5.0", purl: "pkg:npm/left-pad@1.5.0" }]),
  );
  const strong = await checkSbom({
    sbomFile: strongFile,
    findings: [packageFinding("ANT-2026-AFF", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-AFF", "left-pad", "1.0.0", "2.0.0")]),
  });
  const sc = strong.candidates[0]!;
  assert.equal(sc.candidate_decision?.decision, "AFFECTED");
  assert.equal(sc.candidate_decision?.gating_eligible, true);

  // Outside the range: NOT_AFFECTED, not gating.
  const safeFile = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "2.1.0", purl: "pkg:npm/left-pad@2.1.0" }]),
  );
  const safe = await checkSbom({
    sbomFile: safeFile,
    findings: [packageFinding("ANT-2026-NAF", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-NAF", "left-pad", "1.0.0", "2.0.0")]),
  });
  assert.equal(safe.candidates[0]!.candidate_decision?.decision, "NOT_AFFECTED");
  assert.equal(safe.candidates[0]!.candidate_decision?.gating_eligible, false);
});

test("a CVE List V5 product range matches case-insensitively by product name", async () => {
  const file = await writeSbom(cyclonedx([{ type: "library", name: "OpenSSL", version: "3.0.7" }]));
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-OSSL", "openssl/openssl", "npm", "openssl")],
    rangeDataset: rangeDataset([cveRange("ANT-2026-OSSL", "openssl", "3.0.0", "3.0.21")]),
  });
  assert.equal(report.candidates[0]!.range_assessment?.verdict, "affected");
});

test("parses CVE List V5 affected ranges keyed by product, skipping git version types", () => {
  const records = parseCveRanges(
    {
      cveMetadata: { cveId: "CVE-2026-45447" },
      containers: {
        cna: {
          affected: [
            {
              vendor: "openssl",
              product: "openssl",
              versions: [
                { version: "3.0.0", status: "affected", versionType: "semver", lessThan: "3.0.21" },
                { version: "1.1.1", status: "affected", versionType: "custom", lessThan: "1.1.1zh" },
                // A git range carries a commit boundary, not a comparable version.
                { version: "abc123", status: "affected", versionType: "git", lessThan: "def456" },
                // An unaffected entry is not an affected range.
                { version: "2.0.0", status: "unaffected" },
              ],
            },
          ],
        },
      },
    },
    "ANT-2026-OSSL",
    CVE_PROVENANCE,
  );
  assert.equal(records.length, 2);
  assert.equal(records[0]!.source, "cve_list_v5");
  assert.equal(records[0]!.ecosystem, "cve");
  assert.equal(records[0]!.product, "openssl");
  // versionType is preserved and carried onto range_type as the dispatch key.
  assert.equal(records[0]!.version_type, "semver");
  assert.equal(records[0]!.range_type, "SEMVER");
  assert.deepEqual(records[0]!.events, [{ introduced: "3.0.0" }, { fixed: "3.0.21" }]);
  assert.equal(records[1]!.version_type, "custom");
  assert.equal(records[1]!.range_type, "CUSTOM");
  assert.deepEqual(records[1]!.events, [{ introduced: "1.1.1" }, { fixed: "1.1.1zh" }]);
});

test("parseCveRanges marks a version line with changes[] unsupported (fail-safe UNKNOWN)", () => {
  const records = parseCveRanges(
    {
      cveMetadata: { cveId: "CVE-2026-99999" },
      containers: {
        cna: {
          affected: [
            {
              product: "widget",
              versions: [
                // Non-contiguous transitions within one line must not flatten to AFFECTED.
                {
                  version: "2.0.0",
                  status: "affected",
                  versionType: "semver",
                  lessThan: "3.0.0",
                  changes: [
                    { at: "2.5.2", status: "unaffected" },
                    { at: "2.6.0", status: "affected" },
                  ],
                },
              ],
            },
          ],
        },
      },
    },
    "ANT-2026-CHG",
    CVE_PROVENANCE,
  );
  assert.equal(records.length, 1);
  assert.equal(records[0]!.range_type, "CHANGES_UNSUPPORTED");
  assert.equal(records[0]!.version_type, "semver");
  // The interval is not flattened; the version is preserved for audit only.
  assert.deepEqual(records[0]!.events, [{ introduced: "2.0.0" }]);
  assert.equal(records[0]!.versions, undefined);
  // A component inside the naive interval must resolve to unknown, never affected.
  assert.equal(new CveVersionComparator().evaluate("2.5.5", records[0]!), "unknown");
  assert.deepEqual(validateAffectedRangeDataset(rangeDataset(records)), []);
});

test("parseCveRanges preserves rpm versionType so it is not compared as SemVer", () => {
  const records = parseCveRanges(
    {
      cveMetadata: { cveId: "CVE-2026-6479" },
      containers: {
        cna: {
          affected: [
            {
              product: "PostgreSQL",
              versions: [{ version: "0", status: "affected", versionType: "rpm", lessThan: "14.23" }],
            },
          ],
        },
      },
    },
    "ANT-2026-PG",
    CVE_PROVENANCE,
  );
  assert.equal(records.length, 1);
  assert.equal(records[0]!.version_type, "rpm");
  assert.equal(records[0]!.range_type, "RPM");
  assert.equal(new CveVersionComparator().evaluate("14.10", records[0]!), "unknown");
});

test("parses authoritative ranges from an OSV record and skips identity-less entries", () => {
  const records = parseAuthoritativeRanges(
    {
      id: "GHSA-abcd",
      affected: [
        {
          package: { ecosystem: "npm", name: "left-pad" },
          ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }] }],
        },
      ],
    },
    "ANT-2026-OSV",
    "https://osv.dev/vulnerability/GHSA-abcd",
  );
  assert.equal(records.length, 1);
  assert.equal(records[0]!.ecosystem, "npm");
  assert.equal(records[0]!.range_type, "ECOSYSTEM");
  assert.deepEqual(records[0]!.events, [{ introduced: "1.0.0" }, { fixed: "2.0.0" }]);

  const identityLess = parseAuthoritativeRanges(
    { id: "GHSA-x", affected: [{ ranges: [{ type: "GIT", events: [{ fixed: "deadbeef" }] }] }] },
    "ANT-2026-OSV",
    "p",
  );
  assert.equal(identityLess.length, 0);
});

test("keeps affected.versions and emits a versions-only record with no usable range", () => {
  const records = parseAuthoritativeRanges(
    { id: "GHSA-v", affected: [{ package: { ecosystem: "PyPI", name: "requests" }, versions: ["2.19.0", "2.19.1"] }] },
    "ANT-2026-VER",
    "https://osv.dev/vulnerability/GHSA-v",
  );
  assert.equal(records.length, 1);
  assert.equal(records[0]!.range_type, "EXACT");
  assert.deepEqual(records[0]!.events, []);
  assert.deepEqual(records[0]!.versions, ["2.19.0", "2.19.1"]);
  assert.deepEqual(validateAffectedRangeDataset(rangeDataset(records)), []);
});

test("an exactly-listed affected version reaches AFFECTED even without a comparator", async () => {
  // Maven has no comparator, but the version is explicitly published as affected.
  const file = await writeSbom(
    cyclonedx([
      { type: "library", name: "guava", version: "31.0", purl: "pkg:maven/com.google.guava/guava@31.0" },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-EXV", "google/guava", "Maven", "com.google.guava:guava")],
    rangeDataset: rangeDataset([
      {
        ant_id: "ANT-2026-EXV",
        advisory: "GHSA-exact",
        ecosystem: "Maven",
        package: "com.google.guava:guava",
        range_type: "EXACT",
        events: [],
        versions: ["31.0"],
        provenance: "https://osv.dev/vulnerability/GHSA-exact",
      },
    ]),
  });
  const candidate = report.candidates.find((item) => item.identity_strength === "strong");
  assert.ok(candidate);
  assert.equal(candidate!.range_assessment?.verdict, "affected");
});

test("validates and rejects a malformed affected-range dataset", () => {
  assert.deepEqual(validateAffectedRangeDataset(rangeDataset([npmRange("ANT-2026-OK", "x", "0", "1.0.0")])), []);
  const malformed = rangeDataset([
    { ant_id: "not-an-ant", advisory: "", ecosystem: "npm", package: "x", range_type: "ECOSYSTEM", events: [], provenance: "p" },
  ]);
  assert.ok(validateAffectedRangeDataset(malformed).length > 0);
});

test("tolerates a component license carrying both id and name", async () => {
  const file = await writeSbom(
    cyclonedx([
      {
        type: "library",
        name: "nginx",
        version: "1.25.0",
        purl: "pkg:generic/nginx@1.25.0",
        licenses: [{ license: { id: "BSD-2-Clause-FreeBSD", name: "nginx BSD-like", url: "http://nginx.com" } }],
      },
    ]),
  );
  const report = await checkSbom({ sbomFile: file, findings: [] });
  assert.equal(report.package_component_count, 1);
  assert.ok(report.warnings.some((warning) => warning.includes("does not fully conform")));
});

test("projects the CycloneDX root component (metadata.component), not only dependencies", async () => {
  const file = await writeRaw(
    JSON.stringify({
      bomFormat: "CycloneDX",
      specVersion: "1.6",
      version: 1,
      metadata: {
        component: { type: "application", name: "my-app", version: "3.2.1", purl: "pkg:npm/my-app@3.2.1" },
      },
      components: [{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }],
    }),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-ROOT", "acme/my-app", "npm", "my-app")],
  });
  assert.equal(report.package_component_count, 2); // root application + one dependency
  assert.ok(
    report.candidates.some(
      (candidate) => candidate.component.name === "my-app" && candidate.match_type === "ecosystem_package",
    ),
  );
});

test("strict CycloneDX validation rejects a malformed document", async () => {
  const file = await writeSbom({ bomFormat: "CycloneDX", specVersion: "1.6", components: "not-an-array" });
  await assert.rejects(() => checkSbom({ sbomFile: file, findings: [] }), /failed strict schema validation/);
});

test("tolerates a cosmetic metadata violation but never a component violation", async () => {
  // A non-UUID serialNumber violates the official schema but cannot corrupt
  // component identities, so candidate selection proceeds with a warning.
  const tolerated = await writeSbom({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    serialNumber: "urn:uuid:not-a-real-uuid",
    components: [{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }],
  });
  const report = await checkSbom({
    sbomFile: tolerated,
    findings: [packageFinding("ANT-2026-TOLERATE", "stevemao/left-pad", "npm", "left-pad")],
  });
  assert.equal(report.package_component_count, 1);
  assert.equal(report.candidates.length, 1);
  assert.ok(report.warnings.some((warning) => warning.includes("does not fully conform")));

  // A violation inside the components array is still a hard rejection.
  const rejected = await writeSbom({
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    components: [{ type: "not-a-valid-type", name: "x" }],
  });
  await assert.rejects(() => checkSbom({ sbomFile: rejected, findings: [] }), /failed strict schema validation/);
});

test("SemVer comparator evaluates an authoritative npm range", () => {
  const comparator = new SemverComparator();
  const range = {
    ecosystem: "npm",
    range_type: "ECOSYSTEM",
    events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
    provenance: "https://osv.dev/vulnerability/GHSA-xxxx",
  };
  assert.equal(comparator.evaluate("1.5.0", range), "affected");
  assert.equal(comparator.evaluate("2.0.0", range), "not_affected");
  assert.equal(comparator.evaluate("0.9.0", range), "not_affected");
  const fromZero = { ...range, events: [{ introduced: "0" }, { fixed: "1.5.0" }] };
  assert.equal(comparator.evaluate("1.0.0", fromZero), "affected");
  assert.equal(comparator.evaluate("1.5.0", fromZero), "not_affected");
});

test("an OSV limit event is an exclusive upper bound", () => {
  const comparator = new SemverComparator();
  const range = {
    ecosystem: "npm",
    range_type: "ECOSYSTEM",
    events: [{ introduced: "1.0.0" }, { limit: "2.0.0" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("1.5.0", range), "affected");
  assert.equal(comparator.evaluate("2.0.0", range), "not_affected"); // at the limit is outside
  assert.equal(comparator.evaluate("2.1.0", range), "not_affected");
});

test("SemVer security decisions reject versions that require coercion", () => {
  const comparator = new SemverComparator();
  const range = {
    ecosystem: "npm",
    range_type: "SEMVER",
    events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("1.5", range), "unknown");
  assert.equal(comparator.evaluate("1", range), "unknown");
  assert.equal(comparator.evaluate("1.2.3.4", range), "unknown");
  assert.equal(comparator.evaluate("latest", range), "unknown");
  // A leading 'v' is natively valid SemVer, not coercion, so it is evaluated.
  assert.equal(comparator.evaluate("v1.5.0", range), "affected");
});

test("an unsupported ecosystem or range type is unknown, never guessed", () => {
  const comparator = new SemverComparator();
  const mavenRange = {
    ecosystem: "Maven",
    range_type: "MAVEN",
    events: [{ introduced: "1.0" }, { fixed: "2.0" }],
    provenance: "x",
  };
  assert.equal(comparator.supports("Maven", "MAVEN"), false);
  assert.equal(comparator.evaluate("1.5", mavenRange), "unknown");
  const gitRange = { ecosystem: "npm", range_type: "GIT", events: [], provenance: "x" };
  assert.equal(comparator.supports("npm", "GIT"), false);
  assert.equal(comparator.evaluate("1.5.0", gitRange), "unknown");
});

test("SemVer comparator supports Go and crates.io with conformance vectors", () => {
  const comparator = new SemverComparator();

  // Go modules use SemVer (a leading v is tolerated, not coercion).
  const goRange = {
    ecosystem: "Go",
    range_type: "ECOSYSTEM",
    events: [{ introduced: "1.0.0" }, { fixed: "1.6.4" }],
    provenance: "x",
  };
  assert.equal(comparator.supports("Go", "ECOSYSTEM"), true);
  assert.equal(comparator.evaluate("v1.3.7", goRange), "affected");
  assert.equal(comparator.evaluate("1.3.7", goRange), "affected");
  assert.equal(comparator.evaluate("v1.6.4", goRange), "not_affected");
  assert.equal(comparator.evaluate("v0.9.0", goRange), "not_affected");
  assert.equal(comparator.evaluate("v1.3", goRange), "unknown"); // coercion is rejected

  // crates.io uses SemVer.
  const cargoRange = {
    ecosystem: "crates.io",
    range_type: "SEMVER",
    events: [{ introduced: "1.0.0" }, { fixed: "2.0.0" }],
    provenance: "x",
  };
  assert.equal(comparator.supports("crates.io", "SEMVER"), true);
  assert.equal(comparator.evaluate("1.5.0", cargoRange), "affected");
  assert.equal(comparator.evaluate("2.0.0", cargoRange), "not_affected");

  // Ecosystems with their own version scheme are handled elsewhere or excluded.
  assert.equal(comparator.supports("Maven", "ECOSYSTEM"), false);
  assert.equal(comparator.supports("PyPI", "ECOSYSTEM"), false);
  assert.equal(comparator.supports("Packagist", "ECOSYSTEM"), false);
});

test("PEP 440 comparator evaluates PyPI ranges with conformance vectors", () => {
  const comparator = new Pep440Comparator();
  const range = {
    ecosystem: "PyPI",
    range_type: "ECOSYSTEM",
    events: [{ introduced: "2.0.0" }, { fixed: "2.19.0" }],
    provenance: "x",
  };
  assert.equal(comparator.supports("PyPI", "ECOSYSTEM"), true);
  assert.equal(comparator.evaluate("2.10.0", range), "affected");
  assert.equal(comparator.evaluate("2.19.0", range), "not_affected");
  assert.equal(comparator.evaluate("1.9.0", range), "not_affected");
  // PEP 440 accepts two-part and pre-release versions; junk is unknown.
  assert.equal(comparator.evaluate("2.5", range), "affected");
  assert.equal(comparator.evaluate("2.19.0rc1", range), "affected");
  assert.equal(comparator.evaluate("not-a-version", range), "unknown");
  // Non-PyPI ecosystems are not handled by this comparator.
  assert.equal(comparator.supports("npm", "ECOSYSTEM"), false);
  assert.equal(comparator.supports("Maven", "ECOSYSTEM"), false);
});

test("CVE comparator evaluates OpenSSL letter-suffix versions deterministically", () => {
  const comparator = new CveVersionComparator();
  // OpenSSL 1.1.1 series: CVE List V5 labels the letter releases versionType
  // "custom"; base release precedes 1.1.1a; fixed at 1.1.1zh.
  const oneOneOne = {
    ecosystem: "cve",
    range_type: "CUSTOM",
    events: [{ introduced: "1.1.1" }, { fixed: "1.1.1zh" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("1.1.1", oneOneOne), "affected"); // base release is in range
  assert.equal(comparator.evaluate("1.1.1d", oneOneOne), "affected");
  assert.equal(comparator.evaluate("1.1.1g", oneOneOne), "affected");
  assert.equal(comparator.evaluate("1.1.1zh", oneOneOne), "not_affected"); // fixed boundary is exclusive
  assert.equal(comparator.evaluate("1.1.0", oneOneOne), "not_affected");
  assert.equal(comparator.evaluate("1.0.2q", oneOneOne), "not_affected"); // different fix line

  // OpenSSL 1.0.2 series: q is within [1.0.2, 1.0.2zq) — note zq sorts after q.
  const oneZeroTwo = {
    ecosystem: "cve",
    range_type: "CUSTOM",
    events: [{ introduced: "1.0.2" }, { fixed: "1.0.2zq" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("1.0.2", oneZeroTwo), "affected");
  assert.equal(comparator.evaluate("1.0.2k", oneZeroTwo), "affected");
  assert.equal(comparator.evaluate("1.0.2q", oneZeroTwo), "affected");
  assert.equal(comparator.evaluate("1.0.2zq", oneZeroTwo), "not_affected");
  assert.equal(comparator.evaluate("1.0.1e", oneZeroTwo), "not_affected"); // predates the series
  assert.equal(comparator.evaluate("0.9.8p", oneZeroTwo), "not_affected");

  // OpenSSL 3.x is labeled versionType "semver" and compared with node-semver.
  const threeZero = {
    ecosystem: "cve",
    range_type: "SEMVER",
    events: [{ introduced: "3.0.0" }, { fixed: "3.0.21" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("3.0.7", threeZero), "affected");
  assert.equal(comparator.evaluate("3.0.21", threeZero), "not_affected");
  assert.equal(comparator.evaluate("3.0.30", threeZero), "not_affected");
  // A letter version under a SEMVER-typed range is not valid SemVer -> unknown,
  // never coerced into another scheme.
  assert.equal(comparator.evaluate("3.0.7a", threeZero), "unknown");
});

test("CVE comparator dispatches on versionType and refuses schemes it cannot order", () => {
  const comparator = new CveVersionComparator();
  // rpm/debian/maven schemes have their own ordering (epoch, tilde, ~) and must
  // never be compared as SemVer/three-part, even when the values look numeric.
  // PostgreSQL server ranges are published as versionType "rpm".
  const rpm = {
    ecosystem: "cve",
    range_type: "RPM",
    events: [{ introduced: "0" }, { fixed: "14.23" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("14.10", rpm), "unknown");
  assert.equal(comparator.evaluate("42.4.0", rpm), "unknown"); // JDBC-driver namesake

  // A non-contiguous version line (changes[]) is marked unsupported at parse time
  // and must never resolve to a gating AFFECTED from a flattened interval.
  const changes = {
    ecosystem: "cve",
    range_type: "CHANGES_UNSUPPORTED",
    events: [{ introduced: "2.6.0" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("2.6.1", changes), "unknown");

  // FIPS/distro variants and two-part boundaries stay unknown under any typed range.
  const semver34 = {
    ecosystem: "cve",
    range_type: "SEMVER",
    events: [{ introduced: "3.4.0" }, { fixed: "3.4.6" }],
    provenance: "x",
  };
  assert.equal(comparator.evaluate("3.4-fips3.1", semver34), "unknown");
  assert.equal(comparator.evaluate("0.16_p3", semver34), "unknown");

  // Only the `cve` sentinel ecosystem is handled here.
  assert.equal(comparator.supports("cve"), true);
  assert.equal(comparator.supports("npm"), false);
  assert.equal(comparator.supports("PyPI"), false);
});

test("reaches AFFECTED for a PyPI component via a pypi PURL and authoritative range", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "requests", version: "2.10.0", purl: "pkg:pypi/requests@2.10.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-PYPI", "psf/requests", "PyPI", "requests")],
    rangeDataset: rangeDataset([
      {
        ant_id: "ANT-2026-PYPI",
        advisory: "GHSA-pypi",
        ecosystem: "PyPI",
        package: "requests",
        range_type: "ECOSYSTEM",
        events: [{ introduced: "2.0.0" }, { fixed: "2.19.0" }],
        provenance: "https://osv.dev/vulnerability/GHSA-pypi",
      },
    ]),
  });
  const candidate = report.candidates.find((item) => item.identity_strength === "strong");
  assert.ok(candidate, JSON.stringify(report, null, 2));
  assert.equal(candidate!.range_assessment?.verdict, "affected");
});

test("reaches AFFECTED for a Go component via a golang PURL and authoritative range", async () => {
  const file = await writeSbom(
    cyclonedx([
      {
        type: "library",
        name: "circl",
        version: "v1.3.7",
        purl: "pkg:golang/github.com/cloudflare/circl@v1.3.7",
      },
    ]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-GOAFF", "cloudflare/circl", "Go", "github.com/cloudflare/circl")],
    rangeDataset: rangeDataset([
      {
        ant_id: "ANT-2026-GOAFF",
        advisory: "GHSA-go-circl",
        ecosystem: "Go",
        package: "github.com/cloudflare/circl",
        range_type: "ECOSYSTEM",
        events: [{ introduced: "1.0.0" }, { fixed: "1.6.4" }],
        provenance: "https://osv.dev/vulnerability/GHSA-go-circl",
      },
    ]),
  });
  const candidate = report.candidates.find((item) => item.identity_strength === "strong");
  assert.ok(candidate, JSON.stringify(report, null, 2));
  assert.equal(candidate!.range_assessment?.verdict, "affected");
});

test("the report conforms to schema/sbom-check.schema.json", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-SCHEMA", "stevemao/left-pad", "npm", "left-pad")],
    rangeDataset: rangeDataset([npmRange("ANT-2026-SCHEMA", "left-pad", "1.0.0", "2.0.0")]),
  });
  assert.equal(report.candidates[0]!.range_assessment?.verdict, "affected");
  const schemaText = await readFile(
    new URL("../schema/sbom-check.schema.json", import.meta.url),
    "utf8",
  );
  const validate = new Ajv2020({ allErrors: true, strict: true }).compile(
    JSON.parse(schemaText) as object,
  );
  assert.equal(validate(report), true, JSON.stringify(validate.errors, null, 2));
});

test("bridges an exact-PURL candidate into verify-source", async (context) => {
  const repository = await mkdtemp(path.join(os.tmpdir(), "glasswing-sbom-src-"));
  context.after(async () => rm(repository, { recursive: true, force: true }));
  const git = (...args: string[]): Promise<{ stdout: string }> =>
    execFileAsync("git", args, { cwd: repository, encoding: "utf8" });
  await git("init", "-b", "main");
  await git("config", "user.name", "glasswing test");
  await git("config", "user.email", "glasswing@example.invalid");
  await git("remote", "add", "origin", "https://github.com/example/widget.git");

  const vulnerable = "int parse(const char *p){ if(p==0){return -1;} return decode(p); }\n";
  const fixed = "int parse(const char *p){ if(p==0){return -1;} return decode_checked(p); }\n";
  await mkdir(path.join(repository, "src"), { recursive: true });
  await writeFile(path.join(repository, "src/parser.c"), vulnerable);
  await git("add", "-A");
  await git("commit", "-m", "vulnerable");
  await writeFile(path.join(repository, "src/parser.c"), fixed);
  await git("add", "-A");
  await git("commit", "-m", "fix");
  const fixCommit = (await git("rev-parse", "HEAD")).stdout.trim();
  const patch = (await git("diff", "HEAD~1", "HEAD", "--", "src/parser.c")).stdout;
  const fingerprint = fingerprintPatch(patch, "src/parser.c", "src/parser.c");

  const antId = "ANT-2026-BRIDGE01";
  const impactDataset: FixImpactDataset = {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-02T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: 1,
      impact_count: 1,
      complete_count: 1,
      partial_count: 0,
      error_count: 0,
    },
    impacts: [
      {
        repository: "example/widget",
        commit: fixCommit,
        ant_ids: [antId],
        extraction_status: "complete",
        files: [
          {
            path_before: "src/parser.c",
            path_after: "src/parser.c",
            status: "modified",
            patch_available: true,
            hunks: fingerprint.hunks,
          },
        ],
        evidence: [{ source: "github_repository", url: `https://github.com/example/widget/commit/${fixCommit}` }],
        warnings: [],
      },
    ],
  };

  const sbomFile = await writeSbom(
    cyclonedx([{ type: "library", name: "widget", version: "1.0.0", purl: "pkg:npm/widget@1.0.0" }]),
  );
  const report: SbomCheckReport = await checkSbom({
    sbomFile,
    findings: [packageFinding(antId, "example/widget", "npm", "widget")],
    sourceRoot: repository,
    impactDataset,
  });
  const bridged = report.candidates.find((candidate) => candidate.verification);
  assert.ok(bridged, JSON.stringify(report, null, 2));
  assert.equal(bridged!.match_type, "ecosystem_package");
  assert.equal(bridged!.verification!.decision, "VERIFIED_FIXED");
  // The checkout's version is not machine-bound to the SBOM component version.
  assert.equal(bridged!.source_binding, "user_asserted");
  assert.ok(report.warnings.some((warning) => warning.includes("source binding is user_asserted")));
});

test("an explicit --source that cannot execute is an ERROR, not a passing warning", async () => {
  const antId = "ANT-2026-SRCERR1";
  const impactDataset: FixImpactDataset = {
    metadata: {
      schema_version: "1.0.0",
      generated_from: {
        fixmap_schema_version: "1.0.0",
        source_as_of: "2026-09-02T00:00:00Z",
        source_url: "https://red.anthropic.com/2026/cvd/data/payload.json",
      },
      finding_count: 1,
      impact_count: 1,
      complete_count: 1,
      partial_count: 0,
      error_count: 0,
    },
    impacts: [
      {
        repository: "example/widget",
        commit: "a".repeat(40),
        ant_ids: [antId],
        extraction_status: "complete",
        files: [{ path_before: "src/x.c", path_after: "src/x.c", status: "modified", patch_available: true, hunks: [] }],
        evidence: [{ source: "github_repository", url: "https://github.com/example/widget/commit/" + "a".repeat(40) }],
        warnings: [],
      },
    ],
  };
  const sbomFile = await writeSbom(
    cyclonedx([{ type: "library", name: "widget", version: "1.0.0", purl: "pkg:npm/widget@1.0.0" }]),
  );
  const report = await checkSbom({
    sbomFile,
    findings: [packageFinding(antId, "example/widget", "npm", "widget")],
    // A source path that does not exist: verifySource cannot execute.
    sourceRoot: path.join(os.tmpdir(), `glasswing-missing-${antId}`),
    impactDataset,
  });
  const candidate = report.candidates.find((item) => item.verification);
  assert.ok(candidate, JSON.stringify(report, null, 2));
  // Fail closed: an explicit --source that cannot run is ERROR (drives non-zero exit).
  assert.equal(candidate!.verification!.decision, "ERROR");
  assert.equal(candidate!.candidate_decision?.decision, "ERROR");
  assert.equal(candidate!.candidate_decision?.gating_eligible, true);
  // An ERROR must not be bound as user_asserted source evidence.
  assert.equal(candidate!.source_binding, undefined);
  assert.ok(report.warnings.some((warning) => warning.includes("source verification ERROR")));
});

test("readAffectedRangeDataset fails closed on malformed or invalid input", async () => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "glasswing-ranges-"));

  const malformed = path.join(dir, "malformed.json");
  await writeFile(malformed, "{ not json");
  await assert.rejects(readAffectedRangeDataset(malformed), /Malformed affected-range file/);

  const invalid = path.join(dir, "invalid.json");
  // Structurally wrong: a range missing required fields and a bad schema version.
  await writeFile(
    invalid,
    JSON.stringify({
      metadata: {
        schema_version: "9.9.9",
        generated_from: { fixmap_schema_version: "1.0.0", source_as_of: "x", source_url: "y" },
        finding_count: 0,
        record_count: 1,
      },
      ranges: [{ ant_id: "not-an-ant", advisory: "", ecosystem: "cve", package: "p", range_type: "SEMVER", events: [], provenance: "z" }],
    }),
  );
  await assert.rejects(readAffectedRangeDataset(invalid), /Invalid affected-range dataset/);

  const valid = path.join(dir, "valid.json");
  await writeFile(valid, JSON.stringify(rangeDataset([cveRange("ANT-2026-OK", "openssl", "3.0.0", "3.0.21")])));
  const dataset = await readAffectedRangeDataset(valid);
  assert.equal(dataset.ranges.length, 1);
});
