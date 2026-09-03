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
import { Pep440Comparator, SemverComparator } from "../src/sbom/comparator.js";
import { canonicalizePurl } from "../src/sbom/purl.js";
import type { SbomCheckReport } from "../src/sbom/types.js";
import { parseAuthoritativeRanges } from "../src/ranges/extract.js";
import { validateAffectedRangeDataset } from "../src/ranges/read.js";
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
    ecosystem: "npm",
    package: packageName,
    range_type: "ECOSYSTEM",
    events: [{ introduced }, { fixed }],
    provenance: "https://osv.dev/vulnerability/GHSA-test-0001",
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
