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
import { SemverComparator } from "../src/sbom/comparator.js";
import { canonicalizePurl } from "../src/sbom/purl.js";
import type { SbomCheckReport } from "../src/sbom/types.js";

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

test("the report conforms to schema/sbom-check.schema.json", async () => {
  const file = await writeSbom(
    cyclonedx([{ type: "library", name: "left-pad", version: "1.0.0", purl: "pkg:npm/left-pad@1.0.0" }]),
  );
  const report = await checkSbom({
    sbomFile: file,
    findings: [packageFinding("ANT-2026-SCHEMA", "stevemao/left-pad", "npm", "left-pad")],
  });
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
});
