import assert from "node:assert/strict";
import test from "node:test";
import { parseCveRecord } from "../src/sources/cve.js";

test("derives only exclusive or explicit unaffected boundaries", () => {
  const record = {
    cveMetadata: { cveId: "CVE-2026-1", state: "PUBLISHED" },
    containers: {
      cna: {
        affected: [
          {
            product: "example",
            versions: [
              { version: "1.0.0", lessThan: "1.2.3", versionType: "semver", status: "affected" },
              {
                version: "2.0.0",
                lessThanOrEqual: "2.0.9",
                versionType: "semver",
                status: "affected",
              },
            ],
          },
        ],
      },
    },
  };
  const parsed = parseCveRecord(record, "CVE-2026-1", "https://example.test/cve.json");
  assert.deepEqual(
    parsed.fixed_versions.map((version) => version.version),
    ["1.2.3"],
  );
});

test("extracts git status transitions as fix commits", () => {
  const record = {
    cveMetadata: { cveId: "CVE-2026-2", state: "PUBLISHED" },
    containers: {
      cna: {
        affected: [
          {
            product: "example",
            versions: [
              {
                version: "0",
                versionType: "git",
                status: "affected",
                repo: "https://github.com/acme/example",
                changes: [{ at: "abcdef0123456789", status: "unaffected" }],
              },
            ],
          },
        ],
      },
    },
  };
  const parsed = parseCveRecord(record, "CVE-2026-2", "https://example.test/cve.json");
  assert.equal(parsed.fix_commits[0]?.sha, "abcdef0123456789");
  assert.equal(parsed.fix_commits[0]?.repository, "acme/example");
});
