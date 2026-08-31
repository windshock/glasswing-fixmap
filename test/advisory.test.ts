import assert from "node:assert/strict";
import test from "node:test";
import {
  parseAdvisoryRecord,
  parseRepositoryAdvisoryPage,
} from "../src/sources/advisory.js";

test("keeps multiple maintenance branches as separate first patched versions", () => {
  const record = {
    id: "GHSA-mm7m-92g8-7m47",
    aliases: ["CVE-2026-53721"],
    affected: [
      {
        package: { ecosystem: "npm", name: "nuxt" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "4.0.0" }, { fixed: "4.4.7" }] }],
      },
      {
        package: { ecosystem: "npm", name: "nuxt" },
        ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "3.11.0" }, { fixed: "3.21.7" }] }],
      },
    ],
    references: [
      {
        type: "WEB",
        url: "https://github.com/nuxt/nuxt/commit/07e39cd6f26e407b4192b7865bd17bc44536b9bb",
      },
    ],
  };
  const parsed = parseAdvisoryRecord(
    record,
    "https://github.com/github/advisory-database/blob/main/example.json",
  );
  assert.deepEqual(parsed.cve_ids, ["CVE-2026-53721"]);
  assert.deepEqual(parsed.ghsa_ids, ["GHSA-mm7m-92g8-7m47"]);
  assert.deepEqual(
    parsed.fixed_versions.map(({ introduced, version, first_patched }) => ({
      introduced,
      version,
      first_patched,
    })),
    [
      { introduced: "3.11.0", version: "3.21.7", first_patched: true },
      { introduced: "4.0.0", version: "4.4.7", first_patched: true },
    ],
  );
  assert.equal(parsed.fix_commits[0]?.repository, "nuxt/nuxt");
});

test("reads patched versions from a repository security advisory page", () => {
  const html = `
    <main><div class="Box-body"><div>
      <div><h2>Package</h2><div><span class="f4 text-bold">rabbitmq-c</span></div></div>
      <div><h2>Affected versions</h2><div class="f4">&lt;=0.15.0</div></div>
      <div><h2>Patched versions</h2><div class="f4">0.16.0</div></div>
    </div><p>CVE-2026-44236</p></div></main>`;
  const parsed = parseRepositoryAdvisoryPage(
    html,
    "GHSA-jh48-qjf5-fx5v",
    "https://github.com/alanxz/rabbitmq-c/security/advisories/GHSA-jh48-qjf5-fx5v",
  );
  assert.deepEqual(parsed.cve_ids, ["CVE-2026-44236"]);
  assert.deepEqual(
    parsed.fixed_versions.map(({ package: packageName, version, first_patched }) => ({
      packageName,
      version,
      first_patched,
    })),
    [{ packageName: "rabbitmq-c", version: "0.16.0", first_patched: true }],
  );
});
