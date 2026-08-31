import assert from "node:assert/strict";
import test from "node:test";
import { parseAnthropicFindingPage } from "../src/sources/anthropic.js";

test("extracts the upstream commit and reported release from a finding card", () => {
  const html = `
    <main>
      <div class="report-body">
        <h1>wolfSSL accepts truncated authentication tags</h1>
        <p>The issue was fixed in commit a88dd07c70e9415c3daa64d478f9a45bd65f9e5d,
        included in wolfSSL 5.9.1.</p>
      </div>
      <div class="marker">UPSTREAM FIX</div>
      <p class="kicker"><a href="https://github.com/wolfSSL/wolfssl/commit/a88dd07c7?utm_source=test">fix</a></p>
      <div class="marker">TIMELINE</div>
    </main>`;
  const parsed = parseAnthropicFindingPage(
    html,
    "ANT-2026-P23DVQM2",
    "wolfssl/wolfssl",
  );
  assert.equal(parsed.title, "wolfSSL accepts truncated authentication tags");
  assert.deepEqual(
    parsed.fix_commits.map((commit) => commit.sha),
    ["a88dd07c7", "a88dd07c70e9415c3daa64d478f9a45bd65f9e5d"],
  );
  assert.equal(parsed.fix_commits[0]?.repository, "wolfSSL/wolfssl");
  assert.deepEqual(
    parsed.fixed_versions.map((version) => version.version),
    ["5.9.1"],
  );
  assert.equal(parsed.fixed_versions[0]?.first_patched, null);
});

test("does not mistake protocol versions for release claims", () => {
  const html = `
    <main>
      <div class="report-body">
        <h1>Protocol issue</h1>
        <p>The fix is available when TLS 1.2 is enabled.</p>
        <p>The suggested fix follows RFC section 6.2.3.2.</p>
        <p>The fix blocks metadata address 169.254.169.254.</p>
        <table><tr><td>Affected versions</td><td>All current versions, confirmed on v4.5.9</td></tr></table>
        <h2>Suggested Fix</h2><p>Fix the address validation logic.</p>
        <p>It may resemble CVE-2020-1234, which was fixed in 0.15.1.</p>
        <p>The patch shipped in product version 2.4.5; version 2.4.4 is vulnerable.</p>
      </div>
    </main>`;
  const parsed = parseAnthropicFindingPage(html, "ANT-2026-TEST", "acme/example");
  assert.deepEqual(
    parsed.fixed_versions.map((version) => version.version),
    ["2.4.5"],
  );
});
