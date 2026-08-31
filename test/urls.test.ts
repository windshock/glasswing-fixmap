import assert from "node:assert/strict";
import test from "node:test";
import { cveRecordRawUrl, normalizeUrl } from "../src/urls.js";

test("maps CVE IDs to cvelistV5 buckets", () => {
  assert.equal(
    cveRecordRawUrl("CVE-2026-5500"),
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/5xxx/CVE-2026-5500.json",
  );
  assert.equal(
    cveRecordRawUrl("CVE-2026-29198"),
    "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/2026/29xxx/CVE-2026-29198.json",
  );
});

test("removes tracking parameters without changing evidence URLs", () => {
  assert.equal(
    normalizeUrl("https://example.test/fix?utm_source=chatgpt&keep=yes"),
    "https://example.test/fix?keep=yes",
  );
});
