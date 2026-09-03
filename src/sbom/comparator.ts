import semver from "semver";
import * as pep440 from "@renovatebot/pep440";
import type { RangeVerdict } from "./types.js";

export interface RangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
  limit?: string;
}

/**
 * An affected range consumed exactly as published and parsed from OSV/GHSA/CVE.
 * It is never reconstructed from `fixed_versions[]` or from release ordering.
 */
export interface AuthoritativeRange {
  ecosystem: string;
  range_type: string;
  events: RangeEvent[];
  provenance: string;
}

export interface VersionComparator {
  readonly name: string;
  supports(ecosystem: string, rangeType: string): boolean;
  evaluate(version: string, range: AuthoritativeRange): RangeVerdict;
}

/**
 * The ecosystem-specific operations an interval evaluation needs. `valid`
 * returns a comparable version or `null` when the value is not valid for the
 * scheme (never coerced); `gte`/`gt` order two valid versions.
 */
interface VersionOps {
  valid(version: string): string | null;
  gte(a: string, b: string): boolean;
  gt(a: string, b: string): boolean;
}

/**
 * OSV interval semantics shared by every comparator: events are processed in
 * published order; an `introduced` opens an affected interval, and
 * `fixed`/`last_affected` close it. A value that fails strict `valid` parsing
 * yields `unknown` rather than being coerced.
 */
function evaluateInterval(version: string, range: AuthoritativeRange, ops: VersionOps): RangeVerdict {
  const target = ops.valid(version.trim());
  if (target === null) return "unknown";

  let affected = false;
  for (const event of range.events) {
    if (event.introduced !== undefined) {
      if (event.introduced === "0") {
        affected = true;
      } else {
        const introduced = ops.valid(event.introduced);
        if (introduced === null) return "unknown";
        if (ops.gte(target, introduced)) affected = true;
      }
    }
    if (event.fixed !== undefined) {
      const fixed = ops.valid(event.fixed);
      if (fixed === null) return "unknown";
      if (ops.gte(target, fixed)) affected = false;
    }
    if (event.last_affected !== undefined) {
      const lastAffected = ops.valid(event.last_affected);
      if (lastAffected === null) return "unknown";
      if (ops.gt(target, lastAffected)) affected = false;
    }
    if (event.limit !== undefined) {
      // A `limit` is an exclusive upper bound: a version at or past it is outside
      // this range (OSV BeforeLimits semantics).
      const limit = ops.valid(event.limit);
      if (limit === null) return "unknown";
      if (ops.gte(target, limit)) affected = false;
    }
  }
  return affected ? "affected" : "not_affected";
}

const semverOps: VersionOps = {
  valid: (version) => semver.valid(version),
  gte: (a, b) => semver.gte(a, b),
  gt: (a, b) => semver.gt(a, b),
};

const pep440Ops: VersionOps = {
  valid: (version) => pep440.valid(version) ?? null,
  gte: (a, b) => pep440.gte(a, b),
  gt: (a, b) => pep440.gt(a, b),
};

/**
 * OpenSSL classic versioning: `major.minor.fix` with an optional lowercase
 * letter suffix, where the empty suffix (`1.1.1`, the base release) precedes
 * `1.1.1a`, and the suffix advances `a … z, za, zb …` (bijective base-26). A
 * plain three-part numeric version (OpenSSL 3.x, `3.0.7`) is the empty-suffix
 * case and sorts identically to SemVer for these values. Anything else —
 * two-part product lines (`15.18`), FIPS or distro variants (`3.4-fips3.1`,
 * `0.16_p3`) — is not this scheme and must stay unresolved, never coerced.
 */
const OPENSSL_VERSION = /^(\d+)\.(\d+)\.(\d+)([a-z]*)$/;

function bijectiveBase26(letters: string): number {
  let value = 0;
  for (const char of letters) value = value * 26 + (char.charCodeAt(0) - 96);
  return value;
}

/**
 * Encode an OpenSSL version into a fixed-width, lexicographically comparable
 * key so ordinary string comparison yields the correct total order. Returns
 * null for any value that is not OpenSSL classic / three-part numeric.
 */
function opensslKey(version: string): string | null {
  const match = OPENSSL_VERSION.exec(version.trim());
  if (!match) return null;
  const [, major, minor, fix, letters] = match;
  const pad = (value: string, width: number) => value.padStart(width, "0");
  return [
    pad(major!, 6),
    pad(minor!, 6),
    pad(fix!, 6),
    pad(String(bijectiveBase26(letters!)), 5),
  ].join(".");
}

const opensslOps: VersionOps = {
  valid: (version) => opensslKey(version),
  // Keys are fixed width, so lexicographic comparison is the numeric order.
  gte: (a, b) => a >= b,
  gt: (a, b) => a > b,
};

/**
 * SemVer comparator for ecosystems whose versions are genuine Semantic
 * Versioning (npm, Go, crates.io). Security decisions use strict parsing: a
 * version that would need coercion is never forced into SemVer and yields
 * `unknown`. Ecosystems with their own version schemes are handled by dedicated
 * comparators (PyPI) or remain `unknown` until each has a well-maintained
 * implementation and conformance fixtures (Maven, Debian, RPM, Packagist).
 */
export class SemverComparator implements VersionComparator {
  readonly name = "semver";

  private static readonly SEMVER_ECOSYSTEMS = new Set(["npm", "go", "crates.io"]);

  supports(ecosystem: string, rangeType: string): boolean {
    const type = rangeType.trim().toUpperCase();
    if (type !== "SEMVER" && type !== "ECOSYSTEM") return false;
    return SemverComparator.SEMVER_ECOSYSTEMS.has(ecosystem.trim().toLowerCase());
  }

  evaluate(version: string, range: AuthoritativeRange): RangeVerdict {
    if (!this.supports(range.ecosystem, range.range_type)) return "unknown";
    return evaluateInterval(version, range, semverOps);
  }
}

/**
 * PEP 440 comparator for PyPI, backed by the `@renovatebot/pep440`
 * implementation rather than a hand-rolled algorithm.
 */
export class Pep440Comparator implements VersionComparator {
  readonly name = "pep440";

  supports(ecosystem: string, rangeType: string): boolean {
    const type = rangeType.trim().toUpperCase();
    if (type !== "SEMVER" && type !== "ECOSYSTEM") return false;
    return ecosystem.trim().toLowerCase() === "pypi";
  }

  evaluate(version: string, range: AuthoritativeRange): RangeVerdict {
    if (!this.supports(range.ecosystem, range.range_type)) return "unknown";
    return evaluateInterval(version, range, pep440Ops);
  }
}

/**
 * Comparator for the `cve` sentinel ecosystem used by CVE List V5 product
 * ranges. CVE records carry no package ecosystem, so their versions follow the
 * product's own scheme. This handles OpenSSL classic versioning (letter suffix)
 * and plain three-part numeric versions; values outside that scheme (two-part
 * product lines, FIPS/distro variants) stay `unknown` and are routed to
 * adjudication rather than guessed.
 */
export class CveVersionComparator implements VersionComparator {
  readonly name = "cve-openssl";

  supports(ecosystem: string, rangeType: string): boolean {
    const type = rangeType.trim().toUpperCase();
    if (type !== "SEMVER" && type !== "ECOSYSTEM") return false;
    return ecosystem.trim().toLowerCase() === "cve";
  }

  evaluate(version: string, range: AuthoritativeRange): RangeVerdict {
    if (!this.supports(range.ecosystem, range.range_type)) return "unknown";
    return evaluateInterval(version, range, opensslOps);
  }
}

const COMPARATORS: VersionComparator[] = [
  new SemverComparator(),
  new Pep440Comparator(),
  new CveVersionComparator(),
];

export function selectComparator(
  ecosystem: string,
  rangeType: string,
): VersionComparator | undefined {
  return COMPARATORS.find((comparator) => comparator.supports(ecosystem, rangeType));
}
