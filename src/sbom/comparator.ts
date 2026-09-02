import semver from "semver";
import type { RangeVerdict } from "./types.js";

export interface RangeEvent {
  introduced?: string;
  fixed?: string;
  last_affected?: string;
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
 * SemVer comparator for ecosystems whose versions are genuine Semantic
 * Versioning (npm, Go, crates.io). Security decisions use strict parsing: a
 * version that would need coercion is never forced into SemVer and yields
 * `unknown`. Ecosystems with their own version schemes (Maven, PyPI, Debian,
 * RPM, Packagist) are intentionally excluded until each has its own comparator
 * and conformance fixtures.
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
    const target = semver.valid(version.trim());
    if (target === null) return "unknown";

    // OSV interval semantics: events are processed in published order; an
    // `introduced` opens an affected interval, `fixed`/`last_affected` closes it.
    let affected = false;
    for (const event of range.events) {
      if (event.introduced !== undefined) {
        if (event.introduced === "0") {
          affected = true;
        } else {
          const introduced = semver.valid(event.introduced);
          if (introduced === null) return "unknown";
          if (semver.gte(target, introduced)) affected = true;
        }
      }
      if (event.fixed !== undefined) {
        const fixed = semver.valid(event.fixed);
        if (fixed === null) return "unknown";
        if (semver.gte(target, fixed)) affected = false;
      }
      if (event.last_affected !== undefined) {
        const lastAffected = semver.valid(event.last_affected);
        if (lastAffected === null) return "unknown";
        if (semver.gt(target, lastAffected)) affected = false;
      }
    }
    return affected ? "affected" : "not_affected";
  }
}

const COMPARATORS: VersionComparator[] = [new SemverComparator()];

export function selectComparator(
  ecosystem: string,
  rangeType: string,
): VersionComparator | undefined {
  return COMPARATORS.find((comparator) => comparator.supports(ecosystem, rangeType));
}
