/**
 * Distro / vendor / FIPS build-flavor handling. Stripping a downstream suffix to
 * the base upstream version is useful *evidence*, never the final decision: a
 * distro revision may carry a backported fix, so an upstream-affected base must
 * not become a gating AFFECTED for a rebuild. This module only recognizes the
 * flavor and computes a base bound; the caller keeps the final decision UNKNOWN.
 */

const FLAVOR_PATTERNS: RegExp[] = [
  /_p\d+$/i, // Gentoo patch revision, e.g. 0.16_p3
  /[-+]?fips[\d.]*$/i, // FIPS build, e.g. 3.4-fips3.1
  /-\d+\.(?:el|fc)\d+.*$/i, // RPM release, e.g. 1.2.3-4.el8
  /\.(?:el|fc)\d+.*$/i, // RPM dist tag, e.g. 1.2.3.el8
  /\+deb\d+u\d+$/i, // Debian, e.g. 1.2.3+deb12u1
  /-\d+ubuntu[\d.]*$/i, // Ubuntu, e.g. 1.2.3-1ubuntu2
];

export interface StrippedVersion {
  base: string;
  flavor: string;
}

/**
 * Split a downstream-flavored version into its base upstream version and the
 * flavor suffix. Returns null when no recognized flavor is present or the base
 * is not a plain numeric version — never guesses.
 */
export function stripBuildFlavor(version: string | undefined): StrippedVersion | null {
  if (!version) return null;
  for (const pattern of FLAVOR_PATTERNS) {
    const match = version.match(pattern);
    if (match && match.index !== undefined && match.index > 0) {
      const base = version.slice(0, match.index).replace(/[-.]$/, "");
      const flavor = version.slice(match.index);
      if (/^\d+(?:\.\d+){0,3}$/.test(base)) return { base, flavor };
    }
  }
  return null;
}

/** Zero-fill a base version to three numeric parts (its lowest patch level). */
export function baseLowerBound(base: string): string {
  const parts = base.split(".");
  while (parts.length < 3) parts.push("0");
  return parts.slice(0, 3).join(".");
}

/** Fill a base version to three parts with a high patch level (its upper edge). */
export function baseUpperBound(base: string): string {
  const parts = base.split(".");
  while (parts.length < 3) parts.push("999999");
  return parts.slice(0, 3).join(".");
}
