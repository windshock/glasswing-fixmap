import { PackageURL } from "packageurl-js";
import { purlTypeForOsvEcosystem } from "./ecosystems.js";

export interface ParsedPurl {
  canonical: string;
  type: string;
  namespace?: string;
  name: string;
  version?: string;
}

/**
 * Parse and canonicalize a PURL with packageurl-js. A malformed PURL returns
 * `undefined` and is never repaired or concatenated by hand, so it can never
 * become an exact-identity match.
 */
export function canonicalizePurl(raw: string): ParsedPurl | undefined {
  if (typeof raw !== "string" || raw.trim().length === 0) return undefined;
  try {
    const parsed = PackageURL.fromString(raw.trim());
    const result: ParsedPurl = {
      canonical: parsed.toString(),
      type: parsed.type,
      name: parsed.name,
    };
    if (parsed.namespace) result.namespace = parsed.namespace;
    if (parsed.version) result.version = parsed.version;
    return result;
  } catch {
    return undefined;
  }
}

/**
 * A case-insensitive identity key ignoring version and qualifiers, used for
 * `ecosystem + package` equivalence between components and findings.
 */
export function purlIdentityKey(type: string, namespace: string | undefined, name: string): string {
  const scope = namespace ? `${namespace}/` : "";
  return `${type}:${scope}${name}`.toLowerCase();
}

export function identityKeyForParsedPurl(parsed: ParsedPurl): string {
  return purlIdentityKey(parsed.type, parsed.namespace, parsed.name);
}

/**
 * Build the identity key for a finding's `(ecosystem, package)` pair so it can
 * be compared to a component's PURL identity. Returns `undefined` when the
 * ecosystem is not one of the explicitly supported PURL mappings.
 *
 * Maven package names are published as `group:artifact`, which maps onto the
 * PURL `namespace`/`name` split.
 */
export function findingIdentityKey(ecosystem: string, packageName: string): string | undefined {
  const type = purlTypeForOsvEcosystem(ecosystem);
  if (!type) return undefined;
  const trimmed = packageName.trim();
  if (trimmed.length === 0) return undefined;
  if (type === "maven" && trimmed.includes(":")) {
    const separator = trimmed.indexOf(":");
    const namespace = trimmed.slice(0, separator);
    const name = trimmed.slice(separator + 1);
    return purlIdentityKey(type, namespace, name);
  }
  return purlIdentityKey(type, undefined, trimmed);
}
