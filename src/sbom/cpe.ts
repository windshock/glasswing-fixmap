/**
 * Minimal CPE 2.3 identity matching. This is not string equality: CPE attributes
 * carry ANY (`*`) and NA (`-`) semantics, so a component CPE and a range CPE are
 * compared attribute by attribute. Identity is decided on the `part`, `vendor`,
 * and `product` attributes; the version is left to the authoritative range
 * comparator. Both the CPE 2.3 formatted string and the legacy 2.2 URI binding
 * are accepted. Anything unparseable yields `unknown` so the caller falls back to
 * a weaker signal rather than guessing.
 */

export interface ParsedCpe {
  raw: string;
  part: string;
  vendor: string;
  product: string;
  version: string;
}

export type CpeRelation = "match" | "disjoint" | "unknown";

export interface CpeMatch {
  relation: CpeRelation;
  component_cpe?: string;
  range_cpe?: string;
}

/** Split on unescaped `:` so escaped colons inside an attribute are preserved. */
function splitFields(value: string): string[] {
  const fields: string[] = [];
  let current = "";
  for (let index = 0; index < value.length; index += 1) {
    const char = value[index]!;
    if (char === "\\" && index + 1 < value.length) {
      current += char + value[index + 1];
      index += 1;
      continue;
    }
    if (char === ":") {
      fields.push(current);
      current = "";
      continue;
    }
    current += char;
  }
  fields.push(current);
  return fields;
}

/** Lowercase, unescape, and normalize an empty value to ANY. */
function normalizeAttribute(value: string | undefined): string {
  if (value === undefined || value === "") return "*";
  return value.replace(/\\(.)/g, "$1").toLowerCase();
}

export function parseCpe(cpe: string): ParsedCpe | null {
  const raw = cpe.trim();
  const lower = raw.toLowerCase();
  if (lower.startsWith("cpe:2.3:")) {
    // cpe:2.3:part:vendor:product:version:update:...
    const fields = splitFields(raw);
    if (fields.length < 6) return null;
    return {
      raw,
      part: normalizeAttribute(fields[2]),
      vendor: normalizeAttribute(fields[3]),
      product: normalizeAttribute(fields[4]),
      version: normalizeAttribute(fields[5]),
    };
  }
  if (lower.startsWith("cpe:/")) {
    // cpe:/part:vendor:product:version:... (2.2 URI binding)
    const fields = splitFields(raw.slice("cpe:/".length));
    if (fields.length < 3) return null;
    return {
      raw,
      part: normalizeAttribute(fields[0]),
      vendor: normalizeAttribute(fields[1]),
      product: normalizeAttribute(fields[2]),
      version: normalizeAttribute(fields[3]),
    };
  }
  return null;
}

/** Two attributes are compatible when equal or when either is ANY. */
function attributesCompatible(a: string, b: string): boolean {
  if (a === "*" || b === "*") return true;
  return a === b;
}

function identityCompatible(a: ParsedCpe, b: ParsedCpe): boolean {
  return (
    attributesCompatible(a.part, b.part) &&
    attributesCompatible(a.vendor, b.vendor) &&
    attributesCompatible(a.product, b.product)
  );
}

/**
 * Relate a component's CPEs to an authoritative range's CPEs. `match` when some
 * pair shares a compatible part/vendor/product (strong identity). `disjoint` when
 * both sides declare CPEs but none are compatible — the range is a different
 * product (e.g. a JDBC driver vs the database server) and must not apply.
 * `unknown` when either side has no parseable CPE, so the caller falls back to a
 * weaker signal such as a product-name match.
 */
export function cpeRelation(componentCpes: string[], rangeCpes: string[]): CpeMatch {
  const components = componentCpes.map(parseCpe).filter((cpe): cpe is ParsedCpe => cpe !== null);
  const ranges = rangeCpes.map(parseCpe).filter((cpe): cpe is ParsedCpe => cpe !== null);
  if (components.length === 0 || ranges.length === 0) return { relation: "unknown" };
  for (const component of components) {
    for (const range of ranges) {
      if (identityCompatible(component, range)) {
        return { relation: "match", component_cpe: component.raw, range_cpe: range.raw };
      }
    }
  }
  return { relation: "disjoint", component_cpe: components[0]!.raw, range_cpe: ranges[0]!.raw };
}
