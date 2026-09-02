import { readFileSync } from "node:fs";
import { Ajv2020, type ValidateFunction } from "ajv/dist/2020.js";
import addFormatsImport from "ajv-formats";

const addFormats = addFormatsImport as unknown as (ajv: Ajv2020) => void;
import { canonicalizePurl } from "./purl.js";
import type { NormalizedComponent, SbomAdapter, SbomParseResult } from "./types.js";

const SUPPORTED_SYFT_SCHEMA_VERSIONS = new Set(["16.1.2"]);

const VENDORED_SCHEMA: Record<string, string> = {
  "16.1.2": "schema-16.1.2.json",
};

interface SyftArtifact {
  name?: unknown;
  version?: unknown;
  type?: unknown;
  purl?: unknown;
  cpes?: unknown;
  locations?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

const validatorCache = new Map<string, ValidateFunction>();

function schemaValidator(schemaVersion: string): ValidateFunction {
  const cached = validatorCache.get(schemaVersion);
  if (cached) return cached;
  const file = VENDORED_SCHEMA[schemaVersion];
  if (!file) throw new Error(`No vendored Syft schema for version ${schemaVersion}`);
  const schemaUrl = new URL(`../../schema/vendor/syft/${file}`, import.meta.url);
  const schema = JSON.parse(readFileSync(schemaUrl, "utf8")) as object;
  const ajv = new Ajv2020({ strict: false, allErrors: true });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  validatorCache.set(schemaVersion, validate);
  return validate;
}

function cpeStrings(cpes: unknown): string[] {
  if (!Array.isArray(cpes)) return [];
  const values: string[] = [];
  for (const entry of cpes) {
    if (typeof entry === "string") values.push(entry);
    else if (isRecord(entry) && typeof entry.cpe === "string") values.push(entry.cpe);
  }
  return [...new Set(values)];
}

function locationPaths(locations: unknown): string[] {
  if (!Array.isArray(locations)) return [];
  const paths: string[] = [];
  for (const location of locations) {
    if (isRecord(location) && typeof location.path === "string") paths.push(location.path);
  }
  return [...new Set(paths)].sort();
}

function projectArtifact(artifact: SyftArtifact): NormalizedComponent | undefined {
  if (typeof artifact.name !== "string" || artifact.name.trim().length === 0) return undefined;
  const normalized: NormalizedComponent = {
    source_format: "syft",
    name: artifact.name,
    cpes: cpeStrings(artifact.cpes),
    locations: locationPaths(artifact.locations),
  };
  if (typeof artifact.type === "string") normalized.type = artifact.type;
  if (typeof artifact.version === "string") normalized.version = artifact.version;
  if (typeof artifact.purl === "string") {
    const parsed = canonicalizePurl(artifact.purl);
    if (parsed) normalized.purl = parsed.canonical;
  }
  return normalized;
}

export class SyftAdapter implements SbomAdapter {
  readonly format = "syft" as const;

  supports(document: unknown): boolean {
    return (
      isRecord(document) &&
      Array.isArray(document.artifacts) &&
      isRecord(document.schema) &&
      typeof document.schema.version === "string" &&
      SUPPORTED_SYFT_SCHEMA_VERSIONS.has(document.schema.version)
    );
  }

  async parse(document: unknown): Promise<SbomParseResult> {
    if (!isRecord(document) || !isRecord(document.schema) || typeof document.schema.version !== "string") {
      throw new Error("Document is not a recognized Syft JSON BOM");
    }
    const schemaVersion = document.schema.version;
    if (!SUPPORTED_SYFT_SCHEMA_VERSIONS.has(schemaVersion)) {
      throw new Error(`Unsupported Syft schema version: ${schemaVersion}`);
    }
    const validate = schemaValidator(schemaVersion);
    if (!validate(document)) {
      throw new Error(
        `Syft ${schemaVersion} document failed schema validation: ${JSON.stringify(validate.errors?.slice(0, 3))}`,
      );
    }

    const artifacts = Array.isArray(document.artifacts) ? document.artifacts : [];
    const components: NormalizedComponent[] = [];
    for (const artifact of artifacts) {
      if (!isRecord(artifact)) continue;
      const projected = projectArtifact(artifact as SyftArtifact);
      if (projected) components.push(projected);
    }
    return { format: "syft", spec_version: schemaVersion, components, warnings: [] };
  }
}
