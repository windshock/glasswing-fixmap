import { Spec, Validation } from "@cyclonedx/cyclonedx-library";
import { canonicalizePurl } from "./purl.js";
import type { NormalizedComponent, SbomAdapter, SbomParseResult } from "./types.js";

const SUPPORTED_SPEC_VERSIONS: Record<string, Spec.Version> = {
  "1.5": Spec.Version.v1dot5,
  "1.6": Spec.Version.v1dot6,
  "1.7": Spec.Version.v1dot7,
};

interface CycloneDxComponent {
  type?: unknown;
  name?: unknown;
  version?: unknown;
  purl?: unknown;
  cpe?: unknown;
  externalReferences?: unknown;
  components?: unknown;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

/**
 * Extract Ajv instance paths from the official validator's error value, or
 * `undefined` when the error is opaque. An opaque error is treated
 * conservatively as a hard rejection by the caller.
 */
function validationInstancePaths(error: unknown): string[] | undefined {
  if (!Array.isArray(error)) return undefined;
  const paths: string[] = [];
  for (const item of error) {
    if (!isRecord(item) || typeof item.instancePath !== "string") return undefined;
    paths.push(item.instancePath);
  }
  return paths;
}

/**
 * A validation error is identity-critical only when it touches the structural
 * shape of `components` or a field this adapter projects for identity. Cosmetic
 * violations elsewhere (a non-UUID `serialNumber`, a license carrying both `id`
 * and `name`, hashes, supplier) cannot corrupt a projected component identity,
 * so they are tolerated with a warning rather than rejecting the document.
 */
function isIdentityCritical(path: string): boolean {
  if (/(^|\/)components$/.test(path)) return true;
  if (/(^|\/)components\/\d+$/.test(path)) return true;
  return /(^|\/)components\/\d+\/(name|version|purl|cpe|type)$/.test(path);
}

function githubRepository(url: string): string | undefined {
  const match = url.trim().match(/github\.com[/:]([^/]+)\/([^/#?]+?)(?:\.git)?(?:[/#?].*)?$/i);
  return match?.[1] && match[2] ? `${match[1]}/${match[2]}` : undefined;
}

function repositoryFromReferences(references: unknown): string | undefined {
  if (!Array.isArray(references)) return undefined;
  for (const reference of references) {
    if (!isRecord(reference)) continue;
    if (reference.type !== "vcs" || typeof reference.url !== "string") continue;
    const repository = githubRepository(reference.url);
    if (repository) return repository;
  }
  return undefined;
}

function flattenComponents(components: unknown, into: CycloneDxComponent[]): void {
  if (!Array.isArray(components)) return;
  for (const component of components) {
    if (!isRecord(component)) continue;
    into.push(component as CycloneDxComponent);
    if (Array.isArray(component.components)) flattenComponents(component.components, into);
  }
}

function projectComponent(component: CycloneDxComponent): NormalizedComponent | undefined {
  if (typeof component.name !== "string" || component.name.trim().length === 0) return undefined;
  const normalized: NormalizedComponent = {
    source_format: "cyclonedx",
    name: component.name,
    cpes: typeof component.cpe === "string" && component.cpe.trim().length > 0 ? [component.cpe] : [],
    locations: [],
  };
  if (typeof component.type === "string") normalized.type = component.type;
  if (typeof component.version === "string") normalized.version = component.version;
  if (typeof component.purl === "string") {
    const parsed = canonicalizePurl(component.purl);
    if (parsed) normalized.purl = parsed.canonical;
  }
  const repository = repositoryFromReferences(component.externalReferences);
  if (repository) normalized.repository = repository;
  return normalized;
}

export class CycloneDxAdapter implements SbomAdapter {
  readonly format = "cyclonedx" as const;

  supports(document: unknown): boolean {
    return (
      isRecord(document) &&
      document.bomFormat === "CycloneDX" &&
      typeof document.specVersion === "string" &&
      document.specVersion in SUPPORTED_SPEC_VERSIONS
    );
  }

  async parse(document: unknown): Promise<SbomParseResult> {
    if (!isRecord(document) || typeof document.specVersion !== "string") {
      throw new Error("Document is not a recognized CycloneDX BOM");
    }
    const specVersion = document.specVersion;
    const version = SUPPORTED_SPEC_VERSIONS[specVersion];
    if (!version) throw new Error(`Unsupported CycloneDX specVersion: ${specVersion}`);

    const validator = new Validation.JsonStrictValidator(version);
    const validationError = await validator.validate(JSON.stringify(document));
    const warnings: string[] = [];
    if (validationError !== null) {
      const paths = validationInstancePaths(validationError);
      const criticalViolations = paths?.filter(isIdentityCritical) ?? [];
      // Reject when the error is opaque or when it touches component identity;
      // tolerate cosmetic violations that cannot corrupt a projected identity.
      if (paths === undefined || criticalViolations.length > 0) {
        throw new Error(
          `CycloneDX ${specVersion} document failed strict schema validation: ${JSON.stringify(validationError)}`,
        );
      }
      warnings.push(
        `CycloneDX ${specVersion} document does not fully conform to the official schema; proceeding for candidate selection despite ${paths.length} non-identity violation(s): ${[...new Set(paths)].sort().join(", ")}`,
      );
    }

    const flattened: CycloneDxComponent[] = [];
    // Include the BOM's primary/root component (the application the BOM
    // describes) and its nested structure, not only the dependency list.
    if (isRecord(document.metadata) && isRecord(document.metadata.component)) {
      const root = document.metadata.component as CycloneDxComponent;
      flattened.push(root);
      flattenComponents(root.components, flattened);
    }
    flattenComponents(document.components, flattened);
    const components: NormalizedComponent[] = [];
    for (const component of flattened) {
      const projected = projectComponent(component);
      if (projected) components.push(projected);
    }
    return { format: "cyclonedx", spec_version: specVersion, components, warnings };
  }
}
