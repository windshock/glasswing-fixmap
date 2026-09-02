import { lstat, readFile } from "node:fs/promises";
import path from "node:path";
import { validateImpactDataset } from "../impact/validate.js";
import type { FixImpactDataset } from "../impact/types.js";
import { fuseVerificationEvidence } from "./fusion.js";
import { GitAncestryVerifier } from "./git-ancestry.js";
import { GlasswingFingerprintVerifier } from "./native-fingerprint.js";
import { observation, sortObservations } from "./observations.js";
import {
  SOURCE_VERIFICATION_SCHEMA_VERSION,
  type SourceVerificationReport,
  type SourceVerifier,
  type VerifierResult,
} from "./types.js";

export interface VerifySourceOptions {
  antId: string;
  sourceRoot: string;
  impactDataset: FixImpactDataset;
  verifiers?: SourceVerifier[];
}

export async function readImpactDataset(file: string): Promise<FixImpactDataset> {
  return JSON.parse(await readFile(file, "utf8")) as FixImpactDataset;
}

function verifierFailure(verifier: SourceVerifier, error: unknown): VerifierResult {
  const detail = error instanceof Error ? error.message : String(error);
  return {
    backend: { name: verifier.name, version: "unknown" },
    execution_status: "error",
    observations: [
      observation({
        backend: verifier.name,
        type: "BACKEND_ERROR",
        strength: "informational",
        detail,
      }),
    ],
    warnings: [detail],
  };
}

export async function verifySource(options: VerifySourceOptions): Promise<SourceVerificationReport> {
  const antId = options.antId.trim().toUpperCase();
  if (!/^ANT-\d{4}-[A-Z0-9]+$/.test(antId)) throw new Error(`Invalid ANT ID: ${options.antId}`);
  const validationErrors = validateImpactDataset(options.impactDataset);
  if (validationErrors.length > 0) {
    throw new Error(`Invalid fix-impact dataset:\n${validationErrors.join("\n")}`);
  }
  const impacts = options.impactDataset.impacts.filter((impact) => impact.ant_ids.includes(antId));
  if (impacts.length === 0) throw new Error(`No fix impact found for ${antId}`);

  const sourceRoot = path.resolve(options.sourceRoot);
  const sourceMetadata = await lstat(sourceRoot);
  if (!sourceMetadata.isDirectory()) throw new Error(`Source path is not a directory: ${sourceRoot}`);

  const context = { antId, sourceRoot, impacts };
  const verifiers = options.verifiers ?? [
    new GitAncestryVerifier(),
    new GlasswingFingerprintVerifier(),
  ];
  const backendResults = await Promise.all(
    verifiers.map(async (verifier) => {
      try {
        const backend = await verifier.verify(context);
        return {
          ...backend,
          observations: sortObservations(backend.observations),
          warnings: [...new Set(backend.warnings)].sort(),
        };
      } catch (error) {
        return verifierFailure(verifier, error);
      }
    }),
  );
  backendResults.sort((a, b) => a.backend.name.localeCompare(b.backend.name));
  const fused = fuseVerificationEvidence(impacts, backendResults);
  const targets = impacts
    .map((impact) => ({ repository: impact.repository, commit: impact.commit }))
    .sort((a, b) => a.repository.localeCompare(b.repository) || a.commit.localeCompare(b.commit));

  return {
    schema_version: SOURCE_VERIFICATION_SCHEMA_VERSION,
    ant_id: antId,
    source: sourceRoot,
    impact_schema_version: options.impactDataset.metadata.schema_version,
    targets,
    backend_results: backendResults,
    ...fused,
  };
}
