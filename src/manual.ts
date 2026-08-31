import { readFile } from "node:fs/promises";
import type {
  EnrichmentFragment,
  ManualOverride,
  ManualOverrides,
  ReleaseAssessment,
} from "./types.js";
import { mergeCommits, mergeReferences, mergeVersions } from "./merge.js";

export async function loadManualOverrides(file: string): Promise<ManualOverrides> {
  const text = await readFile(file, "utf8");
  const parsed = JSON.parse(text) as unknown;
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Manual override file must contain an object: ${file}`);
  }
  for (const [antId, override] of Object.entries(parsed as Record<string, unknown>)) {
    if (!/^ANT-\d{4}-[A-Z0-9]+$/.test(antId)) {
      throw new Error(`Invalid ANT ID in manual overrides: ${antId}`);
    }
    if (!override || typeof override !== "object" || Array.isArray(override)) {
      throw new Error(`Override for ${antId} must be an object`);
    }
  }
  return parsed as ManualOverrides;
}

export function manualEnrichment(antId: string, override: ManualOverride): EnrichmentFragment {
  const commits = (override.fix_commits ?? []).map((item) => {
    if (!/^[0-9a-f]{7,64}$/i.test(item.sha)) {
      throw new Error(`Invalid manual fix commit for ${antId}: ${item.sha}`);
    }
    return {
      sha: item.sha.toLowerCase(),
      url: item.url,
      ...(item.repository ? { repository: item.repository } : {}),
      confidence: "verified" as const,
      evidence: [
        {
          source: "manual_override" as const,
          url: item.evidence_url,
          locator: antId,
          ...(item.note ? { note: item.note } : {}),
        },
      ],
    };
  });
  const references = (override.fix_references ?? []).map((item) => ({
    kind: item.kind,
    url: item.url,
    ...(item.repository ? { repository: item.repository } : {}),
    ...(item.number === undefined ? {} : { number: item.number }),
    confidence: "verified" as const,
    evidence: [
      {
        source: "manual_override" as const,
        url: item.evidence_url,
        locator: antId,
        ...(item.note ? { note: item.note } : {}),
      },
    ],
  }));
  const versions = (override.fixed_versions ?? []).map((item) => ({
    version: item.version,
    ...(item.package ? { package: item.package } : {}),
    ...(item.ecosystem ? { ecosystem: item.ecosystem } : {}),
    ...(item.branch ? { branch: item.branch } : {}),
    ...(item.introduced ? { introduced: item.introduced } : {}),
    role: item.role ?? (item.first_patched ? "first_patched" : "patched"),
    first_patched: item.first_patched,
    confidence: item.confidence ?? "verified",
    evidence: [
      {
        source: "manual_override" as const,
        url: item.evidence_url,
        locator: antId,
        ...(item.note ? { note: item.note } : {}),
      },
    ],
    commit_verification: { status: "not_run" as const },
  }));
  return {
    ...(override.cve_ids ? { cve_ids: override.cve_ids } : {}),
    ...(override.ghsa_ids ? { ghsa_ids: override.ghsa_ids } : {}),
    fix_commits: mergeCommits(commits),
    fix_references: mergeReferences(references),
    fixed_versions: mergeVersions(versions),
    sources: override.release_assessment
      ? [
          {
            source: "manual_override",
            url: override.release_assessment.evidence_url,
            locator: antId,
            ...(override.release_assessment.note
              ? { note: override.release_assessment.note }
              : {}),
          },
        ]
      : [],
    warnings: [],
  };
}

export function manualReleaseAssessment(
  antId: string,
  override: ManualOverride,
): ReleaseAssessment | undefined {
  const assessment = override.release_assessment;
  if (!assessment) return undefined;
  return {
    status: assessment.status,
    ...(assessment.note ? { note: assessment.note } : {}),
    evidence: [
      {
        source: "manual_override",
        url: assessment.evidence_url,
        locator: antId,
        ...(assessment.note ? { note: assessment.note } : {}),
      },
    ],
  };
}
