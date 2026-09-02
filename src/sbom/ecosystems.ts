/**
 * Conservative, explicit mapping between PackageURL types and OSV/GHSA
 * ecosystem names. Only well-established, unambiguous pairs are listed; an
 * unlisted ecosystem or type is never guessed and simply produces no identity
 * match.
 */
const PURL_TYPE_TO_OSV: Record<string, string> = {
  npm: "npm",
  maven: "Maven",
  pypi: "PyPI",
  golang: "Go",
  composer: "Packagist",
  gem: "RubyGems",
  nuget: "NuGet",
  cargo: "crates.io",
  hex: "Hex",
  pub: "Pub",
};

const OSV_TO_PURL_TYPE: Record<string, string> = Object.fromEntries(
  Object.entries(PURL_TYPE_TO_OSV).map(([type, ecosystem]) => [ecosystem.toLowerCase(), type]),
);

export function purlTypeForOsvEcosystem(ecosystem: string): string | undefined {
  return OSV_TO_PURL_TYPE[ecosystem.trim().toLowerCase()];
}

export function osvEcosystemForPurlType(type: string): string | undefined {
  return PURL_TYPE_TO_OSV[type.trim().toLowerCase()];
}
