import {
  asStringArray,
  collectAdvisoryIds,
  isRecord,
  normalizeSeverity,
  uniqueSorted,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { NormalizedVulnerability, Severity } from "../core/types.js";

/**
 * A package version that a manager refused to install because of its
 * minimum-release-age policy, plus the specifier to add to the exclusion list.
 */
export interface MinimumReleaseAgeExclusion {
  packageName: string;
  version: string;
  specifier: string;
}

/** Collects exclusions while skipping specifiers that were already recorded. */
export function createExclusionCollector(
  toSpecifier: (packageName: string, version: string) => string,
): {
  push(packageName: string, version: string): void;
  exclusions: MinimumReleaseAgeExclusion[];
} {
  const seen = new Set<string>();
  const exclusions: MinimumReleaseAgeExclusion[] = [];

  return {
    exclusions,
    push(packageName, version) {
      const specifier = toSpecifier(packageName, version);

      if (seen.has(specifier)) {
        return;
      }

      seen.add(specifier);
      exclusions.push({ packageName, version, specifier });
    },
  };
}

/** Reads `key` from `record` when it holds a string, otherwise `undefined`. */
export function readOptionalString(
  record: Record<string, unknown>,
  key: string,
): string | undefined {
  const value = record[key];
  return typeof value === "string" ? value : undefined;
}

/** Reads the first of `keys` holding a string, falling back to `"unknown"`. */
export function readStringWithFallback(
  record: Record<string, unknown>,
  keys: readonly string[],
  fallback = "unknown",
): string {
  for (const key of keys) {
    const value = readOptionalString(record, key);

    if (value !== undefined) {
      return value;
    }
  }

  return fallback;
}

/** Sorted unique version strings from a raw audit field, or `["unknown"]`. */
export function toInstalledVersions(value: unknown): string[] {
  const versions = uniqueSorted(asStringArray(value));
  return versions.length > 0 ? versions : ["unknown"];
}

/** Sorted unique `version` fields of a raw audit `findings` array. */
function findingVersions(value: unknown): string[] {
  const findings = Array.isArray(value) ? value : [];

  return toInstalledVersions(
    findings.flatMap((finding) => (isRecord(finding) ? [finding.version] : [])),
  );
}

/** Appends `block` to a config file, inserting a separating newline if needed. */
export function appendConfigBlock(
  source: string,
  block: string,
  newline: string,
): string {
  const needsSeparator =
    source.length > 0 && !source.endsWith("\n") && !source.endsWith("\r");

  return `${source}${needsSeparator ? newline : ""}${block}${newline}`;
}

/** One entry per installed version, sharing the same advisory metadata. */
export function vulnerabilityEntries(input: {
  packageName: string;
  severity: Severity;
  advisoryIds: string[];
  title?: string | undefined;
  url?: string | undefined;
  versions: string[];
}): NormalizedVulnerability[] {
  return input.versions.map((installedVersion) => ({
    key: vulnerabilityKey(
      input.packageName,
      installedVersion,
      input.advisoryIds,
    ),
    packageName: input.packageName,
    installedVersion,
    severity: input.severity,
    advisoryIds: input.advisoryIds,
    title: input.title,
    url: input.url,
  }));
}

/**
 * Normalizes an advisory in the npm registry shape, as reported by `pnpm audit`
 * and `yarn` Classic: package name in `module_name`/`name` and installed
 * versions in `findings[].version`.
 */
export function registryAdvisoryEntries(
  advisory: Record<string, unknown>,
): NormalizedVulnerability[] {
  return vulnerabilityEntries({
    packageName: readStringWithFallback(advisory, ["module_name", "name"]),
    severity: normalizeSeverity(advisory.severity),
    advisoryIds: collectAdvisoryIds(advisory),
    title: readOptionalString(advisory, "title"),
    url: readOptionalString(advisory, "url"),
    versions: findingVersions(advisory.findings),
  });
}
