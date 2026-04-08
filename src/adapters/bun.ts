import {
  collectAdvisoryIds,
  countsFromMetadata,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonObject,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

const BUN_METADATA_KEYS = new Set(["metadata", "summary"]);
const BUN_MINIMUM_RELEASE_AGE_EXCLUDES_KEY = "minimumReleaseAgeExcludes";

export interface BunMinimumReleaseAgeExclusion {
  packageName: string;
  version: string;
  specifier: string;
}

function isBunRegistryAdvisory(
  value: unknown,
): value is Record<string, unknown> {
  return (
    isRecord(value) &&
    (typeof value.title === "string" ||
      typeof value.url === "string" ||
      typeof value.severity === "string" ||
      typeof value.vulnerable_versions === "string" ||
      typeof value.id === "number")
  );
}

function remediationFromVulnerableVersions(
  vulnerableVersions: unknown,
): string | undefined {
  if (typeof vulnerableVersions !== "string") {
    return undefined;
  }

  const trimmed = vulnerableVersions.trim();
  const simpleBoundaryMatch = /^(<=|<)\s*([^\s]+)$/.exec(trimmed);

  if (!simpleBoundaryMatch) {
    return undefined;
  }

  const operator = simpleBoundaryMatch[1];
  const version = simpleBoundaryMatch[2];

  if (!version) {
    return undefined;
  }

  return operator === "<"
    ? `upgrade to >=${version}`
    : `upgrade to >${version}`;
}

function extractBunAuditItems(json: Record<string, unknown>) {
  if (Array.isArray(json.vulnerabilities)) {
    return json.vulnerabilities.filter(isRecord);
  }

  if (Array.isArray(json.advisories)) {
    return json.advisories.filter(isRecord);
  }

  const items: Record<string, unknown>[] = [];

  for (const [packageName, advisories] of Object.entries(json)) {
    if (BUN_METADATA_KEYS.has(packageName) || !Array.isArray(advisories)) {
      continue;
    }

    for (const advisory of advisories) {
      if (!isBunRegistryAdvisory(advisory)) {
        continue;
      }

      items.push({
        ...advisory,
        package: packageName,
      });
    }
  }

  return items;
}

function parseQuotedTomlStrings(text: string): string[] {
  const values: string[] = [];
  const pattern = /"((?:\\.|[^"])*)"|'((?:\\.|[^'])*)'/g;

  for (const match of text.matchAll(pattern)) {
    const rawValue = match[1] ?? match[2];

    if (rawValue === undefined) {
      continue;
    }

    values.push(rawValue.replace(/\\(["'])/g, "$1").replace(/\\\\/g, "\\"));
  }

  return values;
}

function findTomlSectionRange(
  source: string,
  sectionName: string,
): { start: number; bodyStart: number; end: number } | null {
  const sectionPattern = new RegExp(`^\\[${sectionName}\\]\\s*$`, "m");
  const match = sectionPattern.exec(source);

  if (!match || match.index === undefined) {
    return null;
  }

  const start = match.index;
  const sectionLineEnd = source.indexOf("\n", start);
  const bodyStart = sectionLineEnd === -1 ? source.length : sectionLineEnd + 1;
  const nextSectionMatch = /^\[[^\]]+\]\s*$/m.exec(source.slice(bodyStart));
  const end =
    nextSectionMatch && nextSectionMatch.index !== undefined
      ? bodyStart + nextSectionMatch.index
      : source.length;

  return {
    start,
    bodyStart,
    end,
  };
}

function findTomlArrayAssignment(
  source: string,
  key: string,
  sectionName: string,
): { start: number; end: number; value: string } | null {
  const sectionRange = findTomlSectionRange(source, sectionName);

  if (!sectionRange) {
    return null;
  }

  const sectionSource = source.slice(sectionRange.bodyStart, sectionRange.end);
  const keyPattern = new RegExp(`^\\s*${key}\\s*=\\s*\\[`, "m");
  const match = keyPattern.exec(sectionSource);

  if (!match || match.index === undefined) {
    return null;
  }

  const start = sectionRange.bodyStart + match.index;
  const openBracketIndex = source.indexOf("[", start);

  if (openBracketIndex === -1) {
    return null;
  }

  let cursor = openBracketIndex;
  let inSingleQuote = false;
  let inDoubleQuote = false;

  while (cursor < source.length) {
    const char = source[cursor];
    const previousChar = cursor > openBracketIndex ? source[cursor - 1] : "";

    if (char === '"' && !inSingleQuote && previousChar !== "\\") {
      inDoubleQuote = !inDoubleQuote;
    } else if (char === "'" && !inDoubleQuote && previousChar !== "\\") {
      inSingleQuote = !inSingleQuote;
    } else if (char === "]" && !inSingleQuote && !inDoubleQuote) {
      return {
        start,
        end: cursor + 1,
        value: source.slice(openBracketIndex, cursor + 1),
      };
    }

    cursor += 1;
  }

  return null;
}

function parseBunFailedResolutionSpecifier(
  value: string,
): { packageName: string; version: string } | null {
  const separatorIndex = value.lastIndexOf("@");

  if (separatorIndex <= 0 || separatorIndex === value.length - 1) {
    return null;
  }

  return {
    packageName: value.slice(0, separatorIndex),
    version: value.slice(separatorIndex + 1),
  };
}

export function extractBunMinimumReleaseAgeExclusions(result: {
  stdout: string;
  stderr: string;
}): BunMinimumReleaseAgeExclusion[] {
  const seen = new Set<string>();
  const exclusions: BunMinimumReleaseAgeExclusion[] = [];
  const pushExclusion = (packageName: string, version: string) => {
    const specifier = packageName;

    if (seen.has(specifier)) {
      return;
    }

    seen.add(specifier);
    exclusions.push({
      packageName,
      version,
      specifier,
    });
  };

  for (const source of [result.stdout, result.stderr]) {
    const hasMinimumReleaseAgeSignal = source.includes("minimum-release-age");

    const minimumAgeMatches = source.matchAll(
      /No version matching ["']([^"']+)["'] found for specifier ["']([^"']+)["'] \((?:blocked by minimum-release-age: .*?|all versions blocked by minimum-release-age)\)/g,
    );

    for (const match of minimumAgeMatches) {
      const packageName = match[1];
      const version = match[2];

      if (!packageName || !version) {
        continue;
      }

      pushExclusion(packageName, version);
    }

    if (!hasMinimumReleaseAgeSignal) {
      continue;
    }

    const specifierMatches = source.matchAll(
      /No version matching ["']([^"']+)["'] found for specifier ["']([^"']+)["'] \(but package exists\)/g,
    );

    for (const match of specifierMatches) {
      const version = match[1];
      const packageName = match[2];

      if (!packageName || !version) {
        continue;
      }

      pushExclusion(packageName, version);
    }

    const failedResolutionMatches = source.matchAll(
      /error:\s+(\S+)\s+failed to resolve/g,
    );

    for (const match of failedResolutionMatches) {
      const parsedSpecifier = parseBunFailedResolutionSpecifier(match[1] ?? "");

      if (!parsedSpecifier) {
        continue;
      }

      pushExclusion(parsedSpecifier.packageName, parsedSpecifier.version);
    }
  }

  return exclusions;
}

export function parseBunMinimumReleaseAgeExcludesConfig(
  source: string,
): string[] {
  const assignment = findTomlArrayAssignment(
    source,
    BUN_MINIMUM_RELEASE_AGE_EXCLUDES_KEY,
    "install",
  );

  if (!assignment) {
    return [];
  }

  return parseQuotedTomlStrings(assignment.value);
}

export function updateBunMinimumReleaseAgeExcludesConfig(
  source: string,
  excludes: string[],
): string {
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  const assignment = `${BUN_MINIMUM_RELEASE_AGE_EXCLUDES_KEY} = [${excludes.map((entry) => JSON.stringify(entry)).join(", ")}]`;
  const existingAssignment = findTomlArrayAssignment(
    source,
    BUN_MINIMUM_RELEASE_AGE_EXCLUDES_KEY,
    "install",
  );

  if (existingAssignment) {
    return `${source.slice(0, existingAssignment.start)}${assignment}${source.slice(existingAssignment.end)}`;
  }

  const installSection = findTomlSectionRange(source, "install");

  if (installSection) {
    return `${source.slice(0, installSection.bodyStart)}${assignment}${newline}${source.slice(installSection.bodyStart)}`;
  }

  const prefix =
    source.length === 0
      ? ""
      : source.endsWith("\n") || source.endsWith("\r")
        ? ""
        : newline;

  return `${source}${prefix}[install]${newline}${assignment}${newline}`;
}

export const bunAdapter: PackageManagerAdapter = {
  manager: "bun",
  auditExitCodes: [0, 1],

  buildAuditProcess(context) {
    const args = ["audit", "--json", `--audit-level=${context.threshold}`];

    if (context.scope === "prod") {
      args.push("--prod");
    }

    return {
      command: "bun",
      args,
    };
  },

  buildRemediationProcess(context) {
    return null;
  },

  buildPostRemediationProcess() {
    return null;
  },

  buildDedupeProcess() {
    return null;
  },

  parseAudit(stdout, context) {
    const json = parseJsonObject(stdout, "bun");
    const counts =
      countsFromMetadata(
        isRecord(json.metadata) ? json.metadata.vulnerabilities : undefined,
      ) ?? countsFromMetadata(json.summary);
    const items = extractBunAuditItems(json);
    const entries: NormalizedVulnerability[] = [];

    for (const item of items) {
      if (!isRecord(item)) {
        continue;
      }

      const packageName =
        typeof item.package === "string"
          ? item.package
          : typeof item.name === "string"
            ? item.name
            : typeof item.module_name === "string"
              ? item.module_name
              : "unknown";
      const installedVersion =
        typeof item.version === "string"
          ? item.version
          : typeof item.installedVersion === "string"
            ? item.installedVersion
            : "unknown";
      const severity = normalizeSeverity(item.severity);
      const advisories = Array.isArray(item.advisories)
        ? item.advisories.filter(isRecord)
        : [item];
      const advisoryIds = collectAdvisoryIds(item, ...advisories);
      const advisoryWithTitle = advisories.find(
        (advisory) => typeof advisory.title === "string",
      );
      const advisoryWithUrl = advisories.find(
        (advisory) => typeof advisory.url === "string",
      );
      const title =
        typeof item.title === "string"
          ? item.title
          : typeof advisoryWithTitle?.title === "string"
            ? advisoryWithTitle.title
            : undefined;
      const url =
        typeof item.url === "string"
          ? item.url
          : typeof advisoryWithUrl?.url === "string"
            ? advisoryWithUrl.url
            : undefined;
      const advisoryWithVulnerableVersions = advisories.find(
        (advisory) => typeof advisory.vulnerable_versions === "string",
      );
      const remediation = remediationFromVulnerableVersions(
        typeof item.vulnerable_versions === "string"
          ? item.vulnerable_versions
          : advisoryWithVulnerableVersions?.vulnerable_versions,
      );

      entries.push({
        key: vulnerabilityKey(packageName, installedVersion, advisoryIds),
        packageName,
        installedVersion,
        severity,
        advisoryIds,
        remediation,
        title,
        url,
      });
    }

    return createSnapshot({
      manager: "bun",
      threshold: context.threshold,
      scope: context.scope,
      entries,
      counts,
    });
  },
};
