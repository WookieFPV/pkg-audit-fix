import {
  collectAdvisoryIds,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonLines,
  parseJsonObject,
  uniqueSorted,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

export interface YarnMinimumReleaseAgeExclusion {
  packageName: string;
  version: string;
  specifier: string;
}

function isBerryAuditOutput(stdout: string): boolean {
  if (parseBerryAuditOutput(stdout)) {
    return true;
  }

  try {
    const events = parseJsonLines(stdout, "yarn");

    return events.some(
      (event) => typeof event.value === "string" && isRecord(event.children),
    );
  } catch {
    return false;
  }
}

function parseBerryAuditOutput(stdout: string): Record<string, unknown> | null {
  try {
    return parseJsonObject(stdout, "yarn");
  } catch {
    return null;
  }
}

function collectBerryNdjsonEntries(stdout: string): NormalizedVulnerability[] {
  const events = parseJsonLines(stdout, "yarn");
  const entries: NormalizedVulnerability[] = [];

  for (const event of events) {
    if (typeof event.value !== "string" || !isRecord(event.children)) {
      continue;
    }

    const packageName = event.value;
    const advisory = event.children;
    const severity = normalizeSeverity(advisory.Severity);
    const advisoryIds = collectAdvisoryIds(advisory, {
      ghsaId: advisory.URL,
    });
    const title =
      typeof advisory.Issue === "string" ? advisory.Issue : undefined;
    const url = typeof advisory.URL === "string" ? advisory.URL : undefined;
    const versions = uniqueSorted(
      Array.isArray(advisory["Tree Versions"])
        ? advisory["Tree Versions"].filter(
            (version): version is string => typeof version === "string",
          )
        : [],
    );

    for (const installedVersion of versions.length > 0
      ? versions
      : ["unknown"]) {
      entries.push({
        key: vulnerabilityKey(packageName, installedVersion, advisoryIds),
        packageName,
        installedVersion,
        severity,
        advisoryIds,
        title,
        url,
      });
    }
  }

  return entries;
}

function parseYamlScalar(value: string): string {
  const trimmed = value.trim();

  if (
    (trimmed.startsWith('"') && trimmed.endsWith('"')) ||
    (trimmed.startsWith("'") && trimmed.endsWith("'"))
  ) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
}

function findRootYamlKeyRange(
  source: string,
  key: string,
): {
  start: number;
  end: number;
  lineEnd: number;
  value: string;
} | null {
  const keyPattern = new RegExp(`^${key}:([^\\n\\r]*)`, "m");
  const match = keyPattern.exec(source);

  if (!match || match.index === undefined) {
    return null;
  }

  const start = match.index;
  const lineEnd = source.indexOf("\n", start);
  const resolvedLineEnd = lineEnd === -1 ? source.length : lineEnd;
  const blockStart =
    resolvedLineEnd === source.length ? source.length : lineEnd + 1;
  const nextRootKey = /^(?![\s#-])[^:\n\r]+:/m.exec(source.slice(blockStart));
  const end =
    nextRootKey && nextRootKey.index !== undefined
      ? blockStart + nextRootKey.index
      : source.length;

  return {
    start,
    end,
    lineEnd: resolvedLineEnd,
    value: match[1] ?? "",
  };
}

export function extractYarnMinimumReleaseAgeExclusions(result: {
  stdout: string;
  stderr: string;
}): YarnMinimumReleaseAgeExclusion[] {
  const seen = new Set<string>();
  const exclusions: YarnMinimumReleaseAgeExclusion[] = [];
  const pushExclusion = (packageName: string, version: string) => {
    const specifier = `${packageName}@${version}`;

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
    const matches = source.matchAll(
      /YN0016:.*?([@a-zA-Z0-9._/-]+)@npm:[^:\s]+: All versions satisfying "([^"]+)" are quarantined/g,
    );

    for (const match of matches) {
      const packageName = match[1];
      const version = match[2];

      if (!packageName || !version) {
        continue;
      }

      pushExclusion(packageName, version);
    }
  }

  return exclusions;
}

export function parseYarnNpmPreapprovedPackagesConfig(
  source: string,
): string[] {
  const keyRange = findRootYamlKeyRange(source, "npmPreapprovedPackages");

  if (!keyRange) {
    return [];
  }

  const inlineValue = keyRange.value.trim();

  if (inlineValue.startsWith("[") && inlineValue.endsWith("]")) {
    const rawEntries = inlineValue.slice(1, -1).trim();

    if (rawEntries.length === 0) {
      return [];
    }

    return rawEntries
      .split(",")
      .map((entry) => parseYamlScalar(entry))
      .filter((entry) => entry.length > 0);
  }

  const lines = source
    .slice(keyRange.lineEnd, keyRange.end)
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.startsWith("- "))
    .map((line) => parseYamlScalar(line.slice(2)))
    .filter((line) => line.length > 0);

  return lines;
}

export function updateYarnNpmPreapprovedPackagesConfig(
  source: string,
  packages: string[],
): string {
  const newline = source.includes("\r\n") ? "\r\n" : "\n";
  const block =
    packages.length === 0
      ? "npmPreapprovedPackages: []"
      : `npmPreapprovedPackages:${newline}${packages.map((entry) => `  - ${JSON.stringify(entry)}`).join(newline)}`;
  const existingKey = findRootYamlKeyRange(source, "npmPreapprovedPackages");

  if (existingKey) {
    return `${source.slice(0, existingKey.start)}${block}${source.slice(existingKey.end)}`;
  }

  const prefix =
    source.length === 0
      ? ""
      : source.endsWith("\n") || source.endsWith("\r")
        ? ""
        : newline;

  return `${source}${prefix}${block}${newline}`;
}

export const yarnBerryAdapter: PackageManagerAdapter = {
  manager: "yarn",
  auditExitCodes: [0],

  buildAuditProcess(context) {
    const args = [
      "npm",
      "audit",
      "--json",
      "--no-deprecations",
      "--all",
      "--recursive",
      "--severity",
      context.threshold,
    ];

    if (context.scope === "prod") {
      args.push("--environment", "production");
    } else if (context.scope === "dev") {
      args.push("--environment", "development");
    }

    return {
      command: "yarn",
      args,
    };
  },

  buildRemediationProcess() {
    return null;
  },

  buildPostRemediationProcess() {
    return null;
  },

  buildDedupeProcess() {
    return {
      command: "yarn",
      args: ["dedupe"],
    };
  },

  isAuditResult(stdout) {
    return isBerryAuditOutput(stdout);
  },

  parseAudit(stdout, context) {
    const entries: NormalizedVulnerability[] = [];
    const json = parseBerryAuditOutput(stdout);

    if (!json) {
      return createSnapshot({
        manager: "yarn",
        threshold: context.threshold,
        scope: context.scope,
        entries: collectBerryNdjsonEntries(stdout),
      });
    }

    for (const [packageName, advisories] of Object.entries(json)) {
      if (!Array.isArray(advisories)) {
        continue;
      }

      for (const advisory of advisories) {
        if (!isRecord(advisory)) {
          continue;
        }

        const severity = normalizeSeverity(advisory.severity);
        const advisoryIds = collectAdvisoryIds(advisory);
        const title =
          typeof advisory.title === "string" ? advisory.title : undefined;
        const url = typeof advisory.url === "string" ? advisory.url : undefined;
        const versions = uniqueSorted(
          Array.isArray(advisory.versions)
            ? advisory.versions.filter(
                (version): version is string => typeof version === "string",
              )
            : [],
        );

        for (const installedVersion of versions.length > 0
          ? versions
          : ["unknown"]) {
          entries.push({
            key: vulnerabilityKey(packageName, installedVersion, advisoryIds),
            packageName,
            installedVersion,
            severity,
            advisoryIds,
            title,
            url,
          });
        }
      }
    }

    return createSnapshot({
      manager: "yarn",
      threshold: context.threshold,
      scope: context.scope,
      entries,
    });
  },
};
