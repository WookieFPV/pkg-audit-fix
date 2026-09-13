import {
  asStringArray,
  countsFromMetadata,
  createSnapshot,
  isRecord,
  parseJsonObject,
  uniqueSorted,
} from "../core/normalize.js";
import type {
  AuditScope,
  CommandResult,
  NormalizedVulnerability,
} from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";
import {
  createExclusionCollector,
  type MinimumReleaseAgeExclusion,
  registryAdvisoryEntries,
} from "./shared.js";

function scopeArgs(scope: AuditScope): string[] {
  if (scope === "prod") {
    return ["--prod"];
  }

  return scope === "dev" ? ["--dev"] : [];
}

const MINIMUM_RELEASE_AGE_ERROR_CODE = "ERR_PNPM_NO_MATURE_MATCHING_VERSION";

function parsePnpmReporterRecords(text: string): unknown[] {
  const trimmed = text.trim();

  if (trimmed.length === 0) {
    return [];
  }

  const records = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0)
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as unknown];
      } catch {
        return [];
      }
    });

  if (records.length > 0) {
    return records;
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    return Array.isArray(parsed) ? parsed : [parsed];
  } catch {
    return [];
  }
}

function readString(
  object: Record<string, unknown>,
  key: string,
): string | null {
  const value = object[key];
  return typeof value === "string" ? value : null;
}

function readErrorCode(record: Record<string, unknown>): string | null {
  const directCode = readString(record, "code");

  if (directCode) {
    return directCode;
  }

  if (!isRecord(record.err)) {
    return null;
  }

  return readString(record.err, "code");
}

function readPackageName(record: Record<string, unknown>): string | null {
  if (isRecord(record.package)) {
    const packageName = readString(record.package, "name");

    if (packageName) {
      return packageName;
    }
  }

  if (isRecord(record.packageMeta)) {
    const packageName = readString(record.packageMeta, "name");

    if (packageName) {
      return packageName;
    }
  }

  return null;
}

function readVersion(record: Record<string, unknown>): string | null {
  const immatureVersion = readString(record, "immatureVersion");

  if (immatureVersion) {
    return immatureVersion;
  }

  if (isRecord(record.package)) {
    const version = readString(record.package, "version");

    if (version) {
      return version;
    }
  }

  return null;
}

export function extractPnpmMinimumReleaseAgeExclusions(
  result: Pick<CommandResult, "stdout" | "stderr">,
): MinimumReleaseAgeExclusion[] {
  const collector = createExclusionCollector(
    (packageName, version) => `${packageName}@${version}`,
  );

  for (const source of [result.stdout, result.stderr]) {
    for (const record of parsePnpmReporterRecords(source)) {
      if (!isRecord(record)) {
        continue;
      }

      if (readErrorCode(record) !== MINIMUM_RELEASE_AGE_ERROR_CODE) {
        continue;
      }

      const packageName = readPackageName(record);
      const version = readVersion(record);

      if (!packageName || !version) {
        continue;
      }

      collector.push(packageName, version);
    }

    const messageMatches = source.matchAll(
      /Version\s+(\S+)\s+\(released .*?\)\s+of\s+(.+?)\s+does not meet the minimumReleaseAge constraint/g,
    );

    for (const match of messageMatches) {
      const version = match[1];
      const packageName = match[2];

      if (!packageName || !version) {
        continue;
      }

      collector.push(packageName, version);
    }
  }

  return collector.exclusions;
}

/**
 * Parses the JSON printed by `pnpm config get --json`, treating an empty or
 * unset value as `undefined`.
 */
function parsePnpmConfigJson(stdout: string): unknown {
  const trimmed = stdout.trim();

  if (trimmed.length === 0 || trimmed === "null" || trimmed === "undefined") {
    return undefined;
  }

  return JSON.parse(trimmed) as unknown;
}

export function parsePnpmMinimumReleaseAgeExcludeConfig(
  stdout: string,
): string[] {
  const parsed = parsePnpmConfigJson(stdout);

  if (typeof parsed === "string") {
    return [parsed];
  }

  return asStringArray(parsed);
}

export function parsePnpmMinimumReleaseAgeConfig(
  stdout: string,
): number | null {
  const parsed = parsePnpmConfigJson(stdout);
  const value =
    typeof parsed === "number"
      ? parsed
      : typeof parsed === "string" && parsed.trim().length > 0
        ? Number(parsed)
        : Number.NaN;

  return Number.isFinite(value) && value >= 0 ? value : null;
}

export function parsePnpmAuditIgnoreListConfig(stdout: string): string[] {
  return uniqueSorted(
    asStringArray(parsePnpmConfigJson(stdout)).map((entry) =>
      entry.toUpperCase(),
    ),
  );
}

export function parsePnpmPackagePublishedTimes(
  stdout: string,
): Record<string, string> {
  const parsed = parsePnpmConfigJson(stdout);

  if (!isRecord(parsed)) {
    return {};
  }

  return Object.fromEntries(
    Object.entries(parsed).filter(
      (entry): entry is [string, string] => typeof entry[1] === "string",
    ),
  );
}

export const pnpmAdapter: PackageManagerAdapter = {
  manager: "pnpm",
  auditExitCodes: [0, 1],
  remediationExitCodes: [0, 1],

  buildAuditProcess(context) {
    return {
      command: "pnpm",
      args: [
        "audit",
        "--json",
        `--audit-level=${context.threshold}`,
        ...scopeArgs(context.scope),
      ],
    };
  },

  buildRemediationProcess(context) {
    return {
      command: "pnpm",
      args: [
        "audit",
        "--json",
        "--fix",
        "override",
        `--audit-level=${context.threshold}`,
        ...scopeArgs(context.scope),
      ],
    };
  },

  buildPostRemediationProcess() {
    return {
      command: "pnpm",
      args: ["install", "--no-frozen-lockfile", "--reporter", "ndjson"],
    };
  },

  buildDedupeProcess() {
    return {
      command: "pnpm",
      args: ["dedupe"],
    };
  },

  parseAudit(stdout, context) {
    const json = parseJsonObject(stdout, "pnpm");
    const advisories = isRecord(json.advisories)
      ? Object.values(json.advisories)
      : [];
    const entries: NormalizedVulnerability[] = advisories
      .filter(isRecord)
      .flatMap(registryAdvisoryEntries);

    return createSnapshot({
      manager: "pnpm",
      threshold: context.threshold,
      scope: context.scope,
      entries,
      counts: countsFromMetadata(
        isRecord(json.metadata) ? json.metadata.vulnerabilities : undefined,
      ),
    });
  },
};
