import {
  collectAdvisoryIds,
  countsFromMetadata,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonObject,
  uniqueSorted,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { CommandResult, NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

const MINIMUM_RELEASE_AGE_ERROR_CODE = "ERR_PNPM_NO_MATURE_MATCHING_VERSION";

export interface PnpmMinimumReleaseAgeExclusion {
  packageName: string;
  version: string;
  specifier: string;
}

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
): PnpmMinimumReleaseAgeExclusion[] {
  const seen = new Set<string>();
  const exclusions: PnpmMinimumReleaseAgeExclusion[] = [];
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

      pushExclusion(packageName, version);
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

      pushExclusion(packageName, version);
    }
  }

  return exclusions;
}

export function parsePnpmMinimumReleaseAgeExcludeConfig(
  stdout: string,
): string[] {
  const trimmed = stdout.trim();

  if (trimmed.length === 0 || trimmed === "null" || trimmed === "undefined") {
    return [];
  }

  const parsed = JSON.parse(trimmed) as unknown;

  if (Array.isArray(parsed)) {
    return parsed.filter((entry): entry is string => typeof entry === "string");
  }

  if (typeof parsed === "string") {
    return [parsed];
  }

  return [];
}

export const pnpmAdapter: PackageManagerAdapter = {
  manager: "pnpm",
  auditExitCodes: [0, 1],
  remediationExitCodes: [0, 1],

  buildAuditProcess(context) {
    const args = ["audit", "--json", `--audit-level=${context.threshold}`];

    if (context.scope === "prod") {
      args.push("--prod");
    } else if (context.scope === "dev") {
      args.push("--dev");
    }

    return {
      command: "pnpm",
      args,
    };
  },

  buildRemediationProcess(context) {
    const args = [
      "audit",
      "--json",
      "--fix",
      `--audit-level=${context.threshold}`,
    ];

    if (context.scope === "prod") {
      args.push("--prod");
    } else if (context.scope === "dev") {
      args.push("--dev");
    }

    return {
      command: "pnpm",
      args,
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
    const entries: NormalizedVulnerability[] = [];

    for (const advisory of advisories) {
      if (!isRecord(advisory)) {
        continue;
      }

      const packageName =
        typeof advisory.module_name === "string"
          ? advisory.module_name
          : typeof advisory.name === "string"
            ? advisory.name
            : "unknown";
      const severity = normalizeSeverity(advisory.severity);
      const title =
        typeof advisory.title === "string" ? advisory.title : undefined;
      const url = typeof advisory.url === "string" ? advisory.url : undefined;
      const advisoryIds = collectAdvisoryIds(advisory);
      const findings = Array.isArray(advisory.findings)
        ? advisory.findings
        : [];
      const versions = uniqueSorted(
        findings.flatMap((finding) => {
          if (!isRecord(finding)) {
            return [];
          }

          if (typeof finding.version === "string") {
            return [finding.version];
          }

          return [];
        }),
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
