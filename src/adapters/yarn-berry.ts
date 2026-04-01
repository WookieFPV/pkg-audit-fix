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
