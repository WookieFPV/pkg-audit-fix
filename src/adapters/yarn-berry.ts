import {
  collectAdvisoryIds,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonObject,
  uniqueSorted,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

export const yarnBerryAdapter: PackageManagerAdapter = {
  manager: "yarn",
  auditExitCodes: "any",

  buildAuditProcess(context) {
    const args = [
      "npm",
      "audit",
      "--json",
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

  parseAudit(stdout, context) {
    const json = parseJsonObject(stdout, "yarn");
    const entries: NormalizedVulnerability[] = [];

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
