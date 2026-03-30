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

export const npmAdapter: PackageManagerAdapter = {
  manager: "npm",

  buildAuditProcess(context) {
    const args = ["audit", "--json", `--audit-level=${context.threshold}`];

    if (context.scope === "prod") {
      args.push("--omit=dev");
    }

    return {
      command: "npm",
      args,
    };
  },

  buildRemediationProcess(context) {
    const args = [
      "audit",
      "fix",
      "--json",
      `--audit-level=${context.threshold}`,
    ];

    if (context.scope === "prod") {
      args.push("--omit=dev");
    }

    return {
      command: "npm",
      args,
    };
  },

  buildPostRemediationProcess() {
    return null;
  },

  parseAudit(stdout, context) {
    const json = parseJsonObject(stdout, "npm");
    const vulnerabilities = isRecord(json.vulnerabilities)
      ? Object.values(json.vulnerabilities)
      : [];
    const entries: NormalizedVulnerability[] = [];

    for (const vulnerability of vulnerabilities) {
      if (!isRecord(vulnerability)) {
        continue;
      }

      const packageName =
        typeof vulnerability.name === "string"
          ? vulnerability.name
          : typeof vulnerability.packageName === "string"
            ? vulnerability.packageName
            : "unknown";
      const installedVersion =
        typeof vulnerability.installedVersion === "string"
          ? vulnerability.installedVersion
          : typeof vulnerability.version === "string"
            ? vulnerability.version
            : typeof vulnerability.currentVersion === "string"
              ? vulnerability.currentVersion
              : "unknown";
      const severity = normalizeSeverity(vulnerability.severity);
      const via = Array.isArray(vulnerability.via)
        ? vulnerability.via.filter(isRecord)
        : [];
      const advisoryIds = collectAdvisoryIds(vulnerability, ...via);
      const titledVia = via.find((item) => typeof item.title === "string");
      const linkedVia = via.find((item) => typeof item.url === "string");

      entries.push({
        key: vulnerabilityKey(packageName, installedVersion, advisoryIds),
        packageName,
        installedVersion,
        severity,
        advisoryIds,
        title:
          typeof titledVia?.title === "string" ? titledVia.title : undefined,
        url: typeof linkedVia?.url === "string" ? linkedVia.url : undefined,
      });
    }

    return createSnapshot({
      manager: "npm",
      threshold: context.threshold,
      scope: context.scope,
      entries,
      counts: countsFromMetadata(
        isRecord(json.metadata) ? json.metadata.vulnerabilities : undefined,
      ),
    });
  },
};
