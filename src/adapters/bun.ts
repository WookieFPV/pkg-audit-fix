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

export const bunAdapter: PackageManagerAdapter = {
  manager: "bun",

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
    const args = ["update"];

    if (context.scope === "prod") {
      args.push("--production");
    }

    return {
      command: "bun",
      args,
    };
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
    const items = Array.isArray(json.vulnerabilities)
      ? json.vulnerabilities
      : Array.isArray(json.advisories)
        ? json.advisories
        : [];
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
        : [];
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

    return createSnapshot({
      manager: "bun",
      threshold: context.threshold,
      scope: context.scope,
      entries,
      counts,
    });
  },
};
