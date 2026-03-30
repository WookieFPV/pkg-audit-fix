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
