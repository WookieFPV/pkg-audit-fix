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
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

export const pnpmAdapter: PackageManagerAdapter = {
  manager: "pnpm",

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
    const args = ["audit", "--json", "--fix", `--audit-level=${context.threshold}`];

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
      args: ["install"],
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
