import {
  collectAdvisoryIds,
  countsFromMetadata,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonLines,
  uniqueSorted,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";

export const yarnClassicAdapter: PackageManagerAdapter = {
  manager: "yarn",
  auditExitCodes: "any",

  buildAuditProcess(context) {
    const args = ["audit", "--json", "--level", context.threshold];

    if (context.scope === "prod") {
      args.push("--groups", "dependencies");
    } else if (context.scope === "dev") {
      args.push("--groups", "devDependencies");
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
    return null;
  },

  parseAudit(stdout, context) {
    const events = parseJsonLines(stdout, "yarn");
    const entries: NormalizedVulnerability[] = [];
    let counts = null;

    for (const event of events) {
      if (event.type === "auditSummary" && isRecord(event.data)) {
        counts = countsFromMetadata(event.data.vulnerabilities);
        continue;
      }

      if (event.type !== "auditAdvisory" || !isRecord(event.data)) {
        continue;
      }

      const advisory = isRecord(event.data.advisory)
        ? event.data.advisory
        : null;

      if (!advisory) {
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
          if (!isRecord(finding) || typeof finding.version !== "string") {
            return [];
          }

          return [finding.version];
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
      manager: "yarn",
      threshold: context.threshold,
      scope: context.scope,
      entries,
      counts,
    });
  },
};
