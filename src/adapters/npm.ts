import {
  collectAdvisoryIds,
  countsFromMetadata,
  createSnapshot,
  isRecord,
  normalizeSeverity,
  parseJsonObject,
  vulnerabilityKey,
} from "../core/normalize.js";
import type { AuditScope, NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";
import { readOptionalString, readStringWithFallback } from "./shared.js";

function scopeArgs(scope: AuditScope): string[] {
  if (scope === "prod") {
    return ["--omit=dev"];
  }

  return scope === "dev" ? ["--only=dev"] : [];
}

export const npmAdapter: PackageManagerAdapter = {
  manager: "npm",
  auditExitCodes: [0, 1],
  remediationExitCodes: [0, 1],

  buildAuditProcess(context) {
    return {
      command: "npm",
      args: ["audit", "--json", ...scopeArgs(context.scope)],
    };
  },

  buildRemediationProcess(context) {
    return {
      command: "npm",
      args: ["audit", "fix", "--json", ...scopeArgs(context.scope)],
    };
  },

  buildPostRemediationProcess() {
    return null;
  },

  buildDedupeProcess() {
    return {
      command: "npm",
      args: ["dedupe"],
    };
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

      const packageName = readStringWithFallback(vulnerability, [
        "name",
        "packageName",
      ]);
      const installedVersion = readStringWithFallback(vulnerability, [
        "installedVersion",
        "version",
        "currentVersion",
      ]);
      const severity = normalizeSeverity(vulnerability.severity);
      const via = Array.isArray(vulnerability.via)
        ? vulnerability.via.filter(isRecord)
        : [];
      const advisoryIds = collectAdvisoryIds(vulnerability, ...via);
      const title = via
        .map((item) => readOptionalString(item, "title"))
        .find((value) => value !== undefined);
      const url = via
        .map((item) => readOptionalString(item, "url"))
        .find((value) => value !== undefined);

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
