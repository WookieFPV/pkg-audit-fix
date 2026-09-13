import {
  countsFromMetadata,
  createSnapshot,
  isRecord,
  parseJsonLines,
} from "../core/normalize.js";
import type { NormalizedVulnerability } from "../core/types.js";
import type { PackageManagerAdapter } from "./base.js";
import { registryAdvisoryEntries } from "./shared.js";

function isClassicAuditOutput(stdout: string): boolean {
  try {
    const events = parseJsonLines(stdout, "yarn");

    return events.some(
      (event) =>
        event.type === "auditSummary" || event.type === "auditAdvisory",
    );
  } catch {
    return false;
  }
}

export const yarnClassicAdapter: PackageManagerAdapter = {
  manager: "yarn",
  auditExitCodes: [0],

  buildAuditProcess(context) {
    const groups =
      context.scope === "prod"
        ? ["--groups", "dependencies"]
        : context.scope === "dev"
          ? ["--groups", "devDependencies"]
          : [];

    return {
      command: "yarn",
      args: ["audit", "--json", "--level", context.threshold, ...groups],
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

  isAuditResult(stdout) {
    return isClassicAuditOutput(stdout);
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

      entries.push(...registryAdvisoryEntries(advisory));
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
