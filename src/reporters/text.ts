import { formatCount } from "../core/normalize.js";
import {
  CommandExecutionError,
  ManagerDetectionError,
  MinimumReleaseAgeDeclinedError,
  type NormalizedVulnerability,
  type RunAuditFixResult,
} from "../core/types.js";

function formatPackageLine(group: RunAuditFixResult["fixed"][number]): string {
  const versionLabel =
    group.installedVersions.length > 1
      ? `${group.packageName} (${group.installedVersions.join(", ")})`
      : group.installedVersions[0] && group.installedVersions[0] !== "unknown"
        ? `${group.packageName}@${group.installedVersions[0]}`
        : group.packageName;

  if (group.advisoryIds.length === 0) {
    return `- ${versionLabel}`;
  }

  return `- ${versionLabel}: ${group.advisoryIds.join(", ")}`;
}

function formatVulnerabilityLine(entry: NormalizedVulnerability): string {
  const versionLabel =
    entry.installedVersion && entry.installedVersion !== "unknown"
      ? `${entry.packageName}@${entry.installedVersion}`
      : entry.packageName;
  const detail =
    entry.advisoryIds.length > 0
      ? entry.advisoryIds.join(", ")
      : entry.title
        ? entry.title
        : "advisory details unavailable";
  const remediation = entry.remediation ? `; ${entry.remediation}` : "";

  return `- ${versionLabel} [${entry.severity}]: ${detail}${remediation}`;
}

function mergeVulnerabilityEntries(
  entries: NormalizedVulnerability[],
): NormalizedVulnerability[] {
  const merged = new Map<string, NormalizedVulnerability>();

  for (const entry of entries) {
    const detailKey =
      entry.advisoryIds.length > 0
        ? entry.advisoryIds.join(",")
        : (entry.title ?? "advisory details unavailable");
    const key = [
      entry.packageName,
      entry.installedVersion,
      entry.severity,
      detailKey,
    ].join("|");
    const existing = merged.get(key);

    if (!existing) {
      merged.set(key, entry);
      continue;
    }

    if (!existing.remediation && entry.remediation) {
      merged.set(key, {
        ...existing,
        remediation: entry.remediation,
      });
    }
  }

  return [...merged.values()];
}

export function formatVulnerabilityList(
  entries: NormalizedVulnerability[],
): string {
  return mergeVulnerabilityEntries(entries)
    .map(formatVulnerabilityLine)
    .join("\n");
}

export function formatTextSummary(result: RunAuditFixResult): string {
  const lines: string[] = [];

  if (result.initial.total === 0) {
    return "No vulnerabilities found.";
  }

  if (result.dryRun) {
    lines.push(
      `Found ${formatCount(result.initial.total)}. No fixes were applied because this was a dry run.`,
    );
  } else if (result.fixedCount > 0) {
    lines.push(`Resolved ${formatCount(result.fixedCount)}.`);
  } else {
    lines.push("No vulnerabilities were resolved.");

    if (result.manager === "bun" && result.remainingCount > 0) {
      lines.push("Bun does not support `audit --fix`. Fix these manually.");
    }
  }

  if (result.fixedCount > 0 && result.fixed.length > 0) {
    lines.push("Updated packages:");

    for (const group of result.fixed) {
      lines.push(formatPackageLine(group));
    }
  }

  lines.push("");
  lines.push(
    result.remainingCount === 0
      ? "No vulnerabilities remain."
      : result.remainingCount === 1
        ? "1 vulnerability remains."
        : `${formatCount(result.remainingCount)} remain.`,
  );

  if (
    result.manager === "bun" &&
    result.remainingCount > 0 &&
    result.final.entries.length > 0
  ) {
    lines.push("");
    lines.push("Remaining vulnerabilities:");
    lines.push(formatVulnerabilityList(result.final.entries));
  }

  return lines.join("\n");
}

export function formatFailure(error: unknown): string {
  if (error instanceof ManagerDetectionError) {
    return error.message;
  }

  if (error instanceof MinimumReleaseAgeDeclinedError) {
    return `Reason: ${error.message}`;
  }

  if (!(error instanceof CommandExecutionError)) {
    return error instanceof Error ? error.message : "Unknown failure";
  }

  const lines = [`Failed step: ${error.step.label}`];

  if (error.result.stdout.trim().length > 0) {
    lines.push("");
    lines.push("stdout:");
    lines.push(error.result.stdout.trimEnd());
  }

  if (error.result.stderr.trim().length > 0) {
    lines.push("");
    lines.push("stderr:");
    lines.push(error.result.stderr.trimEnd());
  }

  lines.push("");
  lines.push(`Reason: ${error.message}`);

  return lines.join("\n");
}
