import { formatCount } from "../core/normalize.js";
import {
  CommandExecutionError,
  ManagerDetectionError,
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

function formatStepFixSummary(result: RunAuditFixResult): string {
  const parts = result.stepFixes.map((stepFix) => {
    const label =
      stepFix.label === "Apply fixes" ? "apply fixes" : "consolidate tree";
    return `${label}: ${stepFix.fixedCount}`;
  });

  return parts.length > 0 ? ` (${parts.join(", ")})` : "";
}

export function formatTextSummary(result: RunAuditFixResult): string {
  const lines: string[] = [];

  if (result.initial.total === 0) {
    lines.push("chore(deps): no vulnerabilities found");
  } else if (result.fixedCount > 0) {
    lines.push(
      `fix(deps): resolve ${formatCount(result.fixedCount)}${formatStepFixSummary(result)}`,
    );
  } else {
    lines.push("chore(deps): no vulnerabilities resolved");
  }

  if (result.fixedCount > 0 && result.fixed.length > 0) {
    lines.push("");

    for (const group of result.fixed) {
      lines.push(formatPackageLine(group));
    }
  }

  lines.push("");
  lines.push(`remaining: ${formatCount(result.remainingCount)}`);

  return lines.join("\n");
}

export function formatFailure(error: unknown): string {
  if (error instanceof ManagerDetectionError) {
    return error.message;
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
