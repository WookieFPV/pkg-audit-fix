import type { JsonSummary, RunAuditFixResult } from "../core/types.js";

export function toJsonSummary(result: RunAuditFixResult): JsonSummary {
  return {
    manager: result.manager,
    detectionSource: result.detectionSource,
    threshold: result.threshold,
    scope: result.scope,
    dryRun: result.dryRun,
    status: result.status,
    fixedCount: result.fixedCount,
    remainingCount: result.remainingCount,
    exitCode: result.exitCode,
    fixed: result.fixed,
    initial: result.initial,
    final: result.final,
  };
}
