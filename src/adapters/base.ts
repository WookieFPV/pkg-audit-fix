import type {
  AcceptedExitCodes,
  AuditLevel,
  AuditScope,
  NormalizedAuditSnapshot,
  PackageManager,
  ProcessSpec,
} from "../core/types.js";

export interface AdapterContext {
  threshold: AuditLevel;
  scope: AuditScope;
}

export interface PackageManagerAdapter {
  readonly manager: PackageManager;
  readonly auditExitCodes?: AcceptedExitCodes;
  readonly remediationExitCodes?: AcceptedExitCodes;
  buildAuditProcess(context: AdapterContext): ProcessSpec;
  buildRemediationProcess(context: AdapterContext): ProcessSpec | null;
  buildPostRemediationProcess(context: AdapterContext): ProcessSpec | null;
  buildDedupeProcess(context: AdapterContext): ProcessSpec | null;
  isAuditResult?(stdout: string): boolean;
  parseAudit(stdout: string, context: AdapterContext): NormalizedAuditSnapshot;
}
