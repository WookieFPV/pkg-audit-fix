export { detectPackageManager } from "./core/detect-manager.js";
export { createAuditSession, runAuditFix } from "./core/run.js";
export type {
  AuditLevel,
  AuditScope,
  AuditSession,
  AuditSessionActionResult,
  DedupeMode,
  DetectionResult,
  JsonSummary,
  NormalizedAuditSnapshot,
  NormalizedVulnerability,
  PackageManager,
  PackageManagerAgent,
  PackageManagerOverride,
  RunAuditFixOptions,
  RunAuditFixResult,
  Severity,
  StepFixLabel,
  StepFixResult,
  VulnerabilityCounts,
} from "./core/types.js";
export { toJsonSummary } from "./reporters/json.js";
export {
  formatTextSummary,
  formatVulnerabilityList,
} from "./reporters/text.js";
