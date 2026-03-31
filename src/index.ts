export { detectPackageManager } from "./core/detect-manager.js";
export { runAuditFix } from "./core/run.js";
export type {
  AuditLevel,
  AuditScope,
  DedupeMode,
  DetectionResult,
  JsonSummary,
  NormalizedAuditSnapshot,
  NormalizedVulnerability,
  PackageManager,
  PackageManagerOverride,
  RunAuditFixOptions,
  RunAuditFixResult,
  Severity,
  StepFixResult,
  VulnerabilityCounts,
} from "./core/types.js";
export { toJsonSummary } from "./reporters/json.js";
export { formatTextSummary } from "./reporters/text.js";
