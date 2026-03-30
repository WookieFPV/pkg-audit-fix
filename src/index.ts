export { detectPackageManager } from "./core/detect-manager.js";
export { runAuditFix } from "./core/run.js";
export type {
  AuditLevel,
  AuditScope,
  DetectionResult,
  JsonSummary,
  NormalizedAuditSnapshot,
  NormalizedVulnerability,
  PackageManager,
  PackageManagerOverride,
  RunAuditFixOptions,
  RunAuditFixResult,
  Severity,
  VulnerabilityCounts,
} from "./core/types.js";
export { toJsonSummary } from "./reporters/json.js";
export { formatTextSummary } from "./reporters/text.js";
