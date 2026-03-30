export type PackageManager = "pnpm" | "npm" | "bun";

export type PackageManagerOverride = "auto" | PackageManager;

export type AuditScope = "all" | "prod" | "dev";

export type AuditLevel = "low" | "moderate" | "high" | "critical";

export type DedupeMode = "auto" | "always" | "never";

export type Severity = AuditLevel;

export type DetectionSource = "override" | "user-agent" | "filesystem";

export interface VulnerabilityCounts {
  low: number;
  moderate: number;
  high: number;
  critical: number;
  total: number;
}

export interface NormalizedVulnerability {
  key: string;
  packageName: string;
  installedVersion: string;
  severity: Severity;
  advisoryIds: string[];
  title?: string | undefined;
  url?: string | undefined;
}

export interface NormalizedAuditSnapshot {
  manager: PackageManager;
  threshold: AuditLevel;
  scope: AuditScope;
  total: number;
  counts: VulnerabilityCounts;
  entries: NormalizedVulnerability[];
}

export interface ProcessSpec {
  command: string;
  args: string[];
}

export interface CommandStep extends ProcessSpec {
  label: string;
  acceptedExitCodes?: number[] | undefined;
}

export interface CommandResult {
  command: string;
  args: string[];
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
}

export interface RunAuditFixOptions {
  cwd: string;
  manager: PackageManagerOverride;
  scope: AuditScope;
  threshold: AuditLevel;
  dedupe: DedupeMode;
  dryRun: boolean;
  verbose: boolean;
}

export interface StepEvent {
  label: string;
  command: readonly string[];
}

export interface StepLifecycleHooks {
  onStepStart?: ((event: StepEvent) => void) | undefined;
  onStepComplete?: ((event: StepEvent) => void) | undefined;
  onStepFail?: ((event: StepEvent) => void) | undefined;
}

export interface DetectionResult {
  manager: PackageManager;
  source: DetectionSource;
}

export interface FixedPackageGroup {
  packageName: string;
  installedVersions: string[];
  advisoryIds: string[];
  title?: string | undefined;
  url?: string | undefined;
}

export interface RunAuditFixResult {
  manager: PackageManager;
  detectionSource: DetectionSource;
  threshold: AuditLevel;
  scope: AuditScope;
  dedupe: DedupeMode;
  dedupeRan: boolean;
  dryRun: boolean;
  initial: NormalizedAuditSnapshot;
  final: NormalizedAuditSnapshot;
  fixedCount: number;
  remainingCount: number;
  fixed: FixedPackageGroup[];
  exitCode: 0 | 2;
  status: "clean" | "resolved-some" | "no-change";
}

export interface JsonSummary {
  manager: PackageManager;
  detectionSource: DetectionSource;
  threshold: AuditLevel;
  scope: AuditScope;
  dedupe: DedupeMode;
  dedupeRan: boolean;
  dryRun: boolean;
  status: RunAuditFixResult["status"];
  fixedCount: number;
  remainingCount: number;
  exitCode: 0 | 2;
  fixed: FixedPackageGroup[];
  initial: NormalizedAuditSnapshot;
  final: NormalizedAuditSnapshot;
}

export class CliUsageError extends Error {}

export class ManagerDetectionError extends Error {
  readonly exitCode = 3;
}

export class CommandExecutionError extends Error {
  readonly step: CommandStep;
  readonly result: CommandResult;

  constructor(step: CommandStep, result: CommandResult, reason: string) {
    super(reason);
    this.name = "CommandExecutionError";
    this.step = step;
    this.result = result;
  }
}
