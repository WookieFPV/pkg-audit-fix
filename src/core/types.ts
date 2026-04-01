export type PackageManager = "pnpm" | "npm" | "yarn" | "bun";

export type PackageManagerAgent = PackageManager | "yarn@berry" | "pnpm@6";

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

export type AcceptedExitCodes = number[];

export interface CommandStep extends ProcessSpec {
  label: string;
  acceptedExitCodes?: AcceptedExitCodes | undefined;
  acceptResult?: ((result: CommandResult) => boolean) | undefined;
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
  agent: PackageManagerAgent;
  source: DetectionSource;
}

export interface FixedPackageGroup {
  packageName: string;
  installedVersions: string[];
  advisoryIds: string[];
  title?: string | undefined;
  url?: string | undefined;
}

export type StepFixLabel = "Apply fixes" | "Consolidate dependency tree";

export interface StepFixResult {
  label: StepFixLabel;
  fixedCount: number;
  remainingCount: number;
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
  stepFixes: StepFixResult[];
  fixedCount: number;
  remainingCount: number;
  fixed: FixedPackageGroup[];
  exitCode: 0 | 2;
  status: "clean" | "resolved-some" | "no-change";
}

export interface AuditSessionActionResult {
  before: NormalizedAuditSnapshot;
  after: NormalizedAuditSnapshot;
  fixedCount: number;
  remainingCount: number;
}

export interface AuditSession {
  readonly manager: PackageManager;
  readonly detectionSource: DetectionSource;
  readonly initial: NormalizedAuditSnapshot;
  readonly current: NormalizedAuditSnapshot;
  readonly supportsRemediation: boolean;
  readonly supportsDedupe: boolean;
  auditCurrent(label: string): Promise<AuditSessionActionResult>;
  applyFixes(options?: {
    auditLabel?: string | undefined;
  }): Promise<AuditSessionActionResult | null>;
  dedupe(options?: {
    auditLabel?: string | undefined;
  }): Promise<AuditSessionActionResult | null>;
  toResult(options: { dedupe: DedupeMode; dryRun: boolean }): RunAuditFixResult;
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
  stepFixes: StepFixResult[];
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
