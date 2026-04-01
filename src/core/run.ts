import { getAdapter } from "../adapters/index.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import { diffFixedEntries, groupFixedPackages } from "./normalize.js";
import type {
  AuditSession,
  AuditSessionActionResult,
  CommandResult,
  CommandStep,
  DetectionResult,
  NormalizedAuditSnapshot,
  RunAuditFixOptions,
  RunAuditFixResult,
  StepFixLabel,
  StepFixResult,
  StepLifecycleHooks,
} from "./types.js";
import { CommandExecutionError } from "./types.js";

function withLabel(
  label: string,
  command: string,
  args: string[],
  acceptedExitCodes: CommandStep["acceptedExitCodes"] = [0],
  acceptResult?: CommandStep["acceptResult"],
): CommandStep {
  return { label, command, args, acceptedExitCodes, acceptResult };
}

function parseAuditResult(
  step: CommandStep,
  result: CommandResult,
  parse: () => NormalizedAuditSnapshot,
): NormalizedAuditSnapshot {
  try {
    return parse();
  } catch (error) {
    const reason =
      error instanceof Error ? error.message : "Failed to parse audit JSON";
    throw new CommandExecutionError(step, result, reason);
  }
}

function shouldRunDedupe(input: {
  mode: RunAuditFixOptions["dedupe"];
  remainingCount: number;
  supportsDedupe: boolean;
}): boolean {
  if (!input.supportsDedupe) {
    return false;
  }

  if (input.mode === "always") {
    return true;
  }

  if (input.mode === "never") {
    return false;
  }

  return input.remainingCount > 0;
}

function createActionResult(
  before: NormalizedAuditSnapshot,
  after: NormalizedAuditSnapshot,
): AuditSessionActionResult {
  return {
    before,
    after,
    fixedCount: Math.max(before.total - after.total, 0),
    remainingCount: after.total,
  };
}

function buildResult(input: {
  options: Pick<
    RunAuditFixOptions,
    "threshold" | "scope" | "dedupe" | "dryRun"
  >;
  manager: RunAuditFixResult["manager"];
  detectionSource: RunAuditFixResult["detectionSource"];
  initial: NormalizedAuditSnapshot;
  final: NormalizedAuditSnapshot;
  stepFixes: StepFixResult[];
}): RunAuditFixResult {
  const fixedEntries = diffFixedEntries(
    input.initial.entries,
    input.final.entries,
  );
  const fixed = groupFixedPackages(fixedEntries);
  const fixedCount = Math.max(input.initial.total - input.final.total, 0);
  const remainingCount = input.final.total;

  return {
    manager: input.manager,
    detectionSource: input.detectionSource,
    threshold: input.options.threshold,
    scope: input.options.scope,
    dedupe: input.options.dedupe,
    dedupeRan: input.stepFixes.some(
      (stepFix) => stepFix.label === "Consolidate dependency tree",
    ),
    dryRun: input.options.dryRun,
    initial: input.initial,
    final: input.final,
    stepFixes: [...input.stepFixes],
    fixedCount,
    remainingCount,
    fixed,
    exitCode: remainingCount === 0 ? 0 : 2,
    status:
      input.initial.total === 0 && remainingCount === 0
        ? "clean"
        : fixedCount > 0
          ? "resolved-some"
          : "no-change",
  };
}

export async function createAuditSession(
  options: RunAuditFixOptions,
  dependencies: {
    detectManager?: typeof detectPackageManager | undefined;
    exec?: ExecFunction | undefined;
    hooks?: StepLifecycleHooks | undefined;
    onManagerDetected?: ((detection: DetectionResult) => void) | undefined;
  } = {},
): Promise<AuditSession> {
  const detectManager = dependencies.detectManager ?? detectPackageManager;
  const exec = dependencies.exec ?? executeStep;
  const detection = await detectManager({
    cwd: options.cwd,
    override: options.manager,
  });
  dependencies.onManagerDetected?.(detection);
  const adapter = getAdapter(detection.agent);

  if (!adapter) {
    throw new Error(`No adapter registered for ${detection.agent}`);
  }

  const context = {
    threshold: options.threshold,
    scope: options.scope,
  };
  const auditProcess = adapter.buildAuditProcess(context);
  const auditExitCodes = adapter.auditExitCodes ?? [0, 1];
  const supportsRemediation = adapter.buildRemediationProcess(context) !== null;
  const supportsDedupe = adapter.buildDedupeProcess(context) !== null;
  const stepFixes: StepFixResult[] = [];

  const recordStepFix = (
    label: StepFixLabel,
    before: NormalizedAuditSnapshot,
    after: NormalizedAuditSnapshot,
  ) => {
    stepFixes.push({
      label,
      fixedCount: Math.max(before.total - after.total, 0),
      remainingCount: after.total,
    });
  };

  const runStep = async (step: CommandStep) => {
    dependencies.hooks?.onStepStart?.({
      label: step.label,
      command: [step.command, ...step.args],
    });

    try {
      const result = await exec(step, {
        cwd: options.cwd,
        verbose: options.verbose,
      });
      dependencies.hooks?.onStepComplete?.({
        label: step.label,
        command: [step.command, ...step.args],
      });
      return result;
    } catch (error) {
      dependencies.hooks?.onStepFail?.({
        label: step.label,
        command: [step.command, ...step.args],
      });
      throw error;
    }
  };

  const runAudit = async (label: string) => {
    const auditStep = withLabel(
      label,
      auditProcess.command,
      auditProcess.args,
      auditExitCodes,
      (result) => adapter.isAuditResult?.(result.stdout) ?? false,
    );
    const auditResult = await runStep(auditStep);
    return parseAuditResult(auditStep, auditResult, () =>
      adapter.parseAudit(auditResult.stdout, context),
    );
  };

  const initial = await runAudit("Initial audit");
  let current = initial;

  return {
    get manager() {
      return detection.manager;
    },

    get detectionSource() {
      return detection.source;
    },

    get initial() {
      return initial;
    },

    get current() {
      return current;
    },

    supportsRemediation,
    supportsDedupe,

    async auditCurrent(label) {
      const before = current;
      const after = await runAudit(label);
      current = after;
      return createActionResult(before, after);
    },

    async applyFixes({ auditLabel = "Recheck after fixes" } = {}) {
      const remediation = adapter.buildRemediationProcess(context);

      if (!remediation) {
        return null;
      }

      const before = current;
      await runStep(
        withLabel(
          "Apply fixes",
          remediation.command,
          remediation.args,
          adapter.remediationExitCodes ?? [0],
        ),
      );

      const postRemediation = adapter.buildPostRemediationProcess(context);

      if (postRemediation) {
        await runStep(
          withLabel(
            "Reinstall dependencies",
            postRemediation.command,
            postRemediation.args,
          ),
        );
      }

      const after = await runAudit(auditLabel);
      current = after;
      recordStepFix("Apply fixes", before, after);
      return createActionResult(before, after);
    },

    async dedupe({ auditLabel = "Final audit" } = {}) {
      const dedupeProcess = adapter.buildDedupeProcess(context);

      if (!dedupeProcess) {
        return null;
      }

      const before = current;
      await runStep(
        withLabel(
          "Consolidate dependency tree",
          dedupeProcess.command,
          dedupeProcess.args,
        ),
      );
      const after = await runAudit(auditLabel);
      current = after;
      recordStepFix("Consolidate dependency tree", before, after);
      return createActionResult(before, after);
    },

    toResult({ dedupe, dryRun }) {
      return buildResult({
        options: {
          threshold: options.threshold,
          scope: options.scope,
          dedupe,
          dryRun,
        },
        manager: detection.manager,
        detectionSource: detection.source,
        initial,
        final: current,
        stepFixes,
      });
    },
  };
}

export async function runAuditFix(
  options: RunAuditFixOptions,
  dependencies: {
    detectManager?: typeof detectPackageManager | undefined;
    exec?: ExecFunction | undefined;
    hooks?: StepLifecycleHooks | undefined;
    onManagerDetected?: ((detection: DetectionResult) => void) | undefined;
  } = {},
): Promise<RunAuditFixResult> {
  const session = await createAuditSession(options, dependencies);

  if (session.initial.total === 0) {
    return session.toResult({
      dedupe: options.dedupe,
      dryRun: options.dryRun,
    });
  }

  if (options.dryRun) {
    await session.auditCurrent("Final audit");
    return session.toResult({
      dedupe: options.dedupe,
      dryRun: true,
    });
  }

  if (session.supportsRemediation) {
    await session.applyFixes({
      auditLabel:
        options.dedupe === "never" ? "Final audit" : "Recheck after fixes",
    });
  } else if (options.dedupe === "never") {
    await session.auditCurrent("Final audit");
    return session.toResult({
      dedupe: options.dedupe,
      dryRun: false,
    });
  } else if (session.supportsDedupe) {
    await session.auditCurrent("Recheck after fixes");
  }

  if (
    shouldRunDedupe({
      mode: options.dedupe,
      remainingCount: session.current.total,
      supportsDedupe: session.supportsDedupe,
    })
  ) {
    await session.dedupe({ auditLabel: "Final audit" });
  }

  return session.toResult({
    dedupe: options.dedupe,
    dryRun: false,
  });
}
