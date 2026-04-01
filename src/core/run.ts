import { getAdapter } from "../adapters/index.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import { diffFixedEntries, groupFixedPackages } from "./normalize.js";
import type {
  CommandResult,
  CommandStep,
  DetectionResult,
  NormalizedAuditSnapshot,
  ProcessSpec,
  RunAuditFixOptions,
  RunAuditFixResult,
  StepFixResult,
  StepLifecycleHooks,
} from "./types.js";
import { CommandExecutionError } from "./types.js";

function withLabel(
  label: string,
  command: string,
  args: string[],
  acceptedExitCodes: CommandStep["acceptedExitCodes"] = [0],
): CommandStep {
  return { label, command, args, acceptedExitCodes };
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
  dedupeProcess: ProcessSpec | null;
}): boolean {
  if (!input.dedupeProcess) {
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

export async function runAuditFix(
  options: RunAuditFixOptions,
  dependencies: {
    detectManager?: typeof detectPackageManager | undefined;
    exec?: ExecFunction | undefined;
    hooks?: StepLifecycleHooks | undefined;
    onManagerDetected?: ((detection: DetectionResult) => void) | undefined;
  } = {},
): Promise<RunAuditFixResult> {
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
  const stepFixes: StepFixResult[] = [];

  const recordStepFix = (
    label: StepFixResult["label"],
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

  const initialAuditStep = withLabel(
    "Initial audit",
    auditProcess.command,
    auditProcess.args,
    auditExitCodes,
  );
  const initialAuditResult = await runStep(initialAuditStep);
  const initial = parseAuditResult(initialAuditStep, initialAuditResult, () =>
    adapter.parseAudit(initialAuditResult.stdout, context),
  );

  if (initial.total === 0) {
    return {
      manager: detection.manager,
      detectionSource: detection.source,
      threshold: options.threshold,
      scope: options.scope,
      dedupe: options.dedupe,
      dedupeRan: false,
      dryRun: options.dryRun,
      initial,
      final: initial,
      stepFixes,
      fixedCount: 0,
      remainingCount: 0,
      fixed: [],
      exitCode: 0,
      status: "clean",
    };
  }

  let remediationRan = false;
  const dedupeProcess = adapter.buildDedupeProcess(context);

  if (!options.dryRun) {
    const remediation = adapter.buildRemediationProcess(context);

    if (remediation) {
      remediationRan = true;
      await runStep(
        withLabel(
          "Apply fixes",
          remediation.command,
          remediation.args,
          adapter.remediationExitCodes ?? [0],
        ),
      );
    }

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
  }
  let final: NormalizedAuditSnapshot;
  let dedupeRan = false;

  if (options.dryRun || options.dedupe === "never") {
    const finalAuditStep = withLabel(
      "Final audit",
      auditProcess.command,
      auditProcess.args,
      auditExitCodes,
    );
    const finalAuditResult = await runStep(finalAuditStep);
    final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
      adapter.parseAudit(finalAuditResult.stdout, context),
    );

    if (remediationRan) {
      recordStepFix("Apply fixes", initial, final);
    }
  } else if (!remediationRan && !dedupeProcess) {
    final = initial;
  } else {
    const postFixAuditStep = withLabel(
      "Recheck after fixes",
      auditProcess.command,
      auditProcess.args,
      auditExitCodes,
    );
    const postFixAuditResult = await runStep(postFixAuditStep);
    const postFixSnapshot = parseAuditResult(
      postFixAuditStep,
      postFixAuditResult,
      () => adapter.parseAudit(postFixAuditResult.stdout, context),
    );

    if (remediationRan) {
      recordStepFix("Apply fixes", initial, postFixSnapshot);
    }

    if (
      dedupeProcess &&
      shouldRunDedupe({
        mode: options.dedupe,
        remainingCount: postFixSnapshot.total,
        dedupeProcess,
      })
    ) {
      dedupeRan = true;
      await runStep(
        withLabel(
          "Consolidate dependency tree",
          dedupeProcess.command,
          dedupeProcess.args,
        ),
      );

      const finalAuditStep = withLabel(
        "Final audit",
        auditProcess.command,
        auditProcess.args,
        auditExitCodes,
      );
      const finalAuditResult = await runStep(finalAuditStep);
      final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
        adapter.parseAudit(finalAuditResult.stdout, context),
      );
      recordStepFix("Consolidate dependency tree", postFixSnapshot, final);
    } else {
      final = postFixSnapshot;
    }
  }
  const fixedEntries = diffFixedEntries(initial.entries, final.entries);
  const fixed = groupFixedPackages(fixedEntries);
  const fixedCount = Math.max(initial.total - final.total, 0);
  const remainingCount = final.total;

  return {
    manager: detection.manager,
    detectionSource: detection.source,
    threshold: options.threshold,
    scope: options.scope,
    dedupe: options.dedupe,
    dedupeRan,
    dryRun: options.dryRun,
    initial,
    final,
    stepFixes,
    fixedCount,
    remainingCount,
    fixed,
    exitCode: remainingCount === 0 ? 0 : 2,
    status: fixedCount > 0 ? "resolved-some" : "no-change",
  };
}
