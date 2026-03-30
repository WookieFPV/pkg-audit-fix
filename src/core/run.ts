import { getAdapter } from "../adapters/index.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import { diffFixedEntries, groupFixedPackages } from "./normalize.js";
import type {
  CommandResult,
  CommandStep,
  NormalizedAuditSnapshot,
  ProcessSpec,
  RunAuditFixOptions,
  RunAuditFixResult,
  StepLifecycleHooks,
} from "./types.js";
import { CommandExecutionError } from "./types.js";

function withLabel(
  label: string,
  command: string,
  args: string[],
  acceptedExitCodes: number[] = [0],
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
  } = {},
): Promise<RunAuditFixResult> {
  const detectManager = dependencies.detectManager ?? detectPackageManager;
  const exec = dependencies.exec ?? executeStep;
  const detection = await detectManager({
    cwd: options.cwd,
    override: options.manager,
  });
  const adapter = getAdapter(detection.manager);

  if (!adapter) {
    throw new Error(`No adapter registered for ${detection.manager}`);
  }

  const context = {
    threshold: options.threshold,
    scope: options.scope,
  };
  const auditProcess = adapter.buildAuditProcess(context);

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
    [0, 1],
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
      fixedCount: 0,
      remainingCount: 0,
      fixed: [],
      exitCode: 0,
      status: "clean",
    };
  }

  if (!options.dryRun) {
    const remediation = adapter.buildRemediationProcess(context);

    if (remediation) {
      const remediationAcceptedExitCodes =
        remediation.command === "npm" && remediation.args[0] === "audit"
          ? [0, 1]
          : remediation.command === "pnpm" && remediation.args[0] === "audit"
            ? [0, 1]
            : [0];
      await runStep(
        withLabel(
          "Apply fixes",
          remediation.command,
          remediation.args,
          remediationAcceptedExitCodes,
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
      [0, 1],
    );
    const finalAuditResult = await runStep(finalAuditStep);
    final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
      adapter.parseAudit(finalAuditResult.stdout, context),
    );
  } else {
    const postFixAuditStep = withLabel(
      "Recheck after fixes",
      auditProcess.command,
      auditProcess.args,
      [0, 1],
    );
    const postFixAuditResult = await runStep(postFixAuditStep);
    const postFixSnapshot = parseAuditResult(
      postFixAuditStep,
      postFixAuditResult,
      () => adapter.parseAudit(postFixAuditResult.stdout, context),
    );
    const dedupeProcess = adapter.buildDedupeProcess(context);

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
        [0, 1],
      );
      const finalAuditResult = await runStep(finalAuditStep);
      final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
        adapter.parseAudit(finalAuditResult.stdout, context),
      );
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
    fixedCount,
    remainingCount,
    fixed,
    exitCode: remainingCount === 0 ? 0 : 2,
    status: fixedCount > 0 ? "resolved-some" : "no-change",
  };
}
