import { getAdapter } from "../adapters/index.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import { diffFixedEntries, groupFixedPackages } from "./normalize.js";
import type {
  CommandStep,
  RunAuditFixOptions,
  RunAuditFixResult,
  StepReporter,
} from "./types.js";

function withLabel(
  label: string,
  command: string,
  args: string[],
): CommandStep {
  return { label, command, args };
}

export async function runAuditFix(
  options: RunAuditFixOptions,
  dependencies: {
    detectManager?: typeof detectPackageManager | undefined;
    exec?: ExecFunction | undefined;
    onStep?: StepReporter | undefined;
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
    dependencies.onStep?.({
      label: step.label,
      command: [step.command, ...step.args],
    });

    return exec(step, {
      cwd: options.cwd,
      verbose: options.verbose,
    });
  };

  const initialAuditResult = await runStep(
    withLabel("initial audit", auditProcess.command, auditProcess.args),
  );
  const initial = adapter.parseAudit(initialAuditResult.stdout, context);

  if (initial.total === 0) {
    return {
      manager: detection.manager,
      detectionSource: detection.source,
      threshold: options.threshold,
      scope: options.scope,
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
      await runStep(
        withLabel("remediation", remediation.command, remediation.args),
      );
    }

    const postRemediation = adapter.buildPostRemediationProcess(context);

    if (postRemediation) {
      await runStep(
        withLabel(
          "post-remediation install",
          postRemediation.command,
          postRemediation.args,
        ),
      );
    }
  }

  const finalAuditResult = await runStep(
    withLabel("final audit", auditProcess.command, auditProcess.args),
  );
  const final = adapter.parseAudit(finalAuditResult.stdout, context);
  const fixedEntries = diffFixedEntries(initial.entries, final.entries);
  const fixed = groupFixedPackages(fixedEntries);
  const fixedCount = Math.max(initial.total - final.total, 0);
  const remainingCount = final.total;

  return {
    manager: detection.manager,
    detectionSource: detection.source,
    threshold: options.threshold,
    scope: options.scope,
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
