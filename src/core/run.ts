import fs from "node:fs";
import path from "node:path";

import {
  extractBunMinimumReleaseAgeExclusions,
  parseBunMinimumReleaseAgeExcludesConfig,
  updateBunMinimumReleaseAgeExcludesConfig,
} from "../adapters/bun.js";
import { getAdapter } from "../adapters/index.js";
import {
  extractPnpmMinimumReleaseAgeExclusions,
  parsePnpmMinimumReleaseAgeExcludeConfig,
} from "../adapters/pnpm.js";
import {
  extractYarnMinimumReleaseAgeExclusions,
  parseYarnNpmPreapprovedPackagesConfig,
  updateYarnNpmPreapprovedPackagesConfig,
} from "../adapters/yarn-berry.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import { diffFixedEntries, groupFixedPackages } from "./normalize.js";
import type {
  CommandResult,
  CommandStep,
  ConfirmMinimumReleaseAgeExclusions,
  DetectionResult,
  NormalizedAuditSnapshot,
  PackageManager,
  ProcessSpec,
  PromptBunManualRemediationInput,
  RunAuditFixOptions,
  RunAuditFixResult,
  StepFixResult,
  StepLifecycleHooks,
} from "./types.js";
import {
  CommandExecutionError,
  MinimumReleaseAgeDeclinedError,
} from "./types.js";

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
    confirmPnpmMinimumReleaseAgeExclusions?:
      | ConfirmMinimumReleaseAgeExclusions
      | undefined;
    detectManager?: typeof detectPackageManager | undefined;
    exec?: ExecFunction | undefined;
    hooks?: StepLifecycleHooks | undefined;
    onManagerDetected?: ((detection: DetectionResult) => void) | undefined;
    promptBunManualRemediation?:
      | ((input: PromptBunManualRemediationInput) => Promise<void>)
      | undefined;
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
  const attemptedMinimumReleaseAgeExclusions = new Set<string>();

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

  const runStep = async (
    step: CommandStep,
    recoverError?:
      | ((error: unknown) => Promise<CommandResult | null>)
      | undefined,
    stepOptions: { silent?: boolean } = {},
  ) => {
    if (!stepOptions.silent) {
      dependencies.hooks?.onStepStart?.({
        label: step.label,
        command: [step.command, ...step.args],
      });
    }

    try {
      const result = await exec(step, {
        cwd: options.cwd,
        verbose: options.verbose,
      });
      if (!stepOptions.silent) {
        dependencies.hooks?.onStepComplete?.({
          label: step.label,
          command: [step.command, ...step.args],
        });
      }
      return result;
    } catch (error) {
      let finalError = error;

      if (recoverError) {
        try {
          const recoveredResult = await recoverError(error);

          if (recoveredResult) {
            if (!stepOptions.silent) {
              dependencies.hooks?.onStepComplete?.({
                label: step.label,
                command: [step.command, ...step.args],
              });
            }
            return recoveredResult;
          }
        } catch (recoveryError) {
          finalError = recoveryError;
        }
      }

      if (!stepOptions.silent) {
        dependencies.hooks?.onStepFail?.({
          label: step.label,
          command: [step.command, ...step.args],
        });
      }
      throw finalError;
    }
  };

  const runActionStep = async <T>(
    step: Pick<CommandStep, "label" | "command" | "args">,
    action: () => Promise<T>,
    stepOptions: { silent?: boolean } = {},
  ): Promise<T> => {
    if (!stepOptions.silent) {
      dependencies.hooks?.onStepStart?.({
        label: step.label,
        command: [step.command, ...step.args],
      });
    }

    try {
      const result = await action();
      if (!stepOptions.silent) {
        dependencies.hooks?.onStepComplete?.({
          label: step.label,
          command: [step.command, ...step.args],
        });
      }
      return result;
    } catch (error) {
      if (!stepOptions.silent) {
        dependencies.hooks?.onStepFail?.({
          label: step.label,
          command: [step.command, ...step.args],
        });
      }
      throw error;
    }
  };

  const readBunMinimumReleaseAgeExcludes = async (): Promise<string[]> => {
    const bunfigPath = path.join(options.cwd, "bunfig.toml");

    try {
      return parseBunMinimumReleaseAgeExcludesConfig(
        fs.readFileSync(bunfigPath, "utf8"),
      );
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT"
      ) {
        return [];
      }

      throw error;
    }
  };

  const writeBunMinimumReleaseAgeExcludes = async (
    excludes: string[],
  ): Promise<void> => {
    const bunfigPath = path.join(options.cwd, "bunfig.toml");
    let currentSource = "";

    try {
      currentSource = fs.readFileSync(bunfigPath, "utf8");
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "ENOENT"
      ) {
        throw error;
      }
    }

    const nextSource = updateBunMinimumReleaseAgeExcludesConfig(
      currentSource,
      excludes,
    );

    fs.writeFileSync(bunfigPath, nextSource, "utf8");
  };

  const readYarnNpmPreapprovedPackages = async (): Promise<string[]> => {
    const yarnrcPath = path.join(options.cwd, ".yarnrc.yml");

    try {
      return parseYarnNpmPreapprovedPackagesConfig(
        fs.readFileSync(yarnrcPath, "utf8"),
      );
    } catch (error) {
      if (
        error instanceof Error &&
        "code" in error &&
        error.code === "ENOENT"
      ) {
        return [];
      }

      throw error;
    }
  };

  const writeYarnNpmPreapprovedPackages = async (
    packages: string[],
  ): Promise<void> => {
    const yarnrcPath = path.join(options.cwd, ".yarnrc.yml");
    let currentSource = "";

    try {
      currentSource = fs.readFileSync(yarnrcPath, "utf8");
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !("code" in error) ||
        error.code !== "ENOENT"
      ) {
        throw error;
      }
    }

    const nextSource = updateYarnNpmPreapprovedPackagesConfig(
      currentSource,
      packages,
    );

    fs.writeFileSync(yarnrcPath, nextSource, "utf8");
  };

  const recoverMinimumReleaseAgeFailure = async (
    error: unknown,
    step: CommandStep,
  ): Promise<CommandResult | null> => {
    if (
      !(error instanceof CommandExecutionError) ||
      !dependencies.confirmPnpmMinimumReleaseAgeExclusions
    ) {
      return null;
    }

    let manager: PackageManager;
    let configSetting:
      | "minimumReleaseAgeExclude"
      | "minimumReleaseAgeExcludes"
      | "npmPreapprovedPackages";
    let requestedExclusions: { specifier: string }[];
    let currentExclusions: string[];

    if (detection.manager === "pnpm") {
      manager = "pnpm";
      configSetting = "minimumReleaseAgeExclude";
      requestedExclusions = extractPnpmMinimumReleaseAgeExclusions(
        error.result,
      );

      const getConfigStep = withLabel(
        "Read pnpm minimumReleaseAgeExclude",
        "pnpm",
        [
          "config",
          "get",
          "--location=project",
          "--json",
          "minimumReleaseAgeExclude",
        ],
      );
      const currentConfigResult = await runStep(getConfigStep, undefined, {
        silent: true,
      });
      currentExclusions = parsePnpmMinimumReleaseAgeExcludeConfig(
        currentConfigResult.stdout,
      );
    } else if (detection.manager === "bun") {
      manager = "bun";
      configSetting = "minimumReleaseAgeExcludes";
      requestedExclusions = extractBunMinimumReleaseAgeExclusions(error.result);
      currentExclusions = await readBunMinimumReleaseAgeExcludes();
    } else if (detection.agent === "yarn@berry") {
      manager = "yarn";
      configSetting = "npmPreapprovedPackages";
      requestedExclusions = extractYarnMinimumReleaseAgeExclusions(
        error.result,
      );
      currentExclusions = await readYarnNpmPreapprovedPackages();
    } else {
      return null;
    }

    if (requestedExclusions.length === 0) {
      return null;
    }

    const currentExclusionSet = new Set(currentExclusions);
    const nextExclusions = requestedExclusions.filter(
      (entry) =>
        !currentExclusionSet.has(entry.specifier) &&
        !attemptedMinimumReleaseAgeExclusions.has(entry.specifier),
    );

    if (nextExclusions.length === 0) {
      return null;
    }

    dependencies.hooks?.onInteractivePrompt?.();
    const shouldRetry =
      await dependencies.confirmPnpmMinimumReleaseAgeExclusions({
        manager,
        configSetting,
        packages: nextExclusions.map((entry) => entry.specifier),
      });

    if (!shouldRetry) {
      throw new MinimumReleaseAgeDeclinedError({
        step,
        manager,
        configSetting,
        packages: nextExclusions.map((entry) => entry.specifier),
      });
    }

    const updatedExclusions = [...currentExclusions];

    for (const entry of nextExclusions) {
      attemptedMinimumReleaseAgeExclusions.add(entry.specifier);
      updatedExclusions.push(entry.specifier);
    }

    if (manager === "pnpm") {
      await runStep(
        withLabel("Update pnpm minimumReleaseAgeExclude", "pnpm", [
          "config",
          "set",
          "--location=project",
          "--json",
          "minimumReleaseAgeExclude",
          JSON.stringify(updatedExclusions),
        ]),
      );
    } else {
      if (manager === "bun") {
        await runActionStep(
          {
            label: "Update bun minimumReleaseAgeExcludes",
            command: "bun",
            args: ["update"],
          },
          async () => {
            await writeBunMinimumReleaseAgeExcludes(updatedExclusions);
          },
        );
      } else {
        await runActionStep(
          {
            label: "Update yarn npmPreapprovedPackages",
            command: "yarn",
            args: ["config", "set", "npmPreapprovedPackages"],
          },
          async () => {
            await writeYarnNpmPreapprovedPackages(updatedExclusions);
          },
        );
      }
    }

    try {
      return await exec(step, {
        cwd: options.cwd,
        verbose: options.verbose,
      });
    } catch (retryError) {
      const recoveredRetry = await recoverMinimumReleaseAgeFailure(
        retryError,
        step,
      );

      if (recoveredRetry) {
        return recoveredRetry;
      }

      throw retryError;
    }
  };

  const initialAuditStep = withLabel(
    "Initial audit",
    auditProcess.command,
    auditProcess.args,
    auditExitCodes,
    (result) => adapter.isAuditResult?.(result.stdout) ?? false,
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
  const shouldForceBunFinalAudit =
    !options.dryRun && detection.manager === "bun" && initial.total > 0;

  if (shouldForceBunFinalAudit && dependencies.promptBunManualRemediation) {
    dependencies.hooks?.onInteractivePrompt?.();
    await dependencies.promptBunManualRemediation({ initial });
  }

  if (!options.dryRun) {
    const remediation = adapter.buildRemediationProcess(context);

    if (remediation) {
      remediationRan = true;
      const remediationStep = withLabel(
        "Apply fixes",
        remediation.command,
        remediation.args,
        adapter.remediationExitCodes ?? [0],
      );
      await runStep(remediationStep, (error) =>
        recoverMinimumReleaseAgeFailure(error, remediationStep),
      );
    }

    const postRemediation = adapter.buildPostRemediationProcess(context);

    if (postRemediation) {
      const postRemediationStep = withLabel(
        "Reinstall dependencies",
        postRemediation.command,
        postRemediation.args,
      );
      await runStep(postRemediationStep, (error) =>
        recoverMinimumReleaseAgeFailure(error, postRemediationStep),
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
      (result) => adapter.isAuditResult?.(result.stdout) ?? false,
    );
    const finalAuditResult = await runStep(finalAuditStep);
    final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
      adapter.parseAudit(finalAuditResult.stdout, context),
    );

    if (remediationRan) {
      recordStepFix("Apply fixes", initial, final);
    }
  } else if (!remediationRan && !dedupeProcess) {
    if (shouldForceBunFinalAudit) {
      const finalAuditStep = withLabel(
        "Final audit",
        auditProcess.command,
        auditProcess.args,
        auditExitCodes,
        (result) => adapter.isAuditResult?.(result.stdout) ?? false,
      );
      const finalAuditResult = await runStep(finalAuditStep);
      final = parseAuditResult(finalAuditStep, finalAuditResult, () =>
        adapter.parseAudit(finalAuditResult.stdout, context),
      );
    } else {
      final = initial;
    }
  } else {
    const postFixAuditStep = withLabel(
      "Recheck after fixes",
      auditProcess.command,
      auditProcess.args,
      auditExitCodes,
      (result) => adapter.isAuditResult?.(result.stdout) ?? false,
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
      const dedupeStep = withLabel(
        "Consolidate dependency tree",
        dedupeProcess.command,
        dedupeProcess.args,
      );
      await runStep(dedupeStep, (error) =>
        recoverMinimumReleaseAgeFailure(error, dedupeStep),
      );

      const finalAuditStep = withLabel(
        "Final audit",
        auditProcess.command,
        auditProcess.args,
        auditExitCodes,
        (result) => adapter.isAuditResult?.(result.stdout) ?? false,
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
