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
  parsePnpmAuditIgnoreListConfig,
  parsePnpmMinimumReleaseAgeConfig,
  parsePnpmMinimumReleaseAgeExcludeConfig,
  parsePnpmPackagePublishedTimes,
} from "../adapters/pnpm.js";
import type { MinimumReleaseAgeExclusion } from "../adapters/shared.js";
import {
  extractYarnMinimumReleaseAgeExclusions,
  parseYarnNpmPreapprovedPackagesConfig,
  updateYarnNpmPreapprovedPackagesConfig,
} from "../adapters/yarn-berry.js";
import { detectPackageManager } from "./detect-manager.js";
import { type ExecFunction, executeStep } from "./exec.js";
import {
  diffFixedEntries,
  groupFixedPackages,
  isRecord,
  uniqueSorted,
} from "./normalize.js";
import type {
  CommandResult,
  CommandStep,
  ConfirmMinimumReleaseAgeExclusions,
  DetectionResult,
  MinimumReleaseAgeManager,
  MinimumReleaseAgeSetting,
  NormalizedAuditSnapshot,
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

const EXACT_PNPM_VERSION_PATTERN =
  /^\d+\.\d+\.\d+(?:-[0-9A-Za-z-.]+)?(?:\+[0-9A-Za-z-.]+)?$/;

function parseExactPnpmExclusionSpecifier(
  specifier: string,
): { packageName: string; version: string } | null {
  const separatorIndex = specifier.lastIndexOf("@");

  if (separatorIndex <= 0 || separatorIndex >= specifier.length - 1) {
    return null;
  }

  const packageName = specifier.slice(0, separatorIndex);
  const version = specifier.slice(separatorIndex + 1);

  if (!EXACT_PNPM_VERSION_PATTERN.test(version)) {
    return null;
  }

  return { packageName, version };
}

function sameStringList(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return (
    left.length === right.length &&
    left.every((entry, index) => entry === right[index])
  );
}

function formatCountLabel(
  count: number,
  singular: string,
  plural: string,
): string {
  return `${count} ${count === 1 ? singular : plural}`;
}

function createPnpmMinimumReleaseAgeExcludeUpdateLabel(input: {
  removedCount: number;
  addedCount: number;
}): string {
  const details: string[] = [];

  if (input.removedCount > 0) {
    details.push(
      `removed ${formatCountLabel(input.removedCount, "unneeded entry", "unneeded entries")}`,
    );
  }

  if (input.addedCount > 0) {
    details.push(
      `added ${formatCountLabel(input.addedCount, "new entry", "new entries")}`,
    );
  }

  const prefix =
    input.addedCount > 0
      ? "Update pnpm minimumReleaseAgeExclude"
      : "Clean pnpm minimumReleaseAgeExclude";

  return details.length > 0 ? `${prefix}: ${details.join(", ")}` : prefix;
}

function parsePnpmOverridePackageName(selector: string): string {
  const dependencySelector = selector.split(">").at(-1)?.trim() ?? selector;
  const versionSeparatorIndex = dependencySelector.startsWith("@")
    ? dependencySelector.indexOf("@", 1)
    : dependencySelector.indexOf("@");

  if (versionSeparatorIndex <= 0) {
    return dependencySelector;
  }

  return dependencySelector.slice(0, versionSeparatorIndex);
}

/** Reads a file, returning `null` when it does not exist. */
function readFileIfExists(pathname: string): string | null {
  try {
    return fs.readFileSync(pathname, "utf8");
  } catch (error) {
    if (error instanceof Error && "code" in error && error.code === "ENOENT") {
      return null;
    }

    throw error;
  }
}

function readPackageJson(pathname: string): Record<string, unknown> | null {
  const source = readFileIfExists(pathname);
  const parsed = source === null ? null : (JSON.parse(source) as unknown);

  return isRecord(parsed) ? parsed : null;
}

function readPnpmOverrides(
  packageJson: Record<string, unknown> | null,
): Record<string, unknown> {
  if (!packageJson || !isRecord(packageJson.pnpm)) {
    return {};
  }

  return isRecord(packageJson.pnpm.overrides) ? packageJson.pnpm.overrides : {};
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
    const fixedEntries = diffFixedEntries(before.entries, after.entries);

    stepFixes.push({
      label,
      fixedCount: fixedEntries.length,
      remainingCount: after.total,
    });
  };

  /** Runs `action`, reporting its lifecycle to the configured hooks. */
  const withStepHooks = async <T>(
    step: Pick<CommandStep, "label" | "command" | "args">,
    action: () => Promise<T>,
    stepOptions: { silent?: boolean } = {},
  ): Promise<T> => {
    const event = {
      label: step.label,
      command: [step.command, ...step.args],
    };
    const report = (hook: "onStepStart" | "onStepComplete" | "onStepFail") => {
      if (!stepOptions.silent) {
        dependencies.hooks?.[hook]?.(event);
      }
    };

    report("onStepStart");

    try {
      const result = await action();
      report("onStepComplete");
      return result;
    } catch (error) {
      report("onStepFail");
      throw error;
    }
  };

  const runStep = (
    step: CommandStep,
    recoverError?:
      | ((error: unknown) => Promise<CommandResult | null>)
      | undefined,
    stepOptions: { silent?: boolean } = {},
  ) =>
    withStepHooks(
      step,
      async () => {
        try {
          return await exec(step, {
            cwd: options.cwd,
            verbose: options.verbose,
          });
        } catch (error) {
          if (!recoverError) {
            throw error;
          }

          const recoveredResult = await recoverError(error);

          if (!recoveredResult) {
            throw error;
          }

          return recoveredResult;
        }
      },
      stepOptions,
    );

  /** Reads the exclusion list from a manager config file in `options.cwd`. */
  const readExclusionConfig = (
    fileName: string,
    parse: (source: string) => string[],
  ): string[] => {
    const source = readFileIfExists(path.join(options.cwd, fileName));
    return source === null ? [] : parse(source);
  };

  /** Rewrites the exclusion list in a manager config file in `options.cwd`. */
  const writeExclusionConfig = (
    fileName: string,
    update: (source: string, entries: string[]) => string,
    entries: string[],
  ): void => {
    const configPath = path.join(options.cwd, fileName);
    const source = readFileIfExists(configPath) ?? "";

    fs.writeFileSync(configPath, update(source, entries), "utf8");
  };

  const readBunMinimumReleaseAgeExcludes = () =>
    readExclusionConfig("bunfig.toml", parseBunMinimumReleaseAgeExcludesConfig);

  const writeBunMinimumReleaseAgeExcludes = (excludes: string[]) => {
    writeExclusionConfig(
      "bunfig.toml",
      updateBunMinimumReleaseAgeExcludesConfig,
      excludes,
    );
  };

  const readYarnNpmPreapprovedPackages = () =>
    readExclusionConfig(".yarnrc.yml", parseYarnNpmPreapprovedPackagesConfig);

  const writeYarnNpmPreapprovedPackages = (packages: string[]) => {
    writeExclusionConfig(
      ".yarnrc.yml",
      updateYarnNpmPreapprovedPackagesConfig,
      packages,
    );
  };

  const readPnpmMinimumReleaseAge = async (): Promise<number | null> => {
    const result = await runStep(
      withLabel("Read pnpm minimumReleaseAge", "pnpm", [
        "config",
        "get",
        "--json",
        "minimumReleaseAge",
      ]),
      undefined,
      { silent: true },
    );

    return parsePnpmMinimumReleaseAgeConfig(result.stdout);
  };

  const readPnpmAuditIgnoreList = async (
    setting: "ignoreCves" | "ignoreGhsas",
  ): Promise<string[]> => {
    const result = await runStep(
      withLabel(`Read pnpm audit ${setting}`, "pnpm", [
        "config",
        "get",
        "--json",
        `auditConfig.${setting}`,
      ]),
      undefined,
      { silent: true },
    );

    return parsePnpmAuditIgnoreListConfig(result.stdout);
  };

  const readPnpmAuditIgnores = async (): Promise<string[]> => {
    return uniqueSorted([
      ...(await readPnpmAuditIgnoreList("ignoreGhsas")),
      ...(await readPnpmAuditIgnoreList("ignoreCves")),
    ]);
  };

  const cleanIgnoredPnpmAuditFixOverrides = async (input: {
    beforeOverrides: Record<string, unknown>;
    allowedPackageNames: Set<string>;
  }): Promise<number> => {
    if (detection.manager !== "pnpm") {
      return 0;
    }

    const packageJsonPath = path.join(options.cwd, "package.json");
    const packageJson = readPackageJson(packageJsonPath);

    if (!packageJson || !isRecord(packageJson.pnpm)) {
      return 0;
    }

    const overrides = readPnpmOverrides(packageJson);
    const addedOverrideKeys = Object.keys(overrides).filter(
      (key) => !(key in input.beforeOverrides),
    );
    const ignoredOverrideKeys = addedOverrideKeys.filter(
      (key) =>
        !input.allowedPackageNames.has(parsePnpmOverridePackageName(key)),
    );

    if (ignoredOverrideKeys.length === 0) {
      return 0;
    }

    for (const key of ignoredOverrideKeys) {
      delete overrides[key];
    }

    fs.writeFileSync(
      packageJsonPath,
      `${JSON.stringify(packageJson, null, 2)}\n`,
      "utf8",
    );

    return ignoredOverrideKeys.length;
  };

  const readPnpmMinimumReleaseAgeExclude = async (): Promise<string[]> => {
    const result = await runStep(
      withLabel("Read pnpm minimumReleaseAgeExclude", "pnpm", [
        "config",
        "get",
        "--location=project",
        "--json",
        "minimumReleaseAgeExclude",
      ]),
      undefined,
      { silent: true },
    );

    return parsePnpmMinimumReleaseAgeExcludeConfig(result.stdout);
  };

  const retainNeededPnpmMinimumReleaseAgeExclusions = async (
    exclusions: string[],
  ): Promise<string[]> => {
    if (exclusions.length === 0) {
      return exclusions;
    }

    const minimumReleaseAgeMinutes = await readPnpmMinimumReleaseAge();

    if (minimumReleaseAgeMinutes === null) {
      return exclusions;
    }

    const minimumReleaseAgeMs = minimumReleaseAgeMinutes * 60_000;
    const publishedTimesByPackage = new Map<
      string,
      Promise<Record<string, string> | null>
    >();

    const readPublishedTimes = (packageName: string) => {
      let publishedTimes = publishedTimesByPackage.get(packageName);

      if (!publishedTimes) {
        publishedTimes = (async () => {
          try {
            const result = await runStep(
              withLabel("Read pnpm package publish times", "pnpm", [
                "view",
                packageName,
                "time",
                "--json",
              ]),
              undefined,
              { silent: true },
            );

            return parsePnpmPackagePublishedTimes(result.stdout);
          } catch {
            return null;
          }
        })();
        publishedTimesByPackage.set(packageName, publishedTimes);
      }

      return publishedTimes;
    };

    const nextExclusions: string[] = [];
    const now = Date.now();

    for (const specifier of exclusions) {
      const parsedSpecifier = parseExactPnpmExclusionSpecifier(specifier);

      if (!parsedSpecifier) {
        nextExclusions.push(specifier);
        continue;
      }

      const publishedTimes = await readPublishedTimes(
        parsedSpecifier.packageName,
      );
      const publishedAt = publishedTimes?.[parsedSpecifier.version];

      if (!publishedAt) {
        nextExclusions.push(specifier);
        continue;
      }

      const publishedMs = Date.parse(publishedAt);

      if (!Number.isFinite(publishedMs)) {
        nextExclusions.push(specifier);
        continue;
      }

      if (minimumReleaseAgeMs > 0 && now - publishedMs < minimumReleaseAgeMs) {
        nextExclusions.push(specifier);
      }
    }

    return nextExclusions;
  };

  /** Drops stored exclusions whose versions are now old enough to install. */
  const validatePnpmMinimumReleaseAgeExclusions = (
    storedExclusions: string[],
  ): Promise<string[]> =>
    retainNeededPnpmMinimumReleaseAgeExclusions([...new Set(storedExclusions)]);

  const writePnpmMinimumReleaseAgeExclude = async (
    exclusions: string[],
    stepLabel: string,
  ): Promise<void> => {
    await runStep(
      withLabel(stepLabel, "pnpm", [
        "config",
        "set",
        "--location=project",
        "--json",
        "minimumReleaseAgeExclude",
        JSON.stringify(exclusions),
      ]),
    );
  };

  const maintainPnpmMinimumReleaseAgeExclude = async (): Promise<void> => {
    if (options.dryRun || detection.manager !== "pnpm") {
      return;
    }

    const storedExclusions = await readPnpmMinimumReleaseAgeExclude();

    if (storedExclusions.length === 0) {
      return;
    }

    const currentExclusions =
      await validatePnpmMinimumReleaseAgeExclusions(storedExclusions);

    if (sameStringList(storedExclusions, currentExclusions)) {
      return;
    }

    const stepLabel = createPnpmMinimumReleaseAgeExcludeUpdateLabel({
      removedCount: storedExclusions.length - currentExclusions.length,
      addedCount: 0,
    });

    await writePnpmMinimumReleaseAgeExclude(currentExclusions, stepLabel);
  };

  /**
   * Determines which manager blocked the failed step on its minimum release
   * age policy, and which exclusions it is asking for.
   */
  const resolveMinimumReleaseAgeTarget = async (
    result: CommandResult,
  ): Promise<{
    manager: MinimumReleaseAgeManager;
    configSetting: MinimumReleaseAgeSetting;
    requestedExclusions: MinimumReleaseAgeExclusion[];
    currentExclusions: string[];
    /** Exclusions already persisted by pnpm, or `null` for other managers. */
    storedExclusions: string[] | null;
  } | null> => {
    if (detection.manager === "pnpm") {
      const storedExclusions = await readPnpmMinimumReleaseAgeExclude();

      return {
        manager: "pnpm",
        configSetting: "minimumReleaseAgeExclude",
        requestedExclusions: extractPnpmMinimumReleaseAgeExclusions(result),
        currentExclusions:
          storedExclusions.length > 0
            ? await validatePnpmMinimumReleaseAgeExclusions(storedExclusions)
            : [],
        storedExclusions,
      };
    }

    if (detection.manager === "bun") {
      return {
        manager: "bun",
        configSetting: "minimumReleaseAgeExcludes",
        requestedExclusions: extractBunMinimumReleaseAgeExclusions(result),
        currentExclusions: readBunMinimumReleaseAgeExcludes(),
        storedExclusions: null,
      };
    }

    if (detection.agent === "yarn@berry") {
      return {
        manager: "yarn",
        configSetting: "npmPreapprovedPackages",
        requestedExclusions: extractYarnMinimumReleaseAgeExclusions(result),
        currentExclusions: readYarnNpmPreapprovedPackages(),
        storedExclusions: null,
      };
    }

    return null;
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

    const target = await resolveMinimumReleaseAgeTarget(error.result);

    if (!target) {
      return null;
    }

    const { manager, configSetting, requestedExclusions, storedExclusions } =
      target;
    const currentExclusionSet = new Set(target.currentExclusions);
    const packages = requestedExclusions
      .map((entry) => entry.specifier)
      .filter(
        (specifier) =>
          !currentExclusionSet.has(specifier) &&
          !attemptedMinimumReleaseAgeExclusions.has(specifier),
      );

    if (packages.length === 0) {
      return null;
    }

    dependencies.hooks?.onInteractivePrompt?.();

    const confirmed = await dependencies.confirmPnpmMinimumReleaseAgeExclusions(
      { manager, configSetting, packages },
    );

    if (!confirmed) {
      throw new MinimumReleaseAgeDeclinedError({
        step,
        manager,
        configSetting,
        packages,
      });
    }

    const updatedExclusions = [...target.currentExclusions];

    for (const specifier of packages) {
      attemptedMinimumReleaseAgeExclusions.add(specifier);
      updatedExclusions.push(specifier);
    }

    if (manager === "pnpm") {
      const stepLabel = createPnpmMinimumReleaseAgeExcludeUpdateLabel({
        removedCount:
          storedExclusions === null
            ? 0
            : storedExclusions.length +
              packages.length -
              updatedExclusions.length,
        addedCount: packages.length,
      });
      await writePnpmMinimumReleaseAgeExclude(updatedExclusions, stepLabel);
    } else if (manager === "bun") {
      await withStepHooks(
        {
          label: "Update bun minimumReleaseAgeExcludes",
          command: "bun",
          args: ["update"],
        },
        async () => {
          writeBunMinimumReleaseAgeExcludes(updatedExclusions);
        },
      );
    } else {
      await withStepHooks(
        {
          label: "Update yarn npmPreapprovedPackages",
          command: "yarn",
          args: ["config", "set", "npmPreapprovedPackages"],
        },
        async () => {
          writeYarnNpmPreapprovedPackages(updatedExclusions);
        },
      );
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

  /** Runs a step, retrying it once the user approves any needed exclusions. */
  const runRecoverableStep = (step: CommandStep) =>
    runStep(step, (error) => recoverMinimumReleaseAgeFailure(error, step));

  /** Runs the manager's audit command and normalizes its output. */
  const runAudit = async (label: string): Promise<NormalizedAuditSnapshot> => {
    const step = withLabel(
      label,
      auditProcess.command,
      auditProcess.args,
      auditExitCodes,
      (result) => adapter.isAuditResult?.(result.stdout) ?? false,
    );
    const result = await runStep(step);

    return parseAuditResult(step, result, () =>
      adapter.parseAudit(result.stdout, context),
    );
  };

  const initial = await runAudit("Initial audit");

  await maintainPnpmMinimumReleaseAgeExclude();

  const buildResult = (input: {
    final: NormalizedAuditSnapshot;
    dedupeRan: boolean;
  }): RunAuditFixResult => {
    const fixedEntries = diffFixedEntries(initial.entries, input.final.entries);
    const remainingCount = input.final.total;

    return {
      manager: detection.manager,
      detectionSource: detection.source,
      threshold: options.threshold,
      scope: options.scope,
      dedupe: options.dedupe,
      dedupeRan: input.dedupeRan,
      dryRun: options.dryRun,
      initial,
      final: input.final,
      stepFixes,
      fixedCount: fixedEntries.length,
      remainingCount,
      fixed: groupFixedPackages(fixedEntries),
      exitCode: remainingCount === 0 ? 0 : 2,
      status:
        initial.total === 0
          ? "clean"
          : fixedEntries.length > 0
            ? "resolved-some"
            : "no-change",
    };
  };

  if (initial.total === 0) {
    return buildResult({ final: initial, dedupeRan: false });
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
      const pnpmOverridesBeforeFix =
        detection.manager === "pnpm"
          ? readPnpmOverrides(
              readPackageJson(path.join(options.cwd, "package.json")),
            )
          : {};

      if (detection.manager === "pnpm") {
        const ignoredAdvisories = await readPnpmAuditIgnores();

        for (const ignoredAdvisory of ignoredAdvisories) {
          remediation.args.push("--ignore", ignoredAdvisory);
        }
      }

      remediationRan = true;
      const remediationStep = withLabel(
        "Apply fixes",
        remediation.command,
        remediation.args,
        adapter.remediationExitCodes ?? [0],
      );
      await runRecoverableStep(remediationStep);

      await cleanIgnoredPnpmAuditFixOverrides({
        beforeOverrides: pnpmOverridesBeforeFix,
        allowedPackageNames: new Set(
          initial.entries.map((entry) => entry.packageName),
        ),
      });
    }

    const postRemediation = adapter.buildPostRemediationProcess(context);

    if (postRemediation) {
      const postRemediationStep = withLabel(
        "Reinstall dependencies",
        postRemediation.command,
        postRemediation.args,
      );
      await runRecoverableStep(postRemediationStep);
    }
  }
  let final: NormalizedAuditSnapshot;
  let dedupeRan = false;

  if (options.dryRun || options.dedupe === "never") {
    final = await runAudit("Final audit");

    if (remediationRan) {
      recordStepFix("Apply fixes", initial, final);
    }
  } else if (!remediationRan && !dedupeProcess) {
    final = shouldForceBunFinalAudit ? await runAudit("Final audit") : initial;
  } else {
    const postFixSnapshot = await runAudit("Recheck after fixes");

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
      await runRecoverableStep(dedupeStep);

      final = await runAudit("Final audit");
      recordStepFix("Consolidate dependency tree", postFixSnapshot, final);
    } else {
      final = postFixSnapshot;
    }
  }
  return buildResult({ final, dedupeRan });
}
