import type { Spinner as SpinnerInstance } from "picospinner";
import { Spinner } from "picospinner";

import type { StepEvent } from "../core/types.js";

export interface StepLifecycleReporter {
  start(step: StepEvent): void;
  complete(step: StepEvent): void;
  fail(step: StepEvent): void;
  pause(): void;
  hasOutput(): boolean;
}

interface CreateStepLifecycleReporterOptions {
  enabled: boolean;
  color: boolean;
  verbose: boolean;
  showCommands: boolean;
  isInteractive: boolean;
  write: (text: string) => void;
  createSpinner?: ((text: string, color: boolean) => SpinnerLike) | undefined;
}

interface SpinnerLike {
  start(): void;
  succeed(text?: string): void;
  fail(text?: string): void;
  stop(): void;
}

function defaultCreateSpinner(text: string, color: boolean): SpinnerInstance {
  return new Spinner(text, { colors: color });
}

function formatShellWord(word: string): string {
  return /^[A-Za-z0-9_./:=+-]+$/.test(word)
    ? word
    : `'${word.replaceAll("'", `'"'"'`)}'`;
}

function formatCommand(command: readonly string[]): string {
  return command.map(formatShellWord).join(" ");
}

function splitSummaryLabel(label: string, prefix: string): string | null {
  if (label === prefix) {
    return "";
  }

  const withSeparator = `${prefix}: `;

  return label.startsWith(withSeparator)
    ? label.slice(withSeparator.length)
    : null;
}

function getDisplayText(label: string): {
  running: string;
  success: string;
  failure: string;
} {
  const cleanPnpmMinimumReleaseAgeExcludeSummary = splitSummaryLabel(
    label,
    "Clean pnpm minimumReleaseAgeExclude",
  );

  if (cleanPnpmMinimumReleaseAgeExcludeSummary !== null) {
    return {
      running: "Cleaning pnpm minimumReleaseAge exclusions",
      success:
        cleanPnpmMinimumReleaseAgeExcludeSummary.length > 0
          ? `Cleaned pnpm minimumReleaseAge exclusions (${cleanPnpmMinimumReleaseAgeExcludeSummary})`
          : "Cleaned pnpm minimumReleaseAge exclusions",
      failure: "Cleaning pnpm minimumReleaseAge exclusions failed",
    };
  }

  const updatePnpmMinimumReleaseAgeExcludeSummary = splitSummaryLabel(
    label,
    "Update pnpm minimumReleaseAgeExclude",
  );

  if (updatePnpmMinimumReleaseAgeExcludeSummary !== null) {
    return {
      running: "Updating pnpm minimumReleaseAge exclusions",
      success:
        updatePnpmMinimumReleaseAgeExcludeSummary.length > 0
          ? `Updated pnpm minimumReleaseAge exclusions (${updatePnpmMinimumReleaseAgeExcludeSummary})`
          : "Updated pnpm minimumReleaseAge exclusions",
      failure: "Updating pnpm minimumReleaseAge exclusions failed",
    };
  }

  switch (label) {
    case "Initial audit":
      return {
        running: "Auditing dependencies",
        success: "Audited dependencies",
        failure: "Dependency audit failed",
      };
    case "Apply fixes":
      return {
        running: "Applying available fixes",
        success: "Applied available fixes",
        failure: "Applying available fixes failed",
      };
    case "Reinstall dependencies":
      return {
        running: "Reinstalling dependencies",
        success: "Reinstalled dependencies",
        failure: "Reinstalling dependencies failed",
      };
    case "Recheck after fixes":
      return {
        running: "Rechecking vulnerabilities",
        success: "Rechecked vulnerabilities",
        failure: "Rechecking vulnerabilities failed",
      };
    case "Final audit":
      return {
        running: "Checking remaining vulnerabilities",
        success: "Checked remaining vulnerabilities",
        failure: "Checking remaining vulnerabilities failed",
      };
    case "Consolidate dependency tree":
      return {
        running: "Consolidating dependency tree",
        success: "Consolidated dependency tree",
        failure: "Consolidating dependency tree failed",
      };
    case "Read pnpm minimumReleaseAgeExclude":
      return {
        running: "Reading pnpm minimumReleaseAge exclusions",
        success: "Read pnpm minimumReleaseAge exclusions",
        failure: "Reading pnpm minimumReleaseAge exclusions failed",
      };
    case "Update bun minimumReleaseAgeExcludes":
      return {
        running: "Updating bun minimumReleaseAge exclusions",
        success: "Updated bun minimumReleaseAge exclusions",
        failure: "Updating bun minimumReleaseAge exclusions failed",
      };
    case "Update yarn npmPreapprovedPackages":
      return {
        running: "Updating Yarn preapproved packages",
        success: "Updated Yarn preapproved packages",
        failure: "Updating Yarn preapproved packages failed",
      };
    default:
      return {
        running: label,
        success: `${label} complete`,
        failure: `${label} failed`,
      };
  }
}

export function createStepLifecycleReporter(
  options: CreateStepLifecycleReporterOptions,
): StepLifecycleReporter {
  if (!options.enabled) {
    return {
      start() {},
      complete() {},
      fail() {},
      pause() {},
      hasOutput() {
        return false;
      },
    };
  }

  const createSpinner = options.createSpinner ?? defaultCreateSpinner;
  const useSpinner = options.isInteractive && !options.verbose;
  let activeSpinner: SpinnerLike | null = null;
  let activeStep: StepEvent | null = null;
  const pausedSteps = new Set<string>();
  let wroteOutput = false;

  const runningText = (step: StepEvent) =>
    `${getDisplayText(step.label).running}...`;
  const successText = (step: StepEvent) => getDisplayText(step.label).success;
  const failureText = (step: StepEvent) => getDisplayText(step.label).failure;
  const fallbackSuccessText = (step: StepEvent) => `✔ ${successText(step)}\n`;
  const fallbackFailureText = (step: StepEvent) => `✖ ${failureText(step)}\n`;

  return {
    start(step) {
      if (options.showCommands) {
        wroteOutput = true;
        options.write(`$ ${formatCommand(step.command)}\n`);
      }

      if (!useSpinner) {
        wroteOutput = true;
        options.write(`${runningText(step)}\n`);
        return;
      }

      wroteOutput = true;
      activeSpinner = createSpinner(runningText(step), options.color);
      activeSpinner.start();
      activeStep = step;
    },

    complete(step) {
      if (!useSpinner) {
        return;
      }

      if (activeSpinner && activeStep?.label === step.label) {
        activeSpinner.succeed(successText(step));
        activeSpinner = null;
        activeStep = null;
        return;
      }

      if (pausedSteps.has(step.label)) {
        pausedSteps.delete(step.label);
        options.write(fallbackSuccessText(step));
      }
    },

    fail(step) {
      if (!useSpinner) {
        return;
      }

      if (activeSpinner && activeStep?.label === step.label) {
        activeSpinner.fail(failureText(step));
        activeSpinner = null;
        activeStep = null;
        return;
      }

      if (pausedSteps.has(step.label)) {
        pausedSteps.delete(step.label);
        options.write(fallbackFailureText(step));
      }
    },

    pause() {
      if (!useSpinner) {
        return;
      }

      if (!activeSpinner || !activeStep) {
        return;
      }

      pausedSteps.add(activeStep.label);
      activeSpinner.stop();
      activeSpinner = null;
      activeStep = null;
    },

    hasOutput() {
      return wroteOutput;
    },
  };
}
