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

interface StepDisplayText {
  running: string;
  success: string;
  failure: string;
}

/** Verb forms for a step, e.g. `["Auditing", "Audited"]` + a shared object. */
function displayText(
  presentParticiple: string,
  pastTense: string,
  subject: string,
): StepDisplayText {
  return {
    running: `${presentParticiple} ${subject}`,
    success: `${pastTense} ${subject}`,
    failure: `${presentParticiple} ${subject} failed`,
  };
}

/**
 * Labels that carry a trailing summary, as `"<prefix>: <summary>"`. The summary
 * is appended to the success text in parentheses.
 */
const SUMMARIZED_STEP_LABELS: Record<string, StepDisplayText> = {
  "Clean pnpm minimumReleaseAgeExclude": displayText(
    "Cleaning",
    "Cleaned",
    "pnpm minimumReleaseAge exclusions",
  ),
  "Update pnpm minimumReleaseAgeExclude": displayText(
    "Updating",
    "Updated",
    "pnpm minimumReleaseAge exclusions",
  ),
};

const STEP_LABELS: Record<string, StepDisplayText> = {
  "Initial audit": displayText("Auditing", "Audited", "dependencies"),
  "Apply fixes": displayText("Applying", "Applied", "available fixes"),
  "Reinstall dependencies": displayText(
    "Reinstalling",
    "Reinstalled",
    "dependencies",
  ),
  "Recheck after fixes": displayText(
    "Rechecking",
    "Rechecked",
    "vulnerabilities",
  ),
  "Final audit": displayText(
    "Checking",
    "Checked",
    "remaining vulnerabilities",
  ),
  "Consolidate dependency tree": displayText(
    "Consolidating",
    "Consolidated",
    "dependency tree",
  ),
  "Read pnpm minimumReleaseAgeExclude": displayText(
    "Reading",
    "Read",
    "pnpm minimumReleaseAge exclusions",
  ),
  "Update bun minimumReleaseAgeExcludes": displayText(
    "Updating",
    "Updated",
    "bun minimumReleaseAge exclusions",
  ),
  "Update yarn npmPreapprovedPackages": displayText(
    "Updating",
    "Updated",
    "Yarn preapproved packages",
  ),
};

function getDisplayText(label: string): StepDisplayText {
  for (const [prefix, text] of Object.entries(SUMMARIZED_STEP_LABELS)) {
    if (label === prefix) {
      return text;
    }

    if (label.startsWith(`${prefix}: `)) {
      const summary = label.slice(prefix.length + 2);

      return summary.length > 0
        ? { ...text, success: `${text.success} (${summary})` }
        : text;
    }
  }

  return (
    STEP_LABELS[label] ?? {
      running: label,
      success: `${label} complete`,
      failure: `${label} failed`,
    }
  );
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
        options.write(`✔ ${successText(step)}\n`);
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
        options.write(`✖ ${failureText(step)}\n`);
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
