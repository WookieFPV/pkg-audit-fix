import type { Spinner as SpinnerInstance } from "picospinner";
import { Spinner } from "picospinner";

import type { StepEvent } from "../core/types.js";

export interface StepLifecycleReporter {
  start(step: StepEvent): void;
  complete(step: StepEvent): void;
  fail(step: StepEvent): void;
  pause(): void;
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

export function createStepLifecycleReporter(
  options: CreateStepLifecycleReporterOptions,
): StepLifecycleReporter {
  if (!options.enabled) {
    return {
      start() {},
      complete() {},
      fail() {},
      pause() {},
    };
  }

  const createSpinner = options.createSpinner ?? defaultCreateSpinner;
  const useSpinner = options.isInteractive && !options.verbose;
  let activeSpinner: SpinnerLike | null = null;
  let activeStep: StepEvent | null = null;
  const pausedSteps = new Set<string>();

  const runningText = (label: string) => `${label}...`;
  const successText = (step: StepEvent) => `${step.label} complete`;
  const failureText = (label: string) => `${label} failed`;
  const fallbackSuccessText = (step: StepEvent) => `✔ ${successText(step)}\n`;
  const fallbackFailureText = (step: StepEvent) =>
    `✖ ${failureText(step.label)}\n`;

  return {
    start(step) {
      if (options.showCommands) {
        options.write(`$ ${formatCommand(step.command)}\n`);
      }

      if (!useSpinner) {
        options.write(`${runningText(step.label)}\n`);
        return;
      }

      activeSpinner = createSpinner(runningText(step.label), options.color);
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
        activeSpinner.fail(failureText(step.label));
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
  };
}
