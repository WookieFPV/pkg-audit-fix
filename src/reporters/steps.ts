import type { Spinner as SpinnerInstance } from "picospinner";
import { Spinner } from "picospinner";

import type { StepEvent } from "../core/types.js";

export interface StepLifecycleReporter {
  start(step: StepEvent): void;
  complete(step: StepEvent): void;
  fail(step: StepEvent): void;
  info(step: StepEvent): void;
}

interface CreateStepLifecycleReporterOptions {
  enabled: boolean;
  color: boolean;
  verbose: boolean;
  isInteractive: boolean;
  write: (text: string) => void;
  createSpinner?: ((text: string, color: boolean) => SpinnerLike) | undefined;
}

interface SpinnerLike {
  start(): void;
  succeed(text?: string): void;
  fail(text?: string): void;
}

function defaultCreateSpinner(text: string, color: boolean): SpinnerInstance {
  return new Spinner(text, { colors: color });
}

export function createStepLifecycleReporter(
  options: CreateStepLifecycleReporterOptions,
): StepLifecycleReporter {
  if (!options.enabled) {
    return {
      start() {},
      complete() {},
      fail() {},
      info() {},
    };
  }

  const createSpinner = options.createSpinner ?? defaultCreateSpinner;
  const useSpinner = options.isInteractive && !options.verbose;
  let activeSpinner: SpinnerLike | null = null;

  const runningText = (label: string) => `${label}...`;
  const infoText = (step: StepEvent) =>
    step.detail ? `${step.label}: ${step.detail}` : step.label;
  const successText = (step: StepEvent) =>
    step.detail
      ? `${step.label} complete (${step.detail})`
      : `${step.label} complete`;
  const failureText = (label: string) => `${label} failed`;

  return {
    start(step) {
      if (!useSpinner) {
        options.write(`${runningText(step.label)}\n`);
        return;
      }

      activeSpinner = createSpinner(runningText(step.label), options.color);
      activeSpinner.start();
    },

    complete(step) {
      if (!useSpinner) {
        return;
      }

      activeSpinner?.succeed(successText(step));
      activeSpinner = null;
    },

    fail(step) {
      if (!useSpinner) {
        return;
      }

      activeSpinner?.fail(failureText(step.label));
      activeSpinner = null;
    },

    info(step) {
      options.write(`${infoText(step)}\n`);
    },
  };
}
