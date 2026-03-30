import { describe, expect, it, vi } from "vitest";

import { createStepLifecycleReporter } from "../src/reporters/steps.js";

describe("createStepLifecycleReporter", () => {
  it("writes plain step lines when not interactive", () => {
    const writes: string[] = [];
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: false,
      isInteractive: false,
      write: (text) => {
        writes.push(text);
      },
    });

    reporter.start({ label: "initial audit", command: ["pnpm", "audit"] });
    reporter.complete({ label: "initial audit", command: ["pnpm", "audit"] });

    expect(writes).toEqual(["Running: initial audit\n"]);
  });

  it("uses a spinner for interactive non-verbose runs", () => {
    const spinner = {
      start: vi.fn(),
      succeed: vi.fn(),
      fail: vi.fn(),
    };
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: false,
      verbose: false,
      isInteractive: true,
      write: vi.fn(),
      createSpinner: vi.fn(() => spinner),
    });

    reporter.start({ label: "final audit", command: ["npm", "audit"] });
    reporter.complete({ label: "final audit", command: ["npm", "audit"] });

    expect(spinner.start).toHaveBeenCalledOnce();
    expect(spinner.succeed).toHaveBeenCalledWith("Running: final audit");
  });

  it("does not use a spinner in verbose mode", () => {
    const writes: string[] = [];
    const createSpinner = vi.fn();
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: true,
      isInteractive: true,
      write: (text) => {
        writes.push(text);
      },
      createSpinner,
    });

    reporter.start({ label: "remediation", command: ["bun", "update"] });
    reporter.fail({ label: "remediation", command: ["bun", "update"] });

    expect(writes).toEqual(["Running: remediation\n"]);
    expect(createSpinner).not.toHaveBeenCalled();
  });
});
