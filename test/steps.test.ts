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

    reporter.start({ label: "Initial audit", command: ["pnpm", "audit"] });
    reporter.complete({ label: "Initial audit", command: ["pnpm", "audit"] });

    expect(writes).toEqual(["Initial audit...\n"]);
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

    reporter.start({ label: "Final audit", command: ["npm", "audit"] });
    reporter.complete({ label: "Final audit", command: ["npm", "audit"] });

    expect(spinner.start).toHaveBeenCalledOnce();
    expect(spinner.succeed).toHaveBeenCalledWith("Final audit complete");
  });

  it("writes step detail lines", () => {
    const writes: string[] = [];
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: false,
      isInteractive: true,
      write: (text) => {
        writes.push(text);
      },
    });

    reporter.info({
      label: "Apply fixes",
      command: [],
      detail: "fixed 3 vulnerabilities",
    });

    expect(writes).toEqual(["Apply fixes: fixed 3 vulnerabilities\n"]);
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

    reporter.start({ label: "Apply fixes", command: ["bun", "update"] });
    reporter.fail({ label: "Apply fixes", command: ["bun", "update"] });

    expect(writes).toEqual(["Apply fixes...\n"]);
    expect(createSpinner).not.toHaveBeenCalled();
  });
});
