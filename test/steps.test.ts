import { describe, expect, it, vi } from "vitest";

import { createStepLifecycleReporter } from "../src/reporters/steps.js";

describe("createStepLifecycleReporter", () => {
  it("writes plain step lines when not interactive", () => {
    const writes: string[] = [];
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: false,
      showCommands: false,
      isInteractive: false,
      write: (text) => {
        writes.push(text);
      },
    });

    reporter.start({ label: "Initial audit", command: ["pnpm", "audit"] });
    reporter.complete({ label: "Initial audit", command: ["pnpm", "audit"] });

    expect(writes).toEqual(["Auditing dependencies...\n"]);
    expect(reporter.hasOutput()).toBe(true);
  });

  it("uses a spinner for interactive non-verbose runs", () => {
    const spinner = {
      start: vi.fn(),
      succeed: vi.fn(),
      fail: vi.fn(),
      stop: vi.fn(),
    };
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: false,
      verbose: false,
      showCommands: false,
      isInteractive: true,
      write: vi.fn(),
      createSpinner: vi.fn(() => spinner),
    });

    reporter.start({ label: "Final audit", command: ["npm", "audit"] });
    reporter.complete({ label: "Final audit", command: ["npm", "audit"] });

    expect(spinner.start).toHaveBeenCalledOnce();
    expect(spinner.succeed).toHaveBeenCalledWith(
      "Checked remaining vulnerabilities",
    );
    expect(reporter.hasOutput()).toBe(true);
  });

  it("stops the active spinner when paused for an interactive prompt", () => {
    const spinner = {
      start: vi.fn(),
      succeed: vi.fn(),
      fail: vi.fn(),
      stop: vi.fn(),
    };
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: false,
      verbose: false,
      showCommands: false,
      isInteractive: true,
      write: vi.fn(),
      createSpinner: vi.fn(() => spinner),
    });

    reporter.start({
      label: "Reinstall dependencies",
      command: ["pnpm", "install"],
    });
    reporter.pause();

    expect(spinner.stop).toHaveBeenCalledOnce();
  });

  it("writes a completion line for a paused step after the prompt flow finishes", () => {
    const writes: string[] = [];
    const reinstallSpinner = {
      start: vi.fn(),
      succeed: vi.fn(),
      fail: vi.fn(),
      stop: vi.fn(),
    };
    const updateSpinner = {
      start: vi.fn(),
      succeed: vi.fn(),
      fail: vi.fn(),
      stop: vi.fn(),
    };
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: false,
      verbose: false,
      showCommands: false,
      isInteractive: true,
      write: (text) => {
        writes.push(text);
      },
      createSpinner: vi
        .fn()
        .mockReturnValueOnce(reinstallSpinner)
        .mockReturnValueOnce(updateSpinner),
    });

    reporter.start({
      label: "Reinstall dependencies",
      command: ["pnpm", "install"],
    });
    reporter.pause();
    reporter.start({
      label: "Update pnpm minimumReleaseAgeExclude: added 2 new entries",
      command: ["pnpm", "config", "set"],
    });
    reporter.complete({
      label: "Update pnpm minimumReleaseAgeExclude: added 2 new entries",
      command: ["pnpm", "config", "set"],
    });
    reporter.complete({
      label: "Reinstall dependencies",
      command: ["pnpm", "install"],
    });

    expect(reinstallSpinner.stop).toHaveBeenCalledOnce();
    expect(updateSpinner.succeed).toHaveBeenCalledWith(
      "Updated pnpm minimumReleaseAge exclusions (added 2 new entries)",
    );
    expect(writes).toEqual(["✔ Reinstalled dependencies\n"]);
  });

  it("prints a dedicated cleanup message for pnpm minimumReleaseAge exclusions", () => {
    const writes: string[] = [];
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: false,
      showCommands: false,
      isInteractive: false,
      write: (text) => {
        writes.push(text);
      },
    });

    reporter.start({
      label: "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      command: ["pnpm", "config", "set"],
    });

    expect(writes).toEqual(["Cleaning pnpm minimumReleaseAge exclusions...\n"]);
  });

  it("does not use a spinner in verbose mode", () => {
    const writes: string[] = [];
    const createSpinner = vi.fn();
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: true,
      showCommands: false,
      isInteractive: true,
      write: (text) => {
        writes.push(text);
      },
      createSpinner,
    });

    reporter.start({ label: "Apply fixes", command: ["bun", "update"] });
    reporter.fail({ label: "Apply fixes", command: ["bun", "update"] });

    expect(writes).toEqual(["Applying available fixes...\n"]);
    expect(createSpinner).not.toHaveBeenCalled();
  });

  it("prints the command before the step when enabled", () => {
    const writes: string[] = [];
    const reporter = createStepLifecycleReporter({
      enabled: true,
      color: true,
      verbose: false,
      showCommands: true,
      isInteractive: false,
      write: (text) => {
        writes.push(text);
      },
    });

    reporter.start({
      label: "Initial audit",
      command: ["pnpm", "audit", "--filter", "@scope/pkg with space"],
    });

    expect(writes).toEqual([
      "$ pnpm audit --filter '@scope/pkg with space'\n",
      "Auditing dependencies...\n",
    ]);
  });
});
