import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { runAuditFix } from "../src/core/run.js";
import {
  CommandExecutionError,
  type MinimumReleaseAgeDeclinedError,
} from "../src/core/types.js";
import { readFixture } from "./helpers.js";

describe("runAuditFix", () => {
  it("runs dry-run with only audits and returns remaining vulnerabilities", async () => {
    const steps: string[] = [];
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: readFixture("pnpm", "before.json"),
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "auto",
        scope: "all",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: true,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "pnpm",
          agent: "pnpm",
          source: "filesystem",
        }),
        exec,
      },
    );

    expect(steps).toEqual(["Initial audit", "Final audit"]);
    expect(result.stepFixes).toEqual([]);
    expect(result.fixedCount).toBe(0);
    expect(result.remainingCount).toBe(3);
    expect(result.exitCode).toBe(2);
    expect(result.status).toBe("no-change");
  });

  it("runs remediation and post-install steps when the adapter needs them", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("pnpm", "before.json"),
      "Apply fixes": readFixture("pnpm", "before.json"),
      "Reinstall dependencies": "",
      "Final audit": readFixture("pnpm", "after.json"),
    };
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: stdoutByStep[step.label] ?? "",
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "pnpm",
        scope: "prod",
        threshold: "moderate",
        dedupe: "never",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "pnpm",
          agent: "pnpm",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual([
      "Initial audit",
      "Read pnpm minimumReleaseAgeExclude",
      "Apply fixes",
      "Reinstall dependencies",
      "Final audit",
    ]);
    expect(result.fixedCount).toBe(3);
    expect(result.remainingCount).toBe(0);
    expect(result.exitCode).toBe(0);
    expect(result.status).toBe("resolved-some");
    expect(result.dedupeRan).toBe(false);
    expect(result.stepFixes).toEqual([
      {
        label: "Apply fixes",
        fixedCount: 3,
        remainingCount: 0,
      },
    ]);
  });

  it("retries pnpm install after adding too-new packages to minimumReleaseAgeExclude", async () => {
    const steps: string[] = [];
    const startedSteps: string[] = [];
    const completedSteps: string[] = [];
    let reinstallAttempts = 0;
    let currentPnpmMinimumReleaseAgeExclude = '["left-pad@1.0.0"]';
    const stalePublishedAt = new Date(
      Date.now() - 40 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const confirmPnpmMinimumReleaseAgeExclusions = vi.fn(async () => true);
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      if (step.label === "Initial audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "before.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Apply fixes") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "before.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Reinstall dependencies") {
        if (reinstallAttempts === 0) {
          reinstallAttempts += 1;
          throw new CommandExecutionError(
            step,
            {
              command: step.command,
              args: step.args,
              stdout: "",
              stderr: [
                JSON.stringify({
                  name: "pnpm",
                  code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
                  immatureVersion: "4.18.1",
                  package: {
                    name: "lodash",
                    version: ">=4.18.0",
                  },
                }),
                JSON.stringify({
                  name: "pnpm",
                  code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
                  immatureVersion: "5.4.0",
                  package: {
                    name: "chalk",
                    version: "^5.4.0",
                  },
                }),
              ].join("\n"),
              exitCode: 1,
              signal: null,
            },
            "Process exited with code 1",
          );
        }

        reinstallAttempts += 1;
        return {
          command: step.command,
          args: step.args,
          stdout: "",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm minimumReleaseAgeExclude") {
        expect(step.args).toEqual([
          "config",
          "get",
          "--location=project",
          "--json",
          "minimumReleaseAgeExclude",
        ]);

        return {
          command: step.command,
          args: step.args,
          stdout: currentPnpmMinimumReleaseAgeExclude,
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm minimumReleaseAge") {
        expect(step.args).toEqual([
          "config",
          "get",
          "--json",
          "minimumReleaseAge",
        ]);

        return {
          command: step.command,
          args: step.args,
          stdout: "43200",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm package publish times") {
        expect(step.args).toEqual(["view", "left-pad", "time", "--json"]);

        return {
          command: step.command,
          args: step.args,
          stdout: JSON.stringify({
            "1.0.0": stalePublishedAt,
          }),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (
        step.label.startsWith("Update pnpm minimumReleaseAgeExclude") ||
        step.label.startsWith("Clean pnpm minimumReleaseAgeExclude")
      ) {
        const nextExclusions = step.args[5];

        expect(nextExclusions).toMatch(
          /^(?:\[\]|\\?\["lodash@4\.18\.1","chalk@5\.4\.0"\\?\])$/,
        );
        currentPnpmMinimumReleaseAgeExclude = nextExclusions;

        return {
          command: step.command,
          args: step.args,
          stdout: "",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Final audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "pnpm",
        scope: "prod",
        threshold: "moderate",
        dedupe: "never",
        dryRun: false,
        verbose: false,
      },
      {
        confirmPnpmMinimumReleaseAgeExclusions,
        detectManager: async () => ({
          manager: "pnpm",
          agent: "pnpm",
          source: "override",
        }),
        exec,
        hooks: {
          onStepStart: (step) => {
            startedSteps.push(step.label);
          },
          onStepComplete: (step) => {
            completedSteps.push(step.label);
          },
        },
      },
    );

    expect(confirmPnpmMinimumReleaseAgeExclusions).toHaveBeenCalledWith({
      manager: "pnpm",
      configSetting: "minimumReleaseAgeExclude",
      packages: ["lodash@4.18.1", "chalk@5.4.0"],
    });
    expect(steps).toEqual([
      "Initial audit",
      "Read pnpm minimumReleaseAgeExclude",
      "Read pnpm minimumReleaseAge",
      "Read pnpm package publish times",
      "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      "Apply fixes",
      "Reinstall dependencies",
      "Read pnpm minimumReleaseAgeExclude",
      "Update pnpm minimumReleaseAgeExclude: added 2 new entries",
      "Reinstall dependencies",
      "Final audit",
    ]);
    expect(startedSteps).toEqual([
      "Initial audit",
      "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      "Apply fixes",
      "Reinstall dependencies",
      "Update pnpm minimumReleaseAgeExclude: added 2 new entries",
      "Final audit",
    ]);
    expect(completedSteps).toEqual([
      "Initial audit",
      "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      "Apply fixes",
      "Update pnpm minimumReleaseAgeExclude: added 2 new entries",
      "Reinstall dependencies",
      "Final audit",
    ]);
    expect(reinstallAttempts).toBe(2);
    expect(result.fixedCount).toBe(3);
    expect(result.remainingCount).toBe(0);
  });

  it("validates pnpm minimumReleaseAgeExclude during normal runs and removes stale entries without requiring .npmrc", async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-audit-fix-pnpm-"));
    const steps: string[] = [];
    const startedSteps: string[] = [];
    const completedSteps: string[] = [];
    const stalePublishedAt = new Date(
      Date.now() - 40 * 24 * 60 * 60 * 1000,
    ).toISOString();
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      if (step.label === "Initial audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm minimumReleaseAgeExclude") {
        return {
          command: step.command,
          args: step.args,
          stdout: '["left-pad@1.0.0"]',
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm minimumReleaseAge") {
        return {
          command: step.command,
          args: step.args,
          stdout: "43200",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Read pnpm package publish times") {
        return {
          command: step.command,
          args: step.args,
          stdout: JSON.stringify({
            "1.0.0": stalePublishedAt,
          }),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label.startsWith("Clean pnpm minimumReleaseAgeExclude")) {
        expect(step.args).toEqual([
          "config",
          "set",
          "--location=project",
          "--json",
          "minimumReleaseAgeExclude",
          "[]",
        ]);

        return {
          command: step.command,
          args: step.args,
          stdout: "",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    fs.writeFileSync(
      path.join(cwd, "pnpm-workspace.yaml"),
      'packages:\n  - "."\nminimumReleaseAgeExclude:\n  - left-pad@1.0.0\n',
      "utf8",
    );

    try {
      const result = await runAuditFix(
        {
          cwd,
          manager: "pnpm",
          scope: "prod",
          threshold: "moderate",
          dedupe: "never",
          dryRun: false,
          verbose: false,
        },
        {
          detectManager: async () => ({
            manager: "pnpm",
            agent: "pnpm",
            source: "override",
          }),
          exec,
          hooks: {
            onStepStart: (step) => {
              startedSteps.push(step.label);
            },
            onStepComplete: (step) => {
              completedSteps.push(step.label);
            },
          },
        },
      );

      expect(steps).toEqual([
        "Initial audit",
        "Read pnpm minimumReleaseAgeExclude",
        "Read pnpm minimumReleaseAge",
        "Read pnpm package publish times",
        "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      ]);
      expect(startedSteps).toEqual([
        "Initial audit",
        "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      ]);
      expect(completedSteps).toEqual([
        "Initial audit",
        "Clean pnpm minimumReleaseAgeExclude: removed 1 unneeded entry",
      ]);
      expect(result.status).toBe("clean");
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it("fails with a concise minimumReleaseAge error when the prompt is declined", async () => {
    const confirmPnpmMinimumReleaseAgeExclusions = vi.fn(async () => false);
    const exec = vi.fn(async (step) => {
      if (step.label === "Initial audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "before.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Apply fixes") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("pnpm", "before.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Reinstall dependencies") {
        throw new CommandExecutionError(
          step,
          {
            command: step.command,
            args: step.args,
            stdout: "",
            stderr: JSON.stringify({
              name: "pnpm",
              code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
              immatureVersion: "4.18.1",
              package: {
                name: "lodash",
                version: ">=4.18.0",
              },
            }),
            exitCode: 1,
            signal: null,
          },
          "Process exited with code 1",
        );
      }

      if (step.label === "Read pnpm minimumReleaseAgeExclude") {
        return {
          command: step.command,
          args: step.args,
          stdout: "[]",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    try {
      await runAuditFix(
        {
          cwd: "/tmp/project",
          manager: "pnpm",
          scope: "prod",
          threshold: "moderate",
          dedupe: "never",
          dryRun: false,
          verbose: false,
        },
        {
          confirmPnpmMinimumReleaseAgeExclusions,
          detectManager: async () => ({
            manager: "pnpm",
            agent: "pnpm",
            source: "override",
          }),
          exec,
        },
      );
      throw new Error("Expected runAuditFix to reject");
    } catch (error) {
      const declinedError = error as MinimumReleaseAgeDeclinedError;

      expect(declinedError.name).toBe("MinimumReleaseAgeDeclinedError");
      expect(declinedError.packages).toEqual(["lodash@4.18.1"]);
      expect(declinedError.step.label).toBe("Reinstall dependencies");
    }
  });

  it("prompts for manual bun remediation and runs a final audit", async () => {
    const steps: string[] = [];
    const promptBunManualRemediation = vi.fn(async () => {});
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      if (step.label === "Initial audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("bun", "before.json"),
          stderr: "",
          exitCode: 1,
          signal: null,
        };
      }

      if (step.label === "Final audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("bun", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "bun",
        scope: "all",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        promptBunManualRemediation,
        detectManager: async () => ({
          manager: "bun",
          agent: "bun",
          source: "override",
        }),
        exec,
      },
    );

    expect(promptBunManualRemediation).toHaveBeenCalledWith({
      initial: expect.objectContaining({
        manager: "bun",
        total: 2,
      }),
    });
    expect(steps).toEqual(["Initial audit", "Final audit"]);
    expect(result.fixedCount).toBe(2);
    expect(result.remainingCount).toBe(0);
    expect(result.status).toBe("resolved-some");
  });

  it("short-circuits when the initial audit is already clean", async () => {
    const exec = vi.fn(async (step) => ({
      command: step.command,
      args: step.args,
      stdout: readFixture("npm", "after.json"),
      stderr: "",
      exitCode: 0,
      signal: null,
    }));

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "npm",
        scope: "prod",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "npm",
          agent: "npm",
          source: "override",
        }),
        exec,
      },
    );

    expect(exec).toHaveBeenCalledOnce();
    expect(result.exitCode).toBe(0);
    expect(result.status).toBe("clean");
    expect(result.dedupeRan).toBe(false);
    expect(result.stepFixes).toEqual([]);
  });

  it("runs a dedupe pass in auto mode when vulnerabilities remain after fixes", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("pnpm", "before.json"),
      "Apply fixes": readFixture("pnpm", "before.json"),
      "Reinstall dependencies": "",
      "Recheck after fixes": readFixture("pnpm", "before.json"),
      "Consolidate dependency tree": "",
      "Final audit": readFixture("pnpm", "after.json"),
    };
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: stdoutByStep[step.label] ?? "",
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "pnpm",
        scope: "prod",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "pnpm",
          agent: "pnpm",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual([
      "Initial audit",
      "Read pnpm minimumReleaseAgeExclude",
      "Apply fixes",
      "Reinstall dependencies",
      "Recheck after fixes",
      "Consolidate dependency tree",
      "Final audit",
    ]);
    expect(result.dedupeRan).toBe(true);
    expect(result.exitCode).toBe(0);
    expect(result.stepFixes).toEqual([
      {
        label: "Apply fixes",
        fixedCount: 0,
        remainingCount: 3,
      },
      {
        label: "Consolidate dependency tree",
        fixedCount: 3,
        remainingCount: 0,
      },
    ]);
  });

  it("skips dedupe in auto mode when fixes already clear the audit", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("npm", "before.json"),
      "Apply fixes": readFixture("npm", "before.json"),
      "Recheck after fixes": readFixture("npm", "after.json"),
    };
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: stdoutByStep[step.label] ?? "",
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "npm",
        scope: "prod",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "npm",
          agent: "npm",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Recheck after fixes",
    ]);
    expect(result.dedupeRan).toBe(false);
    expect(result.remainingCount).toBe(0);
    expect(result.stepFixes).toEqual([
      {
        label: "Apply fixes",
        fixedCount: 2,
        remainingCount: 0,
      },
    ]);
  });

  it("runs a final bun audit even without an interactive prompt", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("bun", "before.json"),
      "Final audit": readFixture("bun", "after.json"),
    };
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: stdoutByStep[step.label] ?? "",
        stderr: "",
        exitCode: 0,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "bun",
        scope: "all",
        threshold: "moderate",
        dedupe: "always",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "bun",
          agent: "bun",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual(["Initial audit", "Final audit"]);
    expect(result.dedupeRan).toBe(false);
    expect(result.stepFixes).toEqual([]);
  });

  it("does not re-audit when yarn classic has no fix or dedupe step", async () => {
    const steps: string[] = [];
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: readFixture("yarn-classic", "before.jsonl"),
        stderr: "",
        exitCode: 12,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "yarn",
        scope: "all",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "yarn",
          agent: "yarn",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual(["Initial audit"]);
    expect(result.fixedCount).toBe(0);
    expect(result.remainingCount).toBe(2);
    expect(result.dedupeRan).toBe(false);
    expect(result.status).toBe("no-change");
  });

  it("runs a dedupe pass for yarn berry when vulnerabilities remain", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("yarn-berry", "before.json"),
      "Recheck after fixes": readFixture("yarn-berry", "before.json"),
      "Consolidate dependency tree": "",
      "Final audit": readFixture("yarn-berry", "after.json"),
    };
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      return {
        command: step.command,
        args: step.args,
        stdout: stdoutByStep[step.label] ?? "",
        stderr: "",
        exitCode: step.label === "Consolidate dependency tree" ? 0 : 1,
        signal: null,
      };
    });

    const result = await runAuditFix(
      {
        cwd: "/tmp/project",
        manager: "yarn",
        scope: "all",
        threshold: "moderate",
        dedupe: "auto",
        dryRun: false,
        verbose: false,
      },
      {
        detectManager: async () => ({
          manager: "yarn",
          agent: "yarn@berry",
          source: "override",
        }),
        exec,
      },
    );

    expect(steps).toEqual([
      "Initial audit",
      "Recheck after fixes",
      "Consolidate dependency tree",
      "Final audit",
    ]);
    expect(result.dedupeRan).toBe(true);
    expect(result.stepFixes).toEqual([
      {
        label: "Consolidate dependency tree",
        fixedCount: 2,
        remainingCount: 0,
      },
    ]);
  });

  it("retries yarn berry dedupe after adding quarantined packages to npmPreapprovedPackages", async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-audit-fix-yarn-"));
    const steps: string[] = [];
    let dedupeAttempts = 0;
    const confirmPnpmMinimumReleaseAgeExclusions = vi.fn(async () => true);
    const exec = vi.fn(async (step) => {
      steps.push(step.label);

      if (step.label === "Initial audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("yarn-berry", "before.json"),
          stderr: "",
          exitCode: 1,
          signal: null,
        };
      }

      if (step.label === "Recheck after fixes") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("yarn-berry", "before.json"),
          stderr: "",
          exitCode: 1,
          signal: null,
        };
      }

      if (step.label === "Consolidate dependency tree") {
        if (dedupeAttempts === 0) {
          dedupeAttempts += 1;
          throw new CommandExecutionError(
            step,
            {
              command: step.command,
              args: step.args,
              stdout: "",
              stderr:
                '➤ YN0016: │ lodash@npm:4.17.21: All versions satisfying "4.17.21" are quarantined\n',
              exitCode: 1,
              signal: null,
            },
            "Process exited with code 1",
          );
        }

        dedupeAttempts += 1;
        return {
          command: step.command,
          args: step.args,
          stdout: "",
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Final audit") {
        return {
          command: step.command,
          args: step.args,
          stdout: readFixture("yarn-berry", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    fs.writeFileSync(
      path.join(cwd, ".yarnrc.yml"),
      'npmMinimalAgeGate: "3d"\nnpmPreapprovedPackages:\n  - "left-pad@1.0.0"\n',
      "utf8",
    );

    try {
      const result = await runAuditFix(
        {
          cwd,
          manager: "yarn",
          scope: "all",
          threshold: "moderate",
          dedupe: "always",
          dryRun: false,
          verbose: false,
        },
        {
          confirmPnpmMinimumReleaseAgeExclusions,
          detectManager: async () => ({
            manager: "yarn",
            agent: "yarn@berry",
            source: "override",
          }),
          exec,
        },
      );

      expect(confirmPnpmMinimumReleaseAgeExclusions).toHaveBeenCalledWith({
        manager: "yarn",
        configSetting: "npmPreapprovedPackages",
        packages: ["lodash@4.17.21"],
      });
      expect(steps).toEqual([
        "Initial audit",
        "Recheck after fixes",
        "Consolidate dependency tree",
        "Consolidate dependency tree",
        "Final audit",
      ]);
      expect(dedupeAttempts).toBe(2);
      expect(fs.readFileSync(path.join(cwd, ".yarnrc.yml"), "utf8")).toContain(
        '  - "lodash@4.17.21"',
      );
      expect(result.fixedCount).toBe(2);
      expect(result.remainingCount).toBe(0);
      expect(result.stepFixes).toEqual([
        {
          label: "Consolidate dependency tree",
          fixedCount: 2,
          remainingCount: 0,
        },
      ]);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });
});
