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
          stdout: '["left-pad@1.0.0"]',
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      if (step.label === "Update pnpm minimumReleaseAgeExclude") {
        expect(step.args).toEqual([
          "config",
          "set",
          "--location=project",
          "--json",
          "minimumReleaseAgeExclude",
          '["left-pad@1.0.0","lodash@4.18.1","chalk@5.4.0"]',
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
      "Apply fixes",
      "Reinstall dependencies",
      "Read pnpm minimumReleaseAgeExclude",
      "Update pnpm minimumReleaseAgeExclude",
      "Reinstall dependencies",
      "Final audit",
    ]);
    expect(startedSteps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Reinstall dependencies",
      "Update pnpm minimumReleaseAgeExclude",
      "Final audit",
    ]);
    expect(completedSteps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Update pnpm minimumReleaseAgeExclude",
      "Reinstall dependencies",
      "Final audit",
    ]);
    expect(reinstallAttempts).toBe(2);
    expect(result.fixedCount).toBe(3);
    expect(result.remainingCount).toBe(0);
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

  it("retries bun update after adding too-new packages to minimumReleaseAgeExcludes", async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-audit-fix-bun-"));
    const steps: string[] = [];
    let remediationAttempts = 0;
    const confirmPnpmMinimumReleaseAgeExclusions = vi.fn(async () => true);
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

      if (step.label === "Apply fixes") {
        if (remediationAttempts === 0) {
          remediationAttempts += 1;
          throw new CommandExecutionError(
            step,
            {
              command: step.command,
              args: step.args,
              stdout: "",
              stderr: [
                "error: minimum-release-age prevented resolving fresh releases",
                'error: No version matching "5.4.0" found for specifier "chalk" (but package exists)',
              ].join("\n"),
              exitCode: 1,
              signal: null,
            },
            "Process exited with code 1",
          );
        }

        remediationAttempts += 1;
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
          stdout: readFixture("bun", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    fs.writeFileSync(
      path.join(cwd, "bunfig.toml"),
      '[install]\nminimumReleaseAgeExcludes = ["left-pad"]\n',
      "utf8",
    );

    try {
      const result = await runAuditFix(
        {
          cwd,
          manager: "bun",
          scope: "all",
          threshold: "moderate",
          dedupe: "never",
          dryRun: false,
          verbose: false,
        },
        {
          confirmPnpmMinimumReleaseAgeExclusions,
          detectManager: async () => ({
            manager: "bun",
            agent: "bun",
            source: "override",
          }),
          exec,
        },
      );

      expect(confirmPnpmMinimumReleaseAgeExclusions).toHaveBeenCalledWith({
        manager: "bun",
        configSetting: "minimumReleaseAgeExcludes",
        packages: ["chalk"],
      });
      expect(steps).toEqual([
        "Initial audit",
        "Apply fixes",
        "Apply fixes",
        "Final audit",
      ]);
      expect(remediationAttempts).toBe(2);
      expect(fs.readFileSync(path.join(cwd, "bunfig.toml"), "utf8")).toContain(
        'minimumReleaseAgeExcludes = ["left-pad", "chalk"]',
      );
      expect(result.fixedCount).toBe(2);
      expect(result.remainingCount).toBe(0);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it("retries bun update after minimum-age blocks direct and transitive packages", async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-audit-fix-bun-"));
    const steps: string[] = [];
    let remediationAttempts = 0;
    const confirmPnpmMinimumReleaseAgeExclusions = vi.fn(async () => true);
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

      if (step.label === "Apply fixes") {
        if (remediationAttempts === 0) {
          remediationAttempts += 1;
          throw new CommandExecutionError(
            step,
            {
              command: step.command,
              args: step.args,
              stdout: "bun update v1.3.11 (af24e281)\n",
              stderr: [
                "Resolving dependencies",
                "Resolved, downloaded and extracted [4]",
                'error: No version matching "brace-expansion" found for specifier "^1.1.13" (all versions blocked by minimum-release-age)',
                "",
                'error: No version matching "typescript" found for specifier "6.0.2" (blocked by minimum-release-age: 2592000 seconds)',
                "error: typescript@6.0.2 failed to resolve",
              ].join("\n"),
              exitCode: 1,
              signal: null,
            },
            "Process exited with code 1",
          );
        }

        remediationAttempts += 1;
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
          stdout: readFixture("bun", "after.json"),
          stderr: "",
          exitCode: 0,
          signal: null,
        };
      }

      throw new Error(`Unexpected step: ${step.label}`);
    });

    fs.writeFileSync(
      path.join(cwd, "bunfig.toml"),
      "[install]\nminimumReleaseAge = 2592000\n",
      "utf8",
    );

    try {
      const result = await runAuditFix(
        {
          cwd,
          manager: "bun",
          scope: "all",
          threshold: "moderate",
          dedupe: "never",
          dryRun: false,
          verbose: false,
        },
        {
          confirmPnpmMinimumReleaseAgeExclusions,
          detectManager: async () => ({
            manager: "bun",
            agent: "bun",
            source: "override",
          }),
          exec,
        },
      );

      expect(confirmPnpmMinimumReleaseAgeExclusions).toHaveBeenCalledWith({
        manager: "bun",
        configSetting: "minimumReleaseAgeExcludes",
        packages: ["brace-expansion", "typescript"],
      });
      expect(steps).toEqual([
        "Initial audit",
        "Apply fixes",
        "Apply fixes",
        "Final audit",
      ]);
      expect(remediationAttempts).toBe(2);
      expect(fs.readFileSync(path.join(cwd, "bunfig.toml"), "utf8")).toContain(
        'minimumReleaseAgeExcludes = ["brace-expansion", "typescript"]',
      );
      expect(result.fixedCount).toBe(2);
      expect(result.remainingCount).toBe(0);
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
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

  it("does not attempt dedupe for managers without dedupe support", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("bun", "before.json"),
      "Apply fixes": "",
      "Recheck after fixes": readFixture("bun", "after.json"),
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

    expect(steps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Recheck after fixes",
    ]);
    expect(result.dedupeRan).toBe(false);
    expect(result.stepFixes).toEqual([
      {
        label: "Apply fixes",
        fixedCount: 2,
        remainingCount: 0,
      },
    ]);
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
