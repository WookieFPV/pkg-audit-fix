import { describe, expect, it, vi } from "vitest";

import { runAuditFix } from "../src/core/run.js";
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
        detectManager: async () => ({ manager: "pnpm", source: "filesystem" }),
        exec,
      },
    );

    expect(steps).toEqual(["Initial audit", "Final audit"]);
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
        detectManager: async () => ({ manager: "pnpm", source: "override" }),
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
        detectManager: async () => ({ manager: "npm", source: "override" }),
        exec,
      },
    );

    expect(exec).toHaveBeenCalledOnce();
    expect(result.exitCode).toBe(0);
    expect(result.status).toBe("clean");
    expect(result.dedupeRan).toBe(false);
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
        detectManager: async () => ({ manager: "pnpm", source: "override" }),
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
        detectManager: async () => ({ manager: "npm", source: "override" }),
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
        detectManager: async () => ({ manager: "bun", source: "override" }),
        exec,
      },
    );

    expect(steps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Recheck after fixes",
    ]);
    expect(result.dedupeRan).toBe(false);
  });
});
