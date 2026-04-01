import { describe, expect, it, vi } from "vitest";

import { createAuditSession, runAuditFix } from "../src/core/run.js";
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
});

describe("createAuditSession", () => {
  it("tracks manual audit refreshes without creating step fix entries", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("npm", "before.json"),
      "Refresh audit": readFixture("npm", "after.json"),
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

    const session = await createAuditSession(
      {
        cwd: "/tmp/project",
        manager: "npm",
        scope: "all",
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

    const outcome = await session.auditCurrent("Refresh audit");
    const result = session.toResult({ dedupe: "auto", dryRun: false });

    expect(steps).toEqual(["Initial audit", "Refresh audit"]);
    expect(outcome.fixedCount).toBe(2);
    expect(outcome.remainingCount).toBe(0);
    expect(result.stepFixes).toEqual([]);
    expect(result.fixedCount).toBe(2);
    expect(result.remainingCount).toBe(0);
    expect(result.status).toBe("resolved-some");
  });

  it("allows repeated manual fix actions and accumulates their impact", async () => {
    const steps: string[] = [];
    const stdoutByStep: Record<string, string> = {
      "Initial audit": readFixture("pnpm", "before.json"),
      "Apply fixes": readFixture("pnpm", "before.json"),
      "Reinstall dependencies": "",
      "Recheck after fixes": readFixture("pnpm", "before.json"),
      "Consolidate dependency tree": "",
      "Recheck after dedupe": readFixture("pnpm", "after.json"),
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

    const session = await createAuditSession(
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

    const fixOutcome = await session.applyFixes({
      auditLabel: "Recheck after fixes",
    });
    const dedupeOutcome = await session.dedupe({
      auditLabel: "Recheck after dedupe",
    });
    const result = session.toResult({ dedupe: "auto", dryRun: false });

    expect(steps).toEqual([
      "Initial audit",
      "Apply fixes",
      "Reinstall dependencies",
      "Recheck after fixes",
      "Consolidate dependency tree",
      "Recheck after dedupe",
    ]);
    expect(fixOutcome).not.toBeNull();
    expect(dedupeOutcome).not.toBeNull();
    expect(fixOutcome?.fixedCount).toBe(0);
    expect(dedupeOutcome?.fixedCount).toBe(3);
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
    expect(result.fixedCount).toBe(3);
    expect(result.remainingCount).toBe(0);
  });
});
