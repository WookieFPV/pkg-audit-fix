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
        scope: "prod",
        threshold: "moderate",
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
  });
});
