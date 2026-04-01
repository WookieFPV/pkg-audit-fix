import fs from "node:fs";
import path from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

const runAuditFix = vi.fn();

vi.mock("../src/core/run.js", () => ({
  runAuditFix,
}));

describe("cli defaults", () => {
  beforeEach(() => {
    runAuditFix.mockReset();
    runAuditFix.mockResolvedValue({
      manager: "pnpm",
      detectionSource: "filesystem",
      threshold: "low",
      scope: "all",
      dedupe: "auto",
      initial: {
        manager: "pnpm",
        threshold: "low",
        scope: "all",
        total: 0,
        counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        entries: [],
      },
      final: {
        manager: "pnpm",
        threshold: "low",
        scope: "all",
        total: 0,
        counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        entries: [],
      },
      fixedCount: 0,
      remainingCount: 0,
      fixed: [],
      exitCode: 0,
      status: "clean",
      dryRun: false,
      dedupeRan: false,
      stepFixes: [],
    });
  });

  it("defaults --audit-level to low", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main([]);

      expect(exitCode).toBe(0);
      expect(runAuditFix).toHaveBeenCalledWith(
        expect.objectContaining({ threshold: "low" }),
        expect.any(Object),
      );
    } finally {
      stdoutWrite.mockRestore();
    }
  });

  it("supports -v as an alias for --version", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");
    const packageJson = JSON.parse(
      fs.readFileSync(path.join(process.cwd(), "package.json"), "utf8"),
    ) as { version: string };

    try {
      const exitCode = await cli.main(["-v"]);

      expect(exitCode).toBe(0);
      expect(stdoutWrite).toHaveBeenCalledWith(`${packageJson.version}\n`);
      expect(runAuditFix).not.toHaveBeenCalled();
    } finally {
      stdoutWrite.mockRestore();
    }
  });

  it("accepts yarn as a manager override", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main(["--manager", "yarn"]);

      expect(exitCode).toBe(0);
      expect(runAuditFix).toHaveBeenCalledWith(
        expect.objectContaining({ manager: "yarn" }),
        expect.any(Object),
      );
    } finally {
      stdoutWrite.mockRestore();
    }
  });
});
