import fs from "node:fs";
import path from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

const createAuditSession = vi.fn();
const runAuditFix = vi.fn();

vi.mock("../src/core/run.js", () => ({
  createAuditSession,
  runAuditFix,
}));

describe("cli defaults", () => {
  beforeEach(() => {
    createAuditSession.mockReset();
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

  it("prints commands when --show-commands is enabled", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main(["--show-commands"]);
      const [, dependencies] = runAuditFix.mock.calls[0] as [
        unknown,
        {
          hooks: {
            onStepStart: (step: { label: string; command: string[] }) => void;
          };
        },
      ];

      dependencies.hooks.onStepStart({
        label: "Initial audit",
        command: ["pnpm", "audit", "--json"],
      });

      expect(exitCode).toBe(0);
      expect(stdoutWrite).toHaveBeenCalledWith("$ pnpm audit --json\n");
      expect(stdoutWrite).toHaveBeenCalledWith("Initial audit...\n");
    } finally {
      stdoutWrite.mockRestore();
    }
  });

  it("supports -d as an alias for --debug and prints the detected package manager", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main(["-d"]);
      const [, dependencies] = runAuditFix.mock.calls[0] as [
        unknown,
        {
          onManagerDetected: (detection: {
            manager: string;
            agent: string;
            source: string;
          }) => void;
          hooks: {
            onStepStart: (step: { label: string; command: string[] }) => void;
          };
        },
      ];

      dependencies.onManagerDetected({
        manager: "pnpm",
        agent: "pnpm",
        source: "filesystem",
      });
      dependencies.hooks.onStepStart({
        label: "Initial audit",
        command: ["pnpm", "audit", "--json"],
      });

      expect(exitCode).toBe(0);
      expect(stdoutWrite).toHaveBeenCalledWith(
        "Detected package manager: pnpm\n",
      );
      expect(stdoutWrite).toHaveBeenCalledWith("$ pnpm audit --json\n");
    } finally {
      stdoutWrite.mockRestore();
    }
  });

  it("writes debug output to stderr when --json is enabled", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const stderrWrite = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main(["--json", "--debug"]);
      const [, dependencies] = runAuditFix.mock.calls[0] as [
        unknown,
        {
          onManagerDetected: (detection: {
            manager: string;
            agent: string;
            source: string;
          }) => void;
          hooks: {
            onStepStart: (step: { label: string; command: string[] }) => void;
          };
        },
      ];

      dependencies.onManagerDetected({
        manager: "pnpm",
        agent: "pnpm",
        source: "filesystem",
      });
      dependencies.hooks.onStepStart({
        label: "Initial audit",
        command: ["pnpm", "audit", "--json"],
      });

      expect(exitCode).toBe(0);
      expect(stderrWrite).toHaveBeenCalledWith(
        "Detected package manager: pnpm\n",
      );
      expect(stderrWrite).toHaveBeenCalledWith("$ pnpm audit --json\n");
      expect(stdoutWrite).toHaveBeenCalledWith(
        `${JSON.stringify(
          {
            manager: "pnpm",
            detectionSource: "filesystem",
            threshold: "low",
            scope: "all",
            dedupe: "auto",
            dedupeRan: false,
            dryRun: false,
            status: "clean",
            stepFixes: [],
            fixedCount: 0,
            remainingCount: 0,
            exitCode: 0,
            fixed: [],
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
          },
          null,
          2,
        )}\n`,
      );
    } finally {
      stdoutWrite.mockRestore();
      stderrWrite.mockRestore();
    }
  });

  it("writes command tracing to stderr for --json --show-commands", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const stderrWrite = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const cli = await import("../src/cli.js");

    try {
      const exitCode = await cli.main(["--json", "--show-commands"]);
      const [, dependencies] = runAuditFix.mock.calls[0] as [
        unknown,
        {
          hooks: {
            onStepStart: (step: { label: string; command: string[] }) => void;
          };
        },
      ];

      dependencies.hooks.onStepStart({
        label: "Initial audit",
        command: ["pnpm", "audit", "--json"],
      });

      expect(exitCode).toBe(0);
      expect(stderrWrite).toHaveBeenCalledWith("$ pnpm audit --json\n");
      expect(stderrWrite).toHaveBeenCalledWith("Initial audit...\n");
      expect(stdoutWrite).toHaveBeenCalledWith(
        `${JSON.stringify(
          {
            manager: "pnpm",
            detectionSource: "filesystem",
            threshold: "low",
            scope: "all",
            dedupe: "auto",
            dedupeRan: false,
            dryRun: false,
            status: "clean",
            stepFixes: [],
            fixedCount: 0,
            remainingCount: 0,
            exitCode: 0,
            fixed: [],
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
          },
          null,
          2,
        )}\n`,
      );
    } finally {
      stdoutWrite.mockRestore();
      stderrWrite.mockRestore();
    }
  });

  it("runs manual mode through the interactive session loop", async () => {
    const write = vi.fn(() => true);
    const session = {
      manager: "pnpm",
      detectionSource: "override",
      initial: {
        manager: "pnpm",
        threshold: "low",
        scope: "all",
        total: 3,
        counts: { low: 0, moderate: 3, high: 0, critical: 0, total: 3 },
        entries: [],
      },
      current: {
        manager: "pnpm",
        threshold: "low",
        scope: "all",
        total: 0,
        counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        entries: [],
      },
      supportsRemediation: true,
      supportsDedupe: true,
      auditCurrent: vi.fn().mockResolvedValue({
        before: {
          manager: "pnpm",
          threshold: "low",
          scope: "all",
          total: 3,
          counts: { low: 0, moderate: 3, high: 0, critical: 0, total: 3 },
          entries: [],
        },
        after: {
          manager: "pnpm",
          threshold: "low",
          scope: "all",
          total: 0,
          counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
          entries: [],
        },
        fixedCount: 3,
        remainingCount: 0,
      }),
      applyFixes: vi.fn(),
      dedupe: vi.fn(),
      toResult: vi.fn().mockReturnValue({
        manager: "pnpm",
        detectionSource: "override",
        threshold: "low",
        scope: "all",
        dedupe: "auto",
        initial: {
          manager: "pnpm",
          threshold: "low",
          scope: "all",
          total: 3,
          counts: { low: 0, moderate: 3, high: 0, critical: 0, total: 3 },
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
        fixedCount: 3,
        remainingCount: 0,
        fixed: [],
        exitCode: 0,
        status: "resolved-some",
        dryRun: false,
        dedupeRan: false,
        stepFixes: [],
      }),
    };
    createAuditSession.mockResolvedValue(session);
    const selectManualAction = vi.fn().mockResolvedValue("E");
    const cli = await import("../src/cli.js");

    const exitCode = await cli.main(["--manual"], {
      selectManualAction,
      stdin: { isTTY: true },
      stdout: {
        isTTY: true,
        write,
      },
    });

    expect(exitCode).toBe(0);
    expect(createAuditSession).toHaveBeenCalledOnce();
    expect(runAuditFix).not.toHaveBeenCalled();
    expect(selectManualAction).toHaveBeenCalledOnce();
    expect(session.auditCurrent).toHaveBeenCalledWith("Final audit");
    expect(session.toResult).toHaveBeenCalledWith({
      dedupe: "auto",
      dryRun: false,
    });
    expect(write).toHaveBeenCalled();
  });

  it("hides unsupported manual actions and reletters the menu sequentially", async () => {
    vi.resetModules();
    const write = vi.fn(() => true);
    const session = {
      manager: "yarn",
      detectionSource: "override",
      initial: {
        manager: "yarn",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
        entries: [],
      },
      current: {
        manager: "yarn",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
        entries: [],
      },
      supportsRemediation: false,
      supportsDedupe: false,
      auditCurrent: vi.fn().mockResolvedValue({
        before: {
          manager: "yarn",
          threshold: "low",
          scope: "all",
          total: 2,
          counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
          entries: [],
        },
        after: {
          manager: "yarn",
          threshold: "low",
          scope: "all",
          total: 2,
          counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
          entries: [],
        },
        fixedCount: 0,
        remainingCount: 2,
      }),
      applyFixes: vi.fn(),
      dedupe: vi.fn(),
      toResult: vi.fn().mockReturnValue({
        manager: "yarn",
        detectionSource: "override",
        threshold: "low",
        scope: "all",
        dedupe: "auto",
        initial: {
          manager: "yarn",
          threshold: "low",
          scope: "all",
          total: 2,
          counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
          entries: [],
        },
        final: {
          manager: "yarn",
          threshold: "low",
          scope: "all",
          total: 2,
          counts: { low: 0, moderate: 2, high: 0, critical: 0, total: 2 },
          entries: [],
        },
        fixedCount: 0,
        remainingCount: 2,
        fixed: [],
        exitCode: 2,
        status: "no-change",
        dryRun: false,
        dedupeRan: false,
        stepFixes: [],
      }),
    };
    createAuditSession.mockResolvedValue(session);
    vi.doMock("node:readline/promises", () => ({
      createInterface: () => ({
        question: vi.fn().mockResolvedValue("C"),
        close: vi.fn(),
      }),
    }));

    try {
      const cli = await import("../src/cli.js");

      const exitCode = await cli.main(["--manual"], {
        stdin: { isTTY: true },
        stdout: {
          isTTY: true,
          write,
        },
      });

      expect(exitCode).toBe(2);
      expect(write).toHaveBeenCalledWith(
        "Choose an action:\n  A. print result\n  B. list all vulnerabilities\n  C. finish\n",
      );
      expect(write).not.toHaveBeenCalledWith(
        expect.stringContaining("unsupported"),
      );
    } finally {
      vi.doUnmock("node:readline/promises");
      vi.resetModules();
    }
  });

  it("rejects --manual when stdout is not a tty", async () => {
    const cli = await import("../src/cli.js");

    await expect(
      cli.main(["--manual"], {
        stdin: { isTTY: true },
        stdout: {
          isTTY: false,
          write: vi.fn(() => true),
        },
      }),
    ).rejects.toThrow("--manual requires an interactive terminal");
  });
});
