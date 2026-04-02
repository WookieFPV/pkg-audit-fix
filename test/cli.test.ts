import fs from "node:fs";
import path from "node:path";

import { beforeEach, describe, expect, it, vi } from "vitest";

const runAuditFix = vi.fn();

vi.mock("../src/core/run.js", () => ({
  runAuditFix,
}));

function setIsTTY(
  stream: NodeJS.ReadStream | NodeJS.WriteStream,
  value: boolean | undefined,
): void {
  if (value === undefined) {
    delete (stream as { isTTY?: boolean }).isTTY;
    return;
  }

  Object.defineProperty(stream, "isTTY", {
    configurable: true,
    enumerable: true,
    value,
    writable: true,
  });
}

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

  it("does not install the pnpm confirmation prompt on stdout in json mode", async () => {
    const stdoutWrite = vi
      .spyOn(process.stdout, "write")
      .mockImplementation(() => true);
    const stderrWrite = vi
      .spyOn(process.stderr, "write")
      .mockImplementation(() => true);
    const originalStdinIsTTY = process.stdin.isTTY;
    const originalStdoutIsTTY = process.stdout.isTTY;
    const originalStderrIsTTY = process.stderr.isTTY;
    const cli = await import("../src/cli.js");

    setIsTTY(process.stdin, true);
    setIsTTY(process.stdout, true);
    setIsTTY(process.stderr, false);

    try {
      const exitCode = await cli.main(["--json"]);
      const [, dependencies] = runAuditFix.mock.calls[0] as [
        unknown,
        {
          confirmPnpmMinimumReleaseAgeExclusions?: unknown;
        },
      ];

      expect(exitCode).toBe(0);
      expect(
        dependencies.confirmPnpmMinimumReleaseAgeExclusions,
      ).toBeUndefined();
    } finally {
      setIsTTY(process.stdin, originalStdinIsTTY);
      setIsTTY(process.stdout, originalStdoutIsTTY);
      setIsTTY(process.stderr, originalStderrIsTTY);
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
});
