import process from "node:process";

import { describe, expect, it } from "vitest";

import { executeStep } from "../src/core/exec.js";
import { CommandExecutionError } from "../src/core/types.js";
import { repoRoot } from "./helpers.js";

describe("executeStep", () => {
  it("accepts audit-style exit code 1 when configured", async () => {
    const result = await executeStep(
      {
        label: "initial audit",
        command: process.execPath,
        args: ["-e", "console.log('{\"ok\":true}'); process.exit(1)"],
        acceptedExitCodes: [0, 1],
      },
      {
        cwd: repoRoot(),
        verbose: false,
      },
    );

    expect(result.exitCode).toBe(1);
    expect(result.stdout.trim()).toBe('{"ok":true}');
  });

  it("accepts any non-null exit code when configured for bitmask-style audits", async () => {
    const result = await executeStep(
      {
        label: "initial audit",
        command: process.execPath,
        args: ["-e", "console.log('{\"ok\":true}'); process.exit(12)"],
        acceptedExitCodes: "any",
      },
      {
        cwd: repoRoot(),
        verbose: false,
      },
    );

    expect(result.exitCode).toBe(12);
    expect(result.stdout.trim()).toBe('{"ok":true}');
  });

  it("rejects unexpected non-zero exits", async () => {
    await expect(
      executeStep(
        {
          label: "post-remediation install",
          command: process.execPath,
          args: ["-e", "process.exit(1)"],
        },
        {
          cwd: repoRoot(),
          verbose: false,
        },
      ),
    ).rejects.toBeInstanceOf(CommandExecutionError);
  });
});
