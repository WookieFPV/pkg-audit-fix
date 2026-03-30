import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { beforeAll, describe, expect, it } from "vitest";

import { repoRoot } from "./helpers.js";

const root = repoRoot();
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";
const nodeCommand = process.execPath;

describe("built CLI", () => {
  beforeAll(() => {
    execFileSync(npmCommand, ["run", "build"], {
      cwd: root,
      stdio: "pipe",
    });
  }, 120_000);

  it("preserves the node shebang in dist/cli.mjs", () => {
    const builtCli = fs.readFileSync(
      path.join(root, "dist", "cli.mjs"),
      "utf8",
    );
    expect(builtCli.startsWith("#!/usr/bin/env node")).toBe(true);
  });

  it("runs the built help command", () => {
    const result = spawnSync(
      nodeCommand,
      [path.join(root, "dist", "cli.mjs"), "--help"],
      {
        cwd: root,
        encoding: "utf8",
      },
    );

    expect(result.status).toBe(0);
    expect(result.stdout).toContain("pkg-audit-fix");
    expect(result.stdout).toContain("--audit-level");
  });
});
