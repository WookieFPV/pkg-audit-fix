import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { describe, expect, it, vi } from "vitest";

import { detectPackageManager } from "../src/core/detect-manager.js";
import { ManagerDetectionError } from "../src/core/types.js";

describe("detectPackageManager", () => {
  it("prefers an explicit override", async () => {
    const detectFn = vi.fn();
    const getUserAgentFn = vi.fn();
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "pnpm",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "pnpm",
      agent: "pnpm",
      source: "override",
    });
    expect(detectFn).not.toHaveBeenCalled();
    expect(getUserAgentFn).not.toHaveBeenCalled();
  });

  it("keeps the detected berry agent when yarn is explicitly overridden", async () => {
    const detectFn = vi
      .fn()
      .mockResolvedValue({ name: "yarn", agent: "yarn@berry" });
    const getUserAgentFn = vi.fn();
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "yarn",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "yarn",
      agent: "yarn@berry",
      source: "override",
    });
    expect(getUserAgentFn).not.toHaveBeenCalled();
  });

  it("prefers filesystem detection over the invoking user agent", async () => {
    const detectFn = vi.fn().mockResolvedValue({ name: "bun", agent: "bun" });
    const getUserAgentFn = vi.fn().mockResolvedValue({ name: "npm" });
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "auto",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "bun",
      agent: "bun",
      source: "filesystem",
    });
    expect(detectFn).toHaveBeenCalledOnce();
  });

  it("falls back to the current user agent when filesystem detection fails", async () => {
    const detectFn = vi.fn().mockResolvedValue(null);
    const getUserAgentFn = vi.fn().mockResolvedValue("npm");
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "auto",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "npm",
      agent: "npm",
      source: "user-agent",
    });
    expect(detectFn).toHaveBeenCalledOnce();
  });

  it("uses filesystem detection when no user agent is available", async () => {
    const detectFn = vi.fn().mockResolvedValue({ name: "bun", agent: "bun" });
    const getUserAgentFn = vi.fn().mockResolvedValue(null);
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "auto",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "bun",
      agent: "bun",
      source: "filesystem",
    });
    expect(detectFn).toHaveBeenCalledOnce();
  });

  it("detects yarn berry from the filesystem", async () => {
    const detectFn = vi
      .fn()
      .mockResolvedValue({ name: "yarn", agent: "yarn@berry" });
    const getUserAgentFn = vi.fn().mockResolvedValue("npm");
    const result = await detectPackageManager(
      {
        cwd: "/tmp/project",
        override: "auto",
      },
      {
        detectFn,
        getUserAgentFn,
      },
    );

    expect(result).toEqual({
      manager: "yarn",
      agent: "yarn@berry",
      source: "filesystem",
    });
  });

  it("promotes ambiguous yarn detection to berry when berry files are present", async () => {
    const cwd = fs.mkdtempSync(path.join(os.tmpdir(), "pkg-audit-fix-"));

    fs.writeFileSync(path.join(cwd, "yarn.lock"), "");
    fs.writeFileSync(
      path.join(cwd, ".yarnrc.yml"),
      "nodeLinker: node-modules\n",
    );

    try {
      const detectFn = vi
        .fn()
        .mockResolvedValue({ name: "yarn", agent: "yarn" });
      const getUserAgentFn = vi.fn().mockResolvedValue(null);
      const result = await detectPackageManager(
        {
          cwd,
          override: "auto",
        },
        {
          detectFn,
          getUserAgentFn,
        },
      );

      expect(result).toEqual({
        manager: "yarn",
        agent: "yarn@berry",
        source: "filesystem",
      });
    } finally {
      fs.rmSync(cwd, { recursive: true, force: true });
    }
  });

  it("throws with an override hint when no supported manager is found", async () => {
    const detectFn = vi.fn().mockResolvedValue(null);
    const getUserAgentFn = vi.fn().mockResolvedValue(null);

    await expect(
      detectPackageManager(
        {
          cwd: "/tmp/project",
          override: "auto",
        },
        {
          detectFn,
          getUserAgentFn,
        },
      ),
    ).rejects.toBeInstanceOf(ManagerDetectionError);
  });
});
