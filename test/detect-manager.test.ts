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

    expect(result).toEqual({ manager: "pnpm", source: "override" });
    expect(detectFn).not.toHaveBeenCalled();
    expect(getUserAgentFn).not.toHaveBeenCalled();
  });

  it("uses the current user agent before filesystem detection", async () => {
    const detectFn = vi.fn();
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

    expect(result).toEqual({ manager: "npm", source: "user-agent" });
    expect(detectFn).not.toHaveBeenCalled();
  });

  it("falls back to filesystem detection", async () => {
    const detectFn = vi.fn().mockResolvedValue({ name: "bun" });
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

    expect(result).toEqual({ manager: "bun", source: "filesystem" });
    expect(detectFn).toHaveBeenCalledOnce();
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
