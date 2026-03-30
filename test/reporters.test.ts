import { describe, expect, it } from "vitest";

import { CommandExecutionError } from "../src/core/types.js";
import { formatFailure, formatTextSummary } from "../src/reporters/text.js";

describe("formatTextSummary", () => {
  it("groups fixed vulnerabilities by package", () => {
    const summary = formatTextSummary({
      manager: "pnpm",
      detectionSource: "filesystem",
      threshold: "moderate",
      scope: "prod",
      dedupe: "auto",
      dedupeRan: false,
      dryRun: false,
      initial: {
        manager: "pnpm",
        threshold: "moderate",
        scope: "prod",
        total: 3,
        counts: { low: 0, moderate: 2, high: 0, critical: 1, total: 3 },
        entries: [],
      },
      final: {
        manager: "pnpm",
        threshold: "moderate",
        scope: "prod",
        total: 1,
        counts: { low: 0, moderate: 1, high: 0, critical: 0, total: 1 },
        entries: [],
      },
      fixedCount: 2,
      remainingCount: 1,
      fixed: [
        {
          packageName: "brace-expansion",
          installedVersions: ["1.1.12", "2.0.2"],
          advisoryIds: ["CVE-2026-33750", "GHSA-F886-M6HF-6M8V"],
        },
      ],
      exitCode: 2,
      status: "resolved-some",
    });

    expect(summary).toContain("fix(deps): resolve 2 vulnerabilities");
    expect(summary).toContain(
      "- brace-expansion (1.1.12, 2.0.2): CVE-2026-33750, GHSA-F886-M6HF-6M8V",
    );
    expect(summary).toContain("remaining: 1 vulnerability");
  });

  it("formats the clean case", () => {
    const summary = formatTextSummary({
      manager: "npm",
      detectionSource: "user-agent",
      threshold: "moderate",
      scope: "prod",
      dedupe: "auto",
      dedupeRan: false,
      dryRun: false,
      initial: {
        manager: "npm",
        threshold: "moderate",
        scope: "prod",
        total: 0,
        counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        entries: [],
      },
      final: {
        manager: "npm",
        threshold: "moderate",
        scope: "prod",
        total: 0,
        counts: { low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
        entries: [],
      },
      fixedCount: 0,
      remainingCount: 0,
      fixed: [],
      exitCode: 0,
      status: "clean",
    });

    expect(summary).toBe(
      "chore(deps): no vulnerabilities found\n\nremaining: 0 vulnerabilities",
    );
  });
});

describe("formatFailure", () => {
  it("prints buffered subprocess output", () => {
    const output = formatFailure(
      new CommandExecutionError(
        {
          label: "remediation",
          command: "pnpm",
          args: ["audit", "--fix"],
        },
        {
          command: "pnpm",
          args: ["audit", "--fix"],
          stdout: "stdout line\n",
          stderr: "stderr line\n",
          exitCode: 1,
          signal: null,
        },
        "Process exited with code 1",
      ),
    );

    expect(output).toContain("Failed step: remediation");
    expect(output).toContain("stdout:\nstdout line");
    expect(output).toContain("stderr:\nstderr line");
    expect(output).toContain("Reason: Process exited with code 1");
  });
});
