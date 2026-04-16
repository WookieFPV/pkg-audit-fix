import { describe, expect, it } from "vitest";

import {
  CommandExecutionError,
  MinimumReleaseAgeDeclinedError,
} from "../src/core/types.js";
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
      stepFixes: [
        {
          label: "Apply fixes",
          fixedCount: 1,
          remainingCount: 2,
        },
        {
          label: "Consolidate dependency tree",
          fixedCount: 1,
          remainingCount: 1,
        },
      ],
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

    expect(summary).toContain("Resolved 2 vulnerabilities.");
    expect(summary).toContain("Updated packages:");
    expect(summary).toContain(
      "- brace-expansion (1.1.12, 2.0.2): CVE-2026-33750, GHSA-F886-M6HF-6M8V",
    );
    expect(summary).toContain("1 vulnerability remains.");
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
      stepFixes: [],
      fixedCount: 0,
      remainingCount: 0,
      fixed: [],
      exitCode: 0,
      status: "clean",
    });

    expect(summary).toBe("No vulnerabilities found.");
  });

  it("formats dry-run output explicitly", () => {
    const summary = formatTextSummary({
      manager: "npm",
      detectionSource: "user-agent",
      threshold: "moderate",
      scope: "prod",
      dedupe: "auto",
      dedupeRan: false,
      dryRun: true,
      initial: {
        manager: "npm",
        threshold: "moderate",
        scope: "prod",
        total: 2,
        counts: { low: 0, moderate: 1, high: 1, critical: 0, total: 2 },
        entries: [],
      },
      final: {
        manager: "npm",
        threshold: "moderate",
        scope: "prod",
        total: 2,
        counts: { low: 0, moderate: 1, high: 1, critical: 0, total: 2 },
        entries: [],
      },
      stepFixes: [],
      fixedCount: 0,
      remainingCount: 2,
      fixed: [],
      exitCode: 2,
      status: "no-change",
    });

    expect(summary).toBe(
      "Found 2 vulnerabilities. No fixes were applied because this was a dry run.\n\n2 vulnerabilities remain.",
    );
  });

  it("lists remaining bun vulnerabilities when nothing was resolved", () => {
    const summary = formatTextSummary({
      manager: "bun",
      detectionSource: "filesystem",
      threshold: "low",
      scope: "all",
      dedupe: "auto",
      dedupeRan: false,
      dryRun: false,
      initial: {
        manager: "bun",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 1, moderate: 1, high: 0, critical: 0, total: 2 },
        entries: [],
      },
      final: {
        manager: "bun",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 1, moderate: 1, high: 0, critical: 0, total: 2 },
        entries: [
          {
            key: "lodash@4.17.20#GHSA-35JH-R3H4-6JHM",
            packageName: "lodash",
            installedVersion: "4.17.20",
            severity: "high",
            advisoryIds: ["GHSA-35JH-R3H4-6JHM"],
            remediation: "upgrade to >=4.17.21",
          },
          {
            key: "minimist@1.2.5#GHSA-VH95-RMGR-6W4M",
            packageName: "minimist",
            installedVersion: "1.2.5",
            severity: "moderate",
            advisoryIds: ["GHSA-VH95-RMGR-6W4M"],
          },
        ],
      },
      stepFixes: [],
      fixedCount: 0,
      remainingCount: 2,
      fixed: [],
      exitCode: 2,
      status: "no-change",
    });

    expect(summary).toContain("No vulnerabilities were resolved.");
    expect(summary).toContain("Bun does not support `audit --fix`.");
    expect(summary).toContain("Remaining vulnerabilities:");
    expect(summary).toContain(
      "- lodash@4.17.20 [high]: GHSA-35JH-R3H4-6JHM; upgrade to >=4.17.21",
    );
  });

  it("deduplicates repeated vulnerability lines and keeps remediation hints", () => {
    const summary = formatTextSummary({
      manager: "bun",
      detectionSource: "filesystem",
      threshold: "low",
      scope: "all",
      dedupe: "auto",
      dedupeRan: false,
      dryRun: false,
      initial: {
        manager: "bun",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 0, moderate: 1, high: 1, critical: 0, total: 2 },
        entries: [],
      },
      final: {
        manager: "bun",
        threshold: "low",
        scope: "all",
        total: 2,
        counts: { low: 0, moderate: 1, high: 1, critical: 0, total: 2 },
        entries: [
          {
            key: "brace-expansion@unknown#GHSA-F886-M6HF-6M8V",
            packageName: "brace-expansion",
            installedVersion: "unknown",
            severity: "moderate",
            advisoryIds: ["GHSA-F886-M6HF-6M8V"],
            remediation: "upgrade to >=1.1.13",
          },
          {
            key: "brace-expansion@unknown#GHSA-F886-M6HF-6M8V-dup",
            packageName: "brace-expansion",
            installedVersion: "unknown",
            severity: "moderate",
            advisoryIds: ["GHSA-F886-M6HF-6M8V"],
          },
        ],
      },
      stepFixes: [],
      fixedCount: 0,
      remainingCount: 2,
      fixed: [],
      exitCode: 2,
      status: "no-change",
    });

    expect(summary.match(/brace-expansion/g)?.length).toBe(1);
    expect(summary).toContain(
      "- brace-expansion [moderate]: GHSA-F886-M6HF-6M8V; upgrade to >=1.1.13",
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

  it("prints a concise message when the minimumReleaseAge prompt is declined", () => {
    const output = formatFailure(
      new MinimumReleaseAgeDeclinedError({
        step: {
          label: "Reinstall dependencies",
          command: "pnpm",
          args: ["install", "--no-frozen-lockfile"],
        },
        manager: "pnpm",
        configSetting: "minimumReleaseAgeExclude",
        packages: ["lodash@4.18.1", "chalk@5.4.0"],
      }),
    );

    expect(output).toBe(
      "Reason: minimumReleaseAge blocked pnpm install for lodash@4.18.1, chalk@5.4.0. Rerun and answer Y to update minimumReleaseAgeExclude automatically.",
    );
  });
});
