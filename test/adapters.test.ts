import { describe, expect, it } from "vitest";

import { bunAdapter } from "../src/adapters/bun.js";
import { npmAdapter } from "../src/adapters/npm.js";
import { pnpmAdapter } from "../src/adapters/pnpm.js";
import { readFixture } from "./helpers.js";

describe("adapter commands", () => {
  it("builds pnpm audit and remediation commands", () => {
    expect(
      pnpmAdapter.buildAuditProcess({ threshold: "moderate", scope: "all" }),
    ).toEqual({
      command: "pnpm",
      args: ["audit", "--json", "--audit-level=moderate"],
    });
    expect(
      pnpmAdapter.buildAuditProcess({ threshold: "moderate", scope: "prod" }),
    ).toEqual({
      command: "pnpm",
      args: ["audit", "--json", "--audit-level=moderate", "--prod"],
    });
    expect(
      pnpmAdapter.buildRemediationProcess({ threshold: "high", scope: "dev" }),
    ).toEqual({
      command: "pnpm",
      args: ["audit", "--json", "--fix", "--audit-level=high", "--dev"],
    });
    expect(
      pnpmAdapter.buildDedupeProcess({ threshold: "moderate", scope: "prod" }),
    ).toEqual({
      command: "pnpm",
      args: ["dedupe"],
    });
    expect(
      pnpmAdapter.buildPostRemediationProcess({
        threshold: "moderate",
        scope: "all",
      }),
    ).toEqual({
      command: "pnpm",
      args: ["install", "--no-frozen-lockfile"],
    });
  });

  it("builds npm commands with prod omission", () => {
    expect(
      npmAdapter.buildAuditProcess({ threshold: "moderate", scope: "all" }),
    ).toEqual({
      command: "npm",
      args: ["audit", "--json"],
    });
    expect(
      npmAdapter.buildAuditProcess({ threshold: "moderate", scope: "prod" }),
    ).toEqual({
      command: "npm",
      args: ["audit", "--json", "--omit=dev"],
    });
    expect(
      npmAdapter.buildRemediationProcess({
        threshold: "critical",
        scope: "dev",
      }),
    ).toEqual({
      command: "npm",
      args: ["audit", "fix", "--json", "--only=dev"],
    });
    expect(
      npmAdapter.buildDedupeProcess({ threshold: "moderate", scope: "prod" }),
    ).toEqual({
      command: "npm",
      args: ["dedupe"],
    });
  });

  it("builds bun commands with update-based remediation", () => {
    expect(
      bunAdapter.buildAuditProcess({ threshold: "moderate", scope: "all" }),
    ).toEqual({
      command: "bun",
      args: ["audit", "--json", "--audit-level=moderate"],
    });
    expect(
      bunAdapter.buildAuditProcess({ threshold: "moderate", scope: "prod" }),
    ).toEqual({
      command: "bun",
      args: ["audit", "--json", "--audit-level=moderate", "--prod"],
    });
    expect(
      bunAdapter.buildRemediationProcess({
        threshold: "moderate",
        scope: "prod",
      }),
    ).toEqual({
      command: "bun",
      args: ["update", "--production"],
    });
    expect(
      bunAdapter.buildDedupeProcess({ threshold: "moderate", scope: "prod" }),
    ).toBeNull();
  });
});

describe("adapter fixtures", () => {
  it("parses pnpm fixture snapshots", () => {
    const before = pnpmAdapter.parseAudit(readFixture("pnpm", "before.json"), {
      threshold: "moderate",
      scope: "prod",
    });
    const after = pnpmAdapter.parseAudit(readFixture("pnpm", "after.json"), {
      threshold: "moderate",
      scope: "prod",
    });

    expect(before.total).toBe(3);
    expect(before.entries).toHaveLength(3);
    expect(before.entries[0]?.advisoryIds).toContain("CVE-2026-33750");
    expect(after.total).toBe(0);
  });

  it("parses npm fixture snapshots", () => {
    const before = npmAdapter.parseAudit(readFixture("npm", "before.json"), {
      threshold: "moderate",
      scope: "prod",
    });
    const after = npmAdapter.parseAudit(readFixture("npm", "after.json"), {
      threshold: "moderate",
      scope: "prod",
    });

    expect(before.total).toBe(2);
    expect(before.entries.map((entry) => entry.packageName)).toEqual([
      "brace-expansion",
      "node-forge",
    ]);
    expect(after.total).toBe(0);
  });

  it("parses bun fixture snapshots and respects threshold filtering", () => {
    const before = bunAdapter.parseAudit(readFixture("bun", "before.json"), {
      threshold: "moderate",
      scope: "prod",
    });
    const after = bunAdapter.parseAudit(readFixture("bun", "after.json"), {
      threshold: "moderate",
      scope: "prod",
    });

    expect(before.total).toBe(2);
    expect(before.entries.map((entry) => entry.packageName)).toEqual([
      "brace-expansion",
      "node-forge",
    ]);
    expect(before.entries[0]?.advisoryIds).toEqual(["GHSA-F886-M6HF-6M8V"]);
    expect(after.total).toBe(0);
  });
});
