import { describe, expect, it } from "vitest";

import { bunAdapter } from "../src/adapters/bun.js";
import { npmAdapter } from "../src/adapters/npm.js";
import { pnpmAdapter } from "../src/adapters/pnpm.js";
import { yarnBerryAdapter } from "../src/adapters/yarn-berry.js";
import { yarnClassicAdapter } from "../src/adapters/yarn-classic.js";
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

  it("builds yarn classic commands", () => {
    expect(
      yarnClassicAdapter.buildAuditProcess({
        threshold: "moderate",
        scope: "all",
      }),
    ).toEqual({
      command: "yarn",
      args: ["audit", "--json", "--level", "moderate"],
    });
    expect(
      yarnClassicAdapter.buildAuditProcess({
        threshold: "high",
        scope: "prod",
      }),
    ).toEqual({
      command: "yarn",
      args: ["audit", "--json", "--level", "high", "--groups", "dependencies"],
    });
    expect(
      yarnClassicAdapter.buildDedupeProcess({
        threshold: "moderate",
        scope: "prod",
      }),
    ).toBeNull();
  });

  it("builds yarn berry commands", () => {
    expect(
      yarnBerryAdapter.buildAuditProcess({
        threshold: "moderate",
        scope: "all",
      }),
    ).toEqual({
      command: "yarn",
      args: [
        "npm",
        "audit",
        "--json",
        "--no-deprecations",
        "--all",
        "--recursive",
        "--severity",
        "moderate",
      ],
    });
    expect(
      yarnBerryAdapter.buildAuditProcess({
        threshold: "high",
        scope: "dev",
      }),
    ).toEqual({
      command: "yarn",
      args: [
        "npm",
        "audit",
        "--json",
        "--no-deprecations",
        "--all",
        "--recursive",
        "--severity",
        "high",
        "--environment",
        "development",
      ],
    });
    expect(
      yarnBerryAdapter.buildDedupeProcess({
        threshold: "moderate",
        scope: "prod",
      }),
    ).toEqual({
      command: "yarn",
      args: ["dedupe"],
    });
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

  it("parses yarn classic fixture snapshots", () => {
    const before = yarnClassicAdapter.parseAudit(
      readFixture("yarn-classic", "before.jsonl"),
      {
        threshold: "moderate",
        scope: "prod",
      },
    );
    const after = yarnClassicAdapter.parseAudit(
      readFixture("yarn-classic", "after.jsonl"),
      {
        threshold: "moderate",
        scope: "prod",
      },
    );

    expect(before.total).toBe(2);
    expect(before.entries.map((entry) => entry.packageName)).toEqual([
      "brace-expansion",
      "node-forge",
    ]);
    expect(before.entries[0]?.advisoryIds).toEqual(["GHSA-F886-M6HF-6M8V"]);
    expect(after.total).toBe(0);
  });

  it("recognizes valid yarn classic audit payloads", () => {
    expect(
      yarnClassicAdapter.isAuditResult?.(
        readFixture("yarn-classic", "after.jsonl"),
      ),
    ).toBe(true);
    expect(
      yarnClassicAdapter.isAuditResult?.("Usage Error: missing plugin"),
    ).toBe(false);
  });

  it("parses yarn berry fixture snapshots", () => {
    const before = yarnBerryAdapter.parseAudit(
      readFixture("yarn-berry", "before.json"),
      {
        threshold: "moderate",
        scope: "prod",
      },
    );
    const after = yarnBerryAdapter.parseAudit(
      readFixture("yarn-berry", "after.json"),
      {
        threshold: "moderate",
        scope: "prod",
      },
    );

    expect(before.total).toBe(2);
    expect(before.entries.map((entry) => entry.packageName)).toEqual([
      "brace-expansion",
      "node-forge",
    ]);
    expect(before.entries[0]?.installedVersion).toBe("1.1.11");
    expect(before.entries[0]?.advisoryIds).toEqual(["GHSA-F886-M6HF-6M8V"]);
    expect(after.total).toBe(0);
  });

  it("recognizes valid yarn berry audit payloads", () => {
    expect(
      yarnBerryAdapter.isAuditResult?.(readFixture("yarn-berry", "after.json")),
    ).toBe(true);
    expect(yarnBerryAdapter.isAuditResult?.("Network Error")).toBe(false);
  });

  it("parses yarn berry ndjson output", () => {
    const before = yarnBerryAdapter.parseAudit(
      [
        '{"value":"brace-expansion","children":{"ID":1115540,"Issue":"brace-expansion: Zero-step sequence causes process hang and memory exhaustion","URL":"https://github.com/advisories/GHSA-f886-m6hf-6m8v","Severity":"moderate","Vulnerable Versions":"<1.1.13","Tree Versions":["1.1.12"],"Dependents":["minimatch@npm:3.1.2"]}}',
        '{"value":"node-forge","children":{"ID":1115545,"Issue":"Forge has a basicConstraints bypass in its certificate chain verification (RFC 5280 violation)","URL":"https://github.com/advisories/GHSA-2328-f5f3-gj25","Severity":"high","Vulnerable Versions":"<=1.3.3","Tree Versions":["1.3.3"],"Dependents":["@expo/code-signing-certificates@npm:0.0.6"]}}',
      ].join("\n"),
      {
        threshold: "moderate",
        scope: "prod",
      },
    );

    expect(before.total).toBe(2);
    expect(before.entries.map((entry) => entry.packageName)).toEqual([
      "brace-expansion",
      "node-forge",
    ]);
    expect(before.entries[0]?.installedVersion).toBe("1.1.12");
    expect(before.entries[0]?.advisoryIds).toEqual(["GHSA-F886-M6HF-6M8V"]);
  });
});
