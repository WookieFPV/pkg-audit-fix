import { describe, expect, it } from "vitest";

import {
  bunAdapter,
  extractBunMinimumReleaseAgeExclusions,
  parseBunMinimumReleaseAgeExcludesConfig,
  updateBunMinimumReleaseAgeExcludesConfig,
} from "../src/adapters/bun.js";
import { npmAdapter } from "../src/adapters/npm.js";
import {
  extractPnpmMinimumReleaseAgeExclusions,
  parsePnpmMinimumReleaseAgeExcludeConfig,
  pnpmAdapter,
} from "../src/adapters/pnpm.js";
import {
  extractYarnMinimumReleaseAgeExclusions,
  parseYarnNpmPreapprovedPackagesConfig,
  updateYarnNpmPreapprovedPackagesConfig,
  yarnBerryAdapter,
} from "../src/adapters/yarn-berry.js";
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
      args: ["install", "--no-frozen-lockfile", "--reporter", "ndjson"],
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

  it("extracts too-new pnpm install packages from ndjson reporter output", () => {
    const exclusions = extractPnpmMinimumReleaseAgeExclusions({
      stdout: [
        JSON.stringify({
          name: "pnpm",
          code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
          immatureVersion: "4.18.1",
          package: {
            name: "lodash",
            version: ">=4.18.0",
          },
        }),
      ].join("\n"),
      stderr: [
        JSON.stringify({
          name: "pnpm",
          err: {
            code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
          },
          immatureVersion: "5.4.0",
          package: {
            name: "chalk",
            version: "^5.4.0",
          },
        }),
        JSON.stringify({
          name: "pnpm",
          code: "ERR_PNPM_NO_MATURE_MATCHING_VERSION",
          immatureVersion: "4.18.1",
          packageMeta: {
            name: "lodash",
          },
        }),
      ].join("\n"),
    });

    expect(exclusions).toEqual([
      {
        packageName: "lodash",
        version: "4.18.1",
        specifier: "lodash@4.18.1",
      },
      {
        packageName: "chalk",
        version: "5.4.0",
        specifier: "chalk@5.4.0",
      },
    ]);
  });

  it("extracts too-new pnpm install packages from plain error text", () => {
    const exclusions = extractPnpmMinimumReleaseAgeExclusions({
      stdout: "",
      stderr:
        "ERR_PNPM_NO_MATURE_MATCHING_VERSION\nVersion 4.18.1 (released 10 hours ago) of lodash does not meet the minimumReleaseAge constraint\nVersion 5.4.0 (released 2 hours ago) of chalk does not meet the minimumReleaseAge constraint\n",
    });

    expect(exclusions).toEqual([
      {
        packageName: "lodash",
        version: "4.18.1",
        specifier: "lodash@4.18.1",
      },
      {
        packageName: "chalk",
        version: "5.4.0",
        specifier: "chalk@5.4.0",
      },
    ]);
  });

  it("parses pnpm minimumReleaseAgeExclude config output", () => {
    expect(parsePnpmMinimumReleaseAgeExcludeConfig("null")).toEqual([]);
    expect(
      parsePnpmMinimumReleaseAgeExcludeConfig(
        '["lodash@4.18.1","chalk@5.4.0"]',
      ),
    ).toEqual(["lodash@4.18.1", "chalk@5.4.0"]);
  });

  it("ignores bun non-age resolution failures that only say package exists", () => {
    const exclusions = extractBunMinimumReleaseAgeExclusions({
      stdout: "",
      stderr:
        'error: No version matching "5.4.0" found for specifier "chalk" (but package exists)',
    });

    expect(exclusions).toEqual([]);
  });

  it("extracts too-new bun update packages from minimum-age error text", () => {
    const exclusions = extractBunMinimumReleaseAgeExclusions({
      stdout: "",
      stderr: [
        "error: minimum-release-age prevented resolving fresh releases",
        'error: No version matching "5.4.0" found for specifier "chalk" (but package exists)',
        'error: No version matching "^4.18.0" found for specifier "lodash" (but package exists)',
        'error: No version matching "brace-expansion" found for specifier "^1.1.11" (blocked by minimum-release-age: 2592000 seconds)',
      ].join("\n"),
    });

    expect(exclusions).toEqual([
      {
        packageName: "brace-expansion",
        version: "^1.1.11",
        specifier: "brace-expansion",
      },
      {
        packageName: "chalk",
        version: "5.4.0",
        specifier: "chalk",
      },
      {
        packageName: "lodash",
        version: "^4.18.0",
        specifier: "lodash",
      },
    ]);
  });

  it("extracts bun minimum-age exclusions from all-versions-blocked lines", () => {
    const exclusions = extractBunMinimumReleaseAgeExclusions({
      stdout: "",
      stderr:
        'error: No version matching "brace-expansion" found for specifier "^1.1.13" (all versions blocked by minimum-release-age)',
    });

    expect(exclusions).toEqual([
      {
        packageName: "brace-expansion",
        version: "^1.1.13",
        specifier: "brace-expansion",
      },
    ]);
  });

  it("extracts bun minimum-age exclusions from failed-to-resolve lines", () => {
    const exclusions = extractBunMinimumReleaseAgeExclusions({
      stdout: "",
      stderr: [
        'error: No version matching "brace-expansion" found for specifier "^1.1.13" (blocked by minimum-release-age: 2592000 seconds)',
        'error: No version matching "typescript" found for specifier "6.0.2" (blocked by minimum-release-age: 2592000 seconds)',
        "error: brace-expansion@^1.1.13 failed to resolve",
        "error: typescript@6.0.2 failed to resolve",
      ].join("\n"),
    });

    expect(exclusions).toEqual([
      {
        packageName: "brace-expansion",
        version: "^1.1.13",
        specifier: "brace-expansion",
      },
      {
        packageName: "typescript",
        version: "6.0.2",
        specifier: "typescript",
      },
    ]);
  });

  it("parses and updates bun minimumReleaseAgeExcludes config output", () => {
    const source = [
      "[install]",
      "minimumReleaseAge = 259200",
      'minimumReleaseAgeExcludes = ["left-pad"]',
      "",
      "[test]",
      'root = "./test"',
      "",
    ].join("\n");

    expect(parseBunMinimumReleaseAgeExcludesConfig(source)).toEqual([
      "left-pad",
    ]);
    expect(
      updateBunMinimumReleaseAgeExcludesConfig(source, ["left-pad", "chalk"]),
    ).toContain('minimumReleaseAgeExcludes = ["left-pad", "chalk"]');
    expect(updateBunMinimumReleaseAgeExcludesConfig("", ["chalk"])).toBe(
      '[install]\nminimumReleaseAgeExcludes = ["chalk"]\n',
    );
  });

  it("extracts too-new yarn berry packages from quarantined resolution errors", () => {
    const exclusions = extractYarnMinimumReleaseAgeExclusions({
      stdout: "",
      stderr:
        '➤ YN0016: │ lodash@npm:4.17.21: All versions satisfying "4.17.21" are quarantined\n➤ YN0016: │ @types/lodash@npm:^4.17.20: All versions satisfying "^4.17.20" are quarantined\n',
    });

    expect(exclusions).toEqual([
      {
        packageName: "lodash",
        version: "4.17.21",
        specifier: "lodash@4.17.21",
      },
      {
        packageName: "@types/lodash",
        version: "^4.17.20",
        specifier: "@types/lodash@^4.17.20",
      },
    ]);
  });

  it("parses and updates yarn npmPreapprovedPackages config output", () => {
    const source = [
      'npmMinimalAgeGate: "3d"',
      "npmPreapprovedPackages:",
      '  - "left-pad@1.0.0"',
      "",
      "nodeLinker: node-modules",
      "",
    ].join("\n");

    expect(parseYarnNpmPreapprovedPackagesConfig(source)).toEqual([
      "left-pad@1.0.0",
    ]);
    expect(
      updateYarnNpmPreapprovedPackagesConfig(source, [
        "left-pad@1.0.0",
        "lodash@4.17.21",
      ]),
    ).toContain('  - "lodash@4.17.21"');
    expect(updateYarnNpmPreapprovedPackagesConfig("", ["lodash@4.17.21"])).toBe(
      'npmPreapprovedPackages:\n  - "lodash@4.17.21"\n',
    );
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
