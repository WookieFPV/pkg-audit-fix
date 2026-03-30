import { describe, expect, it } from "vitest";

import { createSnapshot } from "../src/core/normalize.js";
import type { NormalizedVulnerability } from "../src/core/types.js";

describe("createSnapshot", () => {
  it("keeps parsed low-severity entries when metadata undercounts them", () => {
    const entries: NormalizedVulnerability[] = [
      {
        key: "minimist@1.2.7#GHSA-vh95-rmgr-6w4m",
        packageName: "minimist",
        installedVersion: "1.2.7",
        severity: "low",
        advisoryIds: ["GHSA-VH95-RMGR-6W4M"],
      },
      {
        key: "brace-expansion@1.1.12#GHSA-f886-m6hf-6m8v",
        packageName: "brace-expansion",
        installedVersion: "1.1.12",
        severity: "moderate",
        advisoryIds: ["GHSA-F886-M6HF-6M8V"],
      },
    ];

    const snapshot = createSnapshot({
      manager: "npm",
      threshold: "low",
      scope: "prod",
      entries,
      counts: {
        low: 0,
        moderate: 1,
        high: 0,
        critical: 0,
        total: 1,
      },
    });

    expect(snapshot.counts).toEqual({
      low: 1,
      moderate: 1,
      high: 0,
      critical: 0,
      total: 2,
    });
    expect(snapshot.total).toBe(2);
    expect(snapshot.entries).toHaveLength(2);
  });
});
