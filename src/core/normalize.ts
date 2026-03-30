import type {
  AuditLevel,
  AuditScope,
  FixedPackageGroup,
  NormalizedAuditSnapshot,
  NormalizedVulnerability,
  PackageManager,
  Severity,
  VulnerabilityCounts,
} from "./types.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  low: 0,
  moderate: 1,
  high: 2,
  critical: 3,
};

export function emptyCounts(): VulnerabilityCounts {
  return {
    low: 0,
    moderate: 0,
    high: 0,
    critical: 0,
    total: 0,
  };
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string");
}

export function uniqueSorted(values: Iterable<string>): string[] {
  return [...new Set([...values].filter(Boolean))].sort((left, right) =>
    left.localeCompare(right, undefined, { numeric: true }),
  );
}

export function normalizeSeverity(value: unknown): Severity {
  if (typeof value === "string") {
    const normalized = value.toLowerCase();
    if (
      normalized === "low" ||
      normalized === "moderate" ||
      normalized === "high" ||
      normalized === "critical"
    ) {
      return normalized;
    }
  }

  return "moderate";
}

export function severityAtOrAbove(
  value: Severity,
  threshold: AuditLevel,
): boolean {
  return SEVERITY_ORDER[value] >= SEVERITY_ORDER[threshold];
}

export function countsFromMetadata(value: unknown): VulnerabilityCounts | null {
  if (!isRecord(value)) {
    return null;
  }

  const read = (key: keyof VulnerabilityCounts) => {
    const entry = value[key];
    return typeof entry === "number" && Number.isFinite(entry) ? entry : 0;
  };

  return {
    low: read("low"),
    moderate: read("moderate"),
    high: read("high"),
    critical: read("critical"),
    total: read("total"),
  };
}

export function countsFromEntries(
  entries: NormalizedVulnerability[],
): VulnerabilityCounts {
  const counts = emptyCounts();

  for (const entry of entries) {
    counts[entry.severity] += 1;
    counts.total += 1;
  }

  return counts;
}

export function createSnapshot(input: {
  manager: PackageManager;
  threshold: AuditLevel;
  scope: AuditScope;
  entries: NormalizedVulnerability[];
  counts?: VulnerabilityCounts | null;
}): NormalizedAuditSnapshot {
  const filteredEntries = input.entries.filter((entry) =>
    severityAtOrAbove(entry.severity, input.threshold),
  );
  const derivedCounts = countsFromEntries(filteredEntries);
  const counts = input.counts
    ? {
        low: Math.max(
          severityAtOrAbove("low", input.threshold) ? input.counts.low : 0,
          derivedCounts.low,
        ),
        moderate: Math.max(
          severityAtOrAbove("moderate", input.threshold)
            ? input.counts.moderate
            : 0,
          derivedCounts.moderate,
        ),
        high: Math.max(
          severityAtOrAbove("high", input.threshold) ? input.counts.high : 0,
          derivedCounts.high,
        ),
        critical: Math.max(
          severityAtOrAbove("critical", input.threshold)
            ? input.counts.critical
            : 0,
          derivedCounts.critical,
        ),
        total: 0,
      }
    : derivedCounts;
  counts.total = counts.low + counts.moderate + counts.high + counts.critical;

  return {
    manager: input.manager,
    threshold: input.threshold,
    scope: input.scope,
    total: counts.total,
    counts,
    entries: filteredEntries,
  };
}

export function parseJsonObject(
  stdout: string,
  manager: PackageManager,
): Record<string, unknown> {
  let parsed: unknown;

  try {
    parsed = JSON.parse(stdout);
  } catch (error) {
    throw new Error(
      `Failed to parse ${manager} audit JSON: ${error instanceof Error ? error.message : "unknown parse error"}`,
    );
  }

  if (!isRecord(parsed)) {
    throw new Error(`Expected ${manager} audit JSON to be an object`);
  }

  return parsed;
}

export function collectAdvisoryIds(...sources: unknown[]): string[] {
  const advisoryIds = new Set<string>();

  for (const source of sources) {
    if (!isRecord(source)) {
      continue;
    }

    const push = (value: unknown) => {
      if (
        typeof value === "string" &&
        /^(CVE-\d{4}-\d+|GHSA-[\w-]+)$/i.test(value)
      ) {
        advisoryIds.add(value.toUpperCase());
        return;
      }

      if (typeof value === "string") {
        const match = /\/advisories\/(GHSA-[\w-]+)/i.exec(value);
        if (match) {
          advisoryIds.add(match[1].toUpperCase());
        }
      }
    };

    push(source.id);
    push(source.github_advisory_id);
    push(source.ghsaId);
    push(source.url);

    for (const value of asStringArray(source.cves)) {
      push(value);
    }

    for (const value of asStringArray(source.github_advisory_ids)) {
      push(value);
    }

    for (const value of asStringArray(source.ghsaIds)) {
      push(value);
    }
  }

  return uniqueSorted(advisoryIds);
}

export function vulnerabilityKey(
  packageName: string,
  installedVersion: string,
  advisoryIds: string[],
): string {
  return `${packageName}@${installedVersion}#${uniqueSorted(advisoryIds).join(",")}`;
}

export function diffFixedEntries(
  initialEntries: NormalizedVulnerability[],
  finalEntries: NormalizedVulnerability[],
): NormalizedVulnerability[] {
  const remaining = new Set(finalEntries.map((entry) => entry.key));
  return initialEntries.filter((entry) => !remaining.has(entry.key));
}

export function groupFixedPackages(
  entries: NormalizedVulnerability[],
): FixedPackageGroup[] {
  const grouped = new Map<string, FixedPackageGroup>();

  for (const entry of entries) {
    const group = grouped.get(entry.packageName) ?? {
      packageName: entry.packageName,
      installedVersions: [],
      advisoryIds: [],
      title: entry.title,
      url: entry.url,
    };

    group.installedVersions = uniqueSorted([
      ...group.installedVersions,
      entry.installedVersion,
    ]);
    group.advisoryIds = uniqueSorted([
      ...group.advisoryIds,
      ...entry.advisoryIds,
    ]);
    group.title ??= entry.title;
    group.url ??= entry.url;
    grouped.set(entry.packageName, group);
  }

  return [...grouped.values()].sort((left, right) =>
    left.packageName.localeCompare(right.packageName),
  );
}

export function formatCount(count: number): string {
  return `${count} ${count === 1 ? "vulnerability" : "vulnerabilities"}`;
}
