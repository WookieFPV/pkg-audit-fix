import { spawn, spawnSync } from "node:child_process";
import {
  chmod,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import type { JsonSummary, PackageManager } from "../src/index.js";
import { repoRoot } from "./helpers.js";

const FIXTURE_PACKAGE = {
  name: "brace-expansion",
  vulnerableVersion: "1.1.11",
  safeRange: "^1.1.13",
};

const E2E_TIMEOUT_MS = 120_000;
const tempProjects: string[] = [];
const root = repoRoot();
const builtCliPath = path.join(root, "dist", "cli.mjs");
const buildRunner = "bun";
const nodeCommand = process.platform === "win32" ? "node.exe" : "node";
const shellCommand = process.platform === "win32" ? "cmd.exe" : "zsh";
const ptyCommand = resolvePtyCommand();
const berryVersion = "4.13.0";
const MINIMUM_AGE_WINDOW_DAYS = 30;
const RECENT_PACKAGE_MAX_AGE_DAYS = 14;
const RECENT_PACKAGE_CANDIDATES = [
  "typescript",
  "@types/node",
  "@types/react",
  "vite",
  "eslint",
] as const;
const MINIMUM_AGE_RECENT_PACKAGE_CANDIDATES: Record<
  ManagerCase["id"],
  readonly string[]
> = {
  npm: [],
  pnpm: ["typescript"],
  bun: ["typescript"],
  "yarn-berry": ["typescript"],
};

interface ManagerCase {
  id: "npm" | "pnpm" | "bun" | "yarn-berry";
  manager: PackageManager;
  command: string;
  installArgs: string[];
  auditArgs: string[];
  setupProject?: ((projectDir: string) => Promise<void>) | undefined;
  supportsMinimumAgeRecovery: boolean;
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

interface RecentPackage {
  packageName: string;
  version: string;
  specifier: string;
  matureVersion: string;
  matureSpecifier: string;
}

type EnvMap = Bun.Env & Record<string, string>;

const managerCases: readonly ManagerCase[] = [
  {
    id: "npm",
    manager: "npm",
    command: "npm",
    installArgs: [
      "install",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json"],
    supportsMinimumAgeRecovery: false,
  },
  {
    id: "pnpm",
    manager: "pnpm",
    command: "pnpm",
    installArgs: [
      "add",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json", "--audit-level=low"],
    supportsMinimumAgeRecovery: true,
  },
  {
    id: "bun",
    manager: "bun",
    command: "bun",
    installArgs: [
      "add",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json", "--audit-level=low"],
    supportsMinimumAgeRecovery: true,
  },
  {
    id: "yarn-berry",
    manager: "yarn",
    command: "yarn",
    installArgs: [
      "add",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: [
      "npm",
      "audit",
      "--json",
      "--no-deprecations",
      "--all",
      "--recursive",
      "--severity",
      "low",
    ],
    setupProject: async (projectDir) => {
      await writeFile(
        path.join(projectDir, ".yarnrc.yml"),
        "nodeLinker: node-modules\n",
        "utf8",
      );
      await writeExecutableScript(
        projectDir,
        "yarn",
        `#!/bin/sh\nexec corepack yarn@${berryVersion} "$@"\n`,
      );
    },
    supportsMinimumAgeRecovery: true,
  },
];

afterEach(async () => {
  await Promise.all(
    tempProjects.splice(0).map((projectDir) =>
      rm(projectDir, {
        recursive: true,
        force: true,
      }),
    ),
  );
});

function isManagerAvailable(command: PackageManager): boolean {
  const result = spawnSync(command, ["--version"], {
    stdio: "ignore",
  });

  return result.status === 0;
}

function isCommandAvailable(command: string): boolean {
  return (
    spawnSync(command, command === "expect" ? ["-v"] : ["--version"], {
      stdio: "ignore",
    }).status === 0
  );
}

function resolvePtyCommand(): string | null {
  if (process.platform === "win32") {
    return null;
  }

  return isCommandAvailable("expect") ? "expect" : null;
}

function buildEnvOverrides(projectDir: string): EnvMap {
  const cacheDir = path.join(projectDir, ".cache");
  const tempDir = path.join(projectDir, ".tmp");
  const toolBinDir = path.join(projectDir, ".tools", "bin");

  return {
    BUN_INSTALL_CACHE_DIR: path.join(cacheDir, "bun"),
    CI: "",
    COREPACK_HOME: path.join(cacheDir, "corepack"),
    NPM_CONFIG_CACHE: path.join(cacheDir, "npm"),
    PNPM_HOME: path.join(cacheDir, "pnpm"),
    TEMP: tempDir,
    TMP: tempDir,
    TMPDIR: tempDir,
    XDG_CACHE_HOME: cacheDir,
    PATH: `${toolBinDir}${path.delimiter}${process.env.PATH ?? ""}`,
    npm_config_cache: path.join(cacheDir, "npm"),
  };
}

async function runCommand(input: {
  command: string;
  args: string[];
  cwd: string;
  envOverrides: EnvMap;
  acceptedExitCodes?: readonly number[];
  stdinText?: string;
}): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(input.command, input.args, {
      cwd: input.cwd,
      env: {
        ...process.env,
        ...input.envOverrides,
      },
      stdio: [
        input.stdinText === undefined ? "ignore" : "pipe",
        "pipe",
        "pipe",
      ],
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

    if (input.stdinText !== undefined) {
      child.stdin?.end(input.stdinText);
    }

    child.on("error", reject);
    child.on("close", (exitCode) => {
      const result = { stdout, stderr, exitCode };
      const acceptedExitCodes = input.acceptedExitCodes ?? [0];

      if (exitCode !== null && acceptedExitCodes.includes(exitCode)) {
        resolve(result);
        return;
      }

      reject(
        new Error(
          [
            `Command failed: ${input.command} ${input.args.join(" ")}`,
            `exitCode: ${exitCode ?? "null"}`,
            stderr.trim(),
            stdout.trim(),
          ]
            .filter(Boolean)
            .join("\n"),
        ),
      );
    });
  });
}

async function createProject(manager: PackageManager): Promise<{
  projectDir: string;
  envOverrides: EnvMap;
}> {
  const projectDir = await mkdtemp(
    path.join(os.tmpdir(), `pkg-audit-fix-e2e-${manager}-`),
  );
  tempProjects.push(projectDir);

  const envOverrides = buildEnvOverrides(projectDir);

  await mkdir(path.join(projectDir, ".cache"), { recursive: true });
  await mkdir(path.join(projectDir, ".tmp"), { recursive: true });
  await mkdir(path.join(projectDir, ".tools", "bin"), { recursive: true });
  await writeFile(
    path.join(projectDir, "package.json"),
    `${JSON.stringify(
      {
        name: `pkg-audit-fix-e2e-${manager}`,
        private: true,
        version: "1.0.0",
      },
      null,
      2,
    )}\n`,
    "utf8",
  );

  return { projectDir, envOverrides };
}

async function writeExecutableScript(
  projectDir: string,
  name: string,
  contents: string,
): Promise<void> {
  const scriptPath = path.join(projectDir, ".tools", "bin", name);

  await writeFile(scriptPath, contents, "utf8");
  await chmod(scriptPath, 0o755);
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", `'"'"'`)}'`;
}

function tclBraceQuote(value: string): string {
  return `{${value.replaceAll("\\", "\\\\").replaceAll("{", "\\{").replaceAll("}", "\\}")}}`;
}

async function addDependencyToManifest(
  projectDir: string,
  dependency: string,
  version: string,
): Promise<void> {
  const packageJsonPath = path.join(projectDir, "package.json");
  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8")) as {
    dependencies?: Record<string, string>;
  };

  packageJson.dependencies ??= {};
  packageJson.dependencies[dependency] = version;

  await writeFile(
    packageJsonPath,
    `${JSON.stringify(packageJson, null, 2)}\n`,
    "utf8",
  );
}

async function installDependency(
  managerCase: ManagerCase,
  projectDir: string,
  envOverrides: EnvMap,
  specifier: string,
): Promise<void> {
  await runCommand({
    command: managerCase.command,
    args: ["add", specifier],
    cwd: projectDir,
    envOverrides,
  });
}

async function relaxDependencyRange(projectDir: string): Promise<void> {
  const packageJsonPath = path.join(projectDir, "package.json");
  const packageJson = JSON.parse(await readFile(packageJsonPath, "utf8")) as {
    dependencies?: Record<string, string>;
  };

  packageJson.dependencies ??= {};
  packageJson.dependencies[FIXTURE_PACKAGE.name] = FIXTURE_PACKAGE.safeRange;

  await writeFile(
    packageJsonPath,
    `${JSON.stringify(packageJson, null, 2)}\n`,
    "utf8",
  );
}

async function configureMinimumAge(
  managerCase: ManagerCase,
  projectDir: string,
): Promise<void> {
  if (managerCase.id === "pnpm") {
    await writeFile(
      path.join(projectDir, ".npmrc"),
      `minimumReleaseAge=${MINIMUM_AGE_WINDOW_DAYS * 24 * 60}\n`,
      "utf8",
    );
    return;
  }

  if (managerCase.id === "bun") {
    await writeFile(
      path.join(projectDir, "bunfig.toml"),
      `[install]\nminimumReleaseAge = ${MINIMUM_AGE_WINDOW_DAYS * 24 * 60 * 60}\n`,
      "utf8",
    );
    return;
  }

  if (managerCase.id === "yarn-berry") {
    await writeFile(
      path.join(projectDir, ".yarnrc.yml"),
      `nodeLinker: node-modules\nnpmMinimalAgeGate: "${MINIMUM_AGE_WINDOW_DAYS}d"\n`,
      "utf8",
    );
  }
}

async function assertMinimumAgeConfigUpdated(
  managerCase: ManagerCase,
  projectDir: string,
): Promise<void> {
  if (managerCase.id === "pnpm") {
    const content = await runCommand({
      command: "pnpm",
      args: [
        "config",
        "get",
        "--location=project",
        "--json",
        "minimumReleaseAgeExclude",
      ],
      cwd: projectDir,
      envOverrides: buildEnvOverrides(projectDir),
    });
    const parsed = JSON.parse(content.stdout) as string[] | string | null;
    const values = Array.isArray(parsed)
      ? parsed
      : typeof parsed === "string"
        ? [parsed]
        : [];

    expect(values.length).toBeGreaterThan(0);
    expect(values.some((value) => value.includes("@"))).toBe(true);
    return;
  }

  if (managerCase.id === "bun") {
    const content = await readFile(
      path.join(projectDir, "bunfig.toml"),
      "utf8",
    );

    expect(content).toContain("minimumReleaseAgeExcludes");
    expect(content).toMatch(/minimumReleaseAgeExcludes = \[[^\]]*"/);
    return;
  }

  if (managerCase.id === "yarn-berry") {
    const content = await readFile(
      path.join(projectDir, ".yarnrc.yml"),
      "utf8",
    );

    expect(content).toContain("npmPreapprovedPackages");
    expect(content).toMatch(/npmPreapprovedPackages:\n(?: {2}- .+\n?)+/);
  }
}

function extractFirstJsonObject(text: string): string | null {
  const start = text.indexOf("{");
  const end = text.lastIndexOf("}");

  if (start === -1 || end === -1 || end < start) {
    return null;
  }

  return text.slice(start, end + 1);
}

function readNestedNumber(
  value: unknown,
  pathSegments: readonly string[],
): number | null {
  let current = value;

  for (const segment of pathSegments) {
    if (
      typeof current !== "object" ||
      current === null ||
      Array.isArray(current)
    ) {
      return null;
    }

    current = (current as Record<string, unknown>)[segment];
  }

  return typeof current === "number" && Number.isFinite(current)
    ? current
    : null;
}

function parseAuditTotal(manager: PackageManager, stdout: string): number {
  if (manager === "yarn") {
    return stdout
      .split(/\r?\n/u)
      .map((line) => line.trim())
      .filter(Boolean)
      .reduce((count, line) => {
        try {
          const parsed = JSON.parse(line) as Record<string, unknown>;
          return typeof parsed.value === "string" &&
            typeof parsed.children === "object" &&
            parsed.children !== null
            ? count + 1
            : count;
        } catch {
          return count;
        }
      }, 0);
  }

  const candidateText = extractFirstJsonObject(stdout) ?? stdout;
  const json = JSON.parse(candidateText) as Record<string, unknown>;
  const metadataTotal = readNestedNumber(json, [
    "metadata",
    "vulnerabilities",
    "total",
  ]);

  if (metadataTotal !== null) {
    return metadataTotal;
  }

  if (manager === "bun") {
    const summaryTotal = readNestedNumber(json, ["summary", "total"]);

    if (summaryTotal !== null) {
      return summaryTotal;
    }

    return Object.entries(json).reduce((count, [key, value]) => {
      if (key === "metadata" || key === "summary" || !Array.isArray(value)) {
        return count;
      }

      return count + value.length;
    }, 0);
  }

  const fallbackKey = manager === "npm" ? "vulnerabilities" : "advisories";
  const fallbackValue = json[fallbackKey];

  if (
    typeof fallbackValue === "object" &&
    fallbackValue !== null &&
    !Array.isArray(fallbackValue)
  ) {
    return Object.keys(fallbackValue).length;
  }

  return 0;
}

async function runAudit(
  managerCase: ManagerCase,
  projectDir: string,
  envOverrides: EnvMap,
): Promise<CommandResult & { total: number }> {
  const result = await runCommand({
    command: managerCase.command,
    args: managerCase.auditArgs,
    cwd: projectDir,
    envOverrides,
    acceptedExitCodes: [0, 1],
  });

  return {
    ...result,
    total: parseAuditTotal(managerCase.manager, result.stdout),
  };
}

async function readInstalledVersion(projectDir: string): Promise<string> {
  return readDependencyVersion(projectDir, FIXTURE_PACKAGE.name);
}

async function readDependencyVersion(
  projectDir: string,
  dependency: string,
): Promise<string> {
  const packageJson = JSON.parse(
    await readFile(
      path.join(projectDir, "node_modules", dependency, "package.json"),
      "utf8",
    ),
  ) as { version?: string };

  return packageJson.version ?? "unknown";
}

async function invokeCli(
  managerCase: ManagerCase,
  projectDir: string,
  envOverrides: EnvMap,
): Promise<{ exitCode: number; summary: JsonSummary }> {
  const result = await runCommand({
    command: nodeCommand,
    args: [
      builtCliPath,
      "--cwd",
      projectDir,
      "--manager",
      managerCase.manager,
      "--json",
      "--no-color",
    ],
    cwd: root,
    envOverrides,
  });

  return {
    exitCode: result.exitCode ?? 1,
    summary: JSON.parse(result.stdout) as JsonSummary,
  };
}

async function invokeCliWithPrompt(
  managerCase: ManagerCase,
  projectDir: string,
  envOverrides: EnvMap,
): Promise<CommandResult> {
  if (!ptyCommand) {
    throw new Error(
      "Interactive minimal-age E2E tests require a PTY wrapper command",
    );
  }

  const commandText =
    process.platform === "win32"
      ? ""
      : `exec ${[
          nodeCommand,
          builtCliPath,
          "--cwd",
          projectDir,
          "--manager",
          managerCase.manager,
          "--no-color",
        ]
          .map(shellQuote)
          .join(" ")}`;
  const expectScript =
    process.platform === "win32"
      ? ""
      : [
          "log_user 1",
          "set timeout 180",
          `spawn -noecho ${shellCommand} -lc ${tclBraceQuote(commandText)}`,
          "expect {",
          '  -re {\\[y/N\\]} { send "y\\r"; exp_continue }',
          "  eof",
          "}",
          "lassign [wait] pid spawnid osError status",
          "exit $status",
        ].join("\n");

  return runCommand({
    command: ptyCommand,
    args: process.platform === "win32" ? [] : ["-c", expectScript],
    cwd: root,
    envOverrides,
  });
}

async function resolveRecentPackage(
  candidates: readonly string[] = RECENT_PACKAGE_CANDIDATES,
): Promise<RecentPackage> {
  const now = Date.now();
  const maxAgeMs = RECENT_PACKAGE_MAX_AGE_DAYS * 24 * 60 * 60 * 1000;
  const minimumAgeMs = MINIMUM_AGE_WINDOW_DAYS * 24 * 60 * 60 * 1000;

  for (const packageName of candidates) {
    const result = await runCommand({
      command: "npm",
      args: ["view", packageName, "version", "versions", "time", "--json"],
      cwd: root,
      envOverrides: {} as EnvMap,
    });
    const parsed = JSON.parse(result.stdout) as {
      version?: string;
      versions?: string[];
      time?: Record<string, string>;
    };
    const version = parsed.version;
    const publishedAt = version ? parsed.time?.[version] : undefined;
    const versions = Array.isArray(parsed.versions) ? parsed.versions : [];

    if (!version || !publishedAt || versions.length === 0) {
      continue;
    }

    const publishedMs = Date.parse(publishedAt);

    if (!Number.isFinite(publishedMs) || now - publishedMs > maxAgeMs) {
      continue;
    }

    const matureVersion = [...versions].reverse().find((candidateVersion) => {
      if (candidateVersion === version) {
        return false;
      }

      if (candidateVersion.includes("-")) {
        return false;
      }

      const candidatePublishedAt = parsed.time?.[candidateVersion];

      if (!candidatePublishedAt) {
        return false;
      }

      const candidatePublishedMs = Date.parse(candidatePublishedAt);

      return (
        Number.isFinite(candidatePublishedMs) &&
        now - candidatePublishedMs > minimumAgeMs
      );
    });

    if (!matureVersion) {
      continue;
    }

    return {
      packageName,
      version,
      specifier: `${packageName}@${version}`,
      matureVersion,
      matureSpecifier: `${packageName}@${matureVersion}`,
    };
  }

  throw new Error(
    `Unable to find a recently published package from ${candidates.join(", ")}`,
  );
}

function getManagerCase(id: ManagerCase["id"]): ManagerCase {
  const managerCase = managerCases.find((entry) => entry.id === id);

  if (!managerCase) {
    throw new Error(`Missing manager case for ${id}`);
  }

  return managerCase;
}

async function expectRealVulnerabilityRemediation(
  managerCase: ManagerCase,
): Promise<void> {
  expect(
    isManagerAvailable(managerCase.manager),
    `${managerCase.manager} must be installed to run the E2E suite`,
  ).toBe(true);

  const { projectDir, envOverrides } = await createProject(managerCase.manager);
  await managerCase.setupProject?.(projectDir);

  await runCommand({
    command: managerCase.command,
    args: managerCase.installArgs,
    cwd: projectDir,
    envOverrides,
  });
  await relaxDependencyRange(projectDir);

  const initialAudit = await runAudit(managerCase, projectDir, envOverrides);
  expect(initialAudit.exitCode).toBe(1);
  expect(initialAudit.total).toBeGreaterThan(0);

  const initialInstalledVersion = await readInstalledVersion(projectDir);
  expect(initialInstalledVersion).toBe(FIXTURE_PACKAGE.vulnerableVersion);

  const cliRun = await invokeCli(managerCase, projectDir, envOverrides);

  expect(cliRun.exitCode).toBe(0);
  expect(cliRun.summary.status).toBe("resolved-some");
  expect(cliRun.summary.initial.total).toBeGreaterThan(0);
  expect(cliRun.summary.final.total).toBe(0);
  expect(
    cliRun.summary.fixed.some(
      (entry) => entry.packageName === FIXTURE_PACKAGE.name,
    ),
  ).toBe(true);

  const finalAudit = await runAudit(managerCase, projectDir, envOverrides);
  expect(finalAudit.exitCode).toBe(0);
  expect(finalAudit.total).toBe(0);

  const finalInstalledVersion = await readInstalledVersion(projectDir);
  expect(finalInstalledVersion).not.toBe(FIXTURE_PACKAGE.vulnerableVersion);
}

async function expectMinimumAgeRecovery(
  managerCase: ManagerCase,
): Promise<void> {
  expect(
    isCommandAvailable(managerCase.command),
    `${managerCase.command} must be installed to run the E2E suite`,
  ).toBe(true);
  expect(
    ptyCommand && isCommandAvailable(ptyCommand),
    `${ptyCommand ?? "script"} must be installed to run interactive minimum-age E2E tests`,
  ).toBe(true);

  const recentPackage = await resolveRecentPackage(
    MINIMUM_AGE_RECENT_PACKAGE_CANDIDATES[managerCase.id],
  );
  const { projectDir, envOverrides } = await createProject(managerCase.manager);
  await managerCase.setupProject?.(projectDir);

  await runCommand({
    command: managerCase.command,
    args: managerCase.installArgs,
    cwd: projectDir,
    envOverrides,
  });
  await installDependency(
    managerCase,
    projectDir,
    envOverrides,
    recentPackage.matureSpecifier,
  );
  await relaxDependencyRange(projectDir);
  await addDependencyToManifest(
    projectDir,
    recentPackage.packageName,
    recentPackage.version,
  );

  const initialAudit = await runAudit(managerCase, projectDir, envOverrides);
  expect(initialAudit.exitCode).toBe(1);
  expect(initialAudit.total).toBeGreaterThan(0);
  expect(await readInstalledVersion(projectDir)).toBe(
    FIXTURE_PACKAGE.vulnerableVersion,
  );

  await configureMinimumAge(managerCase, projectDir);

  const cliRun = await invokeCliWithPrompt(
    managerCase,
    projectDir,
    envOverrides,
  );

  expect(cliRun.exitCode).toBe(0);
  await assertMinimumAgeConfigUpdated(managerCase, projectDir);

  const finalAudit = await runAudit(managerCase, projectDir, envOverrides);
  expect(finalAudit.exitCode).toBe(0);
  expect(finalAudit.total).toBe(0);
  expect(await readInstalledVersion(projectDir)).not.toBe(
    FIXTURE_PACKAGE.vulnerableVersion,
  );
}

describe.sequential("CLI vulnerability remediation", () => {
  beforeAll(async () => {
    expect(
      spawnSync(buildRunner, ["--version"], { stdio: "ignore" }).status,
      `${buildRunner} must be installed to build the CLI for E2E tests`,
    ).toBe(0);
    expect(
      spawnSync(nodeCommand, ["--version"], { stdio: "ignore" }).status,
      `${nodeCommand} must be installed to run the built CLI in E2E tests`,
    ).toBe(0);
    expect(
      spawnSync("corepack", ["--version"], { stdio: "ignore" }).status,
      "corepack must be installed to run the Yarn Berry E2E tests",
    ).toBe(0);

    await runCommand({
      command: buildRunner,
      args: ["run", "build"],
      cwd: root,
      envOverrides: {} as EnvMap,
    });
  }, E2E_TIMEOUT_MS);

  it("fixes a real npm vulnerability in a temp project", {
    timeout: E2E_TIMEOUT_MS,
  }, async () => {
    await expectRealVulnerabilityRemediation(getManagerCase("npm"));
  });

  it("fixes a real pnpm vulnerability in a temp project", {
    timeout: E2E_TIMEOUT_MS,
  }, async () => {
    await expectRealVulnerabilityRemediation(getManagerCase("pnpm"));
  });

  it("fixes a real bun vulnerability in a temp project", {
    timeout: E2E_TIMEOUT_MS,
  }, async () => {
    await expectRealVulnerabilityRemediation(getManagerCase("bun"));
  });

  it("fixes a real yarn vulnerability in a temp project", {
    timeout: E2E_TIMEOUT_MS,
  }, async () => {
    await expectRealVulnerabilityRemediation(getManagerCase("yarn-berry"));
  });

  if (ptyCommand) {
    it("recovers pnpm minimum age gating during remediation", {
      timeout: E2E_TIMEOUT_MS,
    }, async () => {
      await expectMinimumAgeRecovery(getManagerCase("pnpm"));
    });

    it("recovers bun minimum age gating during remediation", {
      timeout: E2E_TIMEOUT_MS,
    }, async () => {
      await expectMinimumAgeRecovery(getManagerCase("bun"));
    });

    it("recovers yarn-berry minimum age gating during remediation", {
      timeout: E2E_TIMEOUT_MS,
    }, async () => {
      await expectMinimumAgeRecovery(getManagerCase("yarn-berry"));
    });
  }
});
