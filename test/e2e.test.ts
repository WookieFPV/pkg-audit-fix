import { spawn, spawnSync } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { afterEach, beforeAll, describe, expect, it } from "vitest";

import type { JsonSummary, PackageManager } from "../src/index.js";
import { repoRoot } from "./helpers.js";

const FIXTURE_PACKAGE = {
  name: "brace-expansion",
  vulnerableVersion: "1.1.11",
  safeRange: "^1.1.11",
};

const E2E_TIMEOUT_MS = 120_000;
const tempProjects: string[] = [];
const root = repoRoot();
const builtCliPath = path.join(root, "dist", "cli.mjs");
const buildRunner = "bun";
const nodeCommand = process.platform === "win32" ? "node.exe" : "node";

interface ManagerCase {
  manager: PackageManager;
  installArgs: string[];
  auditArgs: string[];
}

interface CommandResult {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

type EnvMap = Bun.Env & Record<string, string>;

const managerCases: readonly ManagerCase[] = [
  {
    manager: "npm",
    installArgs: [
      "install",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json"],
  },
  {
    manager: "pnpm",
    installArgs: [
      "add",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json", "--audit-level=low"],
  },
  {
    manager: "bun",
    installArgs: [
      "add",
      `${FIXTURE_PACKAGE.name}@${FIXTURE_PACKAGE.vulnerableVersion}`,
    ],
    auditArgs: ["audit", "--json", "--audit-level=low"],
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

function buildEnvOverrides(projectDir: string): EnvMap {
  const cacheDir = path.join(projectDir, ".cache");
  const tempDir = path.join(projectDir, ".tmp");

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
    npm_config_cache: path.join(cacheDir, "npm"),
  };
}

async function runCommand(input: {
  command: string;
  args: string[];
  cwd: string;
  envOverrides: EnvMap;
  acceptedExitCodes?: readonly number[];
}): Promise<CommandResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(input.command, input.args, {
      cwd: input.cwd,
      env: {
        ...process.env,
        ...input.envOverrides,
      },
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (chunk: Buffer) => {
      stdout += chunk.toString();
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      stderr += chunk.toString();
    });

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
  const json = JSON.parse(stdout) as Record<string, unknown>;
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
    command: managerCase.manager,
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
  const packageJson = JSON.parse(
    await readFile(
      path.join(
        projectDir,
        "node_modules",
        FIXTURE_PACKAGE.name,
        "package.json",
      ),
      "utf8",
    ),
  ) as { version?: string };

  return packageJson.version ?? "unknown";
}

async function invokeCli(
  manager: PackageManager,
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
      manager,
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

    await runCommand({
      command: buildRunner,
      args: ["run", "build"],
      cwd: root,
      envOverrides: {} as EnvMap,
    });
  }, E2E_TIMEOUT_MS);

  for (const managerCase of managerCases) {
    it(`fixes a real ${managerCase.manager} vulnerability in a temp project`, {
      timeout: E2E_TIMEOUT_MS,
    }, async () => {
      expect(
        isManagerAvailable(managerCase.manager),
        `${managerCase.manager} must be installed to run the E2E suite`,
      ).toBe(true);

      const { projectDir, envOverrides } = await createProject(
        managerCase.manager,
      );

      await runCommand({
        command: managerCase.manager,
        args: managerCase.installArgs,
        cwd: projectDir,
        envOverrides,
      });
      await relaxDependencyRange(projectDir);

      const initialAudit = await runAudit(
        managerCase,
        projectDir,
        envOverrides,
      );
      expect(initialAudit.exitCode).toBe(1);
      expect(initialAudit.total).toBeGreaterThan(0);

      const initialInstalledVersion = await readInstalledVersion(projectDir);
      expect(initialInstalledVersion).toBe(FIXTURE_PACKAGE.vulnerableVersion);

      const cliRun = await invokeCli(
        managerCase.manager,
        projectDir,
        envOverrides,
      );

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
    });
  }
});
