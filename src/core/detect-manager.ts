import fs from "node:fs/promises";
import path from "node:path";

import type {
  AgentName as DetectedAgentName,
  DetectResult as PackageManagerDetectResult,
} from "package-manager-detector";
import { detect, getUserAgent } from "package-manager-detector/detect";

import {
  type DetectionResult,
  ManagerDetectionError,
  type PackageManagerAgent,
  type PackageManagerOverride,
} from "./types.js";

const DETECTION_STRATEGIES = [
  "install-metadata",
  "lockfile",
  "packageManager-field",
  "devEngines-field",
] as const;

const YARN_BERRY_HINT_FILES = [".yarnrc.yml", ".pnp.cjs", ".pnp.js"] as const;
const YARN_BERRY_HINT_DIRS = [".yarn"] as const;

async function pathExists(
  target: string,
  type: "file" | "dir",
): Promise<boolean> {
  try {
    const stat = await fs.stat(target);
    return type === "file" ? stat.isFile() : stat.isDirectory();
  } catch {
    return false;
  }
}

function* lookupDirectories(cwd: string): Generator<string> {
  let directory = path.resolve(cwd);
  const { root } = path.parse(directory);

  while (true) {
    yield directory;

    if (directory === root) {
      break;
    }

    directory = path.dirname(directory);
  }
}

async function detectYarnAgentFromFilesystem(
  cwd: string,
): Promise<Extract<PackageManagerAgent, "yarn" | "yarn@berry">> {
  let sawBerryHint = false;

  for (const directory of lookupDirectories(cwd)) {
    const hasBerryHint = (
      await Promise.all([
        ...YARN_BERRY_HINT_FILES.map((entry) =>
          pathExists(path.join(directory, entry), "file"),
        ),
        ...YARN_BERRY_HINT_DIRS.map((entry) =>
          pathExists(path.join(directory, entry), "dir"),
        ),
      ])
    ).some(Boolean);

    if (hasBerryHint) {
      sawBerryHint = true;
    }

    if (await pathExists(path.join(directory, "yarn.lock"), "file")) {
      return hasBerryHint ? "yarn@berry" : "yarn";
    }
  }

  return sawBerryHint ? "yarn@berry" : "yarn";
}

async function resolveDetectedAgent(
  cwd: string,
  detection: Pick<DetectionResult, "manager" | "agent"> | null,
): Promise<Pick<DetectionResult, "manager" | "agent"> | null> {
  if (!detection) {
    return null;
  }

  if (detection.manager === "yarn" && detection.agent === "yarn") {
    return {
      manager: detection.manager,
      agent: await detectYarnAgentFromFilesystem(cwd),
    };
  }

  return detection;
}

function coerceDetection(
  value: DetectedAgentName | PackageManagerDetectResult | null | undefined,
): Pick<DetectionResult, "manager" | "agent"> | null {
  const manager = typeof value === "string" ? value : value?.name;
  const agent = typeof value === "string" ? value : (value?.agent ?? manager);

  if (manager === "pnpm") {
    return {
      manager,
      agent: agent === "pnpm@6" ? "pnpm@6" : "pnpm",
    };
  }

  if (manager === "yarn") {
    return {
      manager,
      agent: agent === "yarn@berry" ? "yarn@berry" : "yarn",
    };
  }

  if (manager === "npm" || manager === "bun") {
    return {
      manager,
      agent: manager,
    };
  }

  return null;
}

async function detectAgentForOverride(
  cwd: string,
  override: Exclude<PackageManagerOverride, "auto">,
  detectFn: typeof detect,
): Promise<PackageManagerAgent> {
  if (override !== "yarn") {
    return override;
  }

  const detected = await Promise.resolve(
    detectFn({
      cwd,
      strategies: [...DETECTION_STRATEGIES],
    }),
  ).catch(() => null);
  const coerced = await resolveDetectedAgent(cwd, coerceDetection(detected));

  if (coerced?.manager === override) {
    return coerced.agent;
  }

  return override;
}

export async function detectPackageManager(
  input: {
    cwd: string;
    override: PackageManagerOverride;
  },
  dependencies: {
    detectFn?: typeof detect;
    getUserAgentFn?: typeof getUserAgent;
  } = {},
): Promise<DetectionResult> {
  const detectFn = dependencies.detectFn ?? detect;
  const getUserAgentFn = dependencies.getUserAgentFn ?? getUserAgent;

  if (input.override !== "auto") {
    return {
      manager: input.override,
      agent: await detectAgentForOverride(input.cwd, input.override, detectFn),
      source: "override",
    };
  }

  const detected = await detectFn({
    cwd: input.cwd,
    strategies: [...DETECTION_STRATEGIES],
  }).catch(() => null);
  const detectedManager = await resolveDetectedAgent(
    input.cwd,
    coerceDetection(detected),
  );

  if (detectedManager) {
    return {
      manager: detectedManager.manager,
      agent: detectedManager.agent,
      source: "filesystem",
    };
  }

  let userAgent: DetectedAgentName | null = null;

  try {
    userAgent = await Promise.resolve(getUserAgentFn());
  } catch {
    userAgent = null;
  }

  const userAgentManager = await resolveDetectedAgent(
    input.cwd,
    coerceDetection(userAgent),
  );

  if (userAgentManager) {
    return {
      manager: userAgentManager.manager,
      agent: userAgentManager.agent,
      source: "user-agent",
    };
  }

  throw new ManagerDetectionError(
    "Could not detect a supported package manager. Re-run with --manager pnpm|npm|yarn|bun.",
  );
}
