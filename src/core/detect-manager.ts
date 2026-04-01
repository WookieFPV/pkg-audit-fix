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
  const coerced = coerceDetection(detected);

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
  const detectedManager = coerceDetection(detected);

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

  const userAgentManager = coerceDetection(userAgent);

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
