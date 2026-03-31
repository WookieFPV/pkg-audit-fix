import type {
  AgentName as DetectedAgentName,
  DetectResult as PackageManagerDetectResult,
} from "package-manager-detector";
import { detect, getUserAgent } from "package-manager-detector/detect";

import {
  type DetectionResult,
  ManagerDetectionError,
  type PackageManagerOverride,
} from "./types.js";

const DETECTION_STRATEGIES = [
  "install-metadata",
  "lockfile",
  "packageManager-field",
  "devEngines-field",
] as const;

function coerceManager(
  value: DetectedAgentName | PackageManagerDetectResult | null | undefined,
): DetectionResult["manager"] | null {
  const manager = typeof value === "string" ? value : value?.name;

  if (manager === "pnpm" || manager === "npm" || manager === "bun") {
    return manager;
  }

  return null;
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
      source: "override",
    };
  }

  const detected = await detectFn({
    cwd: input.cwd,
    strategies: [...DETECTION_STRATEGIES],
  }).catch(() => null);
  const detectedManager = coerceManager(detected);

  if (detectedManager) {
    return {
      manager: detectedManager,
      source: "filesystem",
    };
  }

  let userAgent: DetectedAgentName | null = null;

  try {
    userAgent = await Promise.resolve(getUserAgentFn());
  } catch {
    userAgent = null;
  }

  const userAgentManager = coerceManager(userAgent);

  if (userAgentManager) {
    return {
      manager: userAgentManager,
      source: "user-agent",
    };
  }

  throw new ManagerDetectionError(
    "Could not detect a supported package manager. Re-run with --manager pnpm|npm|bun.",
  );
}
