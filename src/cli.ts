#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import * as readline from "node:readline/promises";
import { fileURLToPath } from "node:url";

import { runAuditFix } from "./core/run.js";
import {
  type AuditLevel,
  type AuditScope,
  CliUsageError,
  type ConfirmMinimumReleaseAgeExclusionsInput,
  type DedupeMode,
  ManagerDetectionError,
  type PackageManagerOverride,
} from "./core/types.js";
import { toJsonSummary } from "./reporters/json.js";
import { createStepLifecycleReporter } from "./reporters/steps.js";
import {
  formatFailure,
  formatTextSummary,
  formatVulnerabilityList,
} from "./reporters/text.js";

const HELP_TEXT = `pkg-audit-fix

Usage:
  pkg-audit-fix [options]

Options:
  --cwd <path>                         Project directory, defaults to process.cwd()
  --manager <auto|pnpm|npm|yarn|bun>   Override package manager detection
  --prod                               Audit production dependencies only
  --dev                                Audit development dependencies only
  --audit-level <low|moderate|high|critical>
                                       Minimum advisory level, defaults to low
  --dedupe <auto|always|never>         Run a dedupe pass after fixes when supported, defaults to auto
  --dry-run                            Run initial and final audits only
  --json                               Emit a machine-readable final summary
  -d, --debug                          Print detected package manager and enable command echoing
  --show-commands                      Print each package-manager command before it runs
  --verbose                            Stream subprocess output during successful runs
  --no-color                           Disable ANSI output
  -v, --version                        Print the package version
  -h, --help                           Print this help
`;

const MANAGER_OVERRIDES = [
  "auto",
  "pnpm",
  "npm",
  "yarn",
  "bun",
] as const satisfies readonly PackageManagerOverride[];

const AUDIT_LEVELS = [
  "low",
  "moderate",
  "high",
  "critical",
] as const satisfies readonly AuditLevel[];

const DEDUPE_MODES = [
  "auto",
  "always",
  "never",
] as const satisfies readonly DedupeMode[];

interface CliOptions {
  cwd: string;
  manager: PackageManagerOverride;
  scope: AuditScope;
  threshold: AuditLevel;
  dedupe: DedupeMode;
  dryRun: boolean;
  json: boolean;
  debug: boolean;
  showCommands: boolean;
  verbose: boolean;
  color: boolean;
  help: boolean;
  version: boolean;
}

function readPackageVersion(): string {
  const packageJsonPath = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "..",
    "package.json",
  );

  try {
    const parsed = JSON.parse(fs.readFileSync(packageJsonPath, "utf8"));
    if (parsed && typeof parsed.version === "string") {
      return parsed.version;
    }
  } catch {
    // Fall through to the unknown marker if package.json is unreadable.
  }

  return "0.0.0-unknown";
}

function parseEnum<T extends string>(
  flag: string,
  allowed: readonly T[],
  value: string,
): T {
  if ((allowed as readonly string[]).includes(value)) {
    return value as T;
  }

  throw new CliUsageError(`Invalid ${flag} value: ${value}`);
}

/** Flags that toggle a boolean option, keyed by every accepted spelling. */
const BOOLEAN_FLAGS: Record<string, (options: CliOptions) => void> = {
  "--help": (options) => {
    options.help = true;
  },
  "-h": (options) => {
    options.help = true;
  },
  "--version": (options) => {
    options.version = true;
  },
  "-v": (options) => {
    options.version = true;
  },
  "--prod": (options) => {
    options.scope = "prod";
  },
  "--dev": (options) => {
    options.scope = "dev";
  },
  "--dry-run": (options) => {
    options.dryRun = true;
  },
  "--json": (options) => {
    options.json = true;
  },
  "--debug": (options) => {
    options.debug = true;
  },
  "-d": (options) => {
    options.debug = true;
  },
  "--show-commands": (options) => {
    options.showCommands = true;
  },
  "--verbose": (options) => {
    options.verbose = true;
  },
  "--no-color": (options) => {
    options.color = false;
  },
};

/** Flags taking a value, accepted as both `--flag value` and `--flag=value`. */
const VALUE_FLAGS: Record<
  string,
  (options: CliOptions, value: string) => void
> = {
  "--cwd": (options, value) => {
    options.cwd = path.resolve(value);
  },
  "--manager": (options, value) => {
    options.manager = parseEnum("--manager", MANAGER_OVERRIDES, value);
  },
  "--audit-level": (options, value) => {
    options.threshold = parseEnum("--audit-level", AUDIT_LEVELS, value);
  },
  "--dedupe": (options, value) => {
    options.dedupe = parseEnum("--dedupe", DEDUPE_MODES, value);
  },
};

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    cwd: process.cwd(),
    manager: "auto",
    scope: "all",
    threshold: "low",
    dedupe: "auto",
    dryRun: false,
    json: false,
    debug: false,
    showCommands: false,
    verbose: false,
    color: !process.env.NO_COLOR,
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index] ?? "";
    const applyBoolean = BOOLEAN_FLAGS[arg];

    if (applyBoolean) {
      applyBoolean(options);
      continue;
    }

    const separatorIndex = arg.indexOf("=");
    const flag = separatorIndex === -1 ? arg : arg.slice(0, separatorIndex);
    const applyValue = VALUE_FLAGS[flag];

    if (!applyValue) {
      throw new CliUsageError(`Unknown option: ${arg}`);
    }

    if (separatorIndex !== -1) {
      applyValue(options, arg.slice(separatorIndex + 1));
      continue;
    }

    const value = argv[index + 1];

    if (!value || value.startsWith("--")) {
      throw new CliUsageError(`Missing value for ${flag}`);
    }

    applyValue(options, value);
    index += 1;
  }

  return options;
}

async function confirmPnpmMinimumReleaseAgeExclusions(
  input: ConfirmMinimumReleaseAgeExclusionsInput & {
    output: NodeJS.WriteStream;
  },
): Promise<boolean> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: input.output,
  });
  const packageList = input.packages.join(", ");

  try {
    const answer = await rl.question(
      `${input.manager} blocked ${packageList} because of minimumReleaseAge. Update ${input.configSetting} and retry? [y/N] `,
    );

    return /^(y|yes)$/i.test(answer.trim());
  } finally {
    rl.close();
  }
}

async function promptBunManualRemediation(input: {
  initial: { entries: Parameters<typeof formatVulnerabilityList>[0] };
  output: NodeJS.WriteStream;
}): Promise<void> {
  const rl = readline.createInterface({
    input: process.stdin,
    output: input.output,
  });
  const vulnerabilityList = formatVulnerabilityList(input.initial.entries);

  try {
    input.output.write(
      [
        "bun does not support audit --fix. Fix these vulnerabilities manually, then press Enter to run a final audit.",
        "",
        "Current vulnerabilities:",
        vulnerabilityList,
        "",
      ].join("\n"),
    );
    await rl.question("Press Enter to continue ");
  } finally {
    rl.close();
  }
}

export async function main(argv = process.argv.slice(2)): Promise<number> {
  const options = parseArgs(argv);

  if (options.help) {
    process.stdout.write(`${HELP_TEXT}\n`);
    return 0;
  }

  if (options.version) {
    process.stdout.write(`${readPackageVersion()}\n`);
    return 0;
  }

  if (!options.color) {
    process.env.NO_COLOR = "1";
  }

  const showCommands = options.showCommands || options.verbose || options.debug;
  const diagnosticsWrite = (text: string) =>
    options.json ? process.stderr.write(text) : process.stdout.write(text);
  const promptOutput =
    options.json || process.stderr.isTTY ? process.stderr : process.stdout;
  const canConfirmPnpmMinimumReleaseAgeExclusions =
    process.stdin.isTTY &&
    (options.json
      ? process.stderr.isTTY
      : process.stderr.isTTY || process.stdout.isTTY);
  const stepReporter = createStepLifecycleReporter({
    enabled: !options.json || options.debug || showCommands,
    color: options.color,
    verbose: options.verbose,
    showCommands,
    isInteractive: Boolean(process.stdout.isTTY),
    write: diagnosticsWrite,
  });

  const result = await runAuditFix(
    {
      cwd: options.cwd,
      manager: options.manager,
      scope: options.scope,
      threshold: options.threshold,
      dedupe: options.dedupe,
      dryRun: options.dryRun,
      verbose: options.verbose,
    },
    {
      confirmPnpmMinimumReleaseAgeExclusions:
        canConfirmPnpmMinimumReleaseAgeExclusions
          ? (input) =>
              confirmPnpmMinimumReleaseAgeExclusions({
                manager: input.manager,
                configSetting: input.configSetting,
                packages: input.packages,
                output: promptOutput,
              })
          : undefined,
      promptBunManualRemediation:
        !options.json && canConfirmPnpmMinimumReleaseAgeExclusions
          ? (input) =>
              promptBunManualRemediation({
                initial: input.initial,
                output: promptOutput,
              })
          : undefined,
      hooks: {
        onStepStart: (step) => {
          stepReporter.start(step);
        },
        onStepComplete: (step) => {
          stepReporter.complete(step);
        },
        onStepFail: (step) => {
          stepReporter.fail(step);
        },
        onInteractivePrompt: () => {
          stepReporter.pause();
        },
      },
      onManagerDetected: (detection) => {
        if (!options.debug) {
          return;
        }

        diagnosticsWrite(`Detected package manager: ${detection.manager}\n`);
      },
    },
  );

  if (options.json) {
    process.stdout.write(`${JSON.stringify(toJsonSummary(result), null, 2)}\n`);
  } else {
    if (stepReporter.hasOutput()) {
      process.stdout.write("\n");
    }

    process.stdout.write(`${formatTextSummary(result)}\n`);
  }

  return result.exitCode;
}

function resolveExecutablePath(filePath: string): string {
  try {
    return fs.realpathSync(filePath);
  } catch {
    return path.resolve(filePath);
  }
}

const invokedDirectly = process.argv[1]
  ? resolveExecutablePath(process.argv[1]) ===
    resolveExecutablePath(fileURLToPath(import.meta.url))
  : false;

if (invokedDirectly) {
  main()
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error: unknown) => {
      const exitCode =
        error instanceof ManagerDetectionError ? error.exitCode : 1;
      const message =
        error instanceof CliUsageError ? error.message : formatFailure(error);

      process.stderr.write(
        process.argv.includes("--json")
          ? `${JSON.stringify({ error: { message, exitCode } }, null, 2)}\n`
          : `${message}\n`,
      );
      process.exitCode = exitCode;
    });
}
