#!/usr/bin/env node

import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { runAuditFix } from "./core/run.js";
import {
  type AuditLevel,
  type AuditScope,
  CliUsageError,
  type DedupeMode,
  ManagerDetectionError,
  type PackageManagerOverride,
} from "./core/types.js";
import { toJsonSummary } from "./reporters/json.js";
import { createStepLifecycleReporter } from "./reporters/steps.js";
import { formatFailure, formatTextSummary } from "./reporters/text.js";

const HELP_TEXT = `pkg-audit-fix

Usage:
  pkg-audit-fix [options]

Options:
  --cwd <path>                         Project directory, defaults to process.cwd()
  --manager <auto|pnpm|npm|bun>       Override package manager detection
  --prod                               Audit production dependencies only
  --dev                                Audit development dependencies only
  --audit-level <low|moderate|high|critical>
                                       Minimum advisory level, defaults to moderate
  --dedupe <auto|always|never>         Run a dedupe pass after fixes when supported, defaults to auto
  --dry-run                            Run initial and final audits only
  --json                               Emit a machine-readable final summary
  --verbose                            Stream subprocess output during successful runs
  --no-color                           Disable ANSI output
  --version                            Print the package version
  --help                               Print this help
`;

interface CliOptions {
  cwd: string;
  manager: PackageManagerOverride;
  scope: AuditScope;
  threshold: AuditLevel;
  dedupe: DedupeMode;
  dryRun: boolean;
  json: boolean;
  verbose: boolean;
  color: boolean;
  help: boolean;
  version: boolean;
}

function readPackageVersion(): string {
  return "0.1.0";
}

function expectValue(argv: string[], index: number, flag: string): string {
  const value = argv[index + 1];

  if (!value || value.startsWith("--")) {
    throw new CliUsageError(`Missing value for ${flag}`);
  }

  return value;
}

function parseManager(value: string): PackageManagerOverride {
  if (
    value === "auto" ||
    value === "pnpm" ||
    value === "npm" ||
    value === "bun"
  ) {
    return value;
  }

  throw new CliUsageError(`Invalid --manager value: ${value}`);
}

function parseAuditLevel(value: string): AuditLevel {
  if (
    value === "low" ||
    value === "moderate" ||
    value === "high" ||
    value === "critical"
  ) {
    return value;
  }

  throw new CliUsageError(`Invalid --audit-level value: ${value}`);
}

function parseDedupeMode(value: string): DedupeMode {
  if (value === "auto" || value === "always" || value === "never") {
    return value;
  }

  throw new CliUsageError(`Invalid --dedupe value: ${value}`);
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    cwd: process.cwd(),
    manager: "auto",
    scope: "all",
    threshold: "moderate",
    dedupe: "auto",
    dryRun: false,
    json: false,
    verbose: false,
    color: !process.env.NO_COLOR,
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help") {
      options.help = true;
      continue;
    }

    if (arg === "--version") {
      options.version = true;
      continue;
    }

    if (arg === "--prod") {
      options.scope = "prod";
      continue;
    }

    if (arg === "--dev") {
      options.scope = "dev";
      continue;
    }

    if (arg === "--dry-run") {
      options.dryRun = true;
      continue;
    }

    if (arg === "--dedupe") {
      options.dedupe = parseDedupeMode(expectValue(argv, index, "--dedupe"));
      index += 1;
      continue;
    }

    if (arg.startsWith("--dedupe=")) {
      options.dedupe = parseDedupeMode(arg.slice("--dedupe=".length));
      continue;
    }

    if (arg === "--json") {
      options.json = true;
      continue;
    }

    if (arg === "--verbose") {
      options.verbose = true;
      continue;
    }

    if (arg === "--no-color") {
      options.color = false;
      continue;
    }

    if (arg === "--cwd") {
      options.cwd = path.resolve(expectValue(argv, index, "--cwd"));
      index += 1;
      continue;
    }

    if (arg.startsWith("--cwd=")) {
      options.cwd = path.resolve(arg.slice("--cwd=".length));
      continue;
    }

    if (arg === "--manager") {
      options.manager = parseManager(expectValue(argv, index, "--manager"));
      index += 1;
      continue;
    }

    if (arg.startsWith("--manager=")) {
      options.manager = parseManager(arg.slice("--manager=".length));
      continue;
    }

    if (arg === "--audit-level") {
      options.threshold = parseAuditLevel(
        expectValue(argv, index, "--audit-level"),
      );
      index += 1;
      continue;
    }

    if (arg.startsWith("--audit-level=")) {
      options.threshold = parseAuditLevel(arg.slice("--audit-level=".length));
      continue;
    }

    throw new CliUsageError(`Unknown option: ${arg}`);
  }

  return options;
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

  const stepReporter = createStepLifecycleReporter({
    enabled: !options.json,
    color: options.color,
    verbose: options.verbose,
    isInteractive: Boolean(process.stdout.isTTY),
    write: (text) => {
      process.stdout.write(text);
    },
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
      },
    },
  );

  if (options.json) {
    process.stdout.write(`${JSON.stringify(toJsonSummary(result), null, 2)}\n`);
  } else {
    process.stdout.write(`${formatTextSummary(result)}\n`);
  }

  return result.exitCode;
}

const invokedDirectly = process.argv[1]
  ? path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url))
  : false;

if (invokedDirectly) {
  main()
    .then((exitCode) => {
      process.exitCode = exitCode;
    })
    .catch((error: unknown) => {
      const wantsJsonError = process.argv.includes("--json");

      if (error instanceof ManagerDetectionError) {
        process.stderr.write(
          wantsJsonError
            ? `${JSON.stringify({ error: { message: error.message, exitCode: error.exitCode } }, null, 2)}\n`
            : `${formatFailure(error)}\n`,
        );
        process.exitCode = error.exitCode;
        return;
      }

      if (error instanceof CliUsageError) {
        process.stderr.write(
          wantsJsonError
            ? `${JSON.stringify({ error: { message: error.message, exitCode: 1 } }, null, 2)}\n`
            : `${error.message}\n`,
        );
        process.exitCode = 1;
        return;
      }

      process.stderr.write(
        wantsJsonError
          ? `${JSON.stringify({ error: { message: formatFailure(error), exitCode: 1 } }, null, 2)}\n`
          : `${formatFailure(error)}\n`,
      );
      process.exitCode = 1;
    });
}
