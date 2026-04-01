#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

import { formatCount } from "./core/normalize.js";
import { createAuditSession, runAuditFix } from "./core/run.js";
import {
  type AuditLevel,
  type AuditScope,
  type AuditSession,
  CliUsageError,
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
  --manager <auto|pnpm|npm|yarn|bun>  Override package manager detection
  --prod                               Audit production dependencies only
  --dev                                Audit development dependencies only
  --audit-level <low|moderate|high|critical>
                                       Minimum advisory level, defaults to low
  --dedupe <auto|always|never>         Run a dedupe pass after fixes when supported, defaults to auto
  --dry-run                            Run initial and final audits only
  --manual                             Run an interactive manual remediation loop
  --json                               Emit a machine-readable final summary
  -d, --debug                          Print detected package manager and enable command echoing
  --show-commands                      Print each package-manager command before it runs
  --verbose                            Stream subprocess output during successful runs
  --no-color                           Disable ANSI output
  -v, --version                        Print the package version
  -h, --help                           Print this help
`;

interface CliOptions {
  cwd: string;
  manager: PackageManagerOverride;
  scope: AuditScope;
  threshold: AuditLevel;
  dedupe: DedupeMode;
  dryRun: boolean;
  manual: boolean;
  json: boolean;
  debug: boolean;
  showCommands: boolean;
  verbose: boolean;
  color: boolean;
  help: boolean;
  version: boolean;
}

type ManualActionId =
  | "audit-fix"
  | "dedupe"
  | "print-result"
  | "list-vulnerabilities"
  | "finish";

interface ManualMenuOption {
  key: string;
  label: string;
  action: ManualActionId;
}

interface CliDependencies {
  runAuditFixImpl?: typeof runAuditFix;
  createAuditSessionImpl?: typeof createAuditSession;
  selectManualAction?:
    | ((context: {
        supportsRemediation: boolean;
        supportsDedupe: boolean;
        write: (text: string) => void;
      }) => Promise<string>)
    | undefined;
  stdout?: Pick<typeof process.stdout, "write" | "isTTY"> | undefined;
  stderr?: Pick<typeof process.stderr, "write"> | undefined;
  stdin?: Pick<typeof process.stdin, "isTTY"> | undefined;
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
    value === "yarn" ||
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
    threshold: "low",
    dedupe: "auto",
    dryRun: false,
    manual: false,
    json: false,
    debug: false,
    showCommands: false,
    verbose: false,
    color: !process.env.NO_COLOR,
    help: false,
    version: false,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];

    if (arg === "--help" || arg === "-h") {
      options.help = true;
      continue;
    }

    if (arg === "--version" || arg === "-v") {
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

    if (arg === "--manual") {
      options.manual = true;
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

    if (arg === "--debug" || arg === "-d") {
      options.debug = true;
      continue;
    }

    if (arg === "--show-commands") {
      options.showCommands = true;
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

function formatManualActionResult(action: string, fixedCount: number): string {
  return `${action} fixed ${formatCount(fixedCount)}.`;
}

function buildManualMenuOptions(input: {
  supportsRemediation: boolean;
  supportsDedupe: boolean;
}): ManualMenuOption[] {
  const options: Array<Omit<ManualMenuOption, "key">> = [];

  if (input.supportsRemediation) {
    options.push({
      label: "audit-fix",
      action: "audit-fix",
    });
  }

  if (input.supportsDedupe) {
    options.push({
      label: "dedupe",
      action: "dedupe",
    });
  }

  options.push(
    {
      label: "print result",
      action: "print-result",
    },
    {
      label: "list all vulnerabilities",
      action: "list-vulnerabilities",
    },
    {
      label: "finish",
      action: "finish",
    },
  );

  return options.map((option, index) => ({
    key: String.fromCharCode(65 + index),
    ...option,
  }));
}

async function defaultSelectManualAction(context: {
  supportsRemediation: boolean;
  supportsDedupe: boolean;
  write: (text: string) => void;
}): Promise<string> {
  const lines = [
    "Choose an action:",
    ...buildManualMenuOptions(context).map(
      (option) => `  ${option.key}. ${option.label}`,
    ),
  ];

  context.write(`${lines.join("\n")}\n`);

  const { createInterface } = await import("node:readline/promises");
  const rl = createInterface({
    input: process.stdin,
    output: process.stdout,
  });

  try {
    return (await rl.question("Select action: ")).trim().toUpperCase();
  } finally {
    rl.close();
  }
}

async function runManualMode(
  options: CliOptions,
  session: AuditSession,
  selectManualAction: NonNullable<CliDependencies["selectManualAction"]>,
  write: (text: string) => void,
): Promise<number> {
  write(
    `manual mode: initial audit found ${formatCount(session.initial.total)}\n\n`,
  );

  while (true) {
    const menuOptions = buildManualMenuOptions({
      supportsRemediation: session.supportsRemediation,
      supportsDedupe: session.supportsDedupe,
    });
    const choice = await selectManualAction({
      supportsRemediation: session.supportsRemediation,
      supportsDedupe: session.supportsDedupe,
      write,
    });
    const selectedOption = menuOptions.find((option) => option.key === choice);

    if (!selectedOption) {
      write(
        `Select ${menuOptions.map((option) => option.key).join(", ")}.\n\n`,
      );
      continue;
    }

    if (selectedOption.action === "audit-fix") {
      const outcome = await session.applyFixes({
        auditLabel: "Recheck after fixes",
      });

      if (!outcome) {
        write("audit-fix is not supported by this package manager.\n\n");
        continue;
      }

      write(
        `${formatManualActionResult("audit-fix", outcome.fixedCount)}\nremaining: ${formatCount(outcome.remainingCount)}\n\n`,
      );
      continue;
    }

    if (selectedOption.action === "dedupe") {
      const outcome = await session.dedupe({
        auditLabel: "Recheck after dedupe",
      });

      if (!outcome) {
        write("dedupe is not supported by this package manager.\n\n");
        continue;
      }

      write(
        `${formatManualActionResult("dedupe", outcome.fixedCount)}\nremaining: ${formatCount(outcome.remainingCount)}\n\n`,
      );
      continue;
    }

    if (selectedOption.action === "print-result") {
      const outcome = await session.auditCurrent("Refresh audit");
      write(
        `${formatManualActionResult("print result", outcome.fixedCount)}\nremaining: ${formatCount(outcome.remainingCount)}\n\n`,
      );
      write(
        `${formatTextSummary(
          session.toResult({ dedupe: options.dedupe, dryRun: false }),
        )}\n\n`,
      );
      continue;
    }

    if (selectedOption.action === "list-vulnerabilities") {
      const outcome = await session.auditCurrent("Refresh audit");
      write(
        `${formatManualActionResult("list all vulnerabilities", outcome.fixedCount)}\nremaining: ${formatCount(outcome.remainingCount)}\n\n`,
      );
      write(`${formatVulnerabilityList(session.current)}\n\n`);
      continue;
    }

    const outcome = await session.auditCurrent("Final audit");
    const result = session.toResult({ dedupe: options.dedupe, dryRun: false });

    write(
      `${formatManualActionResult("finish", outcome.fixedCount)}\nremaining: ${formatCount(outcome.remainingCount)}\n\n`,
    );
    write(`${formatTextSummary(result)}\n`);
    return result.exitCode;
  }
}

export async function main(
  argv = process.argv.slice(2),
  dependencies: CliDependencies = {},
): Promise<number> {
  const options = parseArgs(argv);
  const stdout = dependencies.stdout ?? process.stdout;
  const stderr = dependencies.stderr ?? process.stderr;
  const stdin = dependencies.stdin ?? process.stdin;
  const runAuditFixImpl = dependencies.runAuditFixImpl ?? runAuditFix;
  const createAuditSessionImpl =
    dependencies.createAuditSessionImpl ?? createAuditSession;
  const selectManualAction =
    dependencies.selectManualAction ?? defaultSelectManualAction;

  if (options.help) {
    stdout.write(`${HELP_TEXT}\n`);
    return 0;
  }

  if (options.version) {
    stdout.write(`${readPackageVersion()}\n`);
    return 0;
  }

  if (options.manual && options.json) {
    throw new CliUsageError("--manual cannot be combined with --json");
  }

  if (options.manual && options.dryRun) {
    throw new CliUsageError("--manual cannot be combined with --dry-run");
  }

  if (options.manual && (!stdin.isTTY || !stdout.isTTY)) {
    throw new CliUsageError("--manual requires an interactive terminal");
  }

  if (!options.color) {
    process.env.NO_COLOR = "1";
  }

  const showCommands = options.showCommands || options.verbose || options.debug;
  const diagnosticsWrite = (text: string) =>
    options.json ? stderr.write(text) : stdout.write(text);
  const stepReporter = createStepLifecycleReporter({
    enabled: !options.json || options.debug || showCommands,
    color: options.color,
    verbose: options.verbose,
    showCommands,
    isInteractive: Boolean(stdout.isTTY),
    write: diagnosticsWrite,
  });

  const runOptions = {
    cwd: options.cwd,
    manager: options.manager,
    scope: options.scope,
    threshold: options.threshold,
    dedupe: options.dedupe,
    dryRun: options.dryRun,
    verbose: options.verbose,
  };
  const dependenciesForRun = {
    hooks: {
      onStepStart: (step: { label: string; command: readonly string[] }) => {
        stepReporter.start(step);
      },
      onStepComplete: (step: { label: string; command: readonly string[] }) => {
        stepReporter.complete(step);
      },
      onStepFail: (step: { label: string; command: readonly string[] }) => {
        stepReporter.fail(step);
      },
    },
    onManagerDetected: (detection: {
      manager: string;
      agent: string;
      source: string;
    }) => {
      if (!options.debug) {
        return;
      }

      diagnosticsWrite(`Detected package manager: ${detection.manager}\n`);
    },
  };

  if (options.manual) {
    const session = await createAuditSessionImpl(
      runOptions,
      dependenciesForRun,
    );

    return runManualMode(options, session, selectManualAction, (text) => {
      stdout.write(text);
    });
  }

  const result = await runAuditFixImpl(runOptions, dependenciesForRun);

  if (options.json) {
    stdout.write(`${JSON.stringify(toJsonSummary(result), null, 2)}\n`);
  } else {
    stdout.write(`${formatTextSummary(result)}\n`);
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
