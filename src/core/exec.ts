import { spawn } from "node:child_process";

import {
  CommandExecutionError,
  type CommandResult,
  type CommandStep,
} from "./types.js";

export interface ExecOptions {
  cwd: string;
  verbose: boolean;
}

export type ExecFunction = (
  step: CommandStep,
  options: ExecOptions,
) => Promise<CommandResult>;

export const executeStep: ExecFunction = (step, options) =>
  new Promise((resolve, reject) => {
    const child = spawn(step.command, step.args, {
      cwd: options.cwd,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let stdout = "";
    let stderr = "";

    child.stdout?.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      stdout += text;

      if (options.verbose) {
        process.stdout.write(text);
      }
    });

    child.stderr?.on("data", (chunk: Buffer) => {
      const text = chunk.toString();
      stderr += text;

      if (options.verbose) {
        process.stderr.write(text);
      }
    });

    child.on("error", (error) => {
      reject(
        new CommandExecutionError(
          step,
          {
            command: step.command,
            args: step.args,
            stdout,
            stderr,
            exitCode: null,
            signal: null,
          },
          error.message,
        ),
      );
    });

    child.on("close", (exitCode, signal) => {
      const result: CommandResult = {
        command: step.command,
        args: step.args,
        stdout,
        stderr,
        exitCode,
        signal,
      };
      const acceptedExitCodes = step.acceptedExitCodes ?? [0];

      if (exitCode !== null && acceptedExitCodes.includes(exitCode)) {
        resolve(result);
        return;
      }

      const reason =
        signal !== null
          ? `Process terminated by signal ${signal}`
          : `Process exited with code ${exitCode ?? "unknown"}`;
      reject(new CommandExecutionError(step, result, reason));
    });
  });
