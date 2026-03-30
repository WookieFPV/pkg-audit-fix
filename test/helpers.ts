import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const testDir = path.dirname(fileURLToPath(import.meta.url));

export function readFixture(...segments: string[]): string {
  return fs.readFileSync(path.join(testDir, "fixtures", ...segments), "utf8");
}

export function repoRoot(): string {
  return path.resolve(testDir, "..");
}
