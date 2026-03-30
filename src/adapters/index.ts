import type { PackageManagerAdapter } from "./base.js";
import { bunAdapter } from "./bun.js";
import { npmAdapter } from "./npm.js";
import { pnpmAdapter } from "./pnpm.js";

const adapters = new Map<string, PackageManagerAdapter>([
  ["pnpm", pnpmAdapter],
  ["npm", npmAdapter],
  ["bun", bunAdapter],
]);

export function getAdapter(manager: string): PackageManagerAdapter | null {
  return adapters.get(manager) ?? null;
}
