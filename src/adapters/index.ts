import type { PackageManagerAdapter } from "./base.js";
import { bunAdapter } from "./bun.js";
import { npmAdapter } from "./npm.js";
import { pnpmAdapter } from "./pnpm.js";
import { yarnBerryAdapter } from "./yarn-berry.js";
import { yarnClassicAdapter } from "./yarn-classic.js";

const adapters = new Map<string, PackageManagerAdapter>([
  ["pnpm", pnpmAdapter],
  ["pnpm@6", pnpmAdapter],
  ["npm", npmAdapter],
  ["yarn", yarnClassicAdapter],
  ["yarn@berry", yarnBerryAdapter],
  ["bun", bunAdapter],
]);

export function getAdapter(manager: string): PackageManagerAdapter | null {
  return adapters.get(manager) ?? null;
}
