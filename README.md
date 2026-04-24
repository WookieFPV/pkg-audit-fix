# pkg-audit-fix [![npm][npm-image]][npm-url] ![npm][npm-dl-stats]

One command to audit dependencies and run the native fix flow for `pnpm`, `npm`, `yarn`, and `bun`.

It detects your package manager, applies the best available remediation flow, then summarizes what changed and what still needs attention.

## Requirements

- Node.js `>=20.19`

## Usage

Run in your project:

```bash
npx pkg-audit-fix@latest
```

Or install globally:

```bash
npm install --global pkg-audit-fix
pkg-audit-fix
```

## Examples

```bash
pkg-audit-fix
pkg-audit-fix --cwd ./app
pkg-audit-fix --prod
pkg-audit-fix --dev --audit-level high
pkg-audit-fix --dry-run
pkg-audit-fix --json
```

## Options

- `--manager <auto|pnpm|npm|yarn|bun>`: override detection
- `--prod`: audit production dependencies only
- `--dev`: audit development dependencies only
- `--audit-level <low|moderate|high|critical>`: set the minimum severity
- `--dedupe <auto|always|never>`: run dedupe when supported
- `--dry-run`: audit without applying fixes
- `--json`: output a machine-readable summary
- `--show-commands`: print package-manager commands
- `--verbose`: stream command output

## Package Managers

- `pnpm`: audit, fix, reinstall, and `minimumReleaseAge` handling
- `npm`: audit and `npm audit fix`
- `yarn` Classic: audit and report
- `yarn` Berry: audit, recheck, and optional dedupe
- `bun`: audit, manual remediation prompt, and re-audit

## Programmatic API

```ts
import { formatTextSummary, runAuditFix } from "pkg-audit-fix";

const result = await runAuditFix({
  cwd: process.cwd()
});

console.log(formatTextSummary(result));
```

Use `toJsonSummary(result)` for machine-readable output.

[npm-image]: https://img.shields.io/npm/v/pkg-audit-fix
[npm-url]: https://www.npmjs.com/package/pkg-audit-fix
[npm-dl-stats]: https://img.shields.io/npm/dm/pkg-audit-fix
