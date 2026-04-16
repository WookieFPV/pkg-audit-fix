# pkg-audit-fix [![npm][npm-image]][npm-url] ![npm][npm-dl-stats]

Audit dependencies and run the native fix flow across `pnpm`, `npm`, `yarn`, and `bun`.

`pkg-audit-fix` gives you one command that detects the current package manager, runs the best available audit and remediation flow for it, and prints a clean summary of what changed and what still needs attention.

## Requirements

- Node.js `>=20.19`

## CLI Usage

Run it without installing:

```bash
npx pkg-audit-fix@latest
```

Or install it globally:

```bash
npm install --global pkg-audit-fix
pkg-audit-fix
```

## Common Commands

```bash
pkg-audit-fix
pkg-audit-fix --cwd ./app
pkg-audit-fix --prod
pkg-audit-fix --dev --audit-level high
pkg-audit-fix --dry-run
pkg-audit-fix --json
```

## Supported Package Managers

- `pnpm`: audit, fix, reinstall, and optional help for `minimumReleaseAge` exclusions
- `npm`: audit and `npm audit fix`
- `yarn` Classic: audit and report
- `yarn` Berry: audit, recheck, and optional `yarn dedupe`
- `bun`: audit, prompt for manual remediation, then re-audit and summarize

## Useful Flags

- `--manager <auto|pnpm|npm|yarn|bun>`: override package manager detection
- `--prod`: audit production dependencies only
- `--dev`: audit development dependencies only
- `--audit-level <low|moderate|high|critical>`: set the minimum advisory level
- `--dedupe <auto|always|never>`: run a dedupe pass when supported
- `--dry-run`: audit without applying fixes
- `--json`: print a machine-readable summary
- `--show-commands`: print the underlying package-manager commands
- `--verbose`: stream subprocess output

## Programmatic API

```ts
import { formatTextSummary, runAuditFix } from "pkg-audit-fix";

const result = await runAuditFix({
  cwd: process.cwd()
});

console.log(formatTextSummary(result));
```

Use `toJsonSummary(result)` if you want a machine-readable payload instead of the text reporter.

[npm-image]: https://img.shields.io/npm/v/pkg-audit-fix
[npm-url]: https://www.npmjs.com/package/pkg-audit-fix
[npm-dl-stats]: https://img.shields.io/npm/dm/pkg-audit-fix
