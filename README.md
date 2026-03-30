# pkg-audit-fix

`pkg-audit-fix` is a standalone Node.js CLI that audits and remediates dependency vulnerabilities across `pnpm`, `npm`, and `bun` projects.

## Install

```bash
npm install -g pkg-audit-fix
```

## Usage

```bash
pkg-audit-fix
pkg-audit-fix --cwd ./app
pkg-audit-fix --manager pnpm --verbose
pkg-audit-fix --dev --audit-level high
pkg-audit-fix --json
```

## Behavior

- Detects the active package manager automatically, with `--manager` available as an override.
- Audits production dependencies by default. Use `--dev` to target development dependencies instead.
- Buffers package-manager output unless a step fails or `--verbose` is enabled.
- Prints a commit-message-style summary with grouped advisories and a final remaining count.

## Manager Notes

- `pnpm`: remediation runs `pnpm audit --json --fix` and then `pnpm install`.
- `npm`: remediation runs `npm audit fix --json`. Severity filtering is applied by `pkg-audit-fix` after parsing the audit report, because npm's `--audit-level` only changes npm's failure threshold.
- `bun`: remediation runs `bun update --production` followed by a fresh audit. Bun is modeled as update-plus-reaudit in v1.

## Development

```bash
npm install
npm run ci
```
