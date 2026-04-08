# pkg-audit-fix

`pkg-audit-fix` is a CLI for auditing dependencies and running the package-manager-native fix flow across `pnpm`, `npm`, `yarn`, and `bun`.

Use it when you want one command that:

- detects the current package manager automatically
- applies fixes where the manager supports them
- re-audits and shows exactly what was fixed and what remains

## Example

```bash
npx pkg-audit-fix@latest
```

```text
✔ Audited dependencies
✔ Applied available fixes
✔ Reinstalled dependencies
✔ Rechecked vulnerabilities

Resolved 1 vulnerability.
Updated packages:
- defu@6.1.4: CVE-2026-35209, GHSA-737V-MQG7-C878

No vulnerabilities remain.
```

## Getting Started

Requires Node.js `>=20.19`.

Run it without installing:

```bash
npx pkg-audit-fix@latest
```

Or install it globally:

```bash
npm install --global pkg-audit-fix
pkg-audit-fix
```

## Common Usage

```bash
pkg-audit-fix
pkg-audit-fix --cwd ./app
pkg-audit-fix --prod
pkg-audit-fix --dev --audit-level high
pkg-audit-fix --json
```

## Why Use It

Package manager audit commands are inconsistent. `pkg-audit-fix` gives you a single workflow for:

- `pnpm`
- `npm`
- `yarn`
- `bun`

Instead of remembering different audit and fix commands for each tool, you run one command and get a clear summary back.

## Package Manager Support

- `pnpm`: audits, fixes, reinstalls, and can help recover from `minimumReleaseAge` blocks
- `npm`: audits and runs `npm audit fix`
- `yarn` Classic: audits and reports vulnerabilities
- `yarn` Berry: audits, rechecks, and can run `yarn dedupe`
- `bun`: audits, prompts for manual remediation because Bun does not support `audit --fix`, then re-audits and reports what remains

## Useful Flags

- `--manager <auto|pnpm|npm|yarn|bun>`: override package manager detection
- `--prod`: audit production dependencies only
- `--dev`: audit development dependencies only
- `--audit-level <low|moderate|high|critical>`: set the minimum advisory level
- `--dry-run`: audit without applying fixes
- `--json`: print a machine-readable summary
- `--show-commands`: print the underlying package-manager commands
- `--verbose`: stream subprocess output
