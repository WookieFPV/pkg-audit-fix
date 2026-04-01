# pkg-audit-fix

`pkg-audit-fix` is a standalone Node.js CLI that audits and remediates dependency vulnerabilities across `pnpm`, `npm`, `yarn`, and `bun` projects.

## Install

```bash
npm install -g pkg-audit-fix
```

## Usage

```bash
pkg-audit-fix
pkg-audit-fix --cwd ./app
pkg-audit-fix --manager pnpm --verbose
pkg-audit-fix --prod
pkg-audit-fix --dev --audit-level high
pkg-audit-fix --json
```

## Behavior

- Detects the active package manager automatically, with `--manager` available as an override.
- Audits all dependencies by default. Use `--prod` or `--dev` to narrow the audit scope.
- Uses `low` as the default advisory threshold. Override it with `--audit-level`.
- Buffers package-manager output unless a step fails or `--verbose` is enabled.
- Prints a commit-message-style summary with grouped advisories and a final remaining count.

## Manager Notes

- `pnpm`: remediation runs `pnpm audit --json --fix` and then `pnpm install --no-frozen-lockfile`.
- `npm`: remediation runs `npm audit fix --json`. Severity filtering is applied by `pkg-audit-fix` after parsing the audit report, because npm's `--audit-level` only changes npm's failure threshold.
- `yarn` Classic: audits via `yarn audit --json`. Classic Yarn does not provide an `audit fix` flow, so `pkg-audit-fix` reports findings but does not apply package updates automatically.
- `yarn` Berry: audits via `yarn npm audit --json --all --recursive` and can optionally run `yarn dedupe` after the audit pass.
- `bun`: remediation runs `bun update --production` followed by a fresh audit. Bun is modeled as update-plus-reaudit in v1.

## Development

```bash
npm install
npm run ci
```

## Releases

```bash
bun run changeset
```

- Commit the generated changeset file with the code change it describes.
- Configure npm trusted publishing for `pkg-audit-fix` against `.github/workflows/release.yml`.
- The release workflow on `main` uses Changesets to open or update a release PR.
- npm publishing happens only when that release PR is merged, using GitHub Actions OIDC without an `NPM_TOKEN` secret.
