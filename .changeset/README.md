# Changesets

This directory stores release notes and version bumps for `pkg-audit-fix`.

- Run `bun run changeset` to create a changeset.
- Merge the generated markdown file with the code change it describes.
- The release workflow will open or update a release PR on `main`.
- npm publishing only runs when that Changesets release PR is merged into `main`.
