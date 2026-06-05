# Branching Strategy (GitFlow-lite)

## Long-lived branches

| Branch | Purpose |
|--------|---------|
| `main` | Production-ready code. Protected. Only via PR from `release/*` or `hotfix/*`. |
| `develop` | Integration branch for the next release. Feature PRs merge here first. |

## Short-lived branches

| Pattern | Base | Merge into |
|---------|------|------------|
| `feature/<ticket>-<slug>` | `develop` | `develop` |
| `release/vX.Y.Z` | `develop` | `main` + back-merge to `develop` |
| `hotfix/<slug>` | `main` | `main` + `develop` |

## Workflow

1. Create `feature/...` from `develop`.
2. Open PR → `develop`. CI must pass (backend tests, frontend build, Docker build).
3. When ready to ship: open `release/v1.2.0` from `develop`, fix only release blockers.
4. Merge `release/*` → `main`, tag `v1.2.0` (triggers Docker Hub publish).
5. Urgent fix: `hotfix/...` from `main`, merge to `main` and `develop`.

## Version tags

- Semantic versioning: `vMAJOR.MINOR.PATCH`
- Pushing a tag `v*.*.*` runs **Release** workflow (image + GitHub Release).
- Merges to `main` can auto-bump patch tags via **Auto Tag** workflow (optional; disable if you prefer manual tags only).

## Commit conventions (recommended)

- `feat:` new capability
- `fix:` bug fix
- `chore:` tooling / CI
- `docs:` documentation only
