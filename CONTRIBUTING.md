# Contributing To Velvet

Velvet is an Apache-2.0 open-core project for local, self-hosted agent action
admission and verifiable evidence. Contributions should keep the implemented
claim boundary clear: no hosted enterprise claims, no legal compliance outcome,
and no universal agent-safety guarantees.

## Code of Conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md). By
participating, you are expected to uphold it.

## Development Setup

```bash
uv sync --dev
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 uv run maturin develop
uv run velvet --help
```

Use the focused checks for the area you touched, then broaden before larger
changes:

```bash
uv run ruff check .
uv run pytest
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo fmt --all --check
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo clippy --workspace --all-targets -- -D warnings
CARGO_PROFILE_DEV_DEBUG=0 CARGO_INCREMENTAL=0 cargo test --workspace
```

If disk is tight, start with the touched package or test module and report the
scope in the pull request.

## Pull Request Guidelines

- Keep unrelated refactors out of feature or bugfix pull requests.
- Add or update tests for behavior changes.
- Update docs and `CHANGELOG.md` for user-visible changes.
- Keep generated evidence, benchmark, and paper artifacts repo-relative. Do not
  commit local absolute paths or secrets.

## Claim Boundary

Use the implemented language in [`README.md`](README.md) and
[`docs/public/CLAIMS.md`](docs/public/CLAIMS.md). Velvet currently provides
local/self-hosted evidence and verification surfaces; it is not a hosted
shared-tenant platform, legal compliance determination, audit outcome, or
general solution to agent safety.

## Security

Report vulnerabilities privately as described in [`SECURITY.md`](SECURITY.md).
Please do not open a public issue for a suspected vulnerability.
