# Dependency Policy

Velvet v1 keeps the deterministic core small, uses optional provider credentials at runtime, and avoids npm entirely.

## Python

- Use `uv` and commit `uv.lock`.
- Use `uv sync --locked --dev` in CI.
- Run `uv lock --check` before release.
- Run `pip-audit` and `bandit` in CI.
- `playwright` is a development and optional `shadowpath` dependency used to
  exercise the benchmark's browser and admin-console routes in real Chromium;
  CI installs the pinned lockfile version and browser binary explicitly.
- Publish only through PyPI trusted publishing with OIDC and a protected release
  environment.
- Do not store PyPI API tokens in repository or organization secrets for this
  project.

## Rust

- Commit `Cargo.lock` for reproducible Rust dependency resolution.
- Pin the toolchain in `rust-toolchain.toml`.
- Run `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo test --workspace` in CI before packaging Python wheels.
- `tokio-stream` is allowed in `velvet-rope-proxy` for Axum SSE stream
  adapters; it avoids hand-written stream glue while keeping the transport
  async runtime on Tokio.

## GitHub Actions

- Pin all external Actions by full-length commit SHA.
- Avoid `pull_request_target` for untrusted code paths.
- Keep `permissions` scoped per job.
- Do not share caches with release jobs.
- Prefer GitHub-hosted runners for release jobs.

## npm Policy If JavaScript Is Added Later

JavaScript is out of scope for the current workspace. If npm is introduced later:

- Commit a lockfile and use `npm ci`, not `npm install`, in CI.
- Set `ignore-scripts=true` for routine installs unless a dependency is explicitly
  reviewed and approved.
- Apply a minimum release-age or dependency quarantine policy.
- Use npm trusted publishing through OIDC.
- Disable token publishing for packages that use trusted publishing.
- Generate provenance and SBOM artifacts.
- Review install hooks, transitive dependency changes, and release workflows before
  merging.

## Incident Context

This policy is shaped by May 2026 supply-chain incidents where attackers abused CI
release paths, OIDC token handling, install/import-time hooks, and package manager
trust. Trusted publishing remains useful, but it is not enough by itself; workflow
isolation and cache boundaries are part of the release security model.
