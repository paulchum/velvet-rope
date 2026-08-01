# Security Policy

## Supported Version

Velvet is pre-1.0 research-engineering infrastructure. Security fixes apply to
the current `0.9.x` launch line until a public release process is established.

## Threat Model

`EXECUTE_CODE` is the highest-risk boundary in Velvet. An untrusted prompt,
workflow, or tenant can attempt to turn routed execution into:

- host filesystem reads or writes outside the approved mount set;
- network egress to exfiltrate data or reach internal services;
- denial of service through CPU, memory, process fan-out, wall-clock sleep, or
  unbounded stdout;
- container/runtime escape attempts such as touching `/proc/sys` or a host
  Docker socket;
- audit bypass by forcing decisions that cannot be reconstructed from trace.

The protected assets are host files, credentials, tenant data, runtime sockets,
compute capacity, and the trace itself. The main trust boundary is **Rust
authority → Python execution**: Rust decides and records the sandbox plan;
Python alone performs subprocess, filesystem, and network I/O.

## Backend Guarantees

| Backend | Intended use | Guarantees | Non-guarantees |
| --- | --- | --- | --- |
| `none` | local development only | no isolation; emits repeated WARN logs when explicitly enabled | unsafe for untrusted input; unavailable under `sandbox-required`; forbidden outside development |
| `lightweight` on Linux | fast local isolation | `bwrap` profile, constrained mounts, deny-all network when no egress rules, supervisor limits | not a hosted deployment boundary; non-empty egress lists are rejected until enforceable plumbing exists |
| `lightweight` on macOS | fast local isolation | `sandbox-exec` profile, denied writes outside approved writable paths, deny-all network when no egress rules | **not equivalent to Linux lightweight**; `sandbox-exec` is weaker and deprecated, and it is not the hosted deployment boundary |
| `container` | hosted Linux and macOS | rootless Podman/Docker command plan, digest-pinned image, read-only rootfs, explicit mounts, deny-all network when no egress rules, resource limits | non-empty egress lists are rejected until a container-network list implementation is wired in |

Hosted deployment on **both Linux and macOS requires the `container` backend**.
`lightweight` exists for fast developer workflows, not as a hosted security
boundary.

## Audit Requirements

Every `EXECUTE_CODE` trace must contain:

- the selected sandbox backend and canonical profile hash;
- image digest and runtime when the container backend is selected;
- mount spec, network policy, and applied limits;
- ordered output transforms;
- normalized output hash and any typed sandbox violation jurisdiction_evidence once execution
  completes.

The thread schema is intentionally breaking-change friendly. Old traces are
discarded or regenerated when the schema changes.

## Secure Defaults

- Development defaults to `lightweight`; production defaults to `container`.
- `none` requires the resolved config to contain
  `VELVET_ALLOW_UNSAFE_EXEC=1` and is unavailable when compiled with
  `--features=sandbox-required`.
- Container images must be pinned by digest.
- Output normalization is explicit and traced; no hidden post-processing is
  allowed.
- The dashboard binds to `127.0.0.1` by default, exposes no OpenAPI/docs route, sets a
  restrictive Content Security Policy, and does not use CORS.
- Trace logging redacts likely secret-bearing keys such as tokens, passwords,
  cookies, authorization headers, private keys, and API keys.

## Demo Key Boundary

The repository may contain committed public demo key material and deterministic
local-demo signing helpers so examples, benchmark fixtures, and verifier tests
can be reproduced offline. Demo keys are not production credentials, are
documented as demo-only material, and must be rejected by production signing
profiles. Do not add private production keys, tenant keys, API tokens, cloud
credentials, or hosted-service secrets to the repository.

## Reporting

Report suspected vulnerabilities privately through GitHub's private
vulnerability reporting: open the repository's **Security** tab and choose
**Report a vulnerability** (GitHub Security Advisories). This opens a channel
visible only to the maintainers.

Do not open public issues, pull requests, or discussions containing exploit
details, secrets, tokens, private keys, or credential material.

We aim to acknowledge a report within 3 business days and to share a
remediation timeline within 10 business days. Please allow a reasonable
disclosure window before publishing details; reporters who wish to be credited
will be.

## CI Rules

- Do not use `pull_request_target` for workflows that run untrusted code.
- Pin third-party GitHub Actions by full commit SHA.
- Keep workflow permissions least-privilege.
- Do not use shared dependency caches in release or publish jobs.
- Run tests, type checks, lint checks, workflow policy checks, vulnerability
  scanning, secret scanning, and SBOM generation before public release.
