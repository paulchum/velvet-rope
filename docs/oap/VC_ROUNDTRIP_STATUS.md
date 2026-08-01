# OAP VC Round-Trip Status

Status: `UNTESTED`

Pinned files include:

- `oap/vc/context-oap-v1.jsonld`
- `oap/vc/vc-mapping.md`

This PR does not implement a Decision -> OAP VC -> Decision round-trip. The pinned conformance runner at commit `a706c64b0b7ef4bcff9756a926f9a278e577e8b0` is documented as loading zero cases in the existing conformance results, and the repository does not currently include a digest-preserving VC round-trip harness that Velvet can call without inventing behavior outside the pinned surface.

Until such tooling exists, VC round-trip must not be counted as OAP conformance or production crypto evidence.
