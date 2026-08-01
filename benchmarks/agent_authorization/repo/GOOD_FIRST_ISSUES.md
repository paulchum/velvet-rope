# Good First Issues

Use this queue to pre-seed small contributor tasks. Each item should be
completable from the public benchmark repository without private context.

1. Add an adapter stub for Open Policy Agent that emits a `not_measured` row
   until a reviewer supplies reproducible evidence.
2. Add an adapter stub for Cedar policy that documents the expected evidence
   pointers before any live run is claimed.
3. Add a pass^k edge-case fixture where 19 of 20 repeated runs succeed and the
   reported `pass_k` values are checked by `aab-validate`.
4. Add a short walkthrough for one comparison evidence file, from row to JSON
   pointer to capability cell.
5. Improve the `aab-validate` error message for missing evidence pointers so it
   names the exact capability key.
6. Add a fixture that rejects an absolute path in an evidence pointer.
7. Add a documentation example for a live run that redacts credential names but
   keeps package and version metadata.
8. Add a tiny script that lists all `not_measured` reasons from `results/*.json`.

When opening these as GitHub issues, include the expected file path, one command
to run, and the boundary note if the issue touches public positioning.
