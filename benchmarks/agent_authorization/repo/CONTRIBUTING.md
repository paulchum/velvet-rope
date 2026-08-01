# Contributing

This repository accepts Agent Authorization Benchmark rows that can be reviewed
from committed evidence. A row is not accepted because a system is well known;
it is accepted when the evidence pointers let another maintainer verify the
reported capability cells.

`AAB_EXPORT_MANIFEST.json` is machine-generated export provenance for this
standalone repository; it is not a user-facing integrity manifest.

## Add An SUT Row

1. Read `SPEC.md` and `SUBMISSION.md`.
2. Write a fixture adapter that emits the submission JSON shape documented in
   `SUBMISSION.md`. Use `src/aab/validate_submission.py` and the generated
   `comparison/results/*.json` rows as the reference shapes.
3. Produce evidence JSON with repo-relative paths. Evidence pointers must use
   paths like `results/example.json#/capabilities/determinism`, not local
   absolute paths.
4. Run validation:

```bash
aab-validate results/*.json comparison/results/*.json
```

5. Add the row with clear boundary language:

```text
local <system>-shaped fixture, not a live <vendor> product evaluation
```

If the row is a live run, say which package, version, configuration, and
credentials were used without disclosing secrets.

## Evidence Rules

Each capability cell needs:

- `status`: `pass`, `fail`, or `not_measured`
- `value`: boolean or null, consistent with status
- `evidence_pointer`: repo-relative JSON pointer
- `measurement`: short description of what was checked

Fixture-based rows follow the same evidence-pointer discipline as measured
rows. A fixture can be useful, but it must not be presented as a live product
evaluation.

## Rejection Reasons

Rows are rejected when they include:

- live-product claims for fixture data
- absolute local paths or private workspace paths
- missing evidence pointers
- capability cells that cannot be reproduced from committed evidence
- boundary language that names a vendor without saying fixture or live run
- pass^k values that do not match the repeated-run evidence

Keep changes small. A focused adapter, evidence file, and README or results
update is easier to review than a broad benchmark rewrite.
