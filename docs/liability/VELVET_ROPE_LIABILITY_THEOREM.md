# Velvet Rope Liability Theorem

## Action Path Integrity

For every consequential action `a`:

```text
ExecutedAction(a)
  implies
CandidateActionCaptured(a)
  and AdmissionDecisionCaptured(a)
  and ValidPreExecutionWarrant(a)
  and JurisdictionSatisfied(a)
  and PolicySatisfied(a)
  and BudgetSatisfied(a)
  and ConsentSatisfied(a)
  and ReplayableSeal(a)
```

Equivalent set form:

```text
ExecutedConsequentialActions
  subset
WarrantedActions
  intersection JurisdictionAuthorizedActions
  intersection PolicyAuthorizedActions
  intersection BudgetAuthorizedActions
  intersection ConsentAuthorizedActions
  intersection ReplaySealedActions
```

Any weakening of this invariant should fail tests.
