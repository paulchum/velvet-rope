"""Fleet-level false-lockout control by online e-BH gating (spec E2).

Canonical source: docs/math/fleet_flr_ebh_selection_closure.txt. Ported verbatim from the
external portfolio false-lockout control package (audited 2026-07-07).
Pure stdlib.

This module is intentionally small and decision-keyed.  It consumes one
normalized anytime e-value per irreversible retirement decision.  The e-value
producer must satisfy the frozen contract in docs/math/fleet_flr_ebh_selection_closure.txt:

    under a true retirement null H_j and every stopping time tau_j,
    E_Hj[E_j(tau_j)] <= 1.

No independence between decisions is required.  Arms may recur after rescue or
certificate expiry, but each recurrence must carry a fresh decision_id and a
fresh e_process_id.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Verdict(str, Enum):
    """Gate outcome for one proposed retirement decision."""

    EXECUTED = "executed"
    GATED_OUT = "gated_out"
    REFUSED = "refused"


class RefusalReason(str, Enum):
    """First-class non-execution reasons."""

    BUDGET_EXHAUSTED = "budget_exhausted"
    CONTRACT_VIOLATION = "contract_violation_detected"
    DUPLICATE_DECISION = "duplicate_decision"
    MALFORMED_DECISION = "malformed_decision"
    REUSED_EPROCESS = "reused_eprocess"
    UNSUPPORTED_WINDOW = "unsupported_cross_window"


@dataclass(frozen=True)
class DecisionProposal:
    """A single irreversible retirement proposal.

    decision_id keys the retirement event, not the arm.  e_process_id keys the
    underlying evidence process and must not be reused inside the window.
    """

    decision_id: str
    arm_id: str
    tau: int | float | str
    e_value: float
    e_process_id: str
    window_id: str = "default"
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class BudgetState:
    """Snapshot of one declared decision window."""

    window_id: str
    k_max: int
    delta: float
    registered: int
    executed: int
    remaining: int
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_id": self.window_id,
            "k_max": self.k_max,
            "delta": self.delta,
            "registered": self.registered,
            "executed": self.executed,
            "remaining": self.remaining,
            "status": self.status,
        }


@dataclass(frozen=True)
class VerdictRecord:
    """Exported audit record for a retirement proposal."""

    decision_id: str
    arm_id: str
    window_id: str
    verdict: Verdict
    threshold_used: float | None
    e_value: float | None
    executed_count_before: int
    executed_count_after: int
    registered_count: int
    budget_state: BudgetState
    refusal_reason: RefusalReason | None = None
    sequence_index: int | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "decision_id": self.decision_id,
            "arm_id": self.arm_id,
            "window_id": self.window_id,
            "verdict": self.verdict.value,
            "threshold_used": self.threshold_used,
            "e_value": self.e_value,
            "executed_count_before": self.executed_count_before,
            "executed_count_after": self.executed_count_after,
            "registered_count": self.registered_count,
            "budget_state": self.budget_state.to_dict(),
            "refusal_reason": None
            if self.refusal_reason is None
            else self.refusal_reason.value,
            "sequence_index": self.sequence_index,
            "metadata": dict(self.metadata),
        }


class FLREGate:
    """Online gate for one declared decision window.

    The rule is:

        execute j iff E_j(tau_j) >= K_max / (delta * (|R| + 1)),

    where R is the set of already executed decisions in this window.  At most
    K_max valid decisions can be registered; further proposals are refused
    before their e-values enter the family.
    """

    def __init__(self, k_max: int, delta: float, window_id: str = "default"):
        if not isinstance(k_max, int) or k_max <= 0:
            raise ValueError("k_max must be a positive integer")
        if not (0.0 < float(delta) < 1.0):
            raise ValueError("delta must lie in (0,1)")
        if not str(window_id):
            raise ValueError("window_id must be nonempty")
        self.k_max = k_max
        self.delta = float(delta)
        self.window_id = str(window_id)
        self._registered_count = 0
        self._sequence = 0
        self._decision_ids: set[str] = set()
        self._eprocess_ids: set[str] = set()
        self._executed_ids: list[str] = []
        self._history: list[VerdictRecord] = []

    @property
    def history(self) -> tuple[VerdictRecord, ...]:
        return tuple(self._history)

    @property
    def executed_decision_ids(self) -> tuple[str, ...]:
        return tuple(self._executed_ids)

    @property
    def registered_count(self) -> int:
        return self._registered_count

    def budget_state(self) -> BudgetState:
        remaining = max(self.k_max - self._registered_count, 0)
        return BudgetState(
            window_id=self.window_id,
            k_max=self.k_max,
            delta=self.delta,
            registered=self._registered_count,
            executed=len(self._executed_ids),
            remaining=remaining,
            status="open" if remaining > 0 else "exhausted",
        )

    def threshold(self, executed_count_before: int | None = None) -> float:
        if executed_count_before is None:
            executed_count_before = len(self._executed_ids)
        if executed_count_before < 0:
            raise ValueError("executed_count_before must be nonnegative")
        return self.k_max / (self.delta * (executed_count_before + 1))

    def process(self, proposal: DecisionProposal) -> VerdictRecord:
        """Process one proposal in online order."""

        refusal = self._validate_refusal(proposal)
        if refusal is not None:
            return self._record_refusal(proposal, refusal)

        if self._registered_count >= self.k_max:
            return self._record_refusal(proposal, RefusalReason.BUDGET_EXHAUSTED)

        self._sequence += 1
        self._registered_count += 1
        self._decision_ids.add(str(proposal.decision_id))
        self._eprocess_ids.add(str(proposal.e_process_id))

        executed_before = len(self._executed_ids)
        threshold = self.threshold(executed_before)
        if proposal.e_value >= threshold:
            verdict = Verdict.EXECUTED
            self._executed_ids.append(str(proposal.decision_id))
        else:
            verdict = Verdict.GATED_OUT
        executed_after = len(self._executed_ids)

        record = VerdictRecord(
            decision_id=str(proposal.decision_id),
            arm_id=str(proposal.arm_id),
            window_id=str(proposal.window_id),
            verdict=verdict,
            threshold_used=threshold,
            e_value=float(proposal.e_value),
            executed_count_before=executed_before,
            executed_count_after=executed_after,
            registered_count=self._registered_count,
            budget_state=self.budget_state(),
            sequence_index=self._sequence,
            metadata=dict(proposal.metadata),
        )
        self._history.append(record)
        return record

    def process_batch(self, proposals: Iterable[DecisionProposal]) -> list[VerdictRecord]:
        """Process a simultaneous batch in canonical order.

        Sorting by (tau, decision_id) makes the output independent of the input
        iterable's order.  The theorem only needs a fixed execution order; this
        implementation makes that order reproducible.
        """

        return [self.process(p) for p in sorted(proposals, key=_proposal_sort_key)]

    def self_consistency_slacks(self) -> list[float]:
        """Return e_j/final_threshold for executed decisions in this window.

        Every value is >= 1 when the monotone self-consistency invariant holds.
        """

        final_count = len(self._executed_ids)
        if final_count == 0:
            return []
        final_threshold = self.k_max / (self.delta * final_count)
        return [
            record.e_value / final_threshold
            for record in self._history
            if record.verdict is Verdict.EXECUTED and record.e_value is not None
        ]

    def _validate_refusal(self, proposal: DecisionProposal | None) -> RefusalReason | None:
        if proposal is None:
            return RefusalReason.MALFORMED_DECISION
        if str(proposal.window_id) != self.window_id:
            return RefusalReason.UNSUPPORTED_WINDOW
        if not str(proposal.decision_id) or not str(proposal.arm_id):
            return RefusalReason.MALFORMED_DECISION
        if not str(proposal.e_process_id):
            return RefusalReason.MALFORMED_DECISION
        if not _valid_tau(proposal.tau):
            return RefusalReason.MALFORMED_DECISION
        try:
            e_value = float(proposal.e_value)
        except (TypeError, ValueError):
            return RefusalReason.CONTRACT_VIOLATION
        if not math.isfinite(e_value) or e_value < 0.0:
            return RefusalReason.CONTRACT_VIOLATION
        if str(proposal.decision_id) in self._decision_ids:
            return RefusalReason.DUPLICATE_DECISION
        if str(proposal.e_process_id) in self._eprocess_ids:
            return RefusalReason.REUSED_EPROCESS
        return None

    def _record_refusal(
        self, proposal: DecisionProposal | None, reason: RefusalReason
    ) -> VerdictRecord:
        self._sequence += 1
        decision_id = "" if proposal is None else str(proposal.decision_id)
        arm_id = "" if proposal is None else str(proposal.arm_id)
        window_id = self.window_id if proposal is None else str(proposal.window_id)
        e_value = None
        if proposal is not None:
            try:
                e_value = float(proposal.e_value)
            except (TypeError, ValueError):
                e_value = None
        record = VerdictRecord(
            decision_id=decision_id,
            arm_id=arm_id,
            window_id=window_id,
            verdict=Verdict.REFUSED,
            threshold_used=None,
            e_value=e_value,
            executed_count_before=len(self._executed_ids),
            executed_count_after=len(self._executed_ids),
            registered_count=self._registered_count,
            budget_state=self.budget_state(),
            refusal_reason=reason,
            sequence_index=self._sequence,
            metadata={} if proposal is None else dict(proposal.metadata),
        )
        self._history.append(record)
        return record


def default_gamma(j: int) -> float:
    """Telescoping weights gamma_j = 1/(j*(j+1)), j >= 1; sum over all j is
    exactly 1 (partial sum n/(n+1))."""

    if j < 1:
        raise ValueError("gamma index is 1-based")
    return 1.0 / (j * (j + 1))


def uniform_window_gamma(k_max: int) -> Callable[[int], float]:
    """gamma_j = 1/k_max for j <= k_max, else 0.  With these weights ELondGate
    reproduces FLREGate's thresholds and refusal behavior exactly (route (a) =
    route (b) with uniform window weights; CERTIFICATION T1b unification)."""

    if not isinstance(k_max, int) or k_max <= 0:
        raise ValueError("k_max must be a positive integer")

    def gamma(j: int) -> float:
        if j < 1:
            raise ValueError("gamma index is 1-based")
        return 1.0 / k_max if j <= k_max else 0.0

    return gamma


class ELondGate:
    """Route (b): e-LOND-style online gate for an unbounded decision stream.

    The rule for the j-th REGISTERED decision, with R the currently executed
    set, is:

        execute iff E_j(tau_j) >= 1 / (delta * gamma_j * (|R| + 1)),

    where (gamma_j)_{j>=1} is a DETERMINISTIC nonnegative sequence the caller
    certifies to satisfy sum_j gamma_j <= 1.  The running partial sum is
    enforced online: a proposal whose weight would push the partial sum above
    1 is refused as a contract violation.  gamma_j = 0 refuses the proposal
    (weight budget exhausted) without registering it, matching FLREGate's
    budget refusal under uniform window weights.

    Validity (CERTIFICATION T1b): under the v2 selection-closed contract and
    arbitrary dependence, for every stopping time T,
    FLR(T) <= delta * sum_{j in H0} gamma_j <= delta.  No K_max or window is
    required; declared windows are recovered by weight-spending, with the
    executed count carried globally across windows.
    """

    def __init__(self, delta: float, gamma: Callable[[int], float] = default_gamma,
                 window_id: str = "default"):
        if not (0.0 < float(delta) < 1.0):
            raise ValueError("delta must lie in (0,1)")
        if not str(window_id):
            raise ValueError("window_id must be nonempty")
        self.delta = float(delta)
        self.gamma = gamma
        self.window_id = str(window_id)
        self._registered_count = 0
        self._sequence = 0
        self._gamma_spent = 0.0
        self._decision_ids: set[str] = set()
        self._eprocess_ids: set[str] = set()
        self._executed_ids: list[str] = []
        self._history: list[VerdictRecord] = []

    @property
    def history(self) -> tuple[VerdictRecord, ...]:
        return tuple(self._history)

    @property
    def executed_decision_ids(self) -> tuple[str, ...]:
        return tuple(self._executed_ids)

    @property
    def registered_count(self) -> int:
        return self._registered_count

    @property
    def gamma_spent(self) -> float:
        return self._gamma_spent

    def budget_state(self) -> BudgetState:
        """Stream snapshot.  k_max = -1 and remaining = -1 are the documented
        sentinels for an unbounded e-LOND stream (T0 addendum, route (b))."""

        return BudgetState(
            window_id=self.window_id,
            k_max=-1,
            delta=self.delta,
            registered=self._registered_count,
            executed=len(self._executed_ids),
            remaining=-1,
            status="open",
        )

    def threshold(self, j: int, executed_count_before: int | None = None) -> float:
        """Threshold for the j-th registered decision (1-based)."""

        if executed_count_before is None:
            executed_count_before = len(self._executed_ids)
        if executed_count_before < 0:
            raise ValueError("executed_count_before must be nonnegative")
        g = float(self.gamma(j))
        if g <= 0.0:
            return math.inf
        return 1.0 / (self.delta * g * (executed_count_before + 1))

    def process(self, proposal: DecisionProposal) -> VerdictRecord:
        refusal = self._validate_refusal(proposal)
        if refusal is not None:
            return self._record_refusal(proposal, refusal)

        j = self._registered_count + 1
        g = float(self.gamma(j))
        if not math.isfinite(g) or g < 0.0:
            return self._record_refusal(proposal, RefusalReason.CONTRACT_VIOLATION)
        if g == 0.0:
            return self._record_refusal(proposal, RefusalReason.BUDGET_EXHAUSTED)
        if self._gamma_spent + g > 1.0 + 1e-12:
            return self._record_refusal(proposal, RefusalReason.CONTRACT_VIOLATION)

        self._sequence += 1
        self._registered_count = j
        self._gamma_spent += g
        self._decision_ids.add(str(proposal.decision_id))
        self._eprocess_ids.add(str(proposal.e_process_id))

        executed_before = len(self._executed_ids)
        threshold = self.threshold(j, executed_before)
        if proposal.e_value >= threshold:
            verdict = Verdict.EXECUTED
            self._executed_ids.append(str(proposal.decision_id))
        else:
            verdict = Verdict.GATED_OUT
        executed_after = len(self._executed_ids)

        record = VerdictRecord(
            decision_id=str(proposal.decision_id),
            arm_id=str(proposal.arm_id),
            window_id=str(proposal.window_id),
            verdict=verdict,
            threshold_used=threshold,
            e_value=float(proposal.e_value),
            executed_count_before=executed_before,
            executed_count_after=executed_after,
            registered_count=self._registered_count,
            budget_state=self.budget_state(),
            sequence_index=self._sequence,
            metadata=dict(proposal.metadata),
        )
        self._history.append(record)
        return record

    def process_batch(self, proposals: Iterable[DecisionProposal]) -> list[VerdictRecord]:
        """Process a simultaneous batch in the same canonical order as
        FLREGate: sorted by (tau, decision_id)."""

        return [self.process(p) for p in sorted(proposals, key=_proposal_sort_key)]

    def _validate_refusal(self, proposal: DecisionProposal | None) -> RefusalReason | None:
        if proposal is None:
            return RefusalReason.MALFORMED_DECISION
        if str(proposal.window_id) != self.window_id:
            return RefusalReason.UNSUPPORTED_WINDOW
        if not str(proposal.decision_id) or not str(proposal.arm_id):
            return RefusalReason.MALFORMED_DECISION
        if not str(proposal.e_process_id):
            return RefusalReason.MALFORMED_DECISION
        if not _valid_tau(proposal.tau):
            return RefusalReason.MALFORMED_DECISION
        try:
            e_value = float(proposal.e_value)
        except (TypeError, ValueError):
            return RefusalReason.CONTRACT_VIOLATION
        if not math.isfinite(e_value) or e_value < 0.0:
            return RefusalReason.CONTRACT_VIOLATION
        if str(proposal.decision_id) in self._decision_ids:
            return RefusalReason.DUPLICATE_DECISION
        if str(proposal.e_process_id) in self._eprocess_ids:
            return RefusalReason.REUSED_EPROCESS
        return None

    def _record_refusal(
        self, proposal: DecisionProposal | None, reason: RefusalReason
    ) -> VerdictRecord:
        self._sequence += 1
        record = VerdictRecord(
            decision_id="" if proposal is None else str(proposal.decision_id),
            arm_id="" if proposal is None else str(proposal.arm_id),
            window_id=self.window_id if proposal is None else str(proposal.window_id),
            verdict=Verdict.REFUSED,
            threshold_used=None,
            e_value=None,
            executed_count_before=len(self._executed_ids),
            executed_count_after=len(self._executed_ids),
            registered_count=self._registered_count,
            budget_state=self.budget_state(),
            refusal_reason=reason,
            sequence_index=self._sequence,
            metadata={} if proposal is None else dict(proposal.metadata),
        )
        self._history.append(record)
        return record


def realized_flr(
    records: Iterable[VerdictRecord], true_null_decision_ids: Iterable[str]
) -> dict[str, Any]:
    """Compute realized false-lockout fraction for an executed set."""

    true_nulls = {str(x) for x in true_null_decision_ids}
    executed = [
        r.decision_id
        for r in records
        if r.verdict is Verdict.EXECUTED
    ]
    false_lockouts = [decision_id for decision_id in executed if decision_id in true_nulls]
    denominator = max(len(executed), 1)
    return {
        "executed": len(executed),
        "false_lockouts": len(false_lockouts),
        "flr": len(false_lockouts) / denominator,
        "false_lockout_decision_ids": false_lockouts,
    }


def threshold_for(k_max: int, delta: float, executed_count_before: int) -> float:
    """Stateless threshold helper used by tests and the falsification runner."""

    return FLREGate(k_max=k_max, delta=delta).threshold(executed_count_before)


def _valid_tau(tau: int | float | str | None) -> bool:
    if tau is None:
        return False
    if isinstance(tau, bool):
        return False
    if isinstance(tau, (int, float)):
        return math.isfinite(float(tau))
    return bool(str(tau))


def _tau_key(tau: int | float | str) -> tuple[int, float | str]:
    if isinstance(tau, (int, float)) and not isinstance(tau, bool):
        return (0, float(tau))
    return (1, str(tau))


def _proposal_sort_key(proposal: DecisionProposal) -> tuple[tuple[int, float | str], str]:
    return (_tau_key(proposal.tau), str(proposal.decision_id))

