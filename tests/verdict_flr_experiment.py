#!/usr/bin/env python3
"""Simulation-only falsification runner for the E2 FLR gate.

All output is [SIM].  Passing this script is never a theorem; failing it updates
OBSTRUCTIONS.md before any product claim is retained.

Pre-registered adjudication sides (see references: falsification protocol):

- Validating the bound FLR <= delta (empirical cells): PASS iff the one-sided
  Clopper-Pearson UPPER bound (Bernoulli-FDP cells) or the one-sided Hoeffding
  UPPER bound on the mean FDP (mixed cells) is <= delta.
- Certifying a violation: VIOLATION iff the one-sided Clopper-Pearson LOWER
  bound (Bernoulli-FDP cells) or Hoeffding LOWER bound (mixed cells) is > delta.
- Exact-instance cells (closed-form FLR known by construction): PASS iff
  exact <= delta, the confidence interval contains the exact value (harness
  consistency), and no violation is certified.  The tight boundary cell has
  exact FLR == delta, so demanding cp_upper <= delta there would be wrong.

Power rule:

- Every cell carries a predicted per-fleet failure-event rate; a cell is
  POWERED iff predicted_rate * n_fleets >= 10, else VACUOUS.
- A powered cell observing zero failure events is a power breach and FAILS.
- A vacuous cell observing zero events prints PASS(vacuous), never plain PASS.
- Quorum: at least 2/3 of POWERED F2a cells must show >= 1 failure event or the
  whole run is INDETERMINATE (exit 1).
- Selftest: a deliberately broken gate (K_max dropped from the threshold) is run
  against the subthreshold tripwire instance and MUST be falsified
  (Clopper-Pearson LOWER bound > delta).  A suite that cannot detect a broken
  gate proves nothing.
"""

from __future__ import annotations

import argparse
import csv
import math
import os as _os
import random
import sys

_ROOT = _os.path.dirname(_os.path.dirname(_os.path.abspath(__file__)))
_SRC = _os.path.join(_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from velvet.verdict.flr_ebh import (
    DecisionProposal,
    ELondGate,
    FLREGate,
    default_gamma,
    realized_flr,
    threshold_for,
    uniform_window_gamma,
)

# ---------------------------------------------------------------------------
# Binomial / interval helpers
# ---------------------------------------------------------------------------


def log_comb(n: int, k: int) -> float:
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def binom_cdf_leq(k: int, n: int, p: float) -> float:
    """P[X <= k] for X ~ Bin(n,p), computed by log-sum-exp."""

    if k < 0:
        return 0.0
    if k >= n:
        return 1.0
    if p <= 0.0:
        return 1.0
    if p >= 1.0:
        return 0.0
    logs = [
        log_comb(n, i) + i * math.log(p) + (n - i) * math.log1p(-p)
        for i in range(k + 1)
    ]
    m = max(logs)
    return math.exp(m) * sum(math.exp(x - m) for x in logs)


def clopper_pearson_upper(k: int, n: int, alpha: float = 0.05) -> float:
    """One-sided 1-alpha upper confidence bound for a binomial rate."""

    if not (0 <= k <= n):
        raise ValueError("need 0 <= k <= n")
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha must lie in (0,1)")
    if n == 0:
        return 1.0
    if k == n:
        return 1.0
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if binom_cdf_leq(k, n, mid) > alpha:
            lo = mid
        else:
            hi = mid
    return hi


def clopper_pearson_lower(k: int, n: int, alpha: float = 0.05) -> float:
    """One-sided 1-alpha lower confidence bound for a binomial rate.

    Largest p_lo with P_{p_lo}[X >= k] <= alpha, i.e. F(k-1; n, p_lo) = 1-alpha.
    """

    if not (0 <= k <= n):
        raise ValueError("need 0 <= k <= n")
    if not (0.0 < alpha < 1.0):
        raise ValueError("alpha must lie in (0,1)")
    if n == 0 or k == 0:
        return 0.0
    lo, hi = 0.0, 1.0
    for _ in range(80):
        mid = 0.5 * (lo + hi)
        if binom_cdf_leq(k - 1, n, mid) >= 1.0 - alpha:
            lo = mid
        else:
            hi = mid
    return lo


def hoeffding_ucb(mean: float, n: int, alpha: float = 0.05) -> float:
    """One-sided 1-alpha upper confidence bound for a [0,1]-valued mean."""

    if n <= 0:
        return 1.0
    return min(1.0, mean + math.sqrt(math.log(1.0 / alpha) / (2.0 * n)))


def hoeffding_lcb(mean: float, n: int, alpha: float = 0.05) -> float:
    """One-sided 1-alpha lower confidence bound for a [0,1]-valued mean."""

    if n <= 0:
        return 0.0
    return max(0.0, mean - math.sqrt(math.log(1.0 / alpha) / (2.0 * n)))


# ---------------------------------------------------------------------------
# Broken gate used ONLY by the power selftest
# ---------------------------------------------------------------------------


class BrokenGateNoKmax(FLREGate):
    """Deliberately broken gate: drops K_max from the threshold.

    Threshold 1/(delta*(|R|+1)) instead of K_max/(delta*(|R|+1)).  Exists only
    so the selftest can demonstrate the suite detects a broken procedure.
    """

    def threshold(self, executed_count_before: int | None = None) -> float:
        if executed_count_before is None:
            executed_count_before = len(self._executed_ids)
        return 1.0 / (self.delta * (executed_count_before + 1))


# ---------------------------------------------------------------------------
# Instance builders.  Each returns (proposals, true_null_ids).
# Null e-values always have mean <= 1 by construction, so every instance is
# contract-compliant; exact FLR values are computed in closed form where the
# construction admits one.
# ---------------------------------------------------------------------------


def _mk(decision_id: str, e_value: float, is_null: bool) -> DecisionProposal:
    return DecisionProposal(
        decision_id=decision_id,
        arm_id=f"arm-{decision_id}",
        tau=1,
        e_value=e_value,
        e_process_id=f"ep-{decision_id}",
        metadata={"null": is_null},
    )


def build_legacy(rng: random.Random, k: int, delta: float, *, null_fraction: float,
                 dependence: str) -> tuple[list[DecisionProposal], set[str]]:
    """The v1 construction, kept for regression continuity (weak nulls)."""

    thr0 = threshold_for(k, delta, 0)
    q = min(1.0 / (20.0 * thr0), 0.0005)
    alt_e = 2.0 * thr0
    shared_u = rng.random() if dependence in {"comonotone", "shared_baseline"} else None
    baseline = rng.gauss(0.0, 0.15) if dependence == "shared_baseline" else 0.0

    proposals: list[DecisionProposal] = []
    true_null_ids: set[str] = set()
    for i in range(k):
        decision_id = f"d{i:03d}"
        is_null = (i / k) < null_fraction
        if is_null:
            u = shared_u if dependence == "comonotone" else rng.random()
            e_value = 1.0 / q if u < q else 0.0
            true_null_ids.add(decision_id)
        else:
            multiplier = max(0.25, 1.0 + baseline + 0.05 * rng.random())
            e_value = alt_e * multiplier
        proposals.append(_mk(decision_id, e_value, is_null))
    return proposals, true_null_ids


def legacy_all_null_rate(k: int, delta: float) -> float:
    """Exact FLR of the legacy all-null cell: 1-(1-q)^k (FDP is Bernoulli)."""

    thr0 = threshold_for(k, delta, 0)
    q = min(1.0 / (20.0 * thr0), 0.0005)
    return 1.0 - (1.0 - q) ** k


def build_tight_disjoint(rng: random.Random, k: int, delta: float) -> tuple[list[DecisionProposal], set[str]]:
    """Extremal instance: e_j = (K/delta) * 1{U in I_j}, I_j disjoint of length
    delta/K.  Each null e-value has mean exactly 1.  Exactly one decision spikes
    iff U < delta; the spiker meets threshold(0) with equality and executes; all
    others are zero.  FDP = 1{U < delta}; exact FLR = delta.
    """

    spike = threshold_for(k, delta, 0)  # equality-by-construction with the gate
    u = rng.random()
    proposals = []
    true_null_ids = set()
    for j in range(k):
        lo = j * delta / k
        hi = (j + 1) * delta / k
        e = spike if (lo <= u < hi) else 0.0
        decision_id = f"d{j:03d}"
        proposals.append(_mk(decision_id, e, True))
        true_null_ids.add(decision_id)
    return proposals, true_null_ids


def build_near_tight_indep(rng: random.Random, k: int, delta: float,
                           factor: float = 0.7) -> tuple[list[DecisionProposal], set[str]]:
    """Independent spikes at threshold(0) with prob factor*delta/K (mean = factor
    <= 1).  All null; FDP = 1{any spike}; exact FLR = 1-(1-factor*delta/K)^K.
    """

    spike = threshold_for(k, delta, 0)
    p = factor * delta / k
    proposals = []
    true_null_ids = set()
    for j in range(k):
        e = spike if rng.random() < p else 0.0
        decision_id = f"d{j:03d}"
        proposals.append(_mk(decision_id, e, True))
        true_null_ids.add(decision_id)
    return proposals, true_null_ids


def near_tight_rate(k: int, delta: float, factor: float = 0.7) -> float:
    return 1.0 - (1.0 - factor * delta / k) ** k


def build_subthreshold(rng: random.Random, k: int, delta: float) -> tuple[list[DecisionProposal], set[str]]:
    """Tripwire: spikes at 1/delta with prob delta (mean 1).  Under the correct
    gate nothing can execute because 1/delta < K/delta = threshold(0) for K >= 2
    and thresholds cannot fall below K/(delta*K) = 1/delta without executions.
    Exact FLR = 0 (vacuous by design).  Under BrokenGateNoKmax every spiker
    executes: exact broken FLR = 1-(1-delta)^K, which the selftest must certify
    as a violation.
    """

    spike = 1.0 / (delta * 1.0)  # equals BrokenGateNoKmax.threshold(0) verbatim
    proposals = []
    true_null_ids = set()
    for j in range(k):
        e = spike if rng.random() < delta else 0.0
        decision_id = f"d{j:03d}"
        proposals.append(_mk(decision_id, e, True))
        true_null_ids.add(decision_id)
    return proposals, true_null_ids


def build_ladder_mixed(rng: random.Random, k: int, delta: float, *,
                       comonotone: bool) -> tuple[list[DecisionProposal], set[str]]:
    """Powered mixed cell.  A = ceil(0.7K) alternatives at 2*threshold(0) execute
    first (ids sort before null ids), dropping the threshold to
    c = K/(delta*(A+1)).  N = K-A nulls spike at exactly c with prob 1/c
    (mean 1), independently or comonotonically; every spiker executes.
    FDP = V/(A+V) with V ~ Bin(N, 1/c) (independent) or V in {0, N} w.p.
    {1-1/c, 1/c} (comonotone).  Exact E[FDP] computed in closed form.
    """

    a = math.ceil(0.7 * k)
    n_null = k - a
    thr0 = threshold_for(k, delta, 0)
    c = threshold_for(k, delta, a)  # K/(delta*(A+1)), equality-by-construction
    p = 1.0 / c
    proposals = []
    true_null_ids = set()
    for i in range(a):
        proposals.append(_mk(f"a{i:03d}", 2.0 * thr0, False))
    shared = rng.random()
    for i in range(n_null):
        u = shared if comonotone else rng.random()
        e = c if u < p else 0.0
        decision_id = f"n{i:03d}"
        proposals.append(_mk(decision_id, e, True))
        true_null_ids.add(decision_id)
    return proposals, true_null_ids


def ladder_exact_mean_fdp(k: int, delta: float, *, comonotone: bool) -> float:
    """Closed-form E[FDP] for the ladder cell."""

    a = math.ceil(0.7 * k)
    n_null = k - a
    c = threshold_for(k, delta, a)
    p = 1.0 / c
    if comonotone:
        return p * n_null / (a + n_null)
    total = 0.0
    for v in range(n_null + 1):
        pmf = math.exp(
            log_comb(n_null, v) + v * math.log(p) + (n_null - v) * math.log1p(-p)
        )
        total += pmf * (v / (a + v) if a + v > 0 else 0.0)
    return total


def ladder_event_rate(k: int, delta: float, *, comonotone: bool) -> float:
    a = math.ceil(0.7 * k)
    n_null = k - a
    p = 1.0 / threshold_for(k, delta, a)
    if comonotone:
        return p
    return 1.0 - (1.0 - p) ** n_null


# ---------------------------------------------------------------------------
# F2a validity grid
# ---------------------------------------------------------------------------


def _run_fleet(gate: FLREGate, proposals, true_null_ids) -> tuple[float, bool, float]:
    gate.process_batch(proposals)
    report = realized_flr(gate.history, true_null_ids)
    executed = set(gate.executed_decision_ids)
    alt_ids = {p.decision_id for p in proposals if p.decision_id not in true_null_ids}
    alt_yield = len(executed & alt_ids) / max(len(alt_ids), 1)
    return report["flr"], report["false_lockouts"] > 0, alt_yield


def f2a_cells(k: int, delta: float) -> list[dict[str, object]]:
    return [
        {
            "name": "legacy_all_null_weak",
            "kind": "bernoulli",
            "build": lambda rng: build_legacy(rng, k, delta, null_fraction=1.0, dependence="independent"),
            "exact": legacy_all_null_rate(k, delta),
            "event_rate": legacy_all_null_rate(k, delta),
        },
        {
            "name": "legacy_mixed_shared_baseline",
            "kind": "mean",
            "build": lambda rng: build_legacy(rng, k, delta, null_fraction=0.3, dependence="shared_baseline"),
            "exact": None,
            "event_rate": 1.0 - (1.0 - min(1.0 / (20.0 * threshold_for(k, delta, 0)), 0.0005)) ** int(0.3 * k),
        },
        {
            "name": "legacy_mixed_comonotone",
            "kind": "mean",
            "build": lambda rng: build_legacy(rng, k, delta, null_fraction=0.5, dependence="comonotone"),
            "exact": None,
            "event_rate": min(1.0 / (20.0 * threshold_for(k, delta, 0)), 0.0005),
        },
        {
            "name": "tight_disjoint_spikes",
            "kind": "exact",
            "build": lambda rng: build_tight_disjoint(rng, k, delta),
            "exact": delta,
            "event_rate": delta,
        },
        {
            "name": "near_tight_indep_spikes",
            "kind": "exact",
            "build": lambda rng: build_near_tight_indep(rng, k, delta),
            "exact": near_tight_rate(k, delta),
            "event_rate": near_tight_rate(k, delta),
        },
        {
            "name": "subthreshold_tripwire",
            "kind": "tripwire",
            "build": lambda rng: build_subthreshold(rng, k, delta),
            "exact": 0.0,
            "event_rate": 0.0,
        },
        {
            "name": "ladder_mixed_indep",
            "kind": "mean",
            "build": lambda rng: build_ladder_mixed(rng, k, delta, comonotone=False),
            "exact": ladder_exact_mean_fdp(k, delta, comonotone=False),
            "event_rate": ladder_event_rate(k, delta, comonotone=False),
        },
        {
            "name": "ladder_mixed_comonotone",
            "kind": "mean",
            "build": lambda rng: build_ladder_mixed(rng, k, delta, comonotone=True),
            "exact": ladder_exact_mean_fdp(k, delta, comonotone=True),
            "event_rate": ladder_event_rate(k, delta, comonotone=True),
        },
    ]


def _adjudicate(cell: dict[str, object], *, n: int, events: int, mean_flr: float,
                delta: float) -> tuple[str, dict[str, float | None]]:
    """Return (verdict, stats).  Verdict PASS* iff the cell is consistent with
    FLR <= delta under the pre-registered side conventions."""

    kind = str(cell["kind"])
    exact = cell["exact"]
    rate = float(cell["event_rate"])
    powered = rate * n >= 10.0
    stats: dict[str, float | None] = {
        "cp_lower": None,
        "cp_upper": None,
        "hoeff_lcb": None,
        "hoeff_ucb": None,
        "exact": None if exact is None else float(exact),
        "event_rate": rate,
    }

    if kind == "tripwire":
        # Exact FLR is 0 under the correct gate; any execution is a gate bug.
        if events == 0:
            return "PASS(vacuous-by-design)", stats
        return "FAIL(unexpected-executions)", stats

    if kind in {"bernoulli", "exact"}:
        lo = clopper_pearson_lower(events, n)
        hi = clopper_pearson_upper(events, n)
        stats["cp_lower"], stats["cp_upper"] = lo, hi
        if lo > delta:
            return "VIOLATION-CERTIFIED", stats
        if kind == "exact":
            ex = float(exact)
            if ex > delta:
                return "FAIL(instance-design)", stats
            if powered and events == 0:
                return "FAIL(power-breach)", stats
            if not (lo <= ex <= hi):
                return "FAIL(harness-inconsistent-with-exact)", stats
            return "PASS(boundary)" if ex == delta else "PASS(exact-consistent)", stats
        if events == 0:
            return ("FAIL(power-breach)" if powered else "PASS(vacuous)"), stats
        if hi <= delta:
            return "PASS", stats
        return "INDETERMINATE(boundary)", stats

    if kind == "mean":
        lcb = hoeffding_lcb(mean_flr, n)
        ucb = hoeffding_ucb(mean_flr, n)
        stats["hoeff_lcb"], stats["hoeff_ucb"] = lcb, ucb
        if lcb > delta:
            return "VIOLATION-CERTIFIED", stats
        if powered and events == 0:
            return "FAIL(power-breach)", stats
        if exact is not None and not (lcb <= float(exact) <= ucb):
            return "FAIL(harness-inconsistent-with-exact)", stats
        if events == 0:
            return "PASS(vacuous)", stats
        if ucb <= delta:
            return "PASS", stats
        return "INDETERMINATE(boundary)", stats

    raise ValueError(f"unknown cell kind {kind!r}")


def run_f2a(mode: str, seed: int) -> tuple[bool, list[str], list[dict[str, object]]]:
    n_bern = 300 if mode == "smoke" else 1000
    n_mean = 400 if mode == "smoke" else 1000
    k = 30 if mode == "smoke" else 50
    delta = 0.10
    lines: list[str] = []
    rows: list[dict[str, object]] = []
    ok = True
    powered_cells = 0
    powered_with_events = 0

    for cell in f2a_cells(k, delta):
        name = str(cell["name"])
        kind = str(cell["kind"])
        n = n_mean if kind == "mean" else n_bern
        rng = random.Random(f"{seed}|f2a|{name}")
        fdps: list[float] = []
        events = 0
        for _ in range(n):
            proposals, nulls = cell["build"](rng)
            fdp, had_false, _ = _run_fleet(FLREGate(k_max=k, delta=delta), proposals, nulls)
            fdps.append(fdp)
            events += int(had_false)
        mean_flr = sum(fdps) / n
        verdict, stats = _adjudicate(cell, n=n, events=events, mean_flr=mean_flr, delta=delta)
        rate = float(cell["event_rate"])
        powered = rate * n >= 10.0
        if powered and kind != "tripwire":
            powered_cells += 1
            powered_with_events += int(events > 0)
        power_label = "POWERED" if powered else "VACUOUS"
        cell_ok = verdict.startswith("PASS")
        ok = ok and cell_ok
        if stats["cp_lower"] is not None:
            bounds = f"cp=[{stats['cp_lower']:.5f},{stats['cp_upper']:.5f}]"
        elif stats["hoeff_lcb"] is not None:
            bounds = f"hoeff=[{stats['hoeff_lcb']:.5f},{stats['hoeff_ucb']:.5f}]"
        else:
            bounds = "bounds=n/a"
        exact_txt = "None" if stats["exact"] is None else f"{stats['exact']:.5f}"
        lines.append(
            f"[SIM] F2a mode={mode} cell={name} kind={kind} fleets={n} "
            f"events={events} mean_flr={mean_flr:.5f} {bounds} exact={exact_txt} "
            f"predicted_rate={rate:.5f} power={power_label} verdict={verdict}"
        )
        rows.append(
            {
                "section": "F2a", "mode": mode, "cell": name, "kind": kind,
                "fleets": n, "k": k, "delta": delta, "events": events,
                "mean_flr": mean_flr, "exact": stats["exact"],
                "cp_lower": stats["cp_lower"], "cp_upper": stats["cp_upper"],
                "hoeff_lcb": stats["hoeff_lcb"], "hoeff_ucb": stats["hoeff_ucb"],
                "predicted_rate": rate, "power": power_label, "verdict": verdict,
            }
        )

    quorum_ok = powered_cells == 0 or powered_with_events * 3 >= powered_cells * 2
    lines.append(
        f"[SIM] F2a quorum powered_cells={powered_cells} with_events={powered_with_events} "
        f"quorum_ok={quorum_ok}"
    )
    if not quorum_ok:
        lines.append("[SIM] F2a INDETERMINATE: powered-cell quorum not met")
    return ok and quorum_ok, lines, rows


# ---------------------------------------------------------------------------
# F2h selection hazard: per-arm validity + argmax selection breaks FLR control
# (CERTIFICATION Proposition CX).  This is an EXPECTED violation demonstrating
# the necessity of the selection-closed decision-keyed contract, plus the two
# certified repairs, which must restore control exactly.
# ---------------------------------------------------------------------------


def selection_hazard_fleet(u: float, delta: float, repair: str) -> float:
    """One fleet of Proposition CX.  A = ceil(1/delta) arms, all epsilon-optimal
    (every retirement is a false lockout).  Per-arm e-processes spike to A on
    disjoint U-intervals of length 1/A: each has mean exactly 1 at every
    stopping time.  The evidence layer retires the spiking arm.

    repair = "none":   report that arm's own e-value (naive; contract violated).
    repair = "divide": report value / A (selection dividend; valid).
    repair = "merge":  report the arithmetic mean of all A processes (valid).

    Returns realized FDP for the fleet (K_max = 1).
    """

    a_count = math.ceil(1.0 / delta)
    spike = threshold_for(1, delta, 0)  # == gate threshold(0), ties execute
    spiker = min(int(u * a_count), a_count - 1)
    raw = spike  # the spiking arm's e-value at tau_1
    if repair == "none":
        e_value = raw
    elif repair == "divide":
        e_value = raw / a_count
    elif repair == "merge":
        e_value = raw / a_count  # mean of A processes: one spike, rest zero
    else:
        raise ValueError(f"unknown repair {repair!r}")
    gate = FLREGate(k_max=1, delta=delta)
    gate.process(
        _mk(decision_id=f"retire-arm-{spiker}", e_value=e_value, is_null=True)
    )
    executed = len(gate.executed_decision_ids)
    return 1.0 if executed else 0.0  # all arms optimal: any execution is false


def run_f2h(seed: int) -> tuple[bool, list[str]]:
    n, delta = 300, 0.10
    lines: list[str] = []
    rng = random.Random(f"{seed}|f2h")
    us = [rng.random() for _ in range(n)]

    naive_events = sum(int(selection_hazard_fleet(u, delta, "none") > 0) for u in us)
    lo = clopper_pearson_lower(naive_events, n)
    hazard_certified = lo > delta
    lines.append(
        f"[SIM] F2h naive_selection fleets={n} events={naive_events} "
        f"cp_lower={lo:.5f} exact_flr=1.00000 "
        f"hazard_violation_certified={hazard_certified}"
    )

    repairs_ok = True
    for repair in ("divide", "merge"):
        events = sum(int(selection_hazard_fleet(u, delta, repair) > 0) for u in us)
        mean_flr = events / n
        controlled = events == 0  # exact FLR = 0 for these repairs
        repairs_ok = repairs_ok and controlled
        lines.append(
            f"[SIM] F2h repair={repair} fleets={n} events={events} "
            f"mean_flr={mean_flr:.5f} exact_flr=0.00000 controlled={controlled}"
        )
    return hazard_certified and repairs_ok, lines


# ---------------------------------------------------------------------------
# Power selftest: the suite must detect a deliberately broken gate
# ---------------------------------------------------------------------------


def run_power_selftest(seed: int) -> tuple[bool, list[str]]:
    n, k, delta = 300, 20, 0.10
    rng = random.Random(f"{seed}|selftest")
    events = 0
    for _ in range(n):
        proposals, nulls = build_subthreshold(rng, k, delta)
        _, had_false, _ = _run_fleet(BrokenGateNoKmax(k_max=k, delta=delta), proposals, nulls)
        events += int(had_false)
    lo = clopper_pearson_lower(events, n)
    exact_broken = 1.0 - (1.0 - delta) ** k
    detected = lo > delta
    line = (
        f"[SIM] selftest broken_gate=no_kmax fleets={n} events={events} "
        f"cp_lower={lo:.5f} exact_broken_flr={exact_broken:.5f} "
        f"violation_detected={detected}"
    )
    return detected, [line]


# ---------------------------------------------------------------------------
# F2b non-vacuity
# ---------------------------------------------------------------------------


def run_f2b(mode: str, seed: int) -> tuple[bool, list[str], list[dict[str, object]]]:
    fleets = 30 if mode == "smoke" else 300
    k = 30 if mode == "smoke" else 50
    delta = 0.10
    lines: list[str] = []
    rows: list[dict[str, object]] = []
    ok = True
    cells = [
        ("mixed_shared_baseline", 0.3, "shared_baseline"),
        ("mixed_comonotone", 0.5, "comonotone"),
    ]
    for name, null_fraction, dependence in cells:
        rng = random.Random(f"{seed}|f2b|{name}")
        yields = []
        for _ in range(fleets):
            proposals, nulls = build_legacy(
                rng, k, delta, null_fraction=null_fraction, dependence=dependence
            )
            _, _, alt_yield = _run_fleet(FLREGate(k_max=k, delta=delta), proposals, nulls)
            yields.append(alt_yield)
        mean_yield = sum(yields) / fleets
        target = 1.0 - delta
        cell_ok = mean_yield >= target
        ok = ok and cell_ok
        lines.append(
            f"[SIM] F2b mode={mode} cell={name} fleets={fleets} "
            f"retirement_fraction={mean_yield:.5f} target={target:.5f} pass={cell_ok}"
        )
        rows.append(
            {
                "section": "F2b", "mode": mode, "cell": name, "kind": "yield",
                "fleets": fleets, "k": k, "delta": delta, "events": None,
                "mean_flr": None, "exact": None, "cp_lower": None, "cp_upper": None,
                "hoeff_lcb": None, "hoeff_ucb": None, "predicted_rate": None,
                "power": None, "verdict": f"yield={mean_yield:.5f}>= {target:.5f}: {cell_ok}",
            }
        )
    return ok, lines, rows


# ---------------------------------------------------------------------------
# F2d route (a) vs route (b) power comparison, plus route (b) validity spots
# ---------------------------------------------------------------------------


def _gates(k: int, delta: float) -> list[tuple[str, object]]:
    return [
        ("route_a_window", lambda: FLREGate(k_max=k, delta=delta)),
        ("elond_uniform_k", lambda: ELondGate(delta=delta, gamma=uniform_window_gamma(k))),
        ("elond_telescoping", lambda: ELondGate(delta=delta, gamma=default_gamma)),
    ]


def elond_tight_exact_flr(k: int, delta: float) -> float:
    """Exact FLR of ELondGate(telescoping) on the Lemma 3 tight instance:
    the spiker (value K/delta at slot j, |R| = 0) executes iff
    spike >= 1/(delta*gamma_j), i.e. j(j+1) <= K in exact arithmetic.  The
    count is taken with the SAME float comparison the gate performs, because
    smoke mode hits the exact-arithmetic tie j(j+1) = K at j = 5, K = 30 and
    the certified value must match IEEE behavior (proof-hygiene: numerics)."""

    spike = threshold_for(k, delta, 0)
    j_max = sum(
        1
        for j in range(1, k + 1)
        if spike >= 1.0 / (delta * default_gamma(j) * 1.0)
    )
    return delta * j_max / k


def run_f2d(mode: str, seed: int) -> tuple[bool, list[str]]:
    k = 30 if mode == "smoke" else 50
    n = 300 if mode == "smoke" else 1000
    delta = 0.10
    lines: list[str] = []
    ok = True

    # Power cell 1: strong ladder (alternatives at 2*threshold(0)).
    yields: dict[str, float] = {}
    for gate_name, mk_gate in _gates(k, delta):
        rng = random.Random(f"{seed}|f2d|ladder|{gate_name}")
        total = 0.0
        for _ in range(n if mode == "full" else 100):
            proposals, nulls = build_ladder_mixed(rng, k, delta, comonotone=False)
            _, _, alt_yield = _run_fleet(mk_gate(), proposals, nulls)
            total += alt_yield
        yields[gate_name] = total / (n if mode == "full" else 100)
    lines.append(
        f"[SIM] F2d mode={mode} cell=strong_ladder k={k} "
        + " ".join(f"yield[{g}]={y:.5f}" for g, y in yields.items())
    )

    # Power cell 2: moderate evidence, no ladder start (deterministic).
    # All decisions truly suboptimal with e = 0.2002*threshold(0): route (a)
    # cannot start (yield 0); telescoping e-LOND executes exactly slots
    # j = 1..9 (thresholds 20,30,...,100 <= 100.1 at delta=0.1, then 110 > it).
    # The 1.001 factor keeps the instance off the IEEE tie at exactly
    # threshold(0)/5 (proof-hygiene: numerics).
    moderate = threshold_for(k, delta, 0) * 0.2002
    det_yields: dict[str, float] = {}
    for gate_name, mk_gate in _gates(k, delta):
        gate = mk_gate()
        proposals = [_mk(f"d{i:03d}", moderate, False) for i in range(k)]
        _, _, alt_yield = _run_fleet(gate, proposals, set())
        det_yields[gate_name] = alt_yield
    lines.append(
        f"[SIM] F2d mode={mode} cell=moderate_no_ladder k={k} e=thr0/5 "
        + " ".join(f"yield[{g}]={y:.5f}" for g, y in det_yields.items())
    )
    # The tradeoff both ways must actually show, or the comparison is vacuous.
    tradeoff_ok = (
        det_yields["route_a_window"] == 0.0
        and det_yields["elond_telescoping"] > 0.0
        and yields["route_a_window"] >= yields["elond_telescoping"] - 1e-9
    )
    ok = ok and tradeoff_ok
    lines.append(f"[SIM] F2d tradeoff_documented={tradeoff_ok}")

    # Validity spot: e-LOND(telescoping) on the Lemma 3 tight instance.
    exact = elond_tight_exact_flr(k, delta)
    rng = random.Random(f"{seed}|f2d|tight_elond")
    events = 0
    for _ in range(n):
        proposals, nulls = build_tight_disjoint(rng, k, delta)
        _, had_false, _ = _run_fleet(
            ELondGate(delta=delta, gamma=default_gamma), proposals, nulls
        )
        events += int(had_false)
    lo, hi = clopper_pearson_lower(events, n), clopper_pearson_upper(events, n)
    consistent = lo <= exact <= hi and lo <= delta
    ok = ok and consistent
    lines.append(
        f"[SIM] F2d mode={mode} cell=tight_elond_validity fleets={n} events={events} "
        f"cp=[{lo:.5f},{hi:.5f}] exact={exact:.5f} consistent={consistent}"
    )
    return ok, lines


def replay_spec_lines() -> list[str]:
    return [
        "[SIM] F2c replay spec:",
        "[SIM] 1. Map each historical retirement event to a decision_id, arm_id, tau, e_value, and e_process_id.",
        "[SIM] 2. Mark H_j true or false using long-run holdout ground truth and the epsilon margin.",
        "[SIM] 3. Replay decisions through FLREGate in timestamp/decision_id order without peeking at later e-values.",
        "[SIM] 4. Report realized FLR, retirement yield, refused decisions, and the declared window budget state.",
    ]


def run(mode: str, seed: int = 20260707, csv_path: str | None = None) -> tuple[int, list[str]]:
    lines = [f"[SIM] starting F2 falsification runner mode={mode} seed={seed}"]
    ok_a, lines_a, rows_a = run_f2a(mode, seed)
    ok_self, lines_self = run_power_selftest(seed)
    ok_h, lines_h = run_f2h(seed)
    ok_b, lines_b, rows_b = run_f2b(mode, seed)
    ok_d, lines_d = run_f2d(mode, seed)
    lines.extend(lines_a)
    lines.extend(lines_self)
    lines.extend(lines_h)
    lines.extend(lines_b)
    lines.extend(lines_d)
    lines.extend(replay_spec_lines())
    ok = ok_a and ok_self and ok_h and ok_b and ok_d
    lines.append(f"[SIM] completed mode={mode} pass={ok}")
    if csv_path:
        fields = [
            "section", "mode", "cell", "kind", "fleets", "k", "delta", "events",
            "mean_flr", "exact", "cp_lower", "cp_upper", "hoeff_lcb", "hoeff_ucb",
            "predicted_rate", "power", "verdict",
        ]
        with open(csv_path, "w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            for row in rows_a + rows_b:
                writer.writerow(row)
        lines.append(f"[SIM] wrote per-cell CSV to {csv_path}")
    return (0 if ok else 1), lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("smoke", "full"), default="smoke")
    parser.add_argument("--seed", type=int, default=20260707)
    parser.add_argument("--csv", default=None)
    args = parser.parse_args(argv)
    code, lines = run(args.mode, args.seed, args.csv)
    for line in lines:
        print(line)
    return code


if __name__ == "__main__":
    sys.exit(main())
