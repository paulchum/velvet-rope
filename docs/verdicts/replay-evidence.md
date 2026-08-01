<!-- Math notes: docs/math/theorem_v_finite_horizon_verdict.txt, docs/math/drift_expiry_certificates.txt, docs/math/fleet_flr_ebh_selection_closure.txt, docs/math/anytime_glr_audit_family_m.txt -->

# Replay Evidence: Real-Archive Kill-Rule Study

The `maxde-replay` study (MIT-licensed sibling repository) replays common
kill rules over two public experiment archives and asks, for every kill of
the eventual-best arm, whether the certificate layer that Velvet ports as
Certified Decisions would have licensed that retirement. This page summarizes
the results Velvet cites. Every number below is **measured**, specific to the
named dataset and replay design, and reproduced deterministically by that
repository's `make` targets.

## How to read every number on this page

- An **uncertified kill** means the certificate would not have licensed
  retiring the arm at the stated `c`/`delta` gate — it does not mean the arm
  was better. The arm's true mean is unknown; the study only has a
  large-sample estimate.
- Refusal fractions are **refusal-as-output**: the certificate layer's answer
  is "this kill is not covered," which is neither a safety claim nor a danger
  claim about the killed arm.
- `[BP]` certificate-refusal fractions and `[FM]` audit-overlay fractions are
  different objects in different claim currencies. They are reported
  separately and are never averaged or blended; their disagreement table is a
  result of the study, not a quantity to reconcile.
- Ground truth ("eventual-best arm") is the full-sample winner, and a test is
  adjudicated only when that winner is statistically separated from the
  runner-up. Inconclusive tests are reported separately, never counted as
  kills.

## Study A: Upworthy (semi-synthetic replay)

The Upworthy Research Archive is aggregate-only, so the replay is
**semi-synthetic**: each arm's full-sample click-through rate is taken as its
true mean and Bernoulli arrivals are drawn from it. Rates below are
properties of that replay design on this archive, not forecasts for any other
traffic.

Scale: 22,741 confirmatory headline tests, of which 3,599 are statistically
separated after hygiene and adjudication; 719,800 content-addressed replay
trials over those contests.

- **Greedy delight-gated exploration (unmodified DE)** horizon-abandons the
  eventual-best arm in **12.539%** of trials (95% Wilson CI
  [12.463%, 12.616%]). Of those abandonments, 62.881% are uncertified kills —
  kills without certificate coverage at the study's gate.
- **Fixed-day industry kill rules** retire the eventual-best arm at
  **16.353%** (day 3), **9.416%** (day 7), and **4.436%** (day 14) of
  opportunities. The certificate layer would have refused **96.317%**,
  **97.368%**, and **98.409%** of those kills, respectively.
- **Successive halving** (rung 250) retires the eventual-best arm in
  **20.008%** of trials — more often than the day-3 folklore rule; the
  certificate layer would have refused 95.964% of those kills.

The `[FM]` audit overlay is reported beside the `[BP]` column, in its own
currency: it refuses 100.000% of the adjudicated Upworthy eventual-best-arm
kills for every rule row with at least one such kill, and BP/FM disagree on
37.119% of the DE kills. The confidence intervals condition on the selected,
separated contests and the declared replay design; they do not include
uncertainty from archive selection or label adjudication.

## Study B: ASOS (genuine-sequential replay)

The ASOS Digital Experiments archive supplies native per-checkpoint
cumulative statistics, so this replay is genuinely sequential — no synthetic
arrivals. Scale: 98 control-vs-treatment series, 33 statistically separated.

- **0 anytime-validity violations** and **0 naive-peeking false stops** were
  observed across the replayed series. This is an external-validity check for
  the certificate on real sequential trajectories, not positive evidence that
  naive peeking fails on this metric.
- Across the **2,164 adjudicated native checkpoint decisions**, BP refuses
  48.568% and FM refuses 73.799%; both currencies show **0 final-winner
  certification violations** under the study adjudication.
- ASOS fixed-day rules kill the eventual-best arm in 7/33, 5/33, and 1/33
  separated series at days 3/7/14 — all refused by the certificate layer.

## What this evidence does and does not show

It shows, on these archives and under the stated designs, that widely used
kill rules retire the eventual-best arm at measurable rates, and that the
certificate layer would have answered most of those specific kills with a
refusal instead of a license. Refusal is the product behavior being
demonstrated: the verdict layer's job is to say "not covered" rather than
manufacture a kill certificate
(`docs/verdicts/certified-decisions.md`).

It does not show that the refused kills were wrong, that any killed arm was
better, or that adopting the certificate layer changes revenue: an
uncertified kill means only that the retirement lacked certificate coverage
at the stated gate. The Upworthy rates inherit the semi-synthetic design
(full-sample CTRs as true means); the ASOS rates inherit that archive's
checkpoint granularity and adjudication rules. No number on this page is a
forecast, and none of these fractions transfer across currencies: a `[BP]`
refusal fraction never substitutes for an `[FM]` one, or vice versa.

## Provenance

Upstream study: the `maxde-replay` repository (MIT license; datasets CC-BY
4.0, with pinned download hashes). Its `README.md` and
`paper/empirical_section.md` carry the full tables, cluster bootstrap
intervals, and the claims lint that gates this language. Velvet ports the
verdict machinery those replays exercise as `src/velvet/verdict/`
(provenance: `src/velvet/verdict/UPSTREAM.md`); the theorem summaries are the
math notes linked in this page's header.
