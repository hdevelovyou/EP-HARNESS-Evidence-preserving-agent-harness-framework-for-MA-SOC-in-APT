# Experiment design: Structured Capsule baseline and ablation ladder

Status: **infrastructure implemented and tested without an LLM** (`ep_harness/experiments.py`,
`ep_harness/measurement.py`, `CONTRACT_GATE_MODE`, `ENABLE_EVIDENCE_CARDS`, `MASOC_MAX_RETRIES` in `main.py`);
tests: `tests/test_baseline.py`. No experiment has been run: the model is not chosen yet.

## Why a Structured Capsule baseline

Comparing EP-HARNESS with MA-SOC as is would mix two effects: asking agents for structured, cited claims, and
enforcing evidence at each handoff. The main baseline therefore already has the capsule format; the remaining gap
is what the harness adds by checking, blocking, repairing and steering across handoffs. MA-SOC as is stays as a
reference point.

## Configurations (one change per step)

| Config | Capsules + citations | Evidence cards | Gate | Semantic review | Policy |
|---|---|---|---|---|---|
| B0_masoc | – | – | off | – | fixed retry |
| **B1_structured_capsule** (baseline) | yes | – | shadow (record only) | – | fixed retry |
| B1c_structured_capsule_cards | yes | yes | shadow | – | fixed retry |
| L1_gate | yes | yes | inline | – | fixed retry |
| L2_semantic | yes | yes | inline | yes | fixed retry |
| Full_ep_harness | yes | yes | inline | yes | adaptive |

Reading the ladder: B1 → B1c is the value of guidance alone (cards, nothing enforced); B1c → L1 the gate;
L1 → L2 semantic review; L2 → Full the adaptive policy.

## Fairness rules

- **Same instrument for every run.** After the report is sealed, `measure_run` rebuilds a fresh ledger from the
  masked evidence store and re-reads the Hunter outputs, the Analyst's text and the final report (cited claims
  when a claims block is present, derived claims otherwise), then applies the deterministic checks only:
  reference validity, provenance completeness, semantic verdicts (rules, no judge), unsupported claim rate,
  irrelevant citation rate. Written to `runs/<id>/ech_measurement.json`.
- **Same budget.** `MASOC_MAX_RETRIES=1` (MA-SOC's paper: one re-call; the original code allowed two) and
  `POLICY_TASK_RETRIES=1`. LLM calls, tokens, cost and latency are reported next to quality.
- **Same inputs.** Label masking (technique IDs and simulation markers) in every configuration; every switch set
  explicitly by the runner so nothing leaks from the shell.

## Switches added for the baseline

| Variable | Values | Meaning |
|---|---|---|
| `CONTRACT_GATE_MODE` | `inline` (default) / `shadow` | `shadow`: capsules are built and recorded, nothing is blocked, filtered or withheld; the Verifier's OK/FAIL decides as in MA-SOC; the Reporter gets the analysis with the claims block and tags removed. Cannot be combined with semantic review or the policy |
| `ENABLE_EVIDENCE_CARDS` | `1` (default) / `0` | evidence cards before the task view in cited mode; the Hunter contract points at the cards only when they are given |
| `MASOC_MAX_RETRIES` | default `1` | retries of the fixed (MA-SOC) loop |

## Measures (Objective 3 of the proposal)

| Dimension | From |
|---|---|
| Analysis quality | `eval_report.json`: F1 TTP (scored on masked text), F1 IOC |
| Evidence preservation | `ech_measurement.json`: unsupported claim rate of findings, forwarded findings, analysis and report; reference validity; provenance; irrelevant citations |
| Cost | `eval_report.json`: tokens, cost, latency |
| Stability | standard deviation over repeats (default 5) |

## Running

```bash
python -m ep_harness.experiments plan --repeats 5                 # 6 configs x 3 scenarios x 5 = 90 runs, no call
python -m ep_harness.experiments run --repeats 5 --execute        # calls the LLM
python -m ep_harness.experiments summarize --name EXP20261110     # summary.json + summary.md
```

`run` without `--execute` only writes the plan. Each run is `main.py --scenario <S> --run-name <name>` with the
configuration's environment; the summary reads `eval_report.json` and `ech_measurement.json` from each run folder
and reports mean ± standard deviation per configuration and scenario.

## Known limits

- The instrument's semantic check is the rule layer only; a judge-based measurement would need a fixed model
  shared by all configurations.
- Parent-claim references point at capsules of the run, so they count toward provenance but not toward reference
  validity in the measurement.
- Debate mode is not part of the matrix (`COLLABORATION_STRATEGY=hierarchical`).
