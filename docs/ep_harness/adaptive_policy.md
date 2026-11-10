# Adaptive Evidence-Triggered Policy

Status: **implemented** (`ep_harness/policy.py`, `ep_harness/policy_runner.py`, `ep_harness/inline.py`,
`agents/hunter_agent.py`, `main.py`); tests without LLM calls: `tests/test_policy.py`.
Not yet run with real models, so its effect on quality and cost is not measured.

## Switches

| Variable | Default | Meaning |
|---|---|---|
| `POLICY_MODE` | `fixed` | `fixed` = MA-SOC's loop (up to 3 full Hunter runs on any failure); `adaptive` = this policy; `always_review` = ablation baseline that sends every non-supported claim to review and never retries |
| `POLICY_TASK_RETRIES` | `1` | Targeted retries per task (revise or rerun) |
| `POLICY_REVIEW_BUDGET` | `5` | Claims that may be queued for a human analyst per run |
| `POLICY_LLM_CALL_BUDGET` | `0` | LLM calls the policy may spend per run (Hunter, revise, judge, verify, Analyst retry); `0` = no cap |

`adaptive` and `always_review` require `ENABLE_CONTRACT_GATE=1`; they are most useful with
`ENABLE_CITED_CLAIMS=1` and `ENABLE_SEMANTIC_VERIFIER=1` (claim-level signals). Without semantic review, the
Verifier's OK/FAIL is the only post-gate signal.

## Actions

| Action | Chosen when | Effect |
|---|---|---|
| ACCEPT | at least one claim holds after the steps below | VERIFIED carries supported claims; held/review claims travel as HYPOTHESIS; rejected ones are declared drops |
| TARGETED_RETRY · revise | fixable claim problems and budget left | **one** Hunter LLM call (no tools) rewrites only the failing claims, given their problem and candidate evidence cards; the harness keeps every other claim |
| TARGETED_RETRY · rerun | something must be re-executed (mandatory tool missing, no claims at all) | the Hunter runs again with targeted feedback |
| TARGETED_REVIEW | only disputed claims remain | the finding is `REVIEW_REQUIRED`; claims go to `ech_review_queue.json` |
| REJECT | claims with fabricated references (removed by code, no call), or every claim contradicted/unrelated | removed claims stay in the ledger |
| UNRESOLVED | budget spent, no progress, or a fault the agent cannot fix | the task stops; nothing is forced |

## The Analyst -> Reporter edge

The same signal table drives the ANALYSIS capsule (`policy_runner.run_analysis`), claim by claim, from the gate's
signals at that edge (semantic review of analysis claims belongs to the Output Evidence Guardrail, not built yet):

| Signal on an analysis claim | Action |
|---|---|
| parent claim that does not exist (`unknown_parent_claim`) | removed by code: its record and its narrative lines (no call) |
| R1 / R3 / R4 / ID problems | revise: **one** Analyst call (`AnalystAgent.revise_claims`) rewrites only those claims; the harness replaces their narrative lines in place and keeps every other line and claim |
| claims block missing | revise: re-emit the block for the analysis as written |
| no claims at all, or derived mode (no claim IDs) | rerun the Analyst |
| out of retries | the failing claims are removed (lines and records); the rest goes to the Reporter |
| no accepted parent capsule at all (`missing_parents`) | unresolved: nothing to fix; claims with violations are withheld |

The edge has its own retry budget (task id `ANALYSIS`). Without a policy (`POLICY_MODE=fixed`), the Analyst is
retried as a whole up to `CONTRACT_GATE_ANALYST_RETRIES` as before.

## Signal table (`SIGNAL_TABLE`, version `adaptive-1`)

| Signal | Reaction | Out of retries |
|---|---|---|
| gate `dangling_event`, `dangling_artifact`, `unknown_parent_claim`, `bad_claim_ref`, `empty_claim` | reject (by code, free) | — |
| gate `unanchored_*`, `observable_not_in_evidence`, `level_escalation`, `level_not_allowed`, ID/format codes | revise | reject |
| gate `missing_tool`, `too_few_claims` (capsule level) | rerun (revise when the claims block is missing) | unresolved |
| gate, any other capsule-level code | unresolved | — |
| semantic SUPPORTED, NOT_APPLICABLE | accept | — |
| semantic CONTRADICTED | reject | — |
| semantic UNRELATED | revise | reject |
| semantic INSUFFICIENT | revise | hold (HYPOTHESIS); **review** if the claim is CAUSAL |
| any verdict where the judge overruled a rule-SUPPORTED claim | **review** (layers disagree) | hold or reject when the review budget is spent |

**Progress rule:** each attempt's problems are a signature `{(claim, signal)}`. If an attempt leaves the same
signature as the previous one, the policy stops retrying that task even with budget left.

**Order of cost:** filter by code (free) → revise (1 small call) → rerun (a full Hunter run) → review (human time)
→ unresolved.

## Invariants

- The policy never calls a model and never accepts on its own: ACCEPT forwards what the gate and the Verifier
  accepted. In the ledger the policy (`policy_orchestrator`) may only record `REVIEW_REQUIRED` or `UNRESOLVED`.
- It never adds a conclusion: it removes, lowers, holds or queues claims.
- The signal table and budgets are versioned configuration; they are not changed during a run.
- Every attempt is a new FINDING capsule. A filtered capsule records `derived_by: policy_orchestrator`,
  `filtered_from` and `removed_claims`; a revision records `revision_of`, `kept` and `revised`.

## Output

- `soc_hunt_results.json`: statuses `Verified`, `Review_Required`, `Rejected`, `Unresolved`, `Error`, and
  `policy_decisions` per task.
- `ech_inline_audit.json` → `policy`: version, mode, budget limits and use, action counts, decisions per task;
  `review_queue`.
- `ech_review_queue.json`: claims held for an analyst (ref, text, verdict, reasons, which layer decided).

## Evaluation plan (not yet run)

Same scenarios, same budget, `POLICY_MODE` = `fixed` / `always_review` / `adaptive`: compare IOC/TTP F1,
unsupported claim rate, LLM calls and tokens, and stability over repeated runs. Switching the gate, semantic
review and the policy on one at a time separates their contributions.

## Known limits

- Debate mode's Hunter review is not run under the adaptive policy (the policy replaces that loop).
- At the Analyst edge the policy only has the gate's signals; semantic signals come with the Output Evidence Guardrail.
- Review is a queue for a human; nothing consumes it automatically.
- Defaults (1 retry, 5 reviews) follow MA-SOC's one re-call; they are not tuned.
