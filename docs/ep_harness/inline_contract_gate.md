# Inline Contract Gate

Status: **implemented** (`ep_harness/inline.py`, wired into `main.py`); tests without LLM calls:
`tests/test_inline_gate.py`. Not yet run on the real pipeline with an LLM.

## Switches

| Environment variable | Default | Meaning |
|---|---|---|
| `ENABLE_CONTRACT_GATE` | `0` | `1` enables the inline gate. When off, the pipeline runs exactly like the original MA-SOC |
| `CONTRACT_GATE_ANALYST_RETRIES` | `1` | How many times the Analyst is called again when the ANALYSIS is blocked by a claim-level violation or a missing claims block |
| `ENABLE_CITED_CLAIMS` | `0` | `1` = agents cite their own claims (`docs/ep_harness/cited_evidence_claims.md`); `0` = claims derived from free text |

The toggle values are written to `runs/<id>/orchestration_config.json` like every other toggle.

## Behaviour at each handoff

| Handoff | Capsule | When the gate ACCEPTS | When the gate blocks |
|---|---|---|---|
| Hunter → Verifier | FINDING | The Verifier is called; its verdict is recorded in the ledger (`verifier`: ACCEPTED / REJECTED) | **The Verifier is not called.** The violations become feedback for the Hunter and use the same retry budget. Once retries run out the task is `Gate_Blocked` |
| Verifier → Analyst | VERIFIED (carries every claim) | The task goes into the Analyst's input | The task is `Gate_Blocked`, skips the Analyst, and the Hunter is not retried (the fault is not the Hunter's) |
| Analyst → Reporter | ANALYSIS (claims linked to VERIFIED claims through shared events) | The Reporter gets it as is | On a claim-level violation the Analyst is called again with feedback (up to `CONTRACT_GATE_ANALYST_RETRIES`). Still blocked: the violating lines are **withheld**; the Reporter gets the rest |
| Reporter → output | REPORT | Recorded only | Recorded only, no action (outside the three main handoffs) |

Principles that still hold:
- The gate only checks form and references; it makes no LLM call. A finding blocked by the gate saves one Verifier call.
- The only forcing action is **removing** violating claims; a conclusion is never added.
- Filtering is not deletion: `analyst_result.md` keeps the original of the last attempt, `analyst_result_gated.md` is
  what the Reporter receives; every capsule, blocked ones included, is in `ech_ledger.jsonl`.
- Every attempt is a new capsule (`attempt`, `supersedes`). A FINDING that passed the gate but never got a Verifier
  verdict (API error) is closed as UNRESOLVED by the Policy Orchestrator.

## Output in `runs/<id>/`

| File | Content |
|---|---|
| `ech_ledger.jsonl` | Append-only ledger: events, tool artifacts, capsules, decisions |
| `ech_inline_audit.json` | `summary` (validity, provenance, `claim_flow`, gate outcomes), `handoffs` (each decision and action), ledger record counts |
| `analyst_result_gated.md` | Only present when claims were withheld |
| `soc_hunt_results.json` | Adds the status `Gate_Blocked` next to `Verified` / `Failed_Verification` / `Error` |

The bundle returned by `_execute_agent_runtime` gains an `ech_audit` key.

## Known limits

- With `ENABLE_CITED_CLAIMS=0` agents still write free text. Capsules are built by splitting lines: event references
  are `derived` (observable matching), levels are heuristic, there are no `observables`. In that mode the inline gate
  mainly catches fabricated event IDs (`dangling_event`), missing mandatory tools (`missing_tool`), empty output, and
  an ANALYSIS without accepted parents. Set `ENABLE_CITED_CLAIMS=1` to have agents cite IDs themselves.
- C4 counts the tool artifacts of every attempt of the same task, not only the current one.
- In derived mode, ANALYSIS claims are linked to VERIFIED claims through shared events, so a very common event can
  create spurious links.
- A REPORT is almost always RETRY_REQUIRED/REJECTED because narrative lines are treated as HYPOTHESIS; that is why
  this edge is only recorded for now.
- `max_retries = 2` in `main.py` is unchanged (a separate issue); the gate shares this budget.
