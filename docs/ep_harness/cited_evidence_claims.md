# Agent-cited evidence claims

Status: **implemented** (`ep_harness/claim_parser.py`, `ep_harness/inline.py`, `prompts/agent_prompts.py`, `main.py`);
tests without LLM calls: `tests/test_cited_claims.py`. Not yet run with a real LLM, so how well models follow the
format is still unknown.

## Enabling

```bash
ENABLE_CONTRACT_GATE=1 ENABLE_CITED_CLAIMS=1 python main.py ...
```

`ENABLE_CITED_CLAIMS=1` without the gate fails as soon as the configuration loads: only the inline gate reads and
checks the claims block. With the flag off, prompts are unchanged from MA-SOC and the gate uses claims derived from
free text (`derived`).

## Format agents must emit

The Hunter and the Analyst end their answer with **exactly one** block:

````
```evidence_claims
[{"id": "c1", "text": "...", "level": "OBSERVED", "event_ids": ["event-9"],
  "tools": ["rex_tool"], "observables": ["csc.exe", "tmseiddy.dll"]}]
```
````

| Field | Hunter | Analyst | Mapping to the capsule |
|---|---|---|---|
| `id` | required | required, matches the `[cN]` tag in the text | `claim_id` (`C2`, `2` → `c2`) |
| `text`, `level` | required | required | kept as is; level upper-cased |
| `event_ids` | events in the task log | events in the evidence | `event_ids` |
| `tools` | tools in the Tool Execution Audit | — | the task's `artifact_ids`; a tool that did not run successfully → an ID that does not exist → C3 REJECTED |
| `parent_claims` | — | refs of VERIFIED claims, e.g. `CAP-T7-VERIFIED-a1#c1` | `parent_claims`; `derivation` defaults from the number of parents |
| `observables` | values copied verbatim from the events | as for the Hunter | `observables` → R3 |

The Analyst must also tag the end of every analysis line (table rows included) with `[cN]`. The list of VERIFIED
claims with their refs is added to the Analyst's input (`lean_results[].claims`), and the contract is appended to the
Analyst's evidence context.

## How the parser and the gate split the work

- The parser (`claim_parser.py`) is lenient about shape and judges nothing: JSON → `Claim` with `lineage = "cited"`.
  A missing block or broken JSON → no claims, plus an error note.
- The gate decides everything as before: fabricated event/tool/parent-claim IDs → C3 REJECTED; an observable not in
  the event → R3; a level above the parent claims without own events → R4; a missing block → C2 `too_few_claims`
  plus a `[format]` note in the feedback.
- When blocked, a `[format]` note or a claim-level violation lets the Analyst be called again (`retryable`).

## Analyst → Reporter in cited mode

The Reporter receives the narrative **without the claims block and the `[cN]` tags**. If the ANALYSIS is blocked,
the lines tagged with a violating claim are removed first. `analyst_result.md` keeps the original (with block and
tags). The summarizer receives the Hunter output without the claims block, so the summary artifact keeps its old shape.

## Related changes

- `split_tool_audit` uses `raw_decode`: text appended after the Tool Execution Audit (for example a Debate Judge
  resolution) no longer breaks reading the audit (it used to yield an empty audit → a false C4).
- The shadow adapter (`audit` CLI) uses the claims block when the output has one, and otherwise still derives claims
  from the text.

## Known limits

- **Untagged** Analyst narrative lines still reach the Reporter unchecked.
- The Verifier does not emit claims yet: VERIFIED still carries (CARRIED) every FINDING claim; the Verifier does not
  declare dropped claims (`dropped_claims`).
- The Reporter does not emit a claims block (so the `FINAL_REPORT_SOC.md` format read by the evaluator does not
  change); the Reporter → output edge is still only recorded.
- There is no semantic check: a claim citing the right event but misreading it still passes the gate.
- A FINDING without a claims block is blocked until retries run out; if a model often forgets the block, the
  `Gate_Blocked` rate will rise. Measure this on real runs before comparing quality.
