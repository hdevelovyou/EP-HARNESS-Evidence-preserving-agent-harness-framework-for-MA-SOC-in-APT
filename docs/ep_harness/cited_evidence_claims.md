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

## Design rule: the harness carries the work, not the model

Citing evidence is easy for a strong model and error-prone for a weak one. Each step a weak model gets wrong is
therefore done or checked by the harness, so the choice of model matters as little as possible:

| Step a model can get wrong | What the harness does |
|---|---|
| Finding the right event ID in a ~110 000-character task view | **Evidence cards** (`ep_harness/evidence_cards.py`): one line per event, ID first, then time, activity (event code), actor -> object and command line, read from the event's own fields. Placed before the task view (~6 700 characters for an S23 task) |
| Writing the statement first and looking for evidence afterwards | The contracts ask for **evidence first**: pick cards, copy observables, name tools, then write the statement; the example block lists `evidence` before `text` |
| Small format slips | **Deterministic repair** in the parser: a ```json fence or an unfenced list, trailing commas, single quotes, typographic quotes, separate objects, other field names (`evidence`, `events`, `statement`, `claim_id`…), `Event 9`, `observed`, `C1`. Every repair is recorded (`format_repairs`); only an unreadable block goes back to the agent |
| Forgetting a `[cN]` tag on an Analyst line | **Auto-tagging**: an untagged line that contains a claim's text, or 60% of its words, gets that claim's tag, so a blocked claim is still removed |

`ech_inline_audit.json` → `harness_assist` reports how often the harness stepped in (`format_repairs`,
`handoffs_repaired`, `auto_tagged_lines`), so that the share of the work done by the harness can be compared
across models.

## Format agents must emit

The Hunter and the Analyst end their answer with **exactly one** block:

````
```evidence_claims
[{"id": "c1", "evidence": ["event-9"], "observables": ["csc.exe", "tmseiddy.dll"],
  "tools": ["rex_tool"], "level": "OBSERVED", "text": "csc.exe created tmseiddy.dll"}]
```
````

| Field | Hunter | Analyst | Mapping to the capsule |
|---|---|---|---|
| `id` | required | required, matches the `[cN]` tag in the text | `claim_id` (`C2`, `2` → `c2`) |
| `text`, `level` | required | required | kept as is; level upper-cased |
| `evidence` (or `event_ids`) | event IDs from the evidence cards | events beyond the parent claims, if needed | `event_ids` |
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

- Analyst lines that neither carry a tag nor match a claim (auto-tagging) still reach the Reporter unchecked.
- Whether evidence cards and evidence-first ordering actually narrow the gap between models has not been measured:
  that needs runs with several real models.
- The Verifier does not emit claims yet: VERIFIED still carries (CARRIED) every FINDING claim; the Verifier does not
  declare dropped claims (`dropped_claims`).
- The Reporter does not emit a claims block (so the `FINAL_REPORT_SOC.md` format read by the evaluator does not
  change); the Reporter → output edge is still only recorded.
- There is no semantic check: a claim citing the right event but misreading it still passes the gate.
- A FINDING without a claims block is blocked until retries run out; if a model often forgets the block, the
  `Gate_Blocked` rate will rise. Measure this on real runs before comparing quality.
