# Semantic Evidence Verification

Status: **implemented** (`ep_harness/semantic.py`, `ep_harness/inline.py`, `agents/verifier_agent.py`,
`prompts/agent_prompts.py`, `main.py`); tests without LLM calls: `tests/test_semantic.py`.
The rule layer is checked on real S07/S16/S23 events; the judge layer has only been run with a stubbed LLM.

## What it answers

The Contract Gate checks that a claim's references **exist**. Semantic verification checks, claim by claim,
whether the events a claim cites **back what it says**:

| Verdict | Meaning | Decided by |
|---|---|---|
| SUPPORTED | The cited events are about the claim, nothing in them conflicts with it, and they cover every entity and the activity it asserts | rules, then confirmed (or made stricter) by the judge |
| UNRELATED | No cited event is about the claim | rules |
| INSUFFICIENT | The events are about the claim but do not establish all of it | rules, or the judge |
| CONTRADICTED | A cited event states the opposite of the claim | rules, or the judge |
| NOT_APPLICABLE | Nothing to check: a HYPOTHESIS, or an inference resting only on parent claims | rules |

## Definitions

For a claim `c` and an event `e` in the ledger:

- `A(e)`: the entities of `e`, read from entity-like fields only (host, user, process/image, command line,
  parent, file/target, path, hash, IP/address, domain/DNS query, URL, registry, GUID), with derived forms
  (basename, executable stem, command-line tokens, hash values). Event metadata (codes, outcome, timestamps,
  rule names) is not an entity.
- `A(c)`: the entities `c` names: pattern matches (IP, hash, path, registry key, file name, domain, host name),
  declared `observables`, and any entity-shaped value of any ledger event that the claim text mentions as a token.
- `Triv`: entities present in more than 30% of the ledger's events (`TRIVIAL_DF`), typically the host and the user.
  `Spec(x) = x \ Triv`.
- `B(c)`: the activity kinds the claim asserts (process, network, dns, file, registry, auth, scheduled_task,
  service), from a keyword lexicon. `B(e)`: the kinds the event records, from its event code (Sysmon, Security,
  System, PowerShell), `event.category` and the fields present.
- `rel(c, e)` holds when `Spec(A(c) ∩ A(e)) ≠ ∅`, or when `B(c) ∩ B(e) ≠ ∅` and `c` and `e` share any entity
  (or `c` names none).

Rules, applied to the cited events `E(c)` in this order:

1. `E(c) = ∅` → NOT_APPLICABLE for a HYPOTHESIS or an inference from parent claims, otherwise INSUFFICIENT.
2. `c` names no entity and no activity → INSUFFICIENT (nothing the evidence could be checked against).
3. No `e ∈ E(c)` with `rel(c, e)` → **UNRELATED**. Cited events that fail `rel` while others pass are reported
   as `irrelevant_events` (noise citations).
4. Over the relevant events `R(c)`, a stated attribute disagrees with a recorded one → **CONTRADICTED**:
   - outcome: success vs failure (`event.outcome`, or a failure event code such as 4625);
   - direction: inbound vs egress (`network.direction`);
   - time of day: a stated `HH:MM` more than 10 minutes from every relevant event;
   - order: "A before / then / followed by B" (or "after", reversed) when every A event is later than every B event.
5. Otherwise → **INSUFFICIENT** if any of:
   - an entity of `Spec(A(c))` occurs in no relevant event;
   - `B(c)` and `B(R(c))` are both known and disjoint;
   - the claim is **causal** ("spawned", "launched by", "dropped by", "led to"…) and no event records a link
     between its entities: neither one event naming two distinct entities in different fields (process and
     parent, process and file, process and address), nor a process id / GUID matching another event's parent id.
     Co-occurrence is not causation;
   - the claim is a **correlation** over several events that share no entity.
6. Otherwise → SUPPORTED (by rules), sent to the judge.

Each verdict also records the claim's relation type (ATTRIBUTE, CORRELATION, TEMPORAL, CAUSAL).

## Judge layer

When `ENABLE_SEMANTIC_VERIFIER=1`, the Verifier's single OK/FAIL call is replaced by:

1. the rule layer on every claim of the gate-accepted FINDING (no LLM);
2. **one** judge call (`VerifierAgent.judge_claims`) only if some claim is rule-SUPPORTED, showing only those
   claims and their relevant events (each trimmed to 1500 characters). The judge answers in a
   `claim_verdicts` JSON block;
3. merging: the judge may only make a verdict **stricter** (SUPPORTED → INSUFFICIENT / UNRELATED / CONTRADICTED),
   never looser; a claim it does not answer becomes INSUFFICIENT.

So the number of LLM calls per finding is the same as before (one), or zero when the rules reject every claim.

## Effect on the handoff

| Verdict | In the VERIFIED capsule |
|---|---|
| SUPPORTED, NOT_APPLICABLE | carried unchanged (CARRIED) |
| INSUFFICIENT | carried, level lowered to HYPOTHESIS (never reported as a finding) |
| UNRELATED | dropped, `dropped_claims` reason INSUFFICIENT_EVIDENCE, note "unrelated" |
| CONTRADICTED | dropped, `dropped_claims` reason REFUTED |

The FINDING is ACCEPTED by the Verifier when at least one claim is SUPPORTED, otherwise REJECTED, and the Hunter
receives the per-claim verdicts as feedback (`FAIL: …`). Every verdict is an append-only `claim_verdict` record in
the ledger (actor `verifier`); the author of a claim can never judge it.

## Metrics (`ech_inline_audit.json` → `semantic`)

- `verdicts`, `by_layer` (e.g. `rules:UNRELATED`, `judge:SUPPORTED`)
- `unsupported_claim_rate` = (UNRELATED + INSUFFICIENT + CONTRADICTED) / checked claims (NOT_APPLICABLE excluded)
- `irrelevant_citation_rate` = cited events judged unrelated to their claim / cited events checked

## Synthetic benchmark (`python -m ep_harness.semantic_bench`)

True claims are written from each event's own fields (process → address / DNS query / file / child process) and
perturbed into the three failure kinds. Results of the rule layer (2026-11-10):

| Scenario | Cases | SUPPORTED | UNRELATED | INSUFFICIENT | CONTRADICTED | Accuracy |
|---|---|---|---|---|---|---|
| S07 | 100 | 25 | 25 | 25 | 25 | 1.00 |
| S16 | 162 | 41 | 39 | 41 | 41 | 1.00 |
| S23 | 60 | 15 | 15 | 15 | 15 | 1.00 |

Read these numbers with care:
- the templates are simple and the perturbations are the ones the rules were designed for, so this is a
  consistency check and an upper bound, not the accuracy on claims written by an LLM;
- two rule fixes were made after errors on these runs (entities known to the ledger count as claim entities;
  only entity-shaped values count), so these scenarios are not held-out data for the rule layer.

## Known limits

- The behaviour lexicon and entity patterns are English keyword rules: a paraphrase they miss ("phoned home")
  falls back to entity overlap only.
- Contradiction rules cover outcome, direction, time of day and order; a wrong process or host *attribution*
  is left to the judge.
- The 30% triviality threshold is a fixed setting, not tuned.
- ANALYSIS and REPORT claims are not reviewed semantically yet (Output Evidence Guardrail).
- The judge prompt has not been run against a real model.
