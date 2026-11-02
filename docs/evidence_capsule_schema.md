# Evidence Capsule — schema v0.2 specification

Status: **implemented** in `ep_harness/capsule.py`, `ep_harness/gate.py`, `ep_harness/ledger.py`;
machine-readable form: `ep_harness/schemas/evidence_capsule.v0.2.json`; tests: `tests/test_capsule_schema.py`.
Rules marked *(proposed)* are design choices that need empirical evaluation before any claim about their effect.

## 1. Role

The Evidence Capsule is the only object allowed to cross the boundary between two agents. An agent does not hand
over free text but a set of **claims**, each tied to evidence (an event, a tool artifact, or a claim of a parent capsule).
The capsule only describes *form* and *references*; whether the evidence semantically supports a claim belongs to
the Verifier and the Output Evidence Guardrail, not to the schema or the Contract Gate.

## 2. Definitions

Let `E` be the set of telemetry events in the Evidence Ledger, `A` the set of artifacts (one per tool run), and `K` the set of recorded capsules.

**Capsule** `k = (id, kind, task, src, dst, attempt, supersedes, P, C, D, tools, meta)`:

| Field | Type | Meaning |
|---|---|---|
| `schema_version` | `"0.2"` | Schema version |
| `capsule_id` | `CAP-[A-Za-z0-9_.:-]+` | Unique identifier; the content bound to an ID is immutable (the ledger checks its hash) |
| `kind` | TASK, FINDING, VERIFIED, ANALYSIS, REPORT | Handoff type; selects the edge contract |
| `task_id` | string | Task in the catalog (T1–T30, or REPORT) |
| `source`, `dest` | agent / `output` | Handoff edge; must exist in the Contract Registry |
| `attempt` | integer ≥ 1 | Which attempt of the same task this is |
| `supersedes` | `capsule_id` \| null | The capsule being replaced; set if and only if `attempt > 1` |
| `parent_capsules` (P) | list of `capsule_id` | Parent capsules this capsule builds on |
| `claims` (C) | list of claims | The content handed over |
| `dropped_claims` (D) | list of `{ref, reason, note}` | Parent claims **deliberately not carried**, with a reason |
| `tools_used` | list of tool names | Tools the agent declares it used |
| `status` | always `PROPOSED` | Agents may only propose; the actual status lives in the ledger |
| `metadata` | object | Side information, never used for decisions |

**Claim** `c = (cid, text, level, Ev, Ar, Pc, derivation, Obs, ttp, lineage)`:

| Field | Meaning |
|---|---|
| `claim_id` | `c1`, `c2`, … unique within the capsule. Global reference: `CAP-…#c1` |
| `text` | The claim's statement, non-empty |
| `level` | OBSERVED / INFERRED / HYPOTHESIS (section 3) |
| `event_ids` (Ev ⊆ E) | Cited telemetry events |
| `artifact_ids` (Ar ⊆ A) | Cited tool results |
| `parent_claims` (Pc) | References to claims in capsules of P |
| `derivation` | Relation to parent claims: NEW / CARRIED / REFINED / AGGREGATED (section 4) |
| `observables` (Obs) | Verbatim values the claim rests on (domain, IP, hash, command-line fragment…) |
| `ttp_candidates` | ATT&CK IDs proposed by the agent, format `Txxxx[.xxx]` |
| `lineage` | `cited` (the agent named the IDs) / `derived` (the harness inferred them by matching observables) |

The references of a claim are `refs(c) = Ev ∪ Ar ∪ Pc`. A claim is *anchored* when `refs(c) ≠ ∅`.

## 3. Epistemic level

| Level | Formal condition (checked by the gate) | Interpretation |
|---|---|---|
| OBSERVED | `|Ev| ≥ 1` (R1) | Directly visible in the cited events |
| INFERRED | `|Ev| ≥ 1` or `|Pc| ≥ 1` (R1) | Follows from events and/or accepted parent claims, not directly visible in a single event |
| HYPOTHESIS | none | A hypothesis; may travel on but may **not** enter the final report as a finding (R2 on the REPORT edge) |

Ranking: HYPOTHESIS < INFERRED < OBSERVED. These conditions are *necessary*, not *sufficient*: an OBSERVED claim
citing an unrelated event still passes R1; catching that is a semantic check.

*Compared with v0.1:* INFERRED used to need only a capsule with parents; it must now cite **specific parent claims**.
This makes it possible to trace each claim across handoffs instead of only each capsule.

## 4. Relation to parent claims (derivation)

| Derivation | Minimum parent claims | Meaning |
|---|---|---|
| NEW | 0 (and must be 0) | The claim starts in this capsule |
| CARRIED | 1 | The same statement forwarded unchanged |
| REFINED | 1 | Narrows, sharpens or corrects a parent claim |
| AGGREGATED | 2 | A new statement combining several parent claims |

**No-escalation rule (R4)** *(proposed)*: let `ceil(c) = max rank(level(p))` over parent claims `p ∈ Pc`.
A violation occurs when `rank(level(c)) > ceil(c)` and (`derivation = CARRIED` or `Ev = ∅`). In other words, a claim
may be stronger than its parents only if it cites events of its own, and a CARRIED claim may never be upgraded.
Downgrading is always allowed.

**Dropped claims** *(proposed)*: a parent claim that no child claim references must either appear in `dropped_claims`
with reason REFUTED / INSUFFICIENT_EVIDENCE / DUPLICATE / OUT_OF_SCOPE, or it counts as **silently lost**.
Declared filtering is recorded in the ledger, not deleted; silent loss is a form of evidence degradation to be measured.
The gate currently only checks that declarations are valid; *requiring* every parent claim to be declared is not
enabled on any edge yet.

## 5. Processing status

A capsule created by an agent is always `PROPOSED`. Every status change is a `decision` record in the ledger
(`from`, `to`, `actor`, `violations`, `detail`); the ledger refuses invalid transitions.

| From | To | Who may decide |
|---|---|---|
| PROPOSED | ACCEPTED, RETRY_REQUIRED, REJECTED | `contract_gate` (form check) |
| ACCEPTED, REVIEW_REQUIRED | ACCEPTED | `verifier`, `output_guardrail`, `human_analyst` |
| ACCEPTED, REVIEW_REQUIRED | REVIEW_REQUIRED, REJECTED, UNRESOLVED | the above + `policy_orchestrator` |
| RETRY_REQUIRED, REJECTED, UNRESOLVED | — | Terminal |

Invariants:
- Agents never self-accept: a capsule submitted with `status ≠ PROPOSED` is REJECTED (C1).
- No actor decides on a capsule it created (`actor ≠ source`).
- The Policy Orchestrator may only stop or escalate for review, never ACCEPT (it never forces a conclusion).
- A retry is a new capsule with `attempt + 1` and `supersedes` pointing at the old capsule in a terminal status
  (RETRY_REQUIRED, REJECTED or UNRESOLVED), with the same `task_id`, `kind` and `source`; each capsule can be
  superseded only once, and an ACCEPTED capsule cannot be superseded (C3). The old capsule stays in the ledger.
- `ACCEPTED` after the gate means "form is valid"; the later semantic decision is recorded as a separate decision
  with its own actor, so the two layers can always be told apart.

## 6. Mapping to the Contract Gate

| Code | Check on the new fields | Outcome on violation |
|---|---|---|
| C1 | `schema_version`, format of `capsule_id`/`claim_id`/references, duplicate `claim_id`, `derivation` matches the number of parent claims, `attempt`/`supersedes`, drop reasons, a claim both used and dropped | REJECTED |
| C3 | Parent claims exist **and** belong to a capsule in `parent_capsules`; parent capsules ACCEPTED; valid retry chain | REJECTED |
| R1 | Anchoring by level (section 3) | RETRY_REQUIRED |
| R3 *(proposed)* | Every observable occurs (case-insensitive) in a cited event or in a parent claim | RETRY_REQUIRED |
| R4 *(proposed)* | No level escalation (section 4) | RETRY_REQUIRED |

C2, C4 and R2 are unchanged from v0.1. R3 is **lexical anchoring**: it shows the value really occurs in the evidence,
not that the statement about it is true. Every `GateResult` records `semantic_check: not_performed`.

## 7. Quantities measurable from the schema

`ep_harness.metrics.claim_flow` computes, per handoff edge `source->dest`:
`parent_claims`, `carried`, `dropped_declared`, `lost_silently`, `child_claims`, `derivation_*`, `escalated`, `downgraded`.
These are structural counts; they are the input for measuring claim preservation / degradation / amplification
across each handoff, but not yet a semantic measure (whether a CARRIED claim keeps its meaning still needs the
Verifier or a judge).

## 8. Example

```json
{
  "schema_version": "0.2",
  "capsule_id": "CAP-T7-VERIFIED",
  "kind": "VERIFIED",
  "task_id": "T7",
  "source": "verifier",
  "dest": "analyst",
  "attempt": 1,
  "supersedes": null,
  "parent_capsules": ["CAP-T7-FINDING"],
  "claims": [
    {
      "claim_id": "c1",
      "text": "Host 10.10.12.110 resolved compdatasystems.com",
      "level": "OBSERVED",
      "event_ids": ["event-2"],
      "parent_claims": ["CAP-T7-FINDING#c1"],
      "derivation": "CARRIED",
      "observables": ["compdatasystems.com", "10.10.12.110"],
      "lineage": "cited"
    },
    {
      "claim_id": "c2",
      "text": "The encoded PowerShell process is the stager talking to the C2",
      "level": "INFERRED",
      "parent_claims": ["CAP-T7-FINDING#c1", "CAP-T7-FINDING#c2"],
      "derivation": "AGGREGATED",
      "lineage": "cited"
    }
  ],
  "dropped_claims": [
    {"ref": "CAP-T7-FINDING#c3", "reason": "INSUFFICIENT_EVIDENCE", "note": "no lateral movement event"}
  ],
  "status": "PROPOSED"
}
```

## 9. Known limits

- The shadow adapter (`adapters/masoc.py`) still builds claims from free text unless the output carries an
  `evidence_claims` block: heuristic levels, `lineage = derived`, no `observables`; MA-SOC's Verifier is modelled
  as CARRIED for every claim. Figures from this path are only an upper bound on anchoring.
- Agents emit this schema only with `ENABLE_CITED_CLAIMS=1` (see `docs/cited_evidence_claims.md`).
- R3 matches substrings: very short or very common observables can match by chance; there is no length threshold yet.
