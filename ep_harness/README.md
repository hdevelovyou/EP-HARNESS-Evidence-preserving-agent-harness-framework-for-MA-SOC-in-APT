# ep_harness (v0.2.0: Evidence Capsule schema v0.2, ECH core shadow + inline)

Evidence-aware harness for multi-agent SOC threat hunting. This version audits the handoffs of an
existing MA-SOC run without changing MA-SOC. Schema specification: `docs/ep_harness/evidence_capsule_schema.md`.

## Layout

```
ep_harness/
  capsule.py         Capsule + Claim + ClaimDrop: one schema for every handoff; status transitions
  schemas/           JSON Schema of the capsule (for prompts / output parsers)
  ledger.py          Append-only Evidence Ledger; enforces status transitions and actors
  contracts.py       Handoff edges + per-task mandatory tools
  gate.py            Contract Gate: deterministic checks C1-C4, R1-R4
  metrics.py         Reference validity, provenance completeness, claim flow per handoff
  manifest.py        Component manifest (8 categories) + fingerprint
  harness.json       Default manifest
  adapters/masoc.py  Reads MA-SOC evidence_store.json + soc_hunt_results.json
  inline.py          Inline gate between agents in main.py (ENABLE_CONTRACT_GATE=1)
  claim_parser.py    Reads (and repairs) the ```evidence_claims block agents append (ENABLE_CITED_CLAIMS=1)
  evidence_cards.py  ID-first index of a task's events that the Hunter picks evidence from
  policy.py          Adaptive Evidence-Triggered Policy: signals + budget -> action (POLICY_MODE=adaptive)
  policy_runner.py   Runs one task under the policy (filter, revise, rerun, review, stop)
  label_guard.py     Masks ATT&CK technique IDs before the runtime; restores paths for post-seal IOC scoring
  claim_dataset.py   Labelled claim-evidence set built from masked S07/S16/S23 events
  claim_eval.py      Scores Reference Validity, Provenance, Semantic Support, Unsupported Claim Rate on it
  measurement.py     Same post-run instrument for every configuration (ech_measurement.json)
  experiments.py     Configuration ladder (Structured Capsule baseline -> full EP-HARNESS) x scenarios x repeats
  semantic.py        Semantic evidence verification per claim: rules + one judge call (ENABLE_SEMANTIC_VERIFIER=1)
  semantic_bench.py  Synthetic perturbation benchmark for the semantic rules
  cli.py             `audit` command
```

## Use

```bash
python -m ep_harness.cli audit runs/<scenario_id> --masoc-repo . \
  --out runs/<scenario_id>/ech_audit.json --ledger-out runs/<scenario_id>/ledger.jsonl
```

Tests (no pytest needed): `python tests/run_tests.py`

Inline mode: `ENABLE_CONTRACT_GATE=1 python main.py ...`; see `docs/ep_harness/inline_contract_gate.md`.
Agent-cited claims: add `ENABLE_CITED_CLAIMS=1`; see `docs/ep_harness/cited_evidence_claims.md`.
Semantic evidence verification: add `ENABLE_SEMANTIC_VERIFIER=1`; see `docs/ep_harness/semantic_evidence_verification.md`.
Adaptive policy: add `POLICY_MODE=adaptive`; see `docs/ep_harness/adaptive_policy.md`.
Label guard (always on) and model-free preflight: `python -m ep_harness.cli preflight --scenario S23 --masoc-repo .`;
see `docs/ep_harness/label_guard.md`.
Metric validity: `python -m ep_harness.claim_eval evaluate --scenario S07`; see `docs/ep_harness/claim_evidence_dataset.md`.
Experiments: `python -m ep_harness.experiments plan`; see `docs/ep_harness/experiment_design.md`.

## Gate decisions

| Check | Meaning | Outcome on violation |
|---|---|---|
| C1 schema | enums, IDs, claim refs, derivation vs parent claims, retry fields, drops, no self-accept | REJECTED |
| C2 identity | legal source->dest->kind edge, known task | REJECTED |
| C3 references | cited events/artifacts/parents/parent claims exist, parents ACCEPTED, valid retry lineage | REJECTED |
| C4 tools | task's mandatory tools have successful artifacts | RETRY_REQUIRED |
| R1 anchoring | OBSERVED cites events; INFERRED cites events or parent claims | RETRY_REQUIRED |
| R2 level | claim level allowed on edge (REPORT forbids HYPOTHESIS) | RETRY_REQUIRED |
| R3 observables | declared observables occur in cited events or parent claims | RETRY_REQUIRED |
| R4 escalation | no level above parent claims without own events; CARRIED never escalates | RETRY_REQUIRED |

The gate never judges whether evidence semantically supports a claim (`semantic_check: not_performed`).

## Known limits of shadow mode

- MA-SOC prompts do not ask for event IDs, so references are **derived** by observable matching
  (`lineage: derived`). Derived links show what a claim touches, not that it is supported.
- Claim levels are heuristic (anchored line -> OBSERVED, otherwise HYPOTHESIS).
- Only the final attempt per task is visible, because MA-SOC stores only that.
