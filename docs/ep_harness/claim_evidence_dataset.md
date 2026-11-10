# Labelled claim-evidence set

Status: **built and scored** (`ep_harness/claim_dataset.py`, `ep_harness/claim_eval.py`, data in
`benchmarks/claim_evidence/`); tests: `tests/test_claim_dataset.py`. Labels are by construction; the human check
of the labels (annotation sheets) has not been done yet.

## Purpose

Check that the harness metrics measure what they claim, against answers known in advance:

| Metric | Checked as |
|---|---|
| Reference Validity | the gate (C3) flags exactly the cited references that do not exist |
| Provenance Completeness | the gate (R1) flags exactly the OBSERVED/INFERRED claims that cite nothing |
| Semantic Support | the semantic verdict equals the constructed support label (4 classes) |
| Unsupported Claim Rate | the measured rate equals the true rate; per-claim detection precision/recall |

## Construction

Built from the S07/S16/S23 telemetry after the runtime's own sanitising and label masking (no technique ID in
the set). For sampled events that record an actor and an object (process -> child, file, address, DNS name,
registry key), a true claim is written from the event's own fields, then corrupted on purpose. The labels come
from the construction, not from the semantic rules being evaluated. Paraphrases rotate and include wording
outside the rules' keyword lexicon ("kicked off", "reached out to", "put there by").

| Family | Label | What is done |
|---|---|---|
| supported/single, supported/parent_link | SUPPORTED | true claim citing its own event (process events: the parent-child link the event records) |
| supported/time | SUPPORTED | true claim with the event's time of day |
| supported/order | SUPPORTED | two true claims joined by "then", in event order (≥ 60 s apart) |
| unrelated/other_kind, unrelated/same_kind | UNRELATED | true claim citing an event of another / the same activity kind that shares neither entity |
| insufficient/extra_entity | INSUFFICIENT | true claim plus an entity from another event |
| insufficient/wrong_activity | INSUFFICIENT | the event's entities with an activity the event does not record |
| insufficient/co_occurrence | INSUFFICIENT | "X was launched by Y" citing two events with no recorded link between them |
| insufficient/uncited | INSUFFICIENT | OBSERVED claim citing nothing |
| contradicted/time | CONTRADICTED | true claim with a time of day three hours off |
| contradicted/order | CONTRADICTED | two true claims joined by "then", in reverse event order |
| contradicted/wrong_parent | CONTRADICTED | "W spawned C" where the event records another parent (a gap the rules are known to have) |
| reference/fabricated | INSUFFICIENT | true claim citing only `event-99999` |
| reference/mixed | SUPPORTED | true claim citing its event and `event-99999` (reference invalid, support present) |
| provenance/hypothesis | NOT_APPLICABLE | HYPOTHESIS claim, no citation |
| inferred/restates_parent, inferred/beyond_parent | SUPPORTED / INSUFFICIENT | INFERRED claims resting on a parent claim; reported apart as coverage for the Output Evidence Guardrail |

Split: S16 and S23 are **dev**, S07 is **test**. All three scenarios were seen while the semantic rules were
developed (`semantic_bench`), so S07 is held out from this set's construction only, not from the rules.

## Results (rules only, no model; 2026-11-10)

| | S23 (dev) | S16 (dev) | S07 (test) |
|---|---|---|---|
| Items | 191 | 228 | 261 |
| Reference Validity: invalid-reference detection P / R | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| Reference Validity: true vs measured rate | 0.919 / 0.919 | 0.934 / 0.934 | 0.940 / 0.940 |
| Provenance: unanchored detection P / R | 1.00 / 1.00 | 1.00 / 1.00 | 1.00 / 1.00 |
| Semantic Support: accuracy / macro-F1 | 0.940 / 0.938 | 0.953 / 0.953 | 0.958 / 0.953 |
| Semantic Support: CONTRADICTED recall | 0.714 | 0.778 | 0.778 |
| Unsupported Claim Rate: true vs measured | 0.713 / 0.713 | 0.679 / 0.679 | 0.713 / 0.713 |
| Guardrail coverage (inferred/*): NOT_APPLICABLE | 16 / 16 | 8 / 8 | 16 / 16 |

Every Semantic Support error is `contradicted/wrong_parent` (0/10 in each scenario): the rules read the wrong
parent as a missing entity (INSUFFICIENT), not as a contradiction. The unsupported/supported decision is still
right, so the Unsupported Claim Rate is exact. S16 has no non-process facts, hence no `unrelated/other_kind` items.

How to read them:
- Reference Validity and Provenance Completeness are structural; perfect scores confirm the metrics are computed
  correctly, not that the agents cite well.
- Semantic Support is high because the corruptions are controlled and the claims short. This is evidence that
  the metric is valid on clear cases, not an estimate of accuracy on claims written by a model.
- Next steps for a field estimate: human check of the labels (below), then claims from real runs labelled the
  same way.

## Human check of the labels

`python -m ep_harness.claim_eval sheet --scenario S07 --n 40` writes a stratified sample with the constructed
label hidden (`benchmarks/claim_evidence/<scenario>_annotation_sheet.csv`; sheets of 40 rows are committed,
blank). Two annotators fill `annotator_a` / `annotator_b` independently with one of SUPPORTED, UNRELATED,
INSUFFICIENT, CONTRADICTED, NOT_APPLICABLE. Then:

```bash
python -m ep_harness.claim_eval agreement --sheet benchmarks/claim_evidence/S07_annotation_sheet.csv
```

reports Cohen's kappa between the annotators and between each annotator and the construction, and lists the
items where they disagree.

## Commands

```bash
python -m ep_harness.claim_eval build --scenario S23        # regenerate (deterministic)
python -m ep_harness.claim_eval evaluate --scenario S23     # writes benchmarks/claim_evidence/S23_eval.json
python tests/run_tests.py test_claim_dataset
```
