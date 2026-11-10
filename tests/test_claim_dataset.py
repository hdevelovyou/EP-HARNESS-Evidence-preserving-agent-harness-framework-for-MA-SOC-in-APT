"""The labelled claim-evidence set: construction, label consistency, scoring of the four metrics, human check."""

import csv
import json
from pathlib import Path

from ep_harness.claim_dataset import UNSUPPORTED, build_for_scenario, load_items
from ep_harness.claim_eval import agreement, annotation_sheet, cohen_kappa, evaluate, predict, scenario_ledger
from ep_harness.label_guard import find_labels

REPO = Path(__file__).resolve().parents[1]
DATA = REPO / "benchmarks" / "claim_evidence"
_CACHE = {}


def s23():
    if not _CACHE:
        _CACHE["items"] = build_for_scenario("S23", REPO)
        _CACHE["ledger"] = scenario_ledger("S23", REPO)
    return _CACHE["items"], _CACHE["ledger"]


def test_committed_set_is_reproducible_and_label_free():
    items, _ = s23()
    committed = load_items(DATA / "S23.jsonl")
    assert [i.to_dict() for i in committed] == [i.to_dict() for i in items]
    for path in sorted(DATA.glob("*.jsonl")):
        assert find_labels(path.read_text(encoding="utf-8")) == [], path   # built from masked telemetry


def test_labels_are_consistent_with_the_ledger():
    items, ledger = s23()
    assert len({i.item_id for i in items}) == len(items)
    for item in items:
        labels = item.labels
        assert labels["references"] == {e: ledger.has_event(e) for e in item.claim["event_ids"]}
        assert labels["unsupported"] == (labels["support"] in UNSUPPORTED)
        if item.claim["level"] == "HYPOTHESIS":
            assert labels["anchored"] is None and labels["support"] == "NOT_APPLICABLE"
        else:
            assert labels["anchored"] == bool(item.claim["event_ids"] or item.claim["parent_claims"])
    families = {i.family.split("/")[0] for i in items}
    assert families == {"supported", "unrelated", "insufficient", "contradicted", "reference", "provenance", "inferred"}


def test_metrics_on_s23_and_the_known_gap():
    items, ledger = s23()
    report = evaluate(items, predict(items, ledger))
    assert report["reference_validity"]["invalid_detection"]["recall"] == 1.0
    assert report["reference_validity"]["measured_rate"] == report["reference_validity"]["true_rate"]
    assert report["provenance_completeness"]["unanchored_detection"]["f1"] == 1.0
    assert report["unsupported_claim_rate"]["absolute_error"] == 0.0
    by_family = report["semantic_support"]["accuracy_by_family"]
    assert by_family["supported/single"] == by_family["unrelated/same_kind"] == by_family["contradicted/order"] == 1.0
    # Known gap, kept visible on purpose: a wrong parent process is read as missing evidence, not a contradiction.
    assert by_family["contradicted/wrong_parent"] == 0.0
    assert report["guardrail_coverage"]["not_applicable"] == report["guardrail_coverage"]["items"] > 0


def test_annotation_sheet_hides_the_label_and_kappa():
    items, ledger = s23()
    rows = annotation_sheet(items, ledger, n=20)
    assert len(rows) == 20 and all("support" not in r and r["annotator_a"] == "" for r in rows)
    labels = {i.item_id: i.labels["support"] for i in items}
    assert len({labels[r["item_id"]] for r in rows}) >= 4               # stratified across verdicts
    assert cohen_kappa(["A", "B", "A", "B"], ["A", "B", "A", "B"]) == 1.0
    assert cohen_kappa(["A", "A", "B", "B"], ["A", "B", "A", "B"]) == 0.0
    filled = [dict(r, annotator_a=labels[r["item_id"]], annotator_b=labels[r["item_id"]]) for r in rows]
    filled[0]["annotator_b"] = "SUPPORTED" if labels[filled[0]["item_id"]] != "SUPPORTED" else "UNRELATED"
    result = agreement(filled, items)
    assert result["rated"] == 20 and result["kappa_a_construction"] == 1.0
    assert result["disagreements"] == [filled[0]["item_id"]]


def test_committed_annotation_sheets_are_blank():
    for path in sorted(DATA.glob("*_annotation_sheet.csv")):
        with open(path, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        assert rows and not any(r["annotator_a"] or r["annotator_b"] for r in rows), path
        assert "support" not in rows[0]
