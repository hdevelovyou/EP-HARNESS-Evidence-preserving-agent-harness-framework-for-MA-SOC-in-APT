"""Score the harness metrics against the labelled claim-evidence set, and check the labels with people.

    python -m ep_harness.claim_eval build    --scenario S23          # writes benchmarks/claim_evidence/S23.jsonl
    python -m ep_harness.claim_eval evaluate --scenario S23          # rules only, no model
    python -m ep_harness.claim_eval sheet    --scenario S23 --n 40   # blind annotation sheet (CSV)
    python -m ep_harness.claim_eval agreement --sheet <file.csv>     # Cohen's kappa: annotators vs construction

What each metric is checked against:
  Reference Validity       gate C3 flags exactly the references that do not exist
  Provenance Completeness  gate R1 flags exactly the OBSERVED/INFERRED claims that cite nothing
  Semantic Support         the semantic verdict equals the constructed support label
  Unsupported Claim Rate   the measured rate equals the true rate; per-claim detection

Items of the inferred/* families rest on parent claims. The semantic rules
answer NOT_APPLICABLE for them by design; they are reported as coverage for
the Output Evidence Guardrail, not mixed into the Semantic Support scores.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from collections import Counter
from pathlib import Path

from .capsule import Capsule, Claim
from .claim_dataset import SPLITS, UNSUPPORTED, build_for_scenario, load_items, save_items
from .contracts import default_masoc_registry
from .evidence_cards import card, card_line
from .gate import ContractGate
from .ledger import EvidenceLedger
from .semantic import SemanticVerifier

DEFAULT_DIR = Path("benchmarks") / "claim_evidence"
CLASSES = ("SUPPORTED", "UNRELATED", "INSUFFICIENT", "CONTRADICTED")


def scenario_ledger(scenario: str, repo: Path) -> EvidenceLedger:
    """The masked ledger the runtime would build for this scenario."""
    sys.path.insert(0, str(repo))
    from src.extractor import EvidenceExtractor

    from .adapters.masoc import ledger_from_evidence_store
    from .label_guard import mask_labels

    extractor = EvidenceExtractor()
    raw = (repo / "extracted_scenarios" / f"{scenario}_telemetry.json").read_text(encoding="utf-8")
    return ledger_from_evidence_store(extractor.extract(mask_labels(extractor.sanitize_raw_log(raw), markers=True).text))


def _ratio(a, b):
    return round(a / b, 4) if b else None


def _prf(tp, fp, fn):
    p, r = _ratio(tp, tp + fp), _ratio(tp, tp + fn)
    f1 = round(2 * p * r / (p + r), 4) if p and r else (0.0 if p is not None and r is not None else None)
    return {"precision": p, "recall": r, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


def _claim_of(item, claim_id="c1", parent_ref_map=None) -> Claim:
    c = item.claim
    parents = [parent_ref_map.get(r, r) for r in c["parent_claims"]] if parent_ref_map else list(c["parent_claims"])
    return Claim(c["text"], c["level"], tuple(c["event_ids"]), claim_id=claim_id, parent_claims=tuple(parents),
                 derivation="REFINED" if parents else "NEW", observables=tuple(c.get("observables", ())))


def predict(items, ledger: EvidenceLedger) -> list[dict]:
    """Run the gate and the semantic rules on every item; one capsule per item, so items never interact."""
    gate = ContractGate(ledger, default_masoc_registry(), enforce_task_registry=False)
    verifier = SemanticVerifier(ledger)
    out = []
    for item in items:
        ref_map = {}
        kind, source, dest, parents = "FINDING", "hunter", "verifier", ()
        if item.parents:  # inferred/*: an accepted parent finding, then the claim that builds on it
            parent_id = f"CAP-{item.item_id}-P"
            parent = Capsule(parent_id, "FINDING", "EVAL", "hunter", "verifier", tuple(
                Claim(p["text"], p["level"], tuple(p["event_ids"]), claim_id=f"c{i}")
                for i, p in enumerate(item.parents, 1)))
            gate.check(parent)
            ledger.record_decision(parent_id, "ACCEPTED", "verifier")
            ref_map = {p["ref"]: f"{parent_id}#c{i}" for i, p in enumerate(item.parents, 1)}
            kind, source, dest, parents = "VERIFIED", "verifier", "analyst", (parent_id,)
        capsule = Capsule(f"CAP-{item.item_id}", kind, "EVAL", source, dest, (_claim_of(item, parent_ref_map=ref_map),),
                          parent_capsules=parents)
        result = gate.check(capsule)
        flagged = {v.detail.split(" ")[0] for v in result.violations if v.code in ("dangling_event", "dangling_artifact")}
        unanchored = any(v.code in ("unanchored_observation", "unanchored_inference") for v in result.violations)
        verdict = verifier.check_claim(capsule, capsule.claims[0])
        out.append({"item_id": item.item_id, "family": item.family, "invalid_refs": sorted(flagged),
                    "anchored": not unanchored, "support": verdict.verdict, "reasons": verdict.reasons})
    return out


def evaluate(items, predictions) -> dict:
    by_id = {p["item_id"]: p for p in predictions}

    # Reference Validity: detecting references that do not exist.
    tp = fp = fn = 0
    refs_total = refs_valid_true = refs_valid_measured = 0
    for item in items:
        flagged = set(by_id[item.item_id]["invalid_refs"])
        for ref, exists in item.labels["references"].items():
            refs_total += 1
            refs_valid_true += exists
            refs_valid_measured += ref not in flagged
            if not exists and ref in flagged:
                tp += 1
            elif exists and ref in flagged:
                fp += 1
            elif not exists:
                fn += 1
    reference = {"invalid_detection": _prf(tp, fp, fn), "references": refs_total,
                 "true_rate": _ratio(refs_valid_true, refs_total), "measured_rate": _ratio(refs_valid_measured, refs_total)}

    # Provenance Completeness: detecting OBSERVED/INFERRED claims that cite nothing.
    tp = fp = fn = 0
    scoped = [i for i in items if i.labels["anchored"] is not None]
    for item in scoped:
        truth, pred = item.labels["anchored"], by_id[item.item_id]["anchored"]
        tp += (not truth) and (not pred)
        fp += truth and (not pred)
        fn += (not truth) and pred
    provenance = {"unanchored_detection": _prf(tp, fp, fn), "claims": len(scoped),
                  "true_rate": _ratio(sum(i.labels["anchored"] for i in scoped), len(scoped)),
                  "measured_rate": _ratio(sum(by_id[i.item_id]["anchored"] for i in scoped), len(scoped))}

    # Semantic Support: constructed label vs rule verdict (inferred/* reported apart).
    checkable = [i for i in items if not i.family.startswith("inferred/") and i.labels["support"] != "NOT_APPLICABLE"]
    confusion = {c: Counter() for c in CLASSES}
    for item in checkable:
        confusion[item.labels["support"]][by_id[item.item_id]["support"]] += 1
    per_class = {}
    for c in CLASSES:
        tp = confusion[c][c]
        fp = sum(confusion[o][c] for o in CLASSES if o != c)
        fn = sum(n for p, n in confusion[c].items() if p != c)
        per_class[c] = dict(_prf(tp, fp, fn), n=sum(confusion[c].values()))
    f1s = [v["f1"] for v in per_class.values() if v["f1"] is not None]
    families = {}
    for item in items:
        stats = families.setdefault(item.family, [0, 0])
        stats[0] += by_id[item.item_id]["support"] == item.labels["support"]
        stats[1] += 1
    support = {"items": len(checkable),
               "accuracy": _ratio(sum(confusion[c][c] for c in CLASSES), len(checkable)),
               "macro_f1": round(sum(f1s) / len(f1s), 4) if f1s else None, "per_class": per_class,
               "confusion": {c: dict(confusion[c]) for c in CLASSES},
               "accuracy_by_family": {f: _ratio(a, n) for f, (a, n) in sorted(families.items())}}

    # Unsupported Claim Rate: true vs measured, and per-claim detection.
    tp = sum(1 for i in checkable if i.labels["unsupported"] and by_id[i.item_id]["support"] in UNSUPPORTED)
    fp = sum(1 for i in checkable if not i.labels["unsupported"] and by_id[i.item_id]["support"] in UNSUPPORTED)
    fn = sum(1 for i in checkable if i.labels["unsupported"] and by_id[i.item_id]["support"] not in UNSUPPORTED)
    true_rate = _ratio(sum(i.labels["unsupported"] for i in checkable), len(checkable))
    measured = _ratio(sum(by_id[i.item_id]["support"] in UNSUPPORTED for i in checkable), len(checkable))
    ucr = {"true_rate": true_rate, "measured_rate": measured,
           "absolute_error": round(abs(measured - true_rate), 4) if checkable else None,
           "unsupported_detection": _prf(tp, fp, fn)}

    inferred = [i for i in items if i.family.startswith("inferred/")]
    coverage = {"items": len(inferred),
                "not_applicable": sum(by_id[i.item_id]["support"] == "NOT_APPLICABLE" for i in inferred),
                "note": "claims resting on parent claims need the Output Evidence Guardrail"}
    return {"items": len(items), "reference_validity": reference, "provenance_completeness": provenance,
            "semantic_support": support, "unsupported_claim_rate": ucr, "guardrail_coverage": coverage}


# ---------------------------------------------------------------------- human check of the labels
SHEET_FIELDS = ("item_id", "claim", "level", "cited_events", "annotator_a", "annotator_b", "comment")


def annotation_sheet(items, ledger: EvidenceLedger, n: int, seed: int = 11) -> list[dict]:
    """A stratified sample with the constructed label hidden: the annotators see the claim and the cited cards."""
    rng = random.Random(seed)
    by_label: dict[str, list] = {}
    for item in items:
        if not item.family.startswith("inferred/"):
            by_label.setdefault(item.labels["support"], []).append(item)
    sample = []
    while len(sample) < n and any(by_label.values()):
        for label in sorted(by_label):
            if by_label[label] and len(sample) < n:
                sample.append(by_label[label].pop(rng.randrange(len(by_label[label]))))
    rng.shuffle(sample)
    rows = []
    for item in sample:
        cards = [card_line(card(ledger.event(e)["payload"])) if ledger.has_event(e) else f"{e} | (no such event)"
                 for e in item.claim["event_ids"]]
        rows.append({"item_id": item.item_id, "claim": item.claim["text"], "level": item.claim["level"],
                     "cited_events": " || ".join(cards) or "(none)", "annotator_a": "", "annotator_b": "",
                     "comment": ""})
    return rows


def cohen_kappa(a: list[str], b: list[str]) -> float | None:
    if not a or len(a) != len(b):
        return None
    n = len(a)
    observed = sum(x == y for x, y in zip(a, b)) / n
    ca, cb = Counter(a), Counter(b)
    expected = sum(ca[k] * cb[k] for k in set(ca) | set(cb)) / (n * n)
    return round((observed - expected) / (1 - expected), 4) if expected < 1 else 1.0


def agreement(sheet_rows: list[dict], items) -> dict:
    labels = {i.item_id: i.labels["support"] for i in items}
    done = [r for r in sheet_rows if r.get("annotator_a", "").strip() and r.get("annotator_b", "").strip()]
    a = [r["annotator_a"].strip().upper() for r in done]
    b = [r["annotator_b"].strip().upper() for r in done]
    c = [labels.get(r["item_id"], "") for r in done]
    return {"rated": len(done), "kappa_a_b": cohen_kappa(a, b), "kappa_a_construction": cohen_kappa(a, c),
            "kappa_b_construction": cohen_kappa(b, c),
            "disagreements": [r["item_id"] for r, x, y, z in zip(done, a, b, c) if len({x, y, z}) > 1]}


# ---------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ep_harness.claim_eval")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("build", "evaluate", "sheet"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--scenario", required=True, choices=sorted(SPLITS))
        cmd.add_argument("--repo", default=".")
        cmd.add_argument("--dir", default=str(DEFAULT_DIR))
        if name == "sheet":
            cmd.add_argument("--n", type=int, default=40)
    agree = sub.add_parser("agreement")
    agree.add_argument("--sheet", required=True)
    agree.add_argument("--dir", default=str(DEFAULT_DIR))
    args = parser.parse_args(argv)

    if args.command == "agreement":
        with open(args.sheet, encoding="utf-8-sig", newline="") as handle:
            rows = list(csv.DictReader(handle))
        items = [i for path in Path(args.dir).glob("*.jsonl") for i in load_items(path)]
        print(json.dumps(agreement(rows, items), ensure_ascii=False, indent=2))
        return 0

    repo, folder = Path(args.repo), Path(args.dir)
    path = folder / f"{args.scenario}.jsonl"
    if args.command == "build":
        items = build_for_scenario(args.scenario, repo)
        save_items(items, path)
        print(json.dumps({"written": str(path), "items": len(items),
                          "families": dict(Counter(i.family for i in items))}, indent=2))
        return 0
    items = load_items(path)
    ledger = scenario_ledger(args.scenario, repo)
    if args.command == "sheet":
        rows = annotation_sheet(items, ledger, args.n)
        out = folder / f"{args.scenario}_annotation_sheet.csv"
        with open(out, "w", encoding="utf-8-sig", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=SHEET_FIELDS)
            writer.writeheader()
            writer.writerows(rows)
        print(json.dumps({"written": str(out), "rows": len(rows)}, indent=2))
        return 0
    report = evaluate(items, predict(items, ledger))
    report.update(scenario=args.scenario, split=SPLITS[args.scenario])
    out = folder / f"{args.scenario}_eval.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
