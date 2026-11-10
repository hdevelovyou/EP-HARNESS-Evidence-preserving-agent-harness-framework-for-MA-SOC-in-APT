"""Synthetic perturbation benchmark for the semantic rule layer.

For every event that records an actor and an object (process -> connection,
DNS query, file, child process), a true claim is written from the event's own
fields and then perturbed, so each case has a known label:

  SUPPORTED     the true claim, citing its own event
  UNRELATED     the same claim, citing another event that shares neither entity
  INSUFFICIENT  the true claim plus an entity taken from another event
  CONTRADICTED  the true claim with the opposite direction (egress traffic
                called inbound) or a time of day three hours off

This measures whether the rules separate the four cases on real telemetry
fields. It does not measure LLM-written claims, and the templates are simple,
so its scores are an upper bound for the rule layer, not field performance.

    python -m ep_harness.semantic_bench --dataset datasets/CobaltStrike_Lockbit/artifacts.json --masoc-repo .
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path

from .capsule import Capsule, Claim
from .ledger import EvidenceLedger
from .semantic import SemanticVerifier, event_behaviour, event_time

LABELS = ("SUPPORTED", "UNRELATED", "INSUFFICIENT", "CONTRADICTED")
_TEMPLATES = {
    "network": "{actor} opened a connection to {object}",
    "dns": "{actor} resolved {object}",
    "file": "{actor} created the file {object}",
    "process": "{actor} spawned {object}",
}
_OBJECT_KEYS = {
    "network": ("destination.ip", "eventdata.destinationip"),
    "dns": ("dns.question.name", "eventdata.queryname"),
    "file": ("file.path", "eventdata.targetfilename"),
    "process": ("process.name", "eventdata.image"),
}
_ACTOR_KEYS = {
    "process": ("process.parent.name", "eventdata.parentimage"),
    "default": ("process.name", "eventdata.image"),
}


@dataclass
class Case:
    label: str
    kind: str
    text: str
    event_ids: tuple[str, ...]


def _field(flat: dict, keys) -> str:
    for key in keys:
        value = flat.get(key)
        if value:
            base = str(value).replace("[.]", ".").strip().lower()
            return base.split("\\")[-1].split("/")[-1]
    return ""


def _flat(payload, prefix=""):
    out = {}
    if isinstance(payload, dict):
        for key, value in payload.items():
            out.update(_flat(value, f"{prefix}.{key}" if prefix else str(key).lower()))
    elif not isinstance(payload, list) and payload is not None:
        out[prefix.lower()] = payload
    return out


def _facts(ledger: EvidenceLedger, verifier: SemanticVerifier) -> list[dict]:
    facts = []
    for event_id in ledger.event_ids():
        payload = ledger.event(event_id)["payload"]
        behaviour = event_behaviour(payload)
        kind = next((k for k in ("dns", "network", "file", "process") if k in behaviour), None)
        if kind is None:
            continue
        flat = _flat(payload)
        actor = _field(flat, _ACTOR_KEYS["process"] if kind == "process" else _ACTOR_KEYS["default"])
        obj = _field(flat, _OBJECT_KEYS[kind])
        text = ledger.event_text(event_id)
        if (len(actor) < 4 or len(obj) < 4 or actor == obj or actor not in text or obj not in text
                or verifier.is_trivial(actor) or verifier.is_trivial(obj)):
            continue
        facts.append({"event_id": event_id, "kind": kind, "actor": actor, "object": obj, "text": text,
                      "time": event_time(payload), "egress": flat.get("network.direction") == "egress"})
    return facts


def build_cases(ledger: EvidenceLedger, verifier: SemanticVerifier | None = None) -> list[Case]:
    verifier = verifier or SemanticVerifier(ledger)
    facts = _facts(ledger, verifier)
    cases = []
    for index, fact in enumerate(facts):
        claim = _TEMPLATES[fact["kind"]].format(actor=fact["actor"], object=fact["object"])
        cases.append(Case("SUPPORTED", fact["kind"], claim, (fact["event_id"],)))

        others = facts[index + 1:] + facts[:index]
        unrelated = next((o for o in others if fact["actor"] not in o["text"] and fact["object"] not in o["text"]), None)
        if unrelated:
            cases.append(Case("UNRELATED", fact["kind"], claim, (unrelated["event_id"],)))

        extra = next((o["object"] for o in others if o["kind"] == fact["kind"] and o["object"] not in fact["text"]), None)
        if extra:
            cases.append(Case("INSUFFICIENT", fact["kind"], f"{claim} and {extra}", (fact["event_id"],)))

        if fact["kind"] == "network" and fact["egress"]:
            cases.append(Case("CONTRADICTED", fact["kind"],
                              f"{fact['actor']} received an inbound connection from {fact['object']}",
                              (fact["event_id"],)))
        elif fact["time"] is not None:
            shifted = (fact["time"] + timedelta(hours=3)).strftime("%H:%M")
            cases.append(Case("CONTRADICTED", fact["kind"], f"At {shifted}, {claim}", (fact["event_id"],)))
    return cases


def run_benchmark(ledger: EvidenceLedger) -> dict:
    verifier = SemanticVerifier(ledger)
    cases = build_cases(ledger, verifier)
    capsule = Capsule("CAP-BENCH-FINDING-a1", "FINDING", "BENCH", "hunter", "verifier", tuple(
        Claim(c.text, "OBSERVED", c.event_ids, claim_id=f"c{i}") for i, c in enumerate(cases, 1)
    ))
    predicted = [v.verdict for v in verifier.check(capsule).verdicts]
    matrix = {label: {p: 0 for p in LABELS + ("NOT_APPLICABLE",)} for label in LABELS}
    for case, verdict in zip(cases, predicted):
        matrix[case.label][verdict] += 1
    per_class = {}
    for label in LABELS:
        tp = matrix[label][label]
        predicted_as = sum(matrix[other][label] for other in LABELS)
        actual = sum(matrix[label].values())
        per_class[label] = {
            "n": actual,
            "precision": tp / predicted_as if predicted_as else None,
            "recall": tp / actual if actual else None,
        }
    correct = sum(matrix[label][label] for label in LABELS)
    errors = [
        {"label": c.label, "predicted": p, "text": c.text, "event_ids": list(c.event_ids)}
        for c, p in zip(cases, predicted) if c.label != p
    ]
    return {"cases": len(cases), "accuracy": correct / len(cases) if cases else None,
            "per_class": per_class, "confusion": matrix, "errors": errors}


def _ledger_from_dataset(dataset: Path, masoc_repo: Path) -> EvidenceLedger:
    sys.path.insert(0, str(masoc_repo))
    from src.extractor import EvidenceExtractor  # MA-SOC's own extractor, unchanged

    from .adapters.masoc import ledger_from_evidence_store

    extractor = EvidenceExtractor()
    raw = dataset.read_text(encoding="utf-8")
    return ledger_from_evidence_store(extractor.extract(extractor.sanitize_raw_log(raw)))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ep_harness.semantic_bench")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--dataset", help="raw telemetry JSON (needs --masoc-repo for the extractor)")
    source.add_argument("--evidence-store", help="evidence_store.json written by a run")
    parser.add_argument("--masoc-repo", default=".", help="repo root holding src/extractor.py")
    parser.add_argument("--show-errors", action="store_true")
    args = parser.parse_args(argv)
    if args.dataset:
        ledger = _ledger_from_dataset(Path(args.dataset), Path(args.masoc_repo))
    else:
        from .adapters.masoc import ledger_from_evidence_store

        ledger = ledger_from_evidence_store(json.loads(Path(args.evidence_store).read_text(encoding="utf-8")))
    report = run_benchmark(ledger)
    if not args.show_errors:
        report["errors"] = len(report["errors"])
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
