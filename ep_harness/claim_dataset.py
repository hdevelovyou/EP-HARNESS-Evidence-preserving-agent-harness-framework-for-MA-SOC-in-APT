"""A labelled claim-evidence set for checking the harness metrics against known answers.

Each item is one claim with the references it cites and labels that are true
by construction: claims are written from real (masked) S07/S16/S23 events and
then corrupted on purpose, so the right answer is known without asking the
harness. The labels are NOT produced by the semantic rules they will be used
to judge, and some families are corruptions the current rules are known to
miss (e.g. a wrong parent process), so the evaluation can report gaps.

Labels per item:
  references   event/artifact ID -> exists in the ledger            (Reference Validity)
  anchored     OBSERVED/INFERRED claim cites an event, artifact or
               parent claim; None for HYPOTHESIS                     (Provenance Completeness)
  support      SUPPORTED | UNRELATED | INSUFFICIENT | CONTRADICTED |
               NOT_APPLICABLE                                        (Semantic Support)
  unsupported  support in (UNRELATED, INSUFFICIENT, CONTRADICTED)    (Unsupported Claim Rate)

Families (``family`` = kind/subtype):
  supported/single, supported/time, supported/order, supported/parent_link
  unrelated/other_kind, unrelated/same_kind
  insufficient/extra_entity, insufficient/wrong_activity, insufficient/co_occurrence,
  insufficient/uncited
  contradicted/time, contradicted/order, contradicted/wrong_parent
  reference/fabricated, reference/mixed
  provenance/hypothesis
  inferred/restates_parent, inferred/beyond_parent   (need the Output Evidence Guardrail)

Paraphrases rotate per item, including wording outside the semantic rules'
keyword lexicon, so lexical overfitting shows up as errors.
"""

from __future__ import annotations

import json
import random
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from pathlib import Path

from .evidence_cards import card
from .ledger import EvidenceLedger
from .semantic import SemanticVerifier, _flatten, event_time

DATASET_VERSION = "claim-evidence-1"
SUPPORT_LABELS = ("SUPPORTED", "UNRELATED", "INSUFFICIENT", "CONTRADICTED", "NOT_APPLICABLE")
UNSUPPORTED = ("UNRELATED", "INSUFFICIENT", "CONTRADICTED")
FABRICATED_EVENT = "event-99999"

# Paraphrases: the first of each kind uses the rules' vocabulary, the others deliberately do not.
TEMPLATES = {
    "process": ["{actor} spawned {object}", "{object} was launched by {actor}",
                "{actor} kicked off {object}", "{actor} brought up {object} as a child"],
    "file": ["{actor} created the file {object}", "{actor} wrote {object} to disk",
             "{object} appeared on disk, put there by {actor}", "{actor} produced {object}"],
    "network": ["{actor} connected to {object}", "{actor} reached out to {object}",
                "traffic left {actor} for {object}", "{actor} talked to {object}"],
    "dns": ["{actor} resolved {object}", "{actor} looked up {object}",
            "{actor} asked for the address of {object}", "{actor} queried {object}"],
    "registry": ["{actor} modified the registry key {object}", "{actor} changed {object}",
                 "{actor} touched {object}", "{actor} edited {object}"],
}
WRONG_ACTIVITY = {"process": "{actor} opened a network connection to {object}",
                  "file": "{actor} opened a network connection to {object}",
                  "network": "{actor} created the file {object}",
                  "dns": "{actor} created the file {object}",
                  "registry": "{actor} opened a network connection to {object}"}
_PARENT_KEYS = ("eventdata.parentprocessguid", "eventdata.parentprocessid", "process.parent.entity_id")
_OWN_KEYS = ("eventdata.processguid", "eventdata.processid", "process.entity_id")


@dataclass
class Item:
    item_id: str
    scenario: str
    split: str
    family: str
    relation: str
    claim: dict
    labels: dict
    parents: list = field(default_factory=list)       # parent claims for inferred/* items
    label_source: str = "construction"
    note: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _claim(text, level="OBSERVED", event_ids=(), parent_claims=(), observables=()):
    return {"text": text, "level": level, "event_ids": list(event_ids), "parent_claims": list(parent_claims),
            "observables": list(observables)}


def _ids(payload: dict, keys) -> set[str]:
    flat = dict(_flatten(payload))
    return {flat[k] for k in keys if flat.get(k)}


class DatasetBuilder:
    def __init__(self, ledger: EvidenceLedger, scenario: str, split: str, seed: int = 7, max_facts: int = 25):
        self.ledger = ledger
        self.scenario = scenario
        self.split = split
        self.rng = random.Random(f"{scenario}-{seed}")
        self.max_facts = max_facts
        self.verifier = SemanticVerifier(ledger)
        self.items: list[Item] = []

    # ------------------------------------------------------------------ facts
    def _payload(self, event_id):
        return self.ledger.event(event_id)["payload"]

    def facts(self) -> list[dict]:
        out = []
        for event_id in self.ledger.event_ids():
            c = card(self._payload(event_id))
            actor, obj = c["actor"].lower(), c["object"].lower()
            text = self.ledger.event_text(event_id)
            if c["activity"] not in TEMPLATES or len(actor) < 4 or len(obj) < 4 or actor == obj:
                continue
            if actor not in text or obj not in text or self.verifier.is_trivial(actor) or self.verifier.is_trivial(obj):
                continue
            out.append({"event_id": event_id, "kind": c["activity"], "actor": c["actor"], "object": c["object"],
                        "time": event_time(self._payload(event_id)), "text": text})
        if len(out) > self.max_facts:
            step = len(out) / self.max_facts
            out = [out[int(i * step)] for i in range(self.max_facts)]
        return out

    def _sentence(self, fact, variant: int) -> str:
        templates = TEMPLATES[fact["kind"]]
        return templates[variant % len(templates)].format(actor=fact["actor"], object=fact["object"])

    def _add(self, family, relation, claim, labels, note="", parents=()):
        n = len(self.items) + 1
        self.items.append(Item(f"{self.scenario}-{n:04d}", self.scenario, self.split, family, relation, claim,
                               labels, list(parents), note=note))

    def _labels(self, claim, support):
        refs = {e: self.ledger.has_event(e) for e in claim["event_ids"]}
        anchored = None if claim["level"] == "HYPOTHESIS" else bool(claim["event_ids"] or claim["parent_claims"])
        return {"references": refs, "reference_valid": all(refs.values()) if refs else None, "anchored": anchored,
                "support": support, "unsupported": support in UNSUPPORTED}

    def _unrelated_to(self, fact, facts, same_kind):
        candidates = [o for o in facts if o["event_id"] != fact["event_id"] and (o["kind"] == fact["kind"]) == same_kind
                      and fact["actor"].lower() not in o["text"] and fact["object"].lower() not in o["text"]]
        return self.rng.choice(candidates) if candidates else None

    # ------------------------------------------------------------------ families
    def build(self) -> list[Item]:
        facts = self.facts()
        for i, fact in enumerate(facts):
            e = fact["event_id"]
            sentence = self._sentence(fact, i)
            relation = "CAUSAL" if fact["kind"] == "process" else "ATTRIBUTE"
            if fact["kind"] == "process":
                claim = _claim(sentence, event_ids=[e])
                self._add("supported/parent_link", "CAUSAL", claim, self._labels(claim, "SUPPORTED"),
                          "the event records the parent-child link itself")
            else:
                claim = _claim(sentence, event_ids=[e])
                self._add("supported/single", relation, claim, self._labels(claim, "SUPPORTED"))
            if fact["time"]:
                claim = _claim(f"At {fact['time']:%H:%M}, {sentence}", event_ids=[e])
                self._add("supported/time", "TEMPORAL", claim, self._labels(claim, "SUPPORTED"))
                shifted = fact["time"] + timedelta(hours=3)
                claim = _claim(f"At {shifted:%H:%M}, {sentence}", event_ids=[e])
                self._add("contradicted/time", "TEMPORAL", claim, self._labels(claim, "CONTRADICTED"),
                          f"the event is at {fact['time']:%H:%M}")
            for same_kind in (False, True):
                other = self._unrelated_to(fact, facts, same_kind)
                if other:
                    claim = _claim(sentence, event_ids=[other["event_id"]])
                    family = "unrelated/same_kind" if same_kind else "unrelated/other_kind"
                    self._add(family, relation, claim, self._labels(claim, "UNRELATED"),
                              f"cites {other['event_id']} ({other['actor']} -> {other['object']})")
            extra = next((o["object"] for o in facts[i + 1:] + facts[:i]
                          if o["kind"] == fact["kind"] and o["object"].lower() not in fact["text"]), None)
            if extra:
                claim = _claim(f"{sentence} and {extra}", event_ids=[e])
                self._add("insufficient/extra_entity", relation, claim, self._labels(claim, "INSUFFICIENT"),
                          f"{extra} is not in {e}")
            wrong = WRONG_ACTIVITY[fact["kind"]].format(actor=fact["actor"], object=fact["object"])
            claim = _claim(wrong, event_ids=[e])
            self._add("insufficient/wrong_activity", "ATTRIBUTE", claim, self._labels(claim, "INSUFFICIENT"),
                      f"{e} records {fact['kind']} activity")
        self._pairs(facts)
        self._wrong_parents(facts)
        self._references_and_provenance(facts)
        self._inferred(facts)
        return self.items

    def _pairs(self, facts, limit=10):
        timed = [f for f in facts if f["time"]]
        made = 0
        for a in timed:
            for b in timed:
                if made >= limit:
                    return
                if (b["time"] - a["time"]).total_seconds() < 60 or {a["actor"], a["object"]} & {b["actor"], b["object"]}:
                    continue
                first, second = self._sentence(a, 0), self._sentence(b, 0)
                claim = _claim(f"{first}, then {second}", event_ids=[a["event_id"], b["event_id"]])
                self._add("supported/order", "TEMPORAL", claim, self._labels(claim, "SUPPORTED"))
                claim = _claim(f"{second}, then {first}", event_ids=[a["event_id"], b["event_id"]])
                self._add("contradicted/order", "TEMPORAL", claim, self._labels(claim, "CONTRADICTED"),
                          f"{a['event_id']} ({a['time']:%H:%M:%S}) precedes {b['event_id']} ({b['time']:%H:%M:%S})")
                if not self._linked(a["event_id"], b["event_id"]):
                    claim = _claim(f"{b['actor']} was launched by {a['object']}",
                                   event_ids=[a["event_id"], b["event_id"]])
                    self._add("insufficient/co_occurrence", "CAUSAL", claim, self._labels(claim, "INSUFFICIENT"),
                              "both entities occur in the cited events, but no event records a link")
                made += 1

    def _linked(self, a, b) -> bool:
        pa, pb = self._payload(a), self._payload(b)
        return bool(_ids(pa, _OWN_KEYS) & _ids(pb, _PARENT_KEYS) or _ids(pb, _OWN_KEYS) & _ids(pa, _PARENT_KEYS))

    def _wrong_parents(self, facts, limit=10):
        processes = [f for f in facts if f["kind"] == "process"]
        names = sorted({f["actor"] for f in processes} | {f["object"] for f in processes})
        for fact in processes[:limit]:
            wrong = next((n for n in names if n.lower() not in fact["text"]), None)
            if wrong:
                claim = _claim(f"{wrong} spawned {fact['object']}", event_ids=[fact["event_id"]])
                self._add("contradicted/wrong_parent", "CAUSAL", claim, self._labels(claim, "CONTRADICTED"),
                          f"{fact['event_id']} records {fact['actor']} as the parent")

    def _references_and_provenance(self, facts, limit=8):
        for i, fact in enumerate(facts[:limit]):
            sentence = self._sentence(fact, i + 1)
            claim = _claim(sentence, event_ids=[FABRICATED_EVENT])
            self._add("reference/fabricated", "ATTRIBUTE", claim, self._labels(claim, "INSUFFICIENT"),
                      "the only cited event does not exist")
            claim = _claim(sentence, event_ids=[fact["event_id"], FABRICATED_EVENT])
            self._add("reference/mixed", "ATTRIBUTE", claim, self._labels(claim, "SUPPORTED"),
                      "one real, one fabricated reference")
            claim = _claim(sentence, event_ids=[])
            self._add("insufficient/uncited", "ATTRIBUTE", claim, self._labels(claim, "INSUFFICIENT"),
                      "OBSERVED claim that cites nothing")
            claim = _claim(f"{fact['actor']} may be part of the intrusion", level="HYPOTHESIS")
            self._add("provenance/hypothesis", "ATTRIBUTE", claim, self._labels(claim, "NOT_APPLICABLE"))

    def _inferred(self, facts, limit=8):
        for i, fact in enumerate(facts[:limit]):
            parent = {"ref": "CAP-P-FINDING-a1#c1", "text": self._sentence(fact, 0), "level": "OBSERVED",
                      "event_ids": [fact["event_id"]]}
            claim = _claim(f"{fact['actor']} is tied to {fact['object']}", level="INFERRED",
                           parent_claims=[parent["ref"]])
            self._add("inferred/restates_parent", "CORRELATION", claim, self._labels(claim, "SUPPORTED"),
                      "restates the parent claim; checkable only by the Output Evidence Guardrail", [parent])
            other = self._unrelated_to(fact, facts, same_kind=False)
            if other:
                claim = _claim(f"{fact['actor']} is tied to {other['object']}", level="INFERRED",
                               parent_claims=[parent["ref"]])
                self._add("inferred/beyond_parent", "CORRELATION", claim, self._labels(claim, "INSUFFICIENT"),
                          f"{other['object']} is not in the parent's evidence", [parent])


# ---------------------------------------------------------------------- I/O
SPLITS = {"S16": "dev", "S23": "dev", "S07": "test"}


def build_for_scenario(scenario: str, repo: Path, seed: int = 7) -> list[Item]:
    """Sanitize and mask the scenario exactly as the runtime does, then build its items."""
    import sys

    sys.path.insert(0, str(repo))
    from src.extractor import EvidenceExtractor  # MA-SOC's own extractor, unchanged

    from .adapters.masoc import ledger_from_evidence_store
    from .label_guard import mask_labels

    extractor = EvidenceExtractor()
    raw = (repo / "extracted_scenarios" / f"{scenario}_telemetry.json").read_text(encoding="utf-8")
    masked = mask_labels(extractor.sanitize_raw_log(raw), markers=True).text
    ledger = ledger_from_evidence_store(extractor.extract(masked))
    return DatasetBuilder(ledger, scenario, SPLITS.get(scenario, "dev"), seed).build()


def save_items(items: list[Item], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for item in items:
            handle.write(json.dumps(item.to_dict(), ensure_ascii=False) + "\n")


def load_items(path: Path) -> list[Item]:
    with open(path, encoding="utf-8") as handle:
        return [Item(**json.loads(line)) for line in handle if line.strip()]
