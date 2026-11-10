"""Uniform post-run measurement: the same instrument for every configuration.

Configurations differ in what they enforce (nothing in MA-SOC and in the
Structured Capsule baseline; gate, semantic review and policy in EP-HARNESS),
but they must be measured the same way, or their numbers cannot be compared.
After a run, this module rebuilds a fresh ledger from the (masked) evidence
store and re-reads what the agents produced:

  findings   the last Hunter output of every task (all tasks, and the ones
             forwarded as Verified)
  analysis   the Analyst's text as written
  report     the sealed final report

Claims are read from an evidence_claims block when the output has one, and
otherwise derived line by line (as for MA-SOC's free text). Each claim is then
checked with the deterministic instruments only, never with a model:

  reference validity       cited events/artifacts that exist / all cited
  provenance completeness  OBSERVED/INFERRED claims citing an event, artifact or parent claim
  semantic verdicts        rule layer of ep_harness.semantic (no judge)
  unsupported claim rate   (UNRELATED + INSUFFICIENT + CONTRADICTED) / claims checked
  irrelevant citation rate cited events unrelated to their claim / cited events checked

Parent-claim references point at capsules of the run, not of this fresh
ledger, so they count toward provenance but not toward reference validity.
"""

from __future__ import annotations

from collections import Counter

from .adapters.masoc import (
    claims_from_text,
    finding_claims,
    ledger_from_evidence_store,
    observable_index,
    register_tool_artifacts,
    split_tool_audit,
)
from .capsule import Capsule
from .claim_parser import claims_from_records, extract_claims_block
from .semantic import SemanticVerifier

MEASUREMENT_VERSION = "measure-1"
_UNSUPPORTED = ("UNRELATED", "INSUFFICIENT", "CONTRADICTED")


def _metrics(claims_with_verdicts) -> dict:
    """claims_with_verdicts: list of (Claim, ClaimVerdict, valid_refs, total_refs)."""
    verdicts = Counter(v.verdict for _, v, _, _ in claims_with_verdicts)
    total_refs = sum(t for _, _, _, t in claims_with_verdicts)
    valid_refs = sum(ok for _, _, ok, _ in claims_with_verdicts)
    scoped = [c for c, _, _, _ in claims_with_verdicts if c.level in ("OBSERVED", "INFERRED")]
    anchored = sum(1 for c in scoped if c.event_ids or c.artifact_ids or c.parent_claims)
    checked = sum(n for verdict, n in verdicts.items() if verdict != "NOT_APPLICABLE")
    relevant = sum(len(v.relevant_events) for _, v, _, _ in claims_with_verdicts)
    irrelevant = sum(len(v.irrelevant_events) for _, v, _, _ in claims_with_verdicts)
    return {
        "claims": len(claims_with_verdicts),
        "levels": dict(Counter(c.level for c, _, _, _ in claims_with_verdicts)),
        "cited_references": total_refs,
        "reference_validity": round(valid_refs / total_refs, 4) if total_refs else None,
        "provenance_completeness": round(anchored / len(scoped), 4) if scoped else None,
        "verdicts": dict(verdicts),
        "unsupported_claim_rate": round(sum(verdicts[v] for v in _UNSUPPORTED) / checked, 4) if checked else None,
        "irrelevant_citation_rate": round(irrelevant / (relevant + irrelevant), 4) if relevant + irrelevant else None,
    }


class _Instrument:
    def __init__(self, evidence_store: dict):
        self.ledger = ledger_from_evidence_store(evidence_store)
        self.obs_index = observable_index(evidence_store)
        self.verifier = SemanticVerifier(self.ledger)
        self.sources: Counter = Counter()

    def _refs(self, claim) -> tuple[int, int]:
        refs = list(claim.event_ids) + list(claim.artifact_ids)
        valid = sum(1 for e in claim.event_ids if self.ledger.has_event(e))
        valid += sum(1 for a in claim.artifact_ids if self.ledger.has_artifact(a))
        return valid, len(refs)

    def _check(self, capsule_id: str, kind: str, claims) -> list:
        capsule = Capsule(capsule_id, kind, "MEASURE", "hunter", "verifier", tuple(claims))
        return [(c, self.verifier.check_claim(capsule, c), *self._refs(c)) for c in capsule.claims]

    def finding(self, task_id: str, output: str) -> list:
        body, audit = split_tool_audit(output)
        artifact_ids = register_tool_artifacts(self.ledger, task_id, audit)
        claims, source = finding_claims(body, self.obs_index, audit, artifact_ids)
        self.sources[f"findings:{source}"] += 1
        return self._check(f"CAP-M-{task_id}-FINDING", "FINDING", claims)

    def text(self, name: str, text: str) -> list:
        parsed = extract_claims_block(text)
        if parsed.found:
            claims, source = claims_from_records(parsed.records), "agent"
        else:
            claims, source = claims_from_text(text, self.obs_index, []), "heuristic"
        self.sources[f"{name}:{source}"] += 1
        return self._check(f"CAP-M-{name.upper()}", "ANALYSIS", claims)


def measure_run(evidence_store: dict, final_results: list[dict], analysis_text: str = "",
                report_text: str = "") -> dict:
    instrument = _Instrument(evidence_store)
    all_findings, forwarded = [], []
    for item in final_results:
        checked = instrument.finding(str(item.get("task_id", "")), str(item.get("result", "") or ""))
        all_findings += checked
        if item.get("status") == "Verified":
            forwarded += checked
    return {
        "version": MEASUREMENT_VERSION,
        "tasks": len(final_results),
        "task_status": dict(Counter(str(i.get("status")) for i in final_results)),
        "findings": _metrics(all_findings),
        "forwarded_findings": _metrics(forwarded),
        "analysis": _metrics(instrument.text("analysis", analysis_text)),
        "report": _metrics(instrument.text("report", report_text)),
        "claim_sources": dict(instrument.sources),
    }
