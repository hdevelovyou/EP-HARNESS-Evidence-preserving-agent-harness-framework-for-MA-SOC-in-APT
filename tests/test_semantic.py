"""Semantic Evidence Verification on real S23 telemetry: rules, judge merge, ledger, inline flow, benchmark, main.py."""

import json
import os
import sys
import types
from pathlib import Path

import pytest

from ep_harness import Capsule, Claim, LedgerIntegrityError
from ep_harness.inline import InlineECH
from ep_harness.semantic import SemanticVerifier, apply_judge, parse_judge_verdicts
from ep_harness.semantic_bench import run_benchmark
from test_inline_gate import hunter_output, stubbed_main

REPO = Path(__file__).resolve().parents[1]
S23 = REPO / "extracted_scenarios" / "S23_telemetry.json"
T7_TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
_CACHE = {}


def s23_store():
    if "store" not in _CACHE:
        sys.path.insert(0, str(REPO))
        from src.extractor import EvidenceExtractor

        extractor = EvidenceExtractor()
        _CACHE["store"] = extractor.extract(extractor.sanitize_raw_log(S23.read_text(encoding="utf-8")))
    return _CACHE["store"]


def s23_ech():
    sys.path.insert(0, str(REPO))
    from agents.task_catalog import TASK_INVENTORY

    return InlineECH(s23_store(), TASK_INVENTORY, claim_source="cited")


def verdicts(*claims):
    """Rule verdicts for (text, event_ids[, level]) tuples, in order."""
    ech = s23_ech()
    capsule = Capsule("CAP-T7-FINDING-a1", "FINDING", "T7", "hunter", "verifier", tuple(
        Claim(c[0], c[2] if len(c) > 2 else "OBSERVED", tuple(c[1]), claim_id=f"c{i}") for i, c in enumerate(claims, 1)
    ))
    return SemanticVerifier(ech.ledger).check(capsule).verdicts


# ------------------------------------------------------------ rule layer: the four verdicts
def test_supported_attribute_and_causal_claims():
    attribute, causal = verdicts(
        ("csc.exe created the file tmseiddy.dll", ["event-9"]),
        ("cmd.exe spawned schtasks.exe", ["event-1"]),
    )
    assert (attribute.verdict, attribute.relation) == ("SUPPORTED", "ATTRIBUTE")
    assert (causal.verdict, causal.relation) == ("SUPPORTED", "CAUSAL")
    assert attribute.needs_judge and causal.needs_judge


def test_unrelated_evidence():
    wrong_event, ubiquitous_only = verdicts(
        ("csc.exe created the file tmseiddy.dll", ["event-36"]),          # event-36 is net.exe started by cmd.exe
        ("maryam was active on DESKTOP-FMI6MML", ["event-9"]),            # host and user appear in most events
    )
    assert wrong_event.verdict == "UNRELATED" and wrong_event.irrelevant_events == ["event-36"]
    assert ubiquitous_only.verdict == "UNRELATED"


def test_insufficient_evidence():
    missing, wrong_kind, co_occurrence, vague = verdicts(
        ("csc.exe created the file tmseiddy.dll and lsztxnwp.dll", ["event-9"]),
        ("csc.exe made an outbound connection", ["event-9"]),
        ("csc.exe was launched by schtasks.exe", ["event-1", "event-9"]),
        ("Malicious activity was observed", ["event-9"]),
    )
    assert missing.verdict == "INSUFFICIENT" and missing.missing == ["lsztxnwp.dll"]
    assert wrong_kind.verdict == "INSUFFICIENT" and "events show file" in wrong_kind.reasons[0]
    assert co_occurrence.verdict == "INSUFFICIENT" and "co-occurrence" in co_occurrence.reasons[0]
    assert vague.verdict == "INSUFFICIENT"


def test_contradicted_evidence():
    wrong_time, wrong_order, right_order = verdicts(
        ("At 14:19 csc.exe created the file tmseiddy.dll", ["event-9"]),  # the event is at 11:19
        ("net.exe ran before splunkd.exe created emulate-administrator-tasks.ps1", ["event-36", "event-15"]),
        ("net.exe ran after splunkd.exe created emulate-administrator-tasks.ps1", ["event-36", "event-15"]),
    )
    assert wrong_time.verdict == "CONTRADICTED" and "11:19" in wrong_time.reasons[0]
    assert wrong_order.verdict == "CONTRADICTED" and "order" in wrong_order.reasons[0]
    assert right_order.verdict == "SUPPORTED" and right_order.relation == "TEMPORAL"


def test_nothing_to_check():
    hypothesis, uncited = verdicts(
        ("The actor may be preparing lateral movement", [], "HYPOTHESIS"),
        ("csc.exe created the file tmseiddy.dll", []),
    )
    assert hypothesis.verdict == "NOT_APPLICABLE"
    assert uncited.verdict == "INSUFFICIENT"


# ------------------------------------------------------------ judge layer
def test_judge_can_only_make_verdicts_stricter():
    supported, unrelated = verdicts(
        ("csc.exe created the file tmseiddy.dll", ["event-9"]),
        ("csc.exe created the file tmseiddy.dll", ["event-36"]),
    )
    from ep_harness.semantic import SemanticReport

    report = SemanticReport("CAP-T7-FINDING-a1", [supported, unrelated])
    answer = '```claim_verdicts\n[{"id": "c1", "verdict": "CONTRADICTED", "reason": "wrong user"},' \
             ' {"id": "c2", "verdict": "SUPPORTED"}]\n```'
    judgements, error = parse_judge_verdicts(answer)
    merged = apply_judge(report, judgements, error)
    assert [(v.verdict, v.decided_by) for v in merged.verdicts] == [("CONTRADICTED", "judge"), ("UNRELATED", "rules")]

    kept = apply_judge(report, {"c1": ("SUPPORTED", "")})
    assert kept.verdicts[0].verdict == "SUPPORTED" and kept.verdicts[0].decided_by == "judge"
    silent = apply_judge(report, *parse_judge_verdicts("no block here"))
    assert silent.verdicts[0].verdict == "INSUFFICIENT"
    assert "no ```claim_verdicts block" in silent.verdicts[0].reasons[0]


# ------------------------------------------------------------ ledger
def test_claim_verdicts_are_append_only_and_restricted(tmp_path):
    from ep_harness.ledger import EvidenceLedger

    ech = s23_ech()
    outcome = ech.hunter_handoff("T7", hunter_output(_finding_block([_claim("c1")]), T7_TOOLS))
    ref = f"{outcome.capsule_id}#c1"
    with pytest.raises(LedgerIntegrityError):
        ech.ledger.record_claim_verdict(ref, "SUPPORTED", "hunter")           # the author never judges itself
    with pytest.raises(LedgerIntegrityError):
        ech.ledger.record_claim_verdict(f"{outcome.capsule_id}#c9", "SUPPORTED", "verifier")
    ech.ledger.record_claim_verdict(ref, "SUPPORTED", "verifier")
    ech.ledger.record_claim_verdict(ref, "INSUFFICIENT", "human_analyst")      # a later verdict adds, never erases
    path = tmp_path / "ledger.jsonl"
    ech.ledger.save(path)
    restored = EvidenceLedger.load(path)
    assert [r["verdict"] for r in restored.claim_verdicts(outcome.capsule_id)] == ["SUPPORTED", "INSUFFICIENT"]


# ------------------------------------------------------------ inline flow
def _claim(claim_id, text="csc.exe created the file tmseiddy.dll", events=("event-9",), **extra):
    return dict({"id": claim_id, "text": text, "level": "OBSERVED", "event_ids": list(events), "tools": ["rex_tool"]},
                **extra)


def _finding_block(records):
    return f"csc.exe compiled a DLL.\n\n```evidence_claims\n{json.dumps(records)}\n```"


MIXED = [
    _claim("c1"),
    _claim("c2", events=("event-36",)),
    _claim("c3", text="csc.exe created the file tmseiddy.dll and lsztxnwp.dll"),
    _claim("c4", text="At 14:19 csc.exe created the file tmseiddy.dll"),
]


def test_verified_capsule_follows_the_verdicts():
    ech = s23_ech()
    assert ech.hunter_handoff("T7", hunter_output(_finding_block(MIXED), T7_TOOLS)).accepted
    report = ech.finish_semantic_review("T7", ech.semantic_review("T7"))
    assert report.counts() == {"SUPPORTED": 1, "UNRELATED": 1, "INSUFFICIENT": 1, "CONTRADICTED": 1}
    assert report.feedback().startswith("OK")

    outcome = ech.verifier_handoff("T7")
    assert outcome.accepted, outcome.violations
    verified = ech.ledger.capsule(outcome.capsule_id)
    assert [(c.claim_id, c.level) for c in verified.claims] == [("c1", "OBSERVED"), ("c3", "HYPOTHESIS")]
    assert [(d.ref.split("#")[1], d.reason) for d in verified.dropped_claims] == [
        ("c2", "INSUFFICIENT_EVIDENCE"), ("c4", "REFUTED")]

    summary = ech.summary()
    assert summary["semantic"]["unsupported_claim_rate"] == 0.75
    assert summary["summary"]["claim_flow"]["verifier->analyst"]["dropped_declared"] == 2


def test_finding_without_supported_claims_is_rejected():
    ech = s23_ech()
    ech.hunter_handoff("T7", hunter_output(_finding_block(MIXED[1:]), T7_TOOLS))
    report = ech.finish_semantic_review("T7", ech.semantic_review("T7"))
    assert report.feedback().startswith("FAIL")
    finding = ech._latest[("T7", "FINDING")]
    assert ech.ledger.capsule_status(finding.capsule_id) == "REJECTED"
    assert ech.accepted_task_ids() == set()


def test_semantic_verifier_needs_the_gate():
    sys.path.insert(0, str(REPO))
    from src.orchestration_toggles import load_orchestration_toggles

    saved = {k: os.environ.get(k) for k in ("ENABLE_CONTRACT_GATE", "ENABLE_SEMANTIC_VERIFIER")}
    try:
        os.environ.update(ENABLE_CONTRACT_GATE="0", ENABLE_SEMANTIC_VERIFIER="1")
        with pytest.raises(ValueError):
            load_orchestration_toggles()
    finally:
        for key, value in saved.items():
            os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)


# ------------------------------------------------------------ benchmark
def test_synthetic_benchmark_on_s23():
    report = run_benchmark(s23_ech().ledger)
    assert report["cases"] >= 40
    assert {label: stats["n"] > 0 for label, stats in report["per_class"].items()} == {
        "SUPPORTED": True, "UNRELATED": True, "INSUFFICIENT": True, "CONTRADICTED": True}
    assert report["accuracy"] == 1.0, report["errors"]


# ------------------------------------------------------------ main.py with stubbed agents
def test_main_runs_semantic_review_instead_of_the_verify_call(tmp_path):
    calls = {"verify": 0, "judge": [], "analyst": []}

    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            return [types.SimpleNamespace(content=hunter_output(_finding_block(MIXED), T7_TOOLS))]

    class Verifier:
        def verify(self, *args):
            calls["verify"] += 1
            return "OK"

        def judge_claims(self, task_name, items):
            calls["judge"].append([item["id"] for item in items])
            return '```claim_verdicts\n[{"id": "c1", "verdict": "SUPPORTED", "reason": "event-9 shows it"}]\n```'

    class Analyst:
        def analyze_incident(self, results_str, analysis_context, **kwargs):
            calls["analyst"].append(results_str)
            return "## Findings\ncsc.exe compiled tmseiddy.dll"

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            return f"# Report\n{analysis_text}"

    saved = os.environ.get("ENABLE_SEMANTIC_VERIFIER")
    with stubbed_main(tmp_path, gate_enabled=True, cited=True) as main:
        os.environ["ENABLE_SEMANTIC_VERIFIER"] = "1"
        try:
            main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent = Coordinator, Hunter, Verifier
            main.AnalystAgent, main.ReporterAgent = Analyst, Reporter
            bundle = main._execute_agent_runtime(S23.read_text(encoding="utf-8"), scenario_name="SEM",
                                                 strategy="hierarchical")
        finally:
            os.environ.pop("ENABLE_SEMANTIC_VERIFIER", None) if saved is None else os.environ.__setitem__(
                "ENABLE_SEMANTIC_VERIFIER", saved)

    assert calls["verify"] == 0                      # the claim-level review replaces the OK/FAIL call
    assert calls["judge"] == [["c1"]]                 # only the claim the rules could not reject is judged
    assert [item["status"] for item in bundle["final_results"]] == ["Verified"]
    semantic = bundle["ech_audit"]["semantic"]
    assert semantic["verdicts"] == {"SUPPORTED": 1, "UNRELATED": 1, "INSUFFICIENT": 1, "CONTRADICTED": 1}
    assert semantic["by_layer"]["judge:SUPPORTED"] == 1
    claims_seen = json.loads(calls["analyst"][0])[0]["claims"]
    assert [c["ref"].split("#")[1] for c in claims_seen] == ["c1", "c3"]
