"""Adaptive Evidence-Triggered Policy: decisions from signals and budget, and full task runs on S23 with stubs."""

import json
import os
import sys
import types
from pathlib import Path

from ep_harness.inline import InlineECH
from ep_harness.policy import AdaptivePolicy, Budget, ClaimSignal
from ep_harness.policy_runner import run_task
from test_inline_gate import hunter_output, stubbed_main

REPO = Path(__file__).resolve().parents[1]
S23 = REPO / "extracted_scenarios" / "S23_telemetry.json"
T7 = {"id": "T7", "name": "Infrastructure Extraction"}
TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
_CACHE = {}


def ech():
    if not _CACHE:
        sys.path.insert(0, str(REPO))
        from agents.task_catalog import TASK_INVENTORY
        from src.extractor import EvidenceExtractor

        extractor = EvidenceExtractor()
        _CACHE["store"] = extractor.extract(extractor.sanitize_raw_log(S23.read_text(encoding="utf-8")))
        _CACHE["inventory"] = TASK_INVENTORY
    return InlineECH(_CACHE["store"], _CACHE["inventory"], claim_source="cited")


def sig(claim_id, signal, relation="ATTRIBUTE", conflict=False):
    return ClaimSignal(claim_id, signal, "", relation, conflict)


# ------------------------------------------------------------ decisions from signals
def test_semantic_signals_pick_the_cheapest_useful_action():
    policy = AdaptivePolicy(Budget(task_retries=1))
    first = policy.decide_semantic("T7", [sig("c1", "SUPPORTED"), sig("c2", "CONTRADICTED"), sig("c3", "INSUFFICIENT")])
    assert (first.action, first.mode, first.accept, first.reject, first.revise) == (
        "TARGETED_RETRY", "revise", ["c1"], ["c2"], ["c3"])
    policy.budget.spend_retry("T7")
    second = policy.decide_semantic("T7", [sig("c1", "SUPPORTED"), sig("c3", "INSUFFICIENT"), sig("c4", "UNRELATED")])
    assert (second.action, second.accept, second.hold, second.reject) == ("ACCEPT", ["c1"], ["c3"], ["c4"])


def test_no_progress_stops_retrying_even_with_budget_left():
    policy = AdaptivePolicy(Budget(task_retries=5))
    signals = [sig("c1", "INSUFFICIENT")]
    assert policy.decide_semantic("T7", signals).action == "TARGETED_RETRY"
    again = policy.decide_semantic("T7", signals)
    assert again.action == "UNRESOLVED" and "no progress" in again.reason


def test_disputed_and_causal_claims_go_to_review_within_budget():
    policy = AdaptivePolicy(Budget(task_retries=0, reviews=1))
    decision = policy.decide_semantic("T7", [
        sig("c1", "SUPPORTED"),
        sig("c2", "CONTRADICTED", conflict=True),     # rules said SUPPORTED, the judge disagreed
        sig("c3", "INSUFFICIENT", relation="CAUSAL"),  # no event records the causal link
    ])
    assert decision.action == "ACCEPT" and decision.review == ["c2"]
    assert decision.hold == ["c3"]                     # review budget spent: held as HYPOTHESIS instead
    only_disputed = AdaptivePolicy(Budget(task_retries=0)).decide_semantic("T9", [sig("c1", "UNRELATED", conflict=True)])
    assert only_disputed.action == "TARGETED_REVIEW"


def test_gate_signals_map_to_filter_revise_rerun_or_stop():
    policy = AdaptivePolicy(Budget(task_retries=1))
    assert policy.decide_gate("A", [sig("c2", "dangling_event")], [], []).action == "REJECT"
    revise = policy.decide_gate("B", [sig("c1", "observable_not_in_evidence"), sig("c2", "dangling_event")], [], [])
    assert (revise.action, revise.mode, revise.revise, revise.reject) == ("TARGETED_RETRY", "revise", ["c1"], ["c2"])
    assert policy.decide_gate("C", [], ["missing_tool"], []).mode == "rerun"
    assert policy.decide_gate("D", [], ["too_few_claims"], ["no ```evidence_claims block found"]).mode == "revise"
    assert policy.decide_gate("E", [], ["unknown_edge"], []).action == "UNRESOLVED"


def test_llm_call_budget_and_always_review_mode():
    tight = AdaptivePolicy(Budget(task_retries=3, llm_calls=1))
    tight.budget.spend_call("hunter")
    assert tight.decide_semantic("T7", [sig("c1", "INSUFFICIENT")]).action == "UNRESOLVED"
    review_all = AdaptivePolicy(Budget(task_retries=3), mode="always_review")
    decision = review_all.decide_semantic("T7", [sig("c1", "SUPPORTED"), sig("c2", "INSUFFICIENT")])
    assert (decision.action, decision.review, decision.revise) == ("ACCEPT", ["c2"], [])


# ------------------------------------------------------------ full task runs (S23, stubbed agents)
def block(records):
    return f"csc.exe built DLLs.\n\n```evidence_claims\n{json.dumps(records)}\n```"


GOOD = {"id": "c1", "evidence": ["event-9"], "observables": ["csc.exe", "tmseiddy.dll"], "tools": ["rex_tool"],
        "level": "OBSERVED", "text": "csc.exe created the file tmseiddy.dll"}
THIN = {"id": "c2", "evidence": ["event-9"], "tools": ["rex_tool"], "level": "OBSERVED",
        "text": "csc.exe created the file tmseiddy.dll and lsztxnwp.dll"}
FAKE = {"id": "c3", "evidence": ["event-9999"], "level": "OBSERVED", "text": "Lateral movement reached the DC"}
FIXED = {"id": "c2", "evidence": ["event-9", "event-14"], "level": "OBSERVED",
         "text": "csc.exe created the file tmseiddy.dll and lsztxnwp.dll"}


class Agents:
    """Scripted Hunter/Verifier: outputs, revisions and judge verdicts in order."""

    def __init__(self, outputs, revisions=(), judge_verdict=lambda item: "SUPPORTED"):
        self.outputs, self.revisions, self.judge_verdict = list(outputs), list(revisions), judge_verdict
        self.calls = {"hunter": 0, "revise": [], "judge": 0}

    def hunter_run(self, feedback):
        self.calls["hunter"] += 1
        return self.outputs.pop(0)

    def hunter_revise(self, request, claims_json):
        self.calls["revise"].append(request)
        return self.revisions.pop(0)

    def judge(self, task_name, items):
        self.calls["judge"] += 1
        return "```claim_verdicts\n" + json.dumps(
            [{"id": i["id"], "verdict": self.judge_verdict(i), "reason": "stub"} for i in items]) + "\n```"

    def run(self, harness, policy):
        return run_task(T7, harness, policy, hunter_run=self.hunter_run, hunter_revise=self.hunter_revise,
                        judge=self.judge, semantic=True)


def test_fabricated_claim_is_filtered_and_thin_claim_revised():
    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=1))
    agents = Agents([hunter_output(block([GOOD, THIN, FAKE]), TOOLS)],
                    revisions=["```evidence_claims\n" + json.dumps([FIXED]) + "\n```"])
    result = agents.run(harness, policy)
    assert result.status == "Verified", result
    assert agents.calls["hunter"] == 1 and len(agents.calls["revise"]) == 1
    request = agents.calls["revise"][0]
    assert "c2" in request and "c1" not in request.split("\n", 1)[1] and "candidate card: event-14" in request
    assert [d["action"] for d in result.decisions] == ["REJECT", "TARGETED_RETRY", "ACCEPT"]

    chain = [c for c in harness.capsules if c.kind == "FINDING"]
    assert [chain[0].metadata.get("derived_by"), chain[2].metadata.get("kept")] == [None, ["c1"]]
    assert chain[1].metadata["removed_claims"] == ["c3"] and chain[1].metadata["derived_by"] == "policy_orchestrator"
    verified = harness.ledger.capsule([c for c in harness.capsules if c.kind == "VERIFIED"][-1].capsule_id)
    assert [(c.claim_id, c.level) for c in verified.claims] == [("c1", "OBSERVED"), ("c2", "OBSERVED")]
    assert policy.budget.used_calls == {"hunter": 1, "revise": 1, "judge": 2}


def test_revision_without_progress_keeps_the_claim_as_hypothesis():
    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=1))
    agents = Agents([hunter_output(block([GOOD, THIN]), TOOLS)],
                    revisions=["```evidence_claims\n" + json.dumps([THIN]) + "\n```"])
    result = agents.run(harness, policy)
    assert result.status == "Verified" and result.decisions[-1]["hold"] == ["c2"]
    verified = harness.ledger.capsule([c for c in harness.capsules if c.kind == "VERIFIED"][-1].capsule_id)
    assert [(c.claim_id, c.level) for c in verified.claims] == [("c1", "OBSERVED"), ("c2", "HYPOTHESIS")]


def test_missing_tool_reruns_the_hunter_then_stops():
    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=1))
    no_rex = hunter_output(block([GOOD]), ["ner_tool", "sum_tool"])
    agents = Agents([no_rex, hunter_output(block([GOOD]), TOOLS)])
    assert agents.run(harness, policy).status == "Verified" and agents.calls["hunter"] == 2

    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=1))
    stuck = Agents([no_rex, no_rex]).run(harness, policy)
    assert stuck.status == "Unresolved" and "no progress" in stuck.reason


def test_layer_disagreement_is_reviewed_not_silently_dropped():
    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=0))
    agents = Agents([hunter_output(block([GOOD, FIXED]), TOOLS)],
                    judge_verdict=lambda item: "CONTRADICTED" if item["id"] == "c1" else "SUPPORTED")
    result = agents.run(harness, policy)
    assert result.status == "Verified" and result.decisions[-1]["review"] == ["c1"]
    assert [q["ref"].split("#")[1] for q in harness.review_queue] == ["c1"]
    verified = harness.ledger.capsule([c for c in harness.capsules if c.kind == "VERIFIED"][-1].capsule_id)
    assert [(c.claim_id, c.level) for c in verified.claims] == [("c1", "HYPOTHESIS"), ("c2", "OBSERVED")]

    harness, policy = ech(), AdaptivePolicy(Budget(task_retries=0))
    held = Agents([hunter_output(block([GOOD]), TOOLS)], judge_verdict=lambda item: "UNRELATED").run(harness, policy)
    assert held.status == "Review_Required"
    assert harness.ledger.capsule_status(harness.latest_finding("T7").capsule_id) == "REVIEW_REQUIRED"


# ------------------------------------------------------------ main.py with POLICY_MODE=adaptive
def test_main_runs_tasks_under_the_policy(tmp_path):
    calls = {"verify": 0, "run": 0, "revise": 0, "analyze": 0, "analyst_revise": 0}

    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            calls["run"] += 1
            return [types.SimpleNamespace(content=hunter_output(block([GOOD, THIN, FAKE]), TOOLS))]

        def revise_claims(self, task, request, claims_json, evidence_cards=""):
            calls["revise"] += 1
            assert evidence_cards.startswith("Evidence cards")
            return "```evidence_claims\n" + json.dumps([FIXED]) + "\n```"

    class Verifier:
        def verify(self, *args):
            calls["verify"] += 1
            return "OK"

        def judge_claims(self, task_name, items):
            return "```claim_verdicts\n" + json.dumps([{"id": i["id"], "verdict": "SUPPORTED"} for i in items]) + "\n```"

    class Analyst:
        def analyze_incident(self, *args, **kwargs):
            calls["analyze"] += 1
            return "## Findings\ncsc.exe built two DLLs"          # forgot the claims block

        def revise_claims(self, request, claims_json):
            calls["analyst_revise"] += 1
            assert request.startswith("Re-emit the claims")
            return "```evidence_claims\n" + json.dumps([{"id": "c1", "parent_claims": [
                "CAP-T7-VERIFIED-a1#c1", "CAP-T7-VERIFIED-a1#c2"], "level": "INFERRED",
                "text": "csc.exe built two DLLs"}]) + "\n```"

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            return analysis_text

    saved = {k: os.environ.get(k) for k in ("POLICY_MODE", "ENABLE_SEMANTIC_VERIFIER")}
    with stubbed_main(tmp_path, gate_enabled=True, cited=True) as main:
        os.environ.update(POLICY_MODE="adaptive", ENABLE_SEMANTIC_VERIFIER="1")
        try:
            main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent = Coordinator, Hunter, Verifier
            main.AnalystAgent, main.ReporterAgent = Analyst, Reporter
            bundle = main._execute_agent_runtime(S23.read_text(encoding="utf-8"), scenario_name="POL",
                                                 strategy="hierarchical")
        finally:
            for key, value in saved.items():
                os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value)

    entry = bundle["final_results"][0]
    assert entry["status"] == "Verified"
    assert [d["action"] for d in entry["policy_decisions"]] == ["REJECT", "TARGETED_RETRY", "ACCEPT"]
    assert calls == {"verify": 0, "run": 1, "revise": 1, "analyze": 1, "analyst_revise": 1}
    policy = bundle["ech_audit"]["policy"]
    assert policy["mode"] == "adaptive" and policy["actions"]["TARGETED_RETRY:revise"] == 2   # Hunter + Analyst
    assert [d["action"] for d in policy["tasks"]["ANALYSIS"]] == ["TARGETED_RETRY"]
    assert policy["budget"]["used"]["llm_calls"]["analyst_revise"] == 1


# ------------------------------------------------------------ Analyst -> Reporter under the policy
from ep_harness.policy_runner import run_analysis  # noqa: E402

ANALYSIS_CLAIMS = [
    {"id": "c1", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"], "level": "INFERRED", "text": "csc.exe compiled tmseiddy.dll"},
    {"id": "c2", "parent_claims": ["CAP-T9-VERIFIED-a1#c1"], "level": "INFERRED",          # parent does not exist
     "text": "The DLL was loaded on the domain controller"},
    {"id": "c3", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"], "observables": ["evil.dll"],  # value not in evidence
     "level": "INFERRED", "text": "csc.exe dropped evil.dll in the temp folder"},
]
NARRATIVE = ("## Findings\n- csc.exe compiled tmseiddy.dll [c1]\n- The DLL was loaded on the domain controller [c2]\n"
             "- csc.exe dropped evil.dll in the temp folder [c3]")


def analysis(records):
    return NARRATIVE + "\n```evidence_claims\n" + json.dumps(records) + "\n```"


def verified_ech():
    harness = ech()
    assert harness.hunter_handoff("T7", hunter_output(block([GOOD]), TOOLS)).accepted
    harness.record_verifier("T7", True, "OK")
    assert harness.verifier_handoff("T7").accepted
    return harness


def analyst_stub(revision):
    calls = {"rerun": 0, "revise": []}

    def rerun(feedback):
        calls["rerun"] += 1
        raise AssertionError("the Analyst should not be rerun")

    def revise(request, claims_json):
        calls["revise"].append((request, json.loads(claims_json)))
        return "```evidence_claims\n" + json.dumps(revision) + "\n```"

    return calls, rerun, revise


def test_analysis_fabricated_parent_removed_and_one_claim_revised():
    harness, policy = verified_ech(), AdaptivePolicy(Budget(task_retries=1))
    fixed = dict(ANALYSIS_CLAIMS[2], observables=["tmseiddy.dll"], text="csc.exe dropped tmseiddy.dll in the temp folder")
    calls, rerun, revise = analyst_stub([fixed])
    result = run_analysis(harness, policy, analysis(ANALYSIS_CLAIMS), analyst_rerun=rerun, analyst_revise=revise)
    assert result.accepted and [d["action"] for d in result.decisions] == ["TARGETED_RETRY"]
    request, asked = calls["revise"][0]
    assert [c["id"] for c in asked] == ["c3"] and "CAP-T7-VERIFIED-a1#c1" in request
    assert result.for_reporter == ("## Findings\n- csc.exe compiled tmseiddy.dll\n"
                                   "- csc.exe dropped tmseiddy.dll in the temp folder")
    assert policy.budget.used_calls == {"analyst_revise": 1}


def test_analysis_revision_without_fix_removes_only_that_claim():
    harness, policy = verified_ech(), AdaptivePolicy(Budget(task_retries=1))
    calls, rerun, revise = analyst_stub([ANALYSIS_CLAIMS[2]])
    result = run_analysis(harness, policy, analysis(ANALYSIS_CLAIMS), analyst_rerun=rerun, analyst_revise=revise)
    assert [d["action"] for d in result.decisions] == ["TARGETED_RETRY", "REJECT"]
    assert result.decisions[-1]["reject"] == ["c3"] and result.accepted
    assert result.for_reporter == "## Findings\n- csc.exe compiled tmseiddy.dll"


def test_analysis_with_only_a_fabricated_parent_costs_no_call():
    harness, policy = verified_ech(), AdaptivePolicy(Budget(task_retries=1))
    calls, rerun, revise = analyst_stub([])
    result = run_analysis(harness, policy, analysis(ANALYSIS_CLAIMS[:2]), analyst_rerun=rerun, analyst_revise=revise)
    assert result.accepted and [d["action"] for d in result.decisions] == ["REJECT"]
    assert calls == {"rerun": 0, "revise": []} and policy.budget.used_calls == {}
    # c2 (fabricated parent) is gone; the c3 line has no claim record here, so it is narrative and passes as is.
    assert result.for_reporter == "## Findings\n- csc.exe compiled tmseiddy.dll\n- csc.exe dropped evil.dll in the temp folder"
