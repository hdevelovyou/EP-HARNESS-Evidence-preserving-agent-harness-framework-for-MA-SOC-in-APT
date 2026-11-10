"""Inline Contract Gate: unit tests on InlineECH and a no-LLM run of main.py.

The main.py test replaces every LLM-backed agent with a scripted stub; the
extractor, summarizer, IOC curator and DAG code are the real ones.
"""

import contextlib
import hashlib
import json
import os
import sys
import types
from pathlib import Path

from ep_harness.inline import InlineECH

REPO = Path(__file__).resolve().parents[1]
GOOD_T7 = "Outbound C2 contact to 172.31.234.82 observed from splunkd.exe on the workstation."
FAKE_T7 = "Scheduled task persistence created at 02:00 according to event-9999 in the Security log."
T3_BODY = "Beacon traffic to 172.31.234.82 repeated at a fixed interval."
ANALYSIS_GOOD = "C2 traffic to 172.31.234.82 from splunkd.exe is confirmed by the verified findings."
ANALYSIS_FAKE = "Lateral movement to the domain controller is recorded in event-9999 of the Security log."


def hunter_output(body, tools):
    # One digest per tool name, as a real tool run with the same output would give.
    audit = [{"tool": t, "status": "ok", "output_sha256": hashlib.sha256(t.encode()).hexdigest()} for t in tools]
    return f"{body}\n\nTool Execution Audit:\n{json.dumps(audit)}"


def ech_for(evidence_store):
    sys.path.insert(0, str(REPO))
    from agents.task_catalog import TASK_INVENTORY

    return InlineECH(evidence_store, TASK_INVENTORY)


# ------------------------------------------------------------ InlineECH
def test_blocked_finding_is_returned_with_feedback_then_retry_supersedes(evidence_store):
    ech = ech_for(evidence_store)
    first = ech.hunter_handoff("T7", hunter_output(FAKE_T7, ["ner_tool", "rex_tool", "sum_tool"]))
    assert first.status == "REJECTED" and first.action == "return_to_hunter"
    assert first.feedback.startswith("CONTRACT GATE") and "dangling_event" in first.feedback

    second = ech.hunter_handoff("T7", hunter_output(GOOD_T7, ["ner_tool", "rex_tool", "sum_tool"]))
    assert second.accepted, second.violations
    retry = ech.ledger.capsule(second.capsule_id)
    assert (retry.attempt, retry.supersedes) == (2, first.capsule_id)

    ech.record_verifier("T7", True, "OK")
    verified = ech.verifier_handoff("T7")
    assert verified.accepted, verified.violations
    assert ech.accepted_task_ids() == {"T7"}


def test_verifier_failure_is_a_semantic_rejection(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", hunter_output(GOOD_T7, ["ner_tool", "rex_tool", "sum_tool"]))
    ech.record_verifier("T7", False, "FAIL: no beacon interval shown")
    assert ech.ledger.capsule_status(outcome.capsule_id) == "REJECTED"
    assert ech.ledger.decisions()[-1]["actor"] == "verifier"
    assert ech.accepted_task_ids() == set()


def test_finding_without_verdict_is_closed_as_unresolved(tmp_path, evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", hunter_output(GOOD_T7, ["ner_tool", "rex_tool", "sum_tool"]))
    paths = ech.save(tmp_path)  # e.g. the Verifier call raised on the last attempt
    assert ech.ledger.capsule_status(outcome.capsule_id) == "UNRESOLVED"
    assert Path(paths["ledger"]).exists() and Path(paths["audit"]).exists()


def test_analysis_withholds_only_claims_with_violations(evidence_store):
    ech = ech_for(evidence_store)
    ech.hunter_handoff("T7", hunter_output(GOOD_T7, ["ner_tool", "rex_tool", "sum_tool"]))
    ech.record_verifier("T7", True, "OK")
    ech.verifier_handoff("T7")

    text = f"## Timeline\n{ANALYSIS_GOOD}\n{ANALYSIS_FAKE}\nshort line"
    outcome = ech.analyst_handoff(text)
    assert outcome.status == "REJECTED" and outcome.retryable
    filtered = ech.analysis_for_reporter(text, outcome)
    assert filtered == f"## Timeline\n{ANALYSIS_GOOD}\nshort line"

    analysis = ech.ledger.capsule(outcome.capsule_id)
    assert analysis.claims[0].derivation in ("REFINED", "AGGREGATED")
    assert analysis.claims[0].parent_claims[0].startswith("CAP-T7-VERIFIED-a1#")
    assert ech.handoffs[-1]["withheld_claims"] == [f"{outcome.capsule_id}#c2"]


def test_analysis_without_accepted_parents_is_not_retryable(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.analyst_handoff(ANALYSIS_GOOD)
    assert outcome.status == "RETRY_REQUIRED"
    assert not outcome.retryable  # missing_parents: an Analyst retry cannot fix it


# ------------------------------------------------------------ main.py without LLM calls
_STUBBED = [
    "langchain_community", "langchain_community.callbacks", "langchain_community.callbacks.manager",
    "agents.analyst_agent", "agents.coordinator_agent", "agents.debate_judge_agent", "agents.hunter_agent",
    "agents.llm_config", "agents.reporter_agent", "agents.verifier_agent",
    "evaluation.evaluator", "evaluation.reasoning_evaluator", "src.mitre_mapper",
    "langchain_core", "langchain_core.messages", "langchain_core.prompts",
]
# Imported afresh inside the stub context, so they bind the stubbed modules.
_REIMPORTED = ["main", "prompts", "prompts.agent_prompts"]
_ENV = {
    "ENABLE_DAG_ORCHESTRATOR": "0",
    "ENABLE_TTP_RELATIONS_GRAPH": "0",
    "ENABLE_MITRE_MAPPER": "0",
    "ENABLE_IOC_CURATOR": "1",
}


class _Placeholder:
    def __init__(self, *args, **kwargs):
        pass


@contextlib.contextmanager
def _fake_callback():
    yield types.SimpleNamespace(prompt_tokens=0, completion_tokens=0, total_cost=0.0)


@contextlib.contextmanager
def stubbed_main(tmp_path, gate_enabled, cited=False):
    saved_modules = {name: sys.modules.get(name) for name in _STUBBED + _REIMPORTED}
    saved_env = {name: os.environ.get(name) for name in [*_ENV, "ENABLE_CONTRACT_GATE", "ENABLE_CITED_CLAIMS"]}
    saved_cwd = os.getcwd()
    try:
        for name in _STUBBED:
            module = types.ModuleType(name)
            for attr in ("AnalystAgent", "CoordinatorAgent", "DebateFeedbackAgent", "DebateJudgeAgent",
                         "HunterAgent", "ReporterAgent", "VerifierAgent", "SOCEvaluator",
                         "ReasoningEvaluator", "MitreMapper", "HumanMessage", "SystemMessage",
                         "AIMessage", "ToolMessage", "ChatPromptTemplate"):
                setattr(module, attr, _Placeholder)
            module.get_llm_config_snapshot = lambda roles: {}
            module.get_openai_callback = _fake_callback
            sys.modules[name] = module
        for name in _REIMPORTED:
            sys.modules.pop(name, None)
        sys.path.insert(0, str(REPO))
        os.environ.update(_ENV, ENABLE_CONTRACT_GATE="1" if gate_enabled else "0",
                          ENABLE_CITED_CLAIMS="1" if cited else "0")
        os.chdir(tmp_path)
        import main

        yield main
    finally:
        os.chdir(saved_cwd)
        for name, value in saved_env.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        for name, module in saved_modules.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module


def install_script(main, calls):
    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}, {"id": "T3"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, upstream_context="", verifier_feedback=None,
                previous_hunter_output=None):
            task_id = assigned_tasks[0]["id"]
            calls["hunter"].append((task_id, str(verifier_feedback or "")[:13]))
            if task_id == "T7":
                body = GOOD_T7 if verifier_feedback else FAKE_T7
                output = hunter_output(body, ["ner_tool", "rex_tool", "sum_tool"])
            else:
                output = hunter_output(T3_BODY, ["ner_tool"])  # rex_tool is mandatory for T3
            return [types.SimpleNamespace(content=output)]

    class Verifier:
        def verify(self, name, output, task_log):
            calls["verifier"].append(name)
            return "OK"

    class Analyst:
        def analyze_incident(self, results_str, analysis_context, entity_context=None, ttp_relations_context=None):
            calls["analyst"].append("CONTRACT GATE" in analysis_context)
            return f"## Findings\n{ANALYSIS_GOOD}\n{ANALYSIS_FAKE}"

    class Reporter:
        def generate_final_report(self, analysis, evidence_context=None, entity_context=None):
            calls["reporter"].append(analysis)
            return f"# Final report\n{analysis}"

    main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent = Coordinator, Hunter, Verifier
    main.AnalystAgent, main.ReporterAgent = Analyst, Reporter


def run_stubbed(tmp_path, gate_enabled):
    calls = {"hunter": [], "verifier": [], "analyst": [], "reporter": []}
    raw = (REPO / "extracted_scenarios" / "S23_telemetry.json").read_text(encoding="utf-8")
    with stubbed_main(tmp_path, gate_enabled) as main:
        install_script(main, calls)
        bundle = main._execute_agent_runtime(raw, scenario_name="STUB", strategy="hierarchical")
    return bundle, calls


def test_main_runs_gate_inline_at_three_handoffs(tmp_path):
    bundle, calls = run_stubbed(tmp_path, gate_enabled=True)
    status = {item["task_id"]: item["status"] for item in bundle["final_results"]}
    assert status == {"T7": "Verified", "T3": "Gate_Blocked"}

    # Hunter->Verifier: blocked findings never reach the Verifier.
    assert calls["verifier"] == ["Infrastructure Extraction"]
    assert calls["hunter"][1] == ("T7", "CONTRACT GATE")
    assert len([c for c in calls["hunter"] if c[0] == "T3"]) == 3

    # Analyst->Reporter: one retry with gate feedback, then the bad claim is withheld.
    assert calls["analyst"] == [False, True]
    assert ANALYSIS_GOOD in calls["reporter"][0] and ANALYSIS_FAKE not in calls["reporter"][0]
    run_dir = Path(tmp_path) / bundle["run_dir"]
    assert ANALYSIS_FAKE in (run_dir / "analyst_result.md").read_text(encoding="utf-8")
    assert (run_dir / "analyst_result_gated.md").exists()

    edges = [h["edge"] for h in bundle["ech_audit"]["handoffs"]]
    assert {"hunter->verifier", "verifier->analyst", "analyst->reporter", "reporter->output"} <= set(edges)
    assert (run_dir / "ech_ledger.jsonl").exists() and (run_dir / "ech_inline_audit.json").exists()


def test_main_without_gate_is_unchanged(tmp_path):
    bundle, calls = run_stubbed(tmp_path, gate_enabled=False)
    assert {item["status"] for item in bundle["final_results"]} == {"Verified"}
    assert calls["verifier"] == ["Infrastructure Extraction", "Temporal Pattern Matching"]
    assert calls["analyst"] == [False]
    assert bundle["ech_audit"] is None
    assert not (Path(tmp_path) / bundle["run_dir"] / "ech_ledger.jsonl").exists()
