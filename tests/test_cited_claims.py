"""Agent-cited evidence claims: parser, inline gate in cited mode, prompts, and a no-LLM main.py run."""

import json
import os
import sys
import types
from pathlib import Path

import pytest

from ep_harness.claim_parser import (
    claims_from_records,
    drop_tagged_lines,
    extract_claims_block,
    remove_claims_block,
    strip_claim_tags,
)
from ep_harness.inline import InlineECH
from test_inline_gate import REPO, hunter_output, stubbed_main

T7_TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
GOOD_CLAIM = {"id": "c1", "text": "dfg.exe on WS-FIN-014 opened an egress connection from 10.10.12.110",
              "level": "OBSERVED", "event_ids": ["event-28"], "tools": ["rex_tool"],
              "observables": ["dfg.exe", "10.10.12.110"]}


def block(records):
    return f"```evidence_claims\n{json.dumps(records)}\n```"


def cited_output(records, tools=T7_TOOLS, narrative="Egress connection from the finance workstation."):
    return hunter_output(f"{narrative}\n\n{block(records)}", tools)


def ech_for(evidence_store):
    sys.path.insert(0, str(REPO))
    from agents.task_catalog import TASK_INVENTORY

    return InlineECH(evidence_store, TASK_INVENTORY, claim_source="cited")


def verified_t7(ech):
    assert ech.hunter_handoff("T7", cited_output([GOOD_CLAIM])).accepted
    ech.record_verifier("T7", True, "OK")
    assert ech.verifier_handoff("T7").accepted


# ------------------------------------------------------------ parser
def test_parser_reads_the_last_block_and_reports_problems():
    text = f"intro\n{block([{'text': 'old'}])}\nmiddle\n{block({'claims': [{'id': 'C2', 'text': 'new'}]})}"
    parsed = extract_claims_block(text)
    assert parsed.found and not parsed.error
    assert [r["text"] for r in parsed.records] == ["new"]
    assert "middle" in parsed.body and "new" not in parsed.body

    assert "not valid JSON" in extract_claims_block("```evidence_claims\n[{oops}]\n```").error
    assert "JSON list of objects" in extract_claims_block(block(["a"])).error
    missing = extract_claims_block("just prose")
    assert not missing.found and "no ```evidence_claims block" in missing.error


def test_records_become_cited_claims():
    claims = claims_from_records(
        [{"id": "C2", "text": " a  b ", "level": "observed", "event_ids": "event-1", "tools": ["rex_tool", "spa_tool"]},
         {"id": 3, "text": "c", "level": "INFERRED", "parent_claims": ["CAP-X-a1#c1", "CAP-X-a1#c2"]},
         {"text": "d", "level": "HYPOTHESIS"}],
        {"rex_tool": "tool:T7:rex_tool:abc"},
    )
    assert [c.claim_id for c in claims] == ["c2", "c3", "c3"]  # positional default collides: the gate rejects it
    assert claims[0].text == "a b" and claims[0].level == "OBSERVED" and claims[0].event_ids == ("event-1",)
    assert claims[0].artifact_ids == ("tool:T7:rex_tool:abc", "tool:unexecuted:spa_tool")
    assert claims[1].derivation == "AGGREGATED" and claims[2].derivation == "NEW"
    assert {c.lineage for c in claims} == {"cited"}


def test_tag_helpers():
    text = "keep this [c1]\ndrop this [c2]\n| row | value [c2] |\nuntagged"
    assert drop_tagged_lines(text, ["c2"]) == "keep this [c1]\nuntagged"
    assert strip_claim_tags("beacon every 60 s [c3].") == "beacon every 60 s."
    assert remove_claims_block(f"narrative\n{block([])}") == "narrative"


# ------------------------------------------------------------ Hunter -> Verifier, cited
def test_cited_finding_is_accepted_with_tool_artifacts(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", cited_output([GOOD_CLAIM]))
    assert outcome.accepted, outcome.violations
    claim = ech.ledger.capsule(outcome.capsule_id).claims[0]
    assert claim.lineage == "cited" and claim.event_ids == ("event-28",)
    assert claim.artifact_ids[0].startswith("tool:T7:rex_tool:")


def test_cited_tool_that_never_ran_is_rejected(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", cited_output([dict(GOOD_CLAIM, tools=["spa_tool"])]))
    assert outcome.status == "REJECTED"
    assert {v["code"] for v in outcome.violations} == {"dangling_artifact"}


def test_missing_claims_block_is_rejected_with_format_feedback(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", hunter_output("Egress from dfg.exe on WS-FIN-014.", T7_TOOLS))
    assert outcome.status == "REJECTED" and outcome.retryable
    assert "[format] no ```evidence_claims block found" in outcome.feedback


def test_paraphrased_observable_requires_retry(evidence_store):
    ech = ech_for(evidence_store)
    outcome = ech.hunter_handoff("T7", cited_output([dict(GOOD_CLAIM, observables=["dfg malware"])]))
    assert outcome.status == "RETRY_REQUIRED"
    assert {v["code"] for v in outcome.violations} == {"observable_not_in_evidence"}


# ------------------------------------------------------------ Analyst -> Reporter, cited
def test_analysis_cites_verified_refs_and_blocked_lines_are_withheld(evidence_store):
    ech = ech_for(evidence_store)
    verified_t7(ech)
    refs = [c["ref"] for c in ech.verified_claims()["T7"]]
    assert refs == ["CAP-T7-VERIFIED-a1#c1"]

    text = (
        "## Findings\n"
        "dfg.exe beacons to an external host [c1]\n"
        "The actor moved to the domain controller [c2]\n"
        "Untagged context line.\n"
        + block([
            {"id": "c1", "text": "dfg.exe beacons to an external host", "level": "INFERRED", "parent_claims": refs},
            {"id": "c2", "text": "Lateral movement to the DC", "level": "OBSERVED", "event_ids": ["event-9999"]},
        ])
    )
    outcome = ech.analyst_handoff(text)
    assert outcome.status == "REJECTED"
    assert [v["claim_index"] for v in outcome.violations] == [1]
    for_reporter = ech.analysis_for_reporter(text, outcome)
    assert for_reporter == "## Findings\ndfg.exe beacons to an external host\nUntagged context line."
    assert ech.handoffs[-1]["withheld_claims"] == [f"{outcome.capsule_id}#c2"]


def test_accepted_analysis_reaches_the_reporter_without_block_or_tags(evidence_store):
    ech = ech_for(evidence_store)
    verified_t7(ech)
    claim = {"id": "c1", "text": "beaconing", "level": "INFERRED", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"]}
    text = f"dfg.exe beacons out [c1]\n{block([claim])}"
    outcome = ech.analyst_handoff(text)
    assert outcome.accepted, outcome.violations
    assert ech.analysis_for_reporter(text, outcome) == "dfg.exe beacons out"


# ------------------------------------------------------------ configuration and prompts
def test_cited_claims_need_the_gate():
    sys.path.insert(0, str(REPO))
    from src.orchestration_toggles import load_orchestration_toggles

    saved = {k: os.environ.get(k) for k in ("ENABLE_CONTRACT_GATE", "ENABLE_CITED_CLAIMS")}
    try:
        os.environ.update(ENABLE_CONTRACT_GATE="0", ENABLE_CITED_CLAIMS="1")
        with pytest.raises(ValueError):
            load_orchestration_toggles()
        os.environ["ENABLE_CONTRACT_GATE"] = "1"
        assert load_orchestration_toggles().enable_cited_claims
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def test_hunter_prompt_carries_the_contract_only_when_enabled(tmp_path):
    for cited in (True, False):
        with stubbed_main(tmp_path, gate_enabled=True, cited=cited):
            import prompts

            instruction = prompts.build_hunter_final_instruction("[]")
            assert ("```evidence_claims" in instruction) is cited
            assert instruction.rstrip().endswith("Tool Execution Audit:\n[]")


# ------------------------------------------------------------ main.py, cited, without LLM calls
def test_main_cited_mode_end_to_end(tmp_path):
    calls = {"verifier": 0, "analyst_inputs": [], "reporter": []}
    analysis = (
        "## Findings\n"
        "dfg.exe beacons to an external host [c1]\n"
        "The actor moved to the domain controller [c2]\n"
        + block([
            {"id": "c1", "text": "beaconing", "level": "INFERRED", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"]},
            {"id": "c2", "text": "lateral movement", "level": "OBSERVED", "event_ids": ["event-9999"]},
        ])
    )

    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            return [types.SimpleNamespace(content=cited_output([GOOD_CLAIM]))]

    class Verifier:
        def verify(self, name, output, task_log):
            calls["verifier"] += 1
            return "OK"

    class Analyst:
        def analyze_incident(self, results_str, analysis_context, entity_context=None, ttp_relations_context=None):
            calls["analyst_inputs"].append((results_str, analysis_context))
            return analysis

    class Reporter:
        def generate_final_report(self, analysis_text, evidence_context=None, entity_context=None):
            calls["reporter"].append(analysis_text)
            return f"# Final report\n{analysis_text}"

    raw = (REPO / "datasets" / "CobaltStrike_Lockbit" / "artifacts.json").read_text(encoding="utf-8")
    with stubbed_main(tmp_path, gate_enabled=True, cited=True) as main:
        main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent = Coordinator, Hunter, Verifier
        main.AnalystAgent, main.ReporterAgent = Analyst, Reporter
        bundle = main._execute_agent_runtime(raw, scenario_name="CITED", strategy="hierarchical")

    assert [item["status"] for item in bundle["final_results"]] == ["Verified"]
    assert calls["verifier"] == 1
    results_str, analysis_context = calls["analyst_inputs"][0]
    assert "CAP-T7-VERIFIED-a1#c1" in results_str and "Evidence claims (required)" in analysis_context
    assert "```evidence_claims" not in bundle["final_results"][0]["artifact"]["summary"]

    assert len(calls["analyst_inputs"]) == 2  # one retry with gate feedback
    assert "CONTRACT GATE" in calls["analyst_inputs"][1][1]
    assert calls["reporter"] == ["## Findings\ndfg.exe beacons to an external host"]
    assert bundle["ech_audit"]["claim_source"] == "cited"
    assert (Path(tmp_path) / bundle["run_dir"] / "analyst_result.md").read_text(encoding="utf-8") == analysis
