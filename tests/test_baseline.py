"""Structured Capsule baseline and experiment infrastructure: shadow gate, card switch, uniform measurement, matrix."""

import json
import os
import sys
import types
from pathlib import Path

import pytest

from ep_harness.experiments import CONFIGS, OFF, collect, config_env, plan, summarize, to_markdown
from ep_harness.measurement import measure_run
from test_inline_gate import hunter_output, stubbed_main

REPO = Path(__file__).resolve().parents[1]
S23 = REPO / "extracted_scenarios" / "S23_telemetry.json"
TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
GOOD = {"id": "c1", "evidence": ["event-9"], "observables": ["csc.exe", "tmseiddy.dll"], "tools": ["rex_tool"],
        "level": "OBSERVED", "text": "csc.exe created the file tmseiddy.dll"}
FAKE = {"id": "c2", "evidence": ["event-99999"], "level": "OBSERVED", "text": "Lateral movement reached the DC"}


def block(records):
    return f"csc.exe built a DLL.\n\n```evidence_claims\n{json.dumps(records)}\n```"


# ------------------------------------------------------------ configuration matrix
def test_every_configuration_is_valid_and_fully_specified():
    sys.path.insert(0, str(REPO))
    from src.orchestration_toggles import load_orchestration_toggles

    saved = dict(os.environ)
    try:
        loaded = {}
        for name in CONFIGS:
            env = config_env(name)
            assert set(OFF) <= set(env) and env["MASOC_MAX_RETRIES"] == "1"
            os.environ.update(env)
            loaded[name] = load_orchestration_toggles()
    finally:
        os.environ.clear()
        os.environ.update(saved)
    assert not loaded["B0_masoc"].enable_contract_gate
    b1 = loaded["B1_structured_capsule"]
    assert (b1.contract_gate_mode, b1.enable_cited_claims, b1.enable_evidence_cards) == ("shadow", True, False)
    assert loaded["B1c_structured_capsule_cards"].enable_evidence_cards
    assert loaded["L1_gate"].contract_gate_mode == "inline" and not loaded["L1_gate"].enable_semantic_verifier
    assert loaded["L2_semantic"].enable_semantic_verifier and loaded["L2_semantic"].policy_mode == "fixed"
    assert loaded["Full_ep_harness"].policy_mode == "adaptive"


def test_shadow_cannot_be_combined_with_enforcement():
    sys.path.insert(0, str(REPO))
    from src.orchestration_toggles import load_orchestration_toggles

    saved = dict(os.environ)
    try:
        os.environ.update(config_env("B1_structured_capsule"), ENABLE_SEMANTIC_VERIFIER="1")
        with pytest.raises(ValueError):
            load_orchestration_toggles()
    finally:
        os.environ.clear()
        os.environ.update(saved)


def test_plan_collect_and_summarize(tmp_path):
    experiment = plan("T", configs=["B1_structured_capsule", "Full_ep_harness"], scenarios=["S23"], repeats=2)
    assert len(experiment["runs"]) == 4 and len({r["run_name"] for r in experiment["runs"]}) == 4
    for run, f1 in zip(experiment["runs"][:3], (0.5, 0.7, 0.8)):   # the 4th run never finished
        folder = tmp_path / f"{run['run_name']}_20261110_120000"
        folder.mkdir()
        (folder / "eval_report.json").write_text(json.dumps(
            {"layer_2_audit": {"f1_ttps": f1, "f1_iocs": 0.4}, "metadata": {"openai_metrics": {"input_tokens": 100}}}))
        (folder / "ech_measurement.json").write_text(json.dumps({"findings": {"unsupported_claim_rate": 0.2}}))
    table = summarize(collect(experiment, tmp_path))
    assert [(e["config"], e["finished"]) for e in table] == [("B1_structured_capsule", 2), ("Full_ep_harness", 1)]
    assert table[0]["f1_ttps"] == {"mean": 0.6, "std": 0.1414, "n": 2}
    assert table[1]["ucr_findings"]["mean"] == 0.2
    assert "B1_structured_capsule | S23 | 2/2" in to_markdown(table)


# ------------------------------------------------------------ uniform measurement
def test_measurement_reads_cited_and_free_text_the_same_way():
    sys.path.insert(0, str(REPO))
    from src.extractor import EvidenceExtractor
    from ep_harness.label_guard import mask_labels

    extractor = EvidenceExtractor()
    store = extractor.extract(mask_labels(extractor.sanitize_raw_log(S23.read_text(encoding="utf-8")), markers=True).text)
    results = [
        {"task_id": "T7", "status": "Verified", "result": hunter_output(block([GOOD, FAKE]), TOOLS)},
        {"task_id": "T3", "status": "Failed_Verification",
         "result": hunter_output("Traffic to 172.31.234.82 was seen from splunkd.exe on the host.", ["rex_tool"])},
    ]
    m = measure_run(store, results, analysis_text="## Findings\ncsc.exe built tmseiddy.dll",
                    report_text="# Report\nC2 traffic to 172.31.234.82 was observed.")
    assert m["claim_sources"] == {"findings:agent": 1, "findings:heuristic": 1, "analysis:heuristic": 1,
                                  "report:heuristic": 1}
    assert m["findings"]["claims"] == 3 and m["forwarded_findings"]["claims"] == 2
    assert m["forwarded_findings"]["reference_validity"] < 1.0              # event-99999 counted
    assert m["forwarded_findings"]["verdicts"] == {"SUPPORTED": 1, "INSUFFICIENT": 1}
    assert m["forwarded_findings"]["unsupported_claim_rate"] == 0.5
    assert m["task_status"] == {"Verified": 1, "Failed_Verification": 1}


# ------------------------------------------------------------ shadow mode and the card switch in main.py
def _agents(seen):
    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            seen["hunter_logs"].append(task_log)
            return [types.SimpleNamespace(content=hunter_output(block([GOOD, FAKE]), TOOLS))]

    class Verifier:
        def verify(self, *args):
            seen["verify"] += 1
            return "OK"

    class Analyst:
        def analyze_incident(self, *args, **kwargs):
            return "## Findings\n- csc.exe built tmseiddy.dll [c1]\n- The DC was compromised [c2]\n```evidence_claims\n" + \
                json.dumps([{"id": "c1", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"], "level": "INFERRED",
                             "text": "csc.exe built tmseiddy.dll"},
                            {"id": "c2", "evidence": ["event-99999"], "level": "OBSERVED",
                             "text": "The DC was compromised"}]) + "\n```"

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            seen["reporter"].append(analysis_text)
            return analysis_text

    return Coordinator, Hunter, Verifier, Analyst, Reporter


def _run(tmp_path, extra_env):
    seen = {"hunter_logs": [], "verify": 0, "reporter": []}
    saved = {k: os.environ.get(k) for k in extra_env}
    with stubbed_main(tmp_path, gate_enabled=True, cited=True) as main:
        os.environ.update(extra_env)
        try:
            (main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent, main.AnalystAgent,
             main.ReporterAgent) = _agents(seen)
            bundle = main._execute_agent_runtime(S23.read_text(encoding="utf-8"), scenario_name="BASE",
                                                 strategy="hierarchical")
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    return bundle, seen


def test_shadow_mode_records_but_enforces_nothing(tmp_path):
    shadow, seen = _run(tmp_path, {"CONTRACT_GATE_MODE": "shadow", "ENABLE_EVIDENCE_CARDS": "0"})
    assert [i["status"] for i in shadow["final_results"]] == ["Verified"]   # fabricated claim not blocked
    assert seen["verify"] == 1 and not seen["hunter_logs"][0].startswith("Evidence cards")
    assert "The DC was compromised" in seen["reporter"][0]                   # nothing withheld
    assert "[c" not in seen["reporter"][0] and "evidence_claims" not in seen["reporter"][0]
    statuses = {h.get("status") for h in shadow["ech_audit"]["handoffs"] if h.get("edge") == "hunter->verifier"}
    assert "REJECTED" in statuses                                            # the gate still recorded its verdict
    assert shadow["measurement"]["forwarded_findings"]["reference_validity"] < 1.0
    assert (Path(tmp_path) / shadow["run_dir"] / "ech_measurement.json").exists()

    inline, seen = _run(tmp_path, {"CONTRACT_GATE_MODE": "inline", "ENABLE_EVIDENCE_CARDS": "1"})
    assert [i["status"] for i in inline["final_results"]] == ["Gate_Blocked"]
    assert seen["verify"] == 0 and seen["hunter_logs"][0].startswith("Evidence cards")
