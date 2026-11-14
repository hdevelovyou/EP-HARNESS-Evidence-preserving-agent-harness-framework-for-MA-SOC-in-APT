"""Label guard: technique IDs never reach the runtime; evaluation restores paths without handing out credit."""

import json
import re
import sys
from pathlib import Path

import pytest

from ep_harness.cli import preflight
from ep_harness.label_guard import MARKERS, LabelLeakError, assert_no_labels, find_labels, mask_labels, unmask_artifacts
from test_inline_gate import stubbed_main

REPO = Path(__file__).resolve().parents[1]
LOG = ('{"cmd": "C:\\\\AtomicRedTeam\\\\atomics\\\\T1566.001\\\\bin\\\\PhishingAttachment.xlsm", '
       '"out": "C:\\\\Temp\\\\T1135SharpSharesOutput.txt", "echo": "write-host \'t1566.001 Test\'", '
       '"parent": "atomics\\\\T1218\\\\x.ps1", "ts": "20241109T111958Z", "hash": "a1b2T1234ff"}')


# ------------------------------------------------------------ masking
def test_masking_is_stable_and_leaves_no_label():
    mask = mask_labels(LOG)
    assert find_labels(mask.text) == []
    assert mask.text.count("XTID01") == 2                      # T1566.001 and t1566.001 are the same label
    assert "XTID02SharpSharesOutput.txt" in mask.text and "atomics\\\\XTID03\\\\x.ps1" in mask.text
    assert mask.mapping == {"XTID01": "T1566.001", "XTID02": "T1135", "XTID03": "T1218"}
    assert "20241109T111958Z" in mask.text and "a1b2T1234ff" in mask.text   # not technique IDs


def test_leak_check_stops_the_run():
    with pytest.raises(LabelLeakError):
        assert_no_labels({"events": [{"commandLine": "atomics\\T1003.001\\bin"}]}, "evidence store")
    assert_no_labels(mask_labels(LOG).text, "telemetry")
    with pytest.raises(LabelLeakError):
        mask_labels("already has XTID07 in it")


def test_marker_masking_and_restoring_the_path():
    mask = mask_labels(LOG, markers=True)
    assert "atomics" not in mask.text.lower() and "atomicredteam" not in mask.text.lower()
    assert {v for k, v in mask.mapping.items() if k.startswith("XSIM")} == {"AtomicRedTeam", "atomics"}
    path = r"C:\AtomicRedTeam\atomics\T1566.001\bin\PhishingAttachment.xlsm"
    masked = mask_labels(path, markers=True)
    assert masked.text == r"C:\XSIM01\XSIM02\XTID01\bin\PhishingAttachment.xlsm"
    assert unmask_artifacts(masked.text, masked.mapping) == path   # the IOC path is whole again for scoring


# ------------------------------------------------------------ unmasking for evaluation
def test_unmask_restores_paths_but_never_a_bare_label():
    mask = mask_labels(LOG)
    report = ("IOCs: C:\\AtomicRedTeam\\atomics\\XTID01\\bin\\PhishingAttachment.xlsm and XTID02SharpSharesOutput.txt. "
              "Technique: XTID01. Also (XTID03).")
    restored = unmask_artifacts(report, mask.mapping)
    assert "atomics\\T1566.001\\bin" in restored and "T1135SharpSharesOutput.txt" in restored
    assert "Technique: XTID01." in restored and "(XTID03)" in restored
    assert unmask_artifacts({"files": ["C:\\x\\XTID03\\a.ps1"], "n": 3}, mask.mapping) == {
        "files": ["C:\\x\\T1218\\a.ps1"], "n": 3}


def test_scoring_takes_techniques_from_the_masked_report(tmp_path):
    class Evaluator:
        def _extract_entities(self, source, source_type="log"):
            text = source if isinstance(source, str) else json.dumps(source)
            return {"techniques": sorted(set(re.findall(r"T\d{4}(?:\.\d{3})?", text))),
                    "files": sorted(set(re.findall(r"[\w.]+\.(?:xlsm|txt)", text)))}

    mask = mask_labels(LOG)
    report = "Dropped C:\\AtomicRedTeam\\atomics\\XTID01\\bin\\PhishingAttachment.xlsm; user phishing = T1566.002"
    with stubbed_main(tmp_path, gate_enabled=False) as main:
        entities = main._scoring_entities(Evaluator(), report, "report", mask.mapping)
    assert entities["techniques"] == ["T1566.002"]              # only what the report itself inferred
    assert entities["files"] == ["PhishingAttachment.xlsm"]


# ------------------------------------------------------------ real scenarios
def test_preflight_masks_every_label_in_s07_s16_s23():
    for name in ("S07", "S16", "S23"):
        report = preflight(REPO / "extracted_scenarios" / f"{name}_telemetry.json", REPO)
        assert report["technique_ids_before_masking"], name     # these scenarios do leak labels
        assert report["masked"]["technique_ids"] == len(report["technique_ids_before_masking"])
        assert report["ok"] and report["leaks_after_masking"] == {"sanitized_log": [], "evidence_store": []}


def test_main_masks_before_any_agent_sees_the_telemetry(tmp_path):
    seen = []

    class Coordinator:
        def plan(self, log):
            seen.append(log)
            return []

    class Analyst:
        def analyze_incident(self, results, context, **kwargs):
            seen.append(context)
            return "## Findings\nnothing"

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            return analysis_text

    raw = (REPO / "extracted_scenarios" / "S23_telemetry.json").read_text(encoding="utf-8")
    assert find_labels(raw)
    with stubbed_main(tmp_path, gate_enabled=True) as main:
        main.CoordinatorAgent, main.AnalystAgent, main.ReporterAgent = Coordinator, Analyst, Reporter
        bundle = main._execute_agent_runtime(raw, scenario_name="LBL", strategy="hierarchical")
    assert seen and all(find_labels(text) == [] for text in seen)
    assert all(not MARKERS.search(text) for text in seen)         # simulation markers are masked by default
    run_dir = Path(tmp_path) / bundle["run_dir"]
    assert find_labels((run_dir / "evidence_store.json").read_text(encoding="utf-8")) == []
    assert bundle["label_mask"]["technique_ids"] == 5 and bundle["label_mask"]["markers"] == 4
    assert not (run_dir / "label_mask.json").exists()           # written only by the post-seal evaluation
