"""The harness does the work a weak model gets wrong: evidence cards, format repair, auto-tagging (S23).

These tests feed the pipeline the kind of output a less capable model writes
(wrong fence, other field names, "Event 9", trailing commas, untagged lines)
and check that the harness still gets the claims right, and says what it repaired.
"""

import json
import sys
import types
from pathlib import Path

from ep_harness.claim_parser import extract_claims_block
from ep_harness.evidence_cards import cards_for_task_view
from ep_harness.inline import InlineECH
from test_inline_gate import hunter_output, stubbed_main

REPO = Path(__file__).resolve().parents[1]
S23 = REPO / "extracted_scenarios" / "S23_telemetry.json"
T7_TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
_CACHE = {}


def s23():
    if not _CACHE:
        sys.path.insert(0, str(REPO))
        from agents.task_catalog import TASK_BY_ID, TASK_INVENTORY
        from src.extractor import EvidenceExtractor

        extractor = EvidenceExtractor()
        store = extractor.extract(extractor.sanitize_raw_log(S23.read_text(encoding="utf-8")))
        _CACHE.update(store=store, inventory=TASK_INVENTORY,
                      view=extractor.build_task_view(dict(TASK_BY_ID["T7"]), store))
    return _CACHE


def ech():
    data = s23()
    return InlineECH(data["store"], data["inventory"], claim_source="cited")


CLEAN = '```evidence_claims\n[{"id": "c1", "evidence": ["event-9"], "observables": ["csc.exe", "tmseiddy.dll"], ' \
        '"tools": ["rex_tool"], "level": "OBSERVED", "text": "csc.exe created tmseiddy.dll"}]\n```'
MESSY = "Here are my claims:\n```json\n[{'Claim_ID': 'C1', 'Events': ['Event 9'], 'values': ['csc.exe', " \
        "'tmseiddy.dll'], 'tool': ['rex_tool'], 'Level': 'observed', 'statement': 'csc.exe created tmseiddy.dll',},]\n```"


# ------------------------------------------------------------ evidence cards
def test_cards_index_the_task_view_by_event_id():
    view = s23()["view"]
    cards = cards_for_task_view(view)
    lines = cards.splitlines()
    assert lines[0].startswith("Evidence cards")
    assert "event-9 | 2024-11-09 11:19:58 | file (11) | csc.exe -> tmseiddy.dll" in lines
    assert any(line.startswith("event-1 | 2024-11-09 11:19:19 | process (1) | cmd.exe -> schtasks.exe | schtasks")
               for line in lines)
    assert len(lines) - 1 == len(json.loads(view)["events"])
    assert len(cards) * 10 < len(view)           # an index, not a second copy of the log
    assert cards_for_task_view("not json") == ""


# ------------------------------------------------------------ format repair
def test_messy_block_reads_like_the_clean_one():
    clean, messy = extract_claims_block(CLEAN), extract_claims_block(MESSY)
    assert not clean.repairs and not messy.error
    keep = ("id", "event_ids", "observables", "tools", "level", "text")
    assert [{k: r.get(k) for k in keep} for r in messy.records] == [{k: r.get(k) for k in keep} for r in clean.records]
    assert set(messy.repairs) == {"read a ```json block as the claims block", "removed trailing commas",
                                  "read single-quoted JSON", "mapped field names to the schema"}


def test_unreadable_block_is_still_returned_to_the_agent():
    broken = extract_claims_block('```evidence_claims\n[{"text": "a"\n```')
    assert broken.found and broken.error.startswith("evidence_claims block is not valid JSON")


def test_messy_finding_passes_the_gate_and_the_repairs_are_counted():
    harness = ech()
    outcome = harness.hunter_handoff("T7", hunter_output(f"csc.exe wrote a DLL.\n\n{MESSY}", T7_TOOLS))
    assert outcome.accepted, outcome.violations
    claim = harness.ledger.capsule(outcome.capsule_id).claims[0]
    assert (claim.claim_id, claim.level, claim.event_ids) == ("c1", "OBSERVED", ("event-9",))
    assert claim.artifact_ids[0].startswith("tool:T7:rex_tool:")
    assist = harness.summary()["harness_assist"]
    assert assist["handoffs_repaired"] == 1 and assist["format_repairs"]["read single-quoted JSON"] == 1


# ------------------------------------------------------------ auto-tagging
def test_untagged_lines_of_a_blocked_claim_are_still_withheld():
    harness = ech()
    harness.hunter_handoff("T7", hunter_output(f"csc.exe wrote a DLL.\n\n{CLEAN}", T7_TOOLS))
    harness.record_verifier("T7", True, "OK")
    harness.verifier_handoff("T7")
    analysis = (
        "## Findings\n"
        "- The C# compiler csc.exe built tmseiddy.dll from a temporary source file\n"
        "- Lateral movement reached the domain controller over SMB\n"
        "```evidence_claims\n" + json.dumps([
            {"id": "c1", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"], "level": "INFERRED",
             "text": "csc.exe built tmseiddy.dll from a temporary source file"},
            {"id": "c2", "evidence": ["event-9999"], "level": "OBSERVED",
             "text": "Lateral movement reached the domain controller over SMB"},
        ]) + "\n```"
    )
    outcome = harness.analyst_handoff(analysis)
    assert outcome.status == "REJECTED"
    assert harness.analysis_for_reporter(analysis, outcome) == (
        "## Findings\n- The C# compiler csc.exe built tmseiddy.dll from a temporary source file")
    assert harness.handoffs[-1]["auto_tagged_lines"] == 2


# ------------------------------------------------------------ prompts and main.py
def test_hunter_contract_asks_for_evidence_before_the_statement(tmp_path):
    with stubbed_main(tmp_path, gate_enabled=True, cited=True):
        import prompts

        contract = prompts.build_hunter_claims_contract()
    steps = [contract.index(step) for step in ("1. evidence", "2. observables", "3. tools", "4. level, then text")]
    assert steps == sorted(steps)
    example = json.loads(contract.split("```evidence_claims\n")[1].split("\n```")[0])[0]
    assert list(example)[:2] == ["id", "evidence"] and list(example)[-1] == "text"


def test_main_gives_the_hunter_cards_first_only_in_cited_mode(tmp_path):
    seen = {}

    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            seen.setdefault("logs", []).append(task_log)
            return [types.SimpleNamespace(content=hunter_output(f"csc.exe wrote a DLL.\n\n{MESSY}", T7_TOOLS))]

    class Verifier:
        def verify(self, *args):
            return "OK"

    class Analyst:
        def analyze_incident(self, *args, **kwargs):
            return "## Findings\nnothing more"

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            return analysis_text

    raw = S23.read_text(encoding="utf-8")
    for cited in (True, False):
        seen.clear()
        with stubbed_main(tmp_path, gate_enabled=True, cited=cited) as main:
            main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent = Coordinator, Hunter, Verifier
            main.AnalystAgent, main.ReporterAgent = Analyst, Reporter
            bundle = main._execute_agent_runtime(raw, scenario_name="ASSIST", strategy="hierarchical")
        log = seen["logs"][0]
        assert log.startswith("Evidence cards") is cited
        if cited:
            assert [item["status"] for item in bundle["final_results"]] == ["Verified"]
            assert bundle["ech_audit"]["harness_assist"]["handoffs_repaired"] >= 1
