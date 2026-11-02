"""Tests for the EP-HARNESS ECH core, using the real CobaltStrike_Lockbit dataset.

Set MASOC_REPO to the MA-SOC repository root (default: this repository).
"""

import json
import os
import sys
from pathlib import Path

import pytest

from ep_harness import Capsule, Claim, ContractGate, EvidenceLedger, HarnessManifest, LedgerIntegrityError
from ep_harness.adapters.masoc import audit_hunt_results, ledger_from_evidence_store, task_contracts_from_catalog
from ep_harness.cli import DEFAULT_MANIFEST, load_task_inventory, main

MASOC_REPO = Path(os.environ.get("MASOC_REPO", Path(__file__).resolve().parents[1]))


@pytest.fixture(scope="module")
def evidence_store():
    sys.path.insert(0, str(MASOC_REPO))
    from src.extractor import EvidenceExtractor  # MA-SOC's own extractor, unchanged

    raw = (MASOC_REPO / "datasets" / "CobaltStrike_Lockbit" / "artifacts.json").read_text(encoding="utf-8")
    return EvidenceExtractor().extract(raw)


@pytest.fixture(scope="module")
def registry():
    return task_contracts_from_catalog(load_task_inventory(str(MASOC_REPO)))


def audit_block(*tools):
    audit = [{"tool": t, "status": "ok", "output_sha256": f"{i:064x}"} for i, t in enumerate(tools, 1)]
    return "\n\nTool Execution Audit:\n" + json.dumps(audit)


def hunt_item(task_id, body, tools, status="Verified"):
    return {"task_id": task_id, "status": status, "result": body + audit_block(*tools)}


# ------------------------------------------------------------ ledger
def test_ledger_is_append_only(evidence_store):
    ledger = ledger_from_evidence_store(evidence_store)
    first = evidence_store["events"][0]
    ledger.add_event(first["event_id"], first)  # identical -> idempotent
    tampered = dict(first, message="attacker edited this")
    with pytest.raises(LedgerIntegrityError):
        ledger.add_event(first["event_id"], tampered)


def test_ledger_roundtrip(tmp_path, evidence_store, registry):
    ledger = ledger_from_evidence_store(evidence_store)
    gate = ContractGate(ledger, registry)
    cap = Capsule("CAP-X", "FINDING", "T3", "hunter", "verifier",
                  (Claim("powershell launched from winword", "OBSERVED", ("event-1",), claim_id="c1"),))
    ledger.add_artifact("tool:T3:rex_tool:x", "T3", "rex_tool", "ok", "x")
    gate.check(cap)
    path = tmp_path / "ledger.jsonl"
    ledger.save(path)
    restored = EvidenceLedger.load(path)
    assert restored.counts() == ledger.counts()
    assert restored.capsule_status("CAP-X") == "ACCEPTED"


# ------------------------------------------------------------ gate decisions
def test_good_finding_is_accepted(evidence_store, registry):
    body = "Outbound C2 contact to compdatasystems.com observed from the beacon host 10.10.12.110."
    report = audit_hunt_results(evidence_store, [hunt_item("T7", body, ["ner_tool", "rex_tool", "sum_tool"])], registry)
    finding = report["per_task"][0]["finding_gate"]
    assert finding["status"] == "ACCEPTED", finding
    assert report["per_task"][0]["verified_gate"]["status"] == "ACCEPTED"
    assert finding["semantic_check"] == "not_performed"


def test_missing_mandatory_tool_requires_retry(evidence_store, registry):
    body = "Malware staging observed via compdatasystems.com download in the process tree."
    report = audit_hunt_results(evidence_store, [hunt_item("T1", body, ["ner_tool"])], registry)
    finding = report["per_task"][0]["finding_gate"]
    assert finding["status"] == "RETRY_REQUIRED"
    assert any(v["code"] == "missing_tool" for v in finding["violations"])


def test_fabricated_event_reference_is_rejected(evidence_store, registry):
    body = "Scheduled task persistence created at 02:00 according to event-9999 in the Security log."
    report = audit_hunt_results(evidence_store, [hunt_item("T3", body, ["rex_tool"])], registry)
    finding = report["per_task"][0]["finding_gate"]
    assert finding["status"] == "REJECTED"
    assert any(v["code"] == "dangling_event" for v in finding["violations"])
    # Verifier said Verified, gate blocked: a gate vs Verifier disagreement.
    assert report["gate_vs_verifier"]["gate_block_verifier_pass"] == 1


def test_unanchored_line_becomes_hypothesis_not_finding(evidence_store, registry):
    body = "The attacker likely established persistence using PowerShell across the domain."
    report = audit_hunt_results(evidence_store, [hunt_item("T3", body, ["rex_tool"])], registry)
    capsule = report["_capsules"][0]
    assert capsule.claims[0].level == "HYPOTHESIS"
    assert report["summary"]["anchored_claim_share"] == 0.0


def test_agent_cannot_self_accept(evidence_store, registry):
    ledger = ledger_from_evidence_store(evidence_store)
    cap = Capsule("CAP-SELF", "FINDING", "T3", "hunter", "verifier",
                  (Claim("powershell launched from winword", "OBSERVED", ("event-1",), claim_id="c1"),), status="ACCEPTED")
    assert ContractGate(ledger, registry).check(cap).status == "REJECTED"


def test_report_edge_refuses_hypotheses(evidence_store, registry):
    ledger = ledger_from_evidence_store(evidence_store)
    gate = ContractGate(ledger, registry, enforce_task_registry=False)
    parent = Capsule("CAP-A", "ANALYSIS", "REPORT", "analyst", "reporter",
                     (Claim("C2 beaconing observed", "OBSERVED", ("event-5",), claim_id="c1"),), parent_capsules=())
    ledger.add_capsule(parent)
    ledger.record_decision("CAP-A", "ACCEPTED", "contract_gate")
    report = Capsule("CAP-R", "REPORT", "REPORT", "reporter", "output",
                     (Claim("Attacker is APT29", "HYPOTHESIS", claim_id="c1"),), parent_capsules=("CAP-A",))
    result = gate.check(report)
    assert result.status == "RETRY_REQUIRED"
    assert any(v["code"] == "level_not_allowed" for v in result.to_dict()["violations"])


# ------------------------------------------------------------ manifest / cli
def test_manifest_fingerprint_is_stable():
    manifest = HarnessManifest.load(DEFAULT_MANIFEST)
    assert manifest.fingerprint()["harness_sha256"] == manifest.fingerprint()["harness_sha256"]


def test_cli_audit_on_run_dir(tmp_path, evidence_store):
    run = tmp_path / "run"
    run.mkdir()
    (run / "evidence_store.json").write_text(json.dumps(evidence_store), encoding="utf-8")
    items = [hunt_item("T7", "Contact to compdatasystems.com from 10.10.12.110 observed.",
                       ["ner_tool", "rex_tool", "sum_tool"])]
    (run / "soc_hunt_results.json").write_text(json.dumps(items), encoding="utf-8")
    out = tmp_path / "report.json"
    assert main(["audit", str(run), "--masoc-repo", str(MASOC_REPO), "--out", str(out),
                 "--ledger-out", str(tmp_path / "ledger.jsonl")]) == 0
    report = json.loads(out.read_text())
    assert report["summary"]["evidence_reference_validity"] == 1.0
