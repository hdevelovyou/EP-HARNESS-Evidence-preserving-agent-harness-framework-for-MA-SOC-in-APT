"""Tests for Evidence Capsule schema v0.2 on a small synthetic ledger.

Covers claim IDs and references, derivation, observables (R3), level
escalation (R4), declared drops, retry lineage, status transitions, claim flow.
"""

import json
from pathlib import Path

import pytest

from ep_harness import Capsule, Claim, ClaimDrop, ContractGate, EvidenceLedger, LedgerIntegrityError
from ep_harness import capsule as schema
from ep_harness.contracts import default_masoc_registry
from ep_harness.metrics import claim_flow

SCHEMA_FILE = Path(schema.__file__).resolve().parent / "schemas" / "evidence_capsule.v0.2.json"
FINDING_ID = "CAP-T7-FINDING"


def make_gate():
    ledger = EvidenceLedger()
    ledger.add_event("event-1", {"process": {"command_line": "powershell.exe -enc SQBFAFgA"}, "host": "WS01"})
    ledger.add_event("event-2", {"dns": {"question": "compdatasystems.com"}, "src_ip": "10.10.12.110"})
    ledger.add_event("event-3", {"file": {"path": "C:\\Users\\Public\\beacon.dll"}})
    ledger.add_artifact("tool:T7:rex_tool:aa", "T7", "rex_tool", "ok", "aa")
    return ContractGate(ledger, default_masoc_registry())


def finding(*claims, **kwargs):
    return Capsule(kwargs.pop("capsule_id", FINDING_ID), "FINDING", "T7", "hunter", "verifier", tuple(claims), **kwargs)


def verified(*claims, **kwargs):
    return Capsule("CAP-T7-VERIFIED", "VERIFIED", "T7", "verifier", "analyst", tuple(claims),
                   parent_capsules=(FINDING_ID,), **kwargs)


def accepted_finding(gate, *claims):
    """A FINDING that passed the gate and the Verifier."""
    cap = finding(*claims)
    assert gate.check(cap).status == "ACCEPTED"
    gate.ledger.record_decision(cap.capsule_id, "ACCEPTED", "verifier")
    return cap


def codes(result):
    return {v.code for v in result.violations}


C2_CLAIM = Claim("DNS lookup of compdatasystems.com from 10.10.12.110", "OBSERVED", ("event-2",),
                 claim_id="c1", observables=("compdatasystems.com", "10.10.12.110"))
PS_CLAIM = Claim("Encoded PowerShell executed on WS01", "OBSERVED", ("event-1",), claim_id="c2",
                 observables=("powershell.exe -enc",))
GUESS = Claim("The actor likely moved laterally", "HYPOTHESIS", claim_id="c3")


# ------------------------------------------------------------ schema file / serialisation
def test_python_enums_match_json_schema():
    spec = json.loads(SCHEMA_FILE.read_text(encoding="utf-8"))
    claim_props = spec["$defs"]["claim"]["properties"]
    assert spec["properties"]["schema_version"]["const"] == schema.SCHEMA_VERSION
    assert tuple(spec["properties"]["kind"]["enum"]) == schema.KINDS
    assert tuple(spec["properties"]["source"]["enum"]) == schema.AGENTS
    assert tuple(claim_props["level"]["enum"]) == schema.LEVELS
    assert tuple(claim_props["derivation"]["enum"]) == schema.DERIVATIONS
    assert tuple(claim_props["lineage"]["enum"]) == schema.LINEAGE_SOURCES
    assert tuple(spec["$defs"]["claim_drop"]["properties"]["reason"]["enum"]) == schema.DROP_REASONS
    assert spec["properties"]["status"]["const"] == "PROPOSED"


def test_dict_roundtrip_and_hash_ignores_status():
    cap = verified(Claim("c2 contact", "OBSERVED", ("event-2",), claim_id="c1",
                         parent_claims=(f"{FINDING_ID}#c1",), derivation="CARRIED"),
                   dropped_claims=(ClaimDrop(f"{FINDING_ID}#c2", "REFUTED", "benign admin script"),))
    restored = Capsule.from_dict(cap.to_dict())
    assert restored == cap
    assert Capsule.from_dict(dict(cap.to_dict(), status="ACCEPTED")).content_hash() == cap.content_hash()


def test_parser_numbers_missing_claim_ids():
    cap = Capsule.from_dict({"capsule_id": "CAP-1", "kind": "FINDING", "claims": [{"text": "a"}, {"text": "b"}]})
    assert [c.claim_id for c in cap.claims] == ["c1", "c2"]
    assert cap.claim_refs() == ["CAP-1#c1", "CAP-1#c2"]


# ------------------------------------------------------------ C1
def test_well_formed_finding_is_accepted():
    gate = make_gate()
    result = gate.check(finding(C2_CLAIM, PS_CLAIM, GUESS))
    assert result.status == "ACCEPTED", result.to_dict()


def test_bad_and_duplicate_claim_ids_are_rejected():
    gate = make_gate()
    a = Claim("x seen", "OBSERVED", ("event-1",), claim_id="c1")
    result = gate.check(finding(a, a, Claim("y seen", "OBSERVED", ("event-1",), claim_id="claim-3")))
    assert result.status == "REJECTED"
    assert {"duplicate_claim_id", "bad_claim_id"} <= codes(result)


def test_derivation_must_match_parent_claims():
    gate = make_gate()
    accepted_finding(gate, C2_CLAIM, PS_CLAIM)
    new_with_parent = Claim("a", "INFERRED", claim_id="c1", parent_claims=(f"{FINDING_ID}#c1",), derivation="NEW")
    thin_aggregate = Claim("b", "INFERRED", claim_id="c2", parent_claims=(f"{FINDING_ID}#c1",),
                           derivation="AGGREGATED")
    result = gate.check(verified(new_with_parent, thin_aggregate))
    assert result.status == "REJECTED"
    assert [v.claim_index for v in result.violations if v.code == "derivation_mismatch"] == [0, 1]


def test_retry_fields_must_agree():
    gate = make_gate()
    result = gate.check(finding(C2_CLAIM, capsule_id="CAP-T7-FINDING-2", attempt=2))
    assert "bad_retry_fields" in codes(result)


# ------------------------------------------------------------ C3: claim references
def test_verifier_can_carry_accepted_parent_claims():
    gate = make_gate()
    accepted_finding(gate, C2_CLAIM, PS_CLAIM)
    carried = Claim(C2_CLAIM.text, "OBSERVED", ("event-2",), claim_id="c1",
                    parent_claims=(f"{FINDING_ID}#c1",), derivation="CARRIED", observables=("compdatasystems.com",))
    inferred = Claim("PowerShell stager reached the C2 domain", "INFERRED", claim_id="c2",
                     parent_claims=(f"{FINDING_ID}#c1", f"{FINDING_ID}#c2"), derivation="AGGREGATED")
    result = gate.check(verified(carried, inferred))
    assert result.status == "ACCEPTED", result.to_dict()
    assert result.reference_stats["validity"] == 1.0


def test_parent_claim_must_exist_in_a_listed_parent():
    gate = make_gate()
    accepted_finding(gate, C2_CLAIM)
    ghost = Claim("x", "INFERRED", claim_id="c1", parent_claims=(f"{FINDING_ID}#c9",), derivation="REFINED")
    outside = Claim("y", "INFERRED", claim_id="c2", parent_claims=("CAP-T1-FINDING#c1",), derivation="REFINED")
    result = gate.check(verified(ghost, outside))
    assert result.status == "REJECTED"
    assert [v.claim_index for v in result.violations if v.code == "unknown_parent_claim"] == [0, 1]


# ------------------------------------------------------------ R3 / R4
def test_observable_must_occur_in_cited_evidence():
    gate = make_gate()
    wrong_event = Claim("DNS lookup of compdatasystems.com", "OBSERVED", ("event-1",), claim_id="c1",
                        observables=("compdatasystems.com",))
    windows_path = Claim("Beacon DLL dropped", "OBSERVED", ("event-3",), claim_id="c2",
                         observables=("c:\\users\\public\\beacon.dll",))
    result = gate.check(finding(wrong_event, windows_path))
    assert result.status == "RETRY_REQUIRED"
    assert [v.claim_index for v in result.violations if v.code == "observable_not_in_evidence"] == [0]


def test_carried_hypothesis_cannot_become_inference():
    gate = make_gate()
    accepted_finding(gate, GUESS)
    upgraded = Claim(GUESS.text, "INFERRED", claim_id="c1", parent_claims=(f"{FINDING_ID}#c3",),
                     derivation="CARRIED")
    result = gate.check(verified(upgraded))
    assert result.status == "RETRY_REQUIRED"
    assert codes(result) == {"level_escalation"}


def test_refined_claim_may_escalate_with_its_own_events():
    gate = make_gate()
    accepted_finding(gate, GUESS)
    refined = Claim("Encoded PowerShell on WS01 is the lateral movement step", "OBSERVED", ("event-1",),
                    claim_id="c1", parent_claims=(f"{FINDING_ID}#c3",), derivation="REFINED")
    assert gate.check(verified(refined)).status == "ACCEPTED"


# ------------------------------------------------------------ dropped claims / claim flow
def test_dropped_claims_are_validated():
    gate = make_gate()
    accepted_finding(gate, C2_CLAIM, PS_CLAIM)
    carried = Claim(C2_CLAIM.text, "OBSERVED", ("event-2",), claim_id="c1",
                    parent_claims=(f"{FINDING_ID}#c1",), derivation="CARRIED")
    result = gate.check(verified(carried, dropped_claims=(
        ClaimDrop(f"{FINDING_ID}#c1", "REFUTED"),
        ClaimDrop(f"{FINDING_ID}#c2", "BORING"),
    )))
    assert result.status == "REJECTED"
    assert {"carried_and_dropped", "bad_drop_reason"} <= codes(result)


def test_claim_flow_separates_declared_drops_from_silent_loss():
    parent = finding(C2_CLAIM, PS_CLAIM, GUESS)
    child = verified(
        Claim(C2_CLAIM.text, "OBSERVED", ("event-2",), claim_id="c1",
              parent_claims=(f"{FINDING_ID}#c1",), derivation="CARRIED"),
        Claim("Stager contacted C2", "OBSERVED", ("event-1",), claim_id="c2",
              parent_claims=(f"{FINDING_ID}#c3",), derivation="REFINED"),
        dropped_claims=(ClaimDrop(f"{FINDING_ID}#c2", "INSUFFICIENT_EVIDENCE"),),
    )
    flow = claim_flow([parent, child])["verifier->analyst"]
    assert flow["parent_claims"] == 3
    assert (flow["carried"], flow["dropped_declared"], flow.get("lost_silently", 0)) == (2, 1, 0)
    assert flow["escalated"] == 1
    lossy = claim_flow([parent, verified(child.claims[0])])["verifier->analyst"]
    assert lossy["lost_silently"] == 2


# ------------------------------------------------------------ retry lineage
def test_retry_must_supersede_a_retry_required_capsule_once():
    gate = make_gate()
    unanchored = Claim("DNS lookup of compdatasystems.com", "OBSERVED", claim_id="c1")
    assert gate.check(finding(unanchored)).status == "RETRY_REQUIRED"
    retry = finding(C2_CLAIM, capsule_id="CAP-T7-FINDING-a2", attempt=2, supersedes=FINDING_ID)
    assert gate.check(retry).status == "ACCEPTED"
    second = finding(C2_CLAIM, capsule_id="CAP-T7-FINDING-a2b", attempt=2, supersedes=FINDING_ID)
    assert "already_superseded" in codes(gate.check(second))
    of_accepted = finding(C2_CLAIM, capsule_id="CAP-T7-FINDING-a3", attempt=3, supersedes="CAP-T7-FINDING-a2")
    assert "superseded_not_retryable" in codes(gate.check(of_accepted))


# ------------------------------------------------------------ status transitions
def test_status_transitions_and_actors_are_enforced():
    gate = make_gate()
    cap = finding(C2_CLAIM)
    gate.ledger.add_capsule(cap)
    with pytest.raises(LedgerIntegrityError):  # the gate cannot be skipped
        gate.ledger.record_decision(cap.capsule_id, "ACCEPTED", "verifier")
    gate.ledger.record_decision(cap.capsule_id, "ACCEPTED", "contract_gate")
    with pytest.raises(LedgerIntegrityError):  # the policy may stop, never accept
        gate.ledger.record_decision(cap.capsule_id, "ACCEPTED", "policy_orchestrator")
    gate.ledger.record_decision(cap.capsule_id, "UNRESOLVED", "policy_orchestrator")
    with pytest.raises(LedgerIntegrityError):  # terminal
        gate.ledger.record_decision(cap.capsule_id, "ACCEPTED", "human_analyst")


def test_no_actor_decides_on_its_own_capsule():
    gate = make_gate()
    accepted_finding(gate, C2_CLAIM)
    own = verified(Claim(C2_CLAIM.text, "OBSERVED", ("event-2",), claim_id="c1",
                         parent_claims=(f"{FINDING_ID}#c1",), derivation="CARRIED"))
    assert gate.check(own).status == "ACCEPTED"
    with pytest.raises(LedgerIntegrityError):
        gate.ledger.record_decision(own.capsule_id, "ACCEPTED", "verifier")
