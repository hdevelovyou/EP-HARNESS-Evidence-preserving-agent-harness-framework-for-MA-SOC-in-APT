"""Adapter between the existing MA-SOC pipeline outputs and EP-HARNESS.

Shadow mode: reads files MA-SOC already writes (evidence_store.json,
soc_hunt_results.json) and audits every Hunter->Verifier->Analyst handoff
without changing MA-SOC behavior.

Current MA-SOC prompts do not ask agents to cite event IDs, so event
references are DERIVED here by matching observable values against the
evidence inventory (lineage="derived"). Derived references show which events
a claim *touches*; they are an upper bound on support, not proof of it.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from ..capsule import Capsule, Claim, claim_ref
from ..contracts import ContractRegistry, TaskContract, default_masoc_registry
from ..gate import ContractGate, GateResult
from ..ledger import EvidenceLedger
from ..metrics import summarize

_AUDIT_MARKER = "Tool Execution Audit:"
_EVENT_REF = re.compile(r"\bevent-\d+\b")
_TTP = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_MIN_OBSERVABLE_LEN = 4
_MIN_CLAIM_LEN = 20


# ---------------------------------------------------------------- ledger
def ledger_from_evidence_store(evidence_store: dict) -> EvidenceLedger:
    ledger = EvidenceLedger()
    for event in evidence_store.get("events", []):
        winlog = event.get("winlog") or {}
        ledger.add_event(
            event["event_id"],
            event,
            source=str(winlog.get("channel", "")),
            timestamp=str(event.get("timestamp", "")),
        )
    return ledger


def observable_index(evidence_store: dict) -> dict[str, tuple[str, ...]]:
    index = {}
    for entries in evidence_store.get("observables", {}).values():
        for entry in entries:
            value = str(entry.get("value", "")).strip().lower()
            if len(value) >= _MIN_OBSERVABLE_LEN:
                index[value] = tuple(entry.get("event_ids", ()))
    return index


def task_contracts_from_catalog(task_inventory: list[dict]) -> ContractRegistry:
    registry = default_masoc_registry()
    for task in task_inventory:
        registry.add_task(
            TaskContract(task["id"], tuple(task.get("tools", ())), tuple(task.get("produces", ())))
        )
    return registry


# ---------------------------------------------------------------- parsing
def split_tool_audit(hunter_output: str) -> tuple[str, list[dict]]:
    text = str(hunter_output or "")
    marker = text.find(_AUDIT_MARKER)
    if marker < 0:
        return text.strip(), []
    body, audit_text = text[:marker].strip(), text[marker + len(_AUDIT_MARKER):].strip()
    try:
        audit = json.loads(audit_text)
    except json.JSONDecodeError:
        audit = []
    return body, audit if isinstance(audit, list) else []


def register_tool_artifacts(ledger: EvidenceLedger, task_id: str, audit: list[dict]) -> list[str]:
    artifact_ids = []
    for item in audit:
        tool = str(item.get("tool", ""))
        digest = str(item.get("output_sha256", ""))
        artifact_id = f"tool:{task_id}:{tool}:{digest[:12] or 'nooutput'}"
        ledger.add_artifact(artifact_id, task_id, tool, str(item.get("status", "")), digest)
        artifact_ids.append(artifact_id)
    return artifact_ids


def claims_from_text(text: str, obs_index: dict[str, tuple[str, ...]], artifact_ids: list[str]) -> list[Claim]:
    """One claim per substantive line.

    Level is heuristic because MA-SOC output is free text: a line that touches
    ledger evidence is OBSERVED; a line that touches none is kept as a
    HYPOTHESIS (narrative), so it may travel but can never reach the final
    report as a finding. The gate never rewrites levels itself.
    """
    claims = []
    for raw_line in text.splitlines():
        line = " ".join(raw_line.strip().lstrip("-*#> ").split())
        if len(line) < _MIN_CLAIM_LEN:
            continue
        lowered = line.lower()
        cited = tuple(sorted(set(_EVENT_REF.findall(lowered))))
        derived = sorted({eid for value, eids in obs_index.items() if value in lowered for eid in eids})
        event_ids = cited or tuple(derived)
        claims.append(
            Claim(
                text=line[:500],
                level="OBSERVED" if event_ids else "HYPOTHESIS",
                event_ids=event_ids,
                artifact_ids=tuple(artifact_ids) if event_ids else (),
                ttp_candidates=tuple(sorted({t.upper() for t in _TTP.findall(line)})),
                lineage="cited" if cited else "derived",
                claim_id=f"c{len(claims) + 1}",
            )
        )
    return claims


# ---------------------------------------------------------------- audit
def audit_hunt_results(evidence_store: dict, hunt_results: list[dict], registry: ContractRegistry) -> dict:
    ledger = ledger_from_evidence_store(evidence_store)
    obs_index = observable_index(evidence_store)
    gate = ContractGate(ledger, registry)
    capsules: list[Capsule] = []
    results: list[GateResult] = []
    per_task = []
    disagreement = {"gate_accept_verifier_pass": 0, "gate_accept_verifier_fail": 0,
                    "gate_block_verifier_pass": 0, "gate_block_verifier_fail": 0}

    for item in hunt_results:
        task_id = str(item.get("task_id", ""))
        body, audit = split_tool_audit(item.get("result", ""))
        artifact_ids = register_tool_artifacts(ledger, task_id, audit)
        finding = Capsule(
            capsule_id=f"CAP-{task_id}-FINDING",
            kind="FINDING",
            task_id=task_id,
            source="hunter",
            dest="verifier",
            claims=tuple(claims_from_text(body, obs_index, artifact_ids)),
            tools_used=tuple(a.get("tool", "") for a in audit),
            metadata={"masoc_status": item.get("status"), "level_source": "heuristic"},
        )
        gate_result = gate.check(finding)
        capsules.append(finding)
        results.append(gate_result)

        verifier_passed = item.get("status") == "Verified"
        gate_ok = gate_result.status == "ACCEPTED"
        key = f"gate_{'accept' if gate_ok else 'block'}_verifier_{'pass' if verifier_passed else 'fail'}"
        disagreement[key] += 1

        verified_result = None
        if gate_ok:
            # The Verifier's verdict is the semantic decision on this edge.
            ledger.record_decision(
                finding.capsule_id,
                "ACCEPTED" if verifier_passed else "UNRESOLVED",
                "verifier",
                detail={"masoc_status": item.get("status")},
            )
            if verifier_passed:
                verified = Capsule(
                    capsule_id=f"CAP-{task_id}-VERIFIED",
                    kind="VERIFIED",
                    task_id=task_id,
                    source="verifier",
                    dest="analyst",
                    # MA-SOC's Verifier passes the whole finding on unchanged.
                    claims=tuple(
                        replace(c, parent_claims=(claim_ref(finding.capsule_id, c.claim_id),), derivation="CARRIED")
                        for c in finding.claims
                    ),
                    parent_capsules=(finding.capsule_id,),
                )
                verified_result = gate.check(verified)
                capsules.append(verified)
                results.append(verified_result)

        per_task.append({
            "task_id": task_id,
            "masoc_status": item.get("status"),
            "claims": len(finding.claims),
            "finding_gate": gate_result.to_dict(),
            "verified_gate": verified_result.to_dict() if verified_result else None,
        })

    return {
        "summary": summarize(capsules, results),
        "gate_vs_verifier": disagreement,
        "ledger_counts": ledger.counts(),
        "per_task": per_task,
        "_ledger": ledger,
        "_capsules": capsules,
    }


def audit_run_dir(run_dir, task_inventory: list[dict] | None = None) -> dict:
    run_dir = Path(run_dir)
    evidence_store = json.loads((run_dir / "evidence_store.json").read_text(encoding="utf-8"))
    hunt_results = json.loads((run_dir / "soc_hunt_results.json").read_text(encoding="utf-8"))
    registry = task_contracts_from_catalog(task_inventory) if task_inventory else default_masoc_registry()
    return audit_hunt_results(evidence_store, hunt_results, registry)
