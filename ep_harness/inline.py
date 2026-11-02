"""Inline Evidence-Centric Handoff for the MA-SOC runtime.

Unlike adapters.masoc (a shadow audit after the run), this module sits between
agents while the run is going on, and its decisions change what the next agent
receives:

  Hunter   -> Verifier : the FINDING is gated before the Verifier is called.
                         A blocked finding goes back to the Hunter with the
                         gate violations as feedback; the Verifier is not called.
  Verifier -> Analyst  : the Verifier's verdict is recorded on the FINDING; a
                         VERIFIED capsule carries its claims. Only tasks whose
                         VERIFIED capsule is ACCEPTED reach the Analyst.
  Analyst  -> Reporter : the ANALYSIS is gated. The caller may retry the
                         Analyst with gate feedback; claims that still violate a
                         claim-level check are withheld from the Reporter
                         (filtering only: the ledger keeps the original capsule).
  Reporter -> output   : gated and recorded only; no action is taken.

Agents still write free text, so claims are parsed per line with derived event
references, exactly as in the shadow adapter. Links to parent claims are
derived from shared event references (metadata.parent_link).
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from .adapters.masoc import (
    claim_lines,
    claims_from_text,
    ledger_from_evidence_store,
    observable_index,
    register_tool_artifacts,
    split_tool_audit,
    task_contracts_from_catalog,
)
from .capsule import Capsule, Claim, claim_ref
from .contracts import TaskContract, default_masoc_registry
from .gate import ContractGate, GateResult
from .metrics import summarize

ANALYSIS_TASK = "ANALYSIS"
REPORT_TASK = "REPORT"
_OPEN_STATUSES = ("ACCEPTED", "REVIEW_REQUIRED")


@dataclass
class HandoffOutcome:
    edge: str
    capsule_id: str
    status: str
    violations: list[dict] = field(default_factory=list)
    feedback: str = ""
    action: str = ""

    @property
    def accepted(self) -> bool:
        return self.status == "ACCEPTED"

    @property
    def has_claim_violations(self) -> bool:
        """True when some violation points at a claim the agent could fix."""
        return any(v["claim_index"] is not None for v in self.violations)

    def to_dict(self) -> dict:
        return {
            "edge": self.edge,
            "capsule_id": self.capsule_id,
            "status": self.status,
            "violations": self.violations,
            "action": self.action,
        }


def gate_feedback(capsule: Capsule, result: GateResult) -> str:
    """Deterministic feedback for the producing agent. Never starts with 'OK'."""
    lines = [
        "CONTRACT GATE: the handoff was blocked by the deterministic form/reference check "
        f"(status {result.status}). Problems:",
    ]
    for violation in result.violations:
        line = f"- [{violation.check} {violation.code}] {violation.detail}"
        if violation.claim_index is not None and violation.claim_index < len(capsule.claims):
            line += f' (claim: "{capsule.claims[violation.claim_index].text[:160]}")'
        lines.append(line)
    lines.append(
        "Fix only these problems: cite only event IDs that exist in the provided telemetry, "
        "run every mandatory tool, and keep each statement grounded in the events. "
        "Do not add new conclusions to satisfy the gate."
    )
    return "\n".join(lines)


class InlineECH:
    def __init__(self, evidence_store: dict, task_inventory: list[dict] | None = None):
        self.ledger = ledger_from_evidence_store(evidence_store)
        self.registry = task_contracts_from_catalog(task_inventory) if task_inventory else default_masoc_registry()
        for pseudo_task in (ANALYSIS_TASK, REPORT_TASK):
            self.registry.add_task(TaskContract(pseudo_task))
        self.gate = ContractGate(self.ledger, self.registry)
        self.obs_index = observable_index(evidence_store)
        self.capsules: list[Capsule] = []
        self.results: list[GateResult] = []
        self.handoffs: list[dict] = []
        self._latest: dict[tuple[str, str], Capsule] = {}
        self._line_index: dict[str, list[int]] = {}

    # ---------------------------------------------------------------- helpers
    def _status(self, capsule: Capsule | None) -> str | None:
        return self.ledger.capsule_status(capsule.capsule_id) if capsule else None

    def _next_identity(self, task_id: str, kind: str) -> tuple[str, int, str | None]:
        """ID, attempt and supersedes for the next capsule of (task, kind).

        A previous attempt that never got a semantic decision (e.g. the
        Verifier call raised) is closed as UNRESOLVED first, so the retry can
        supersede it.
        """
        base = f"CAP-{kind}" if task_id == kind else f"CAP-{task_id}-{kind}"
        previous = self._latest.get((task_id, kind))
        if previous is None:
            return f"{base}-a1", 1, None
        if self._awaits_verdict(previous):
            self.ledger.record_decision(
                previous.capsule_id,
                "UNRESOLVED",
                "policy_orchestrator",
                detail={"reason": "superseded_without_verifier_verdict"},
            )
        attempt = previous.attempt + 1
        return f"{base}-a{attempt}", attempt, previous.capsule_id

    def _check(self, capsule: Capsule, edge: str, action_if_blocked: str) -> HandoffOutcome:
        result = self.gate.check(capsule)
        self.capsules.append(capsule)
        self.results.append(result)
        self._latest[(capsule.task_id, capsule.kind)] = capsule
        outcome = HandoffOutcome(
            edge=edge,
            capsule_id=capsule.capsule_id,
            status=result.status,
            violations=[v.to_dict() for v in result.violations],
            feedback="" if result.status == "ACCEPTED" else gate_feedback(capsule, result),
            action="forward" if result.status == "ACCEPTED" else action_if_blocked,
        )
        self.handoffs.append(outcome.to_dict())
        return outcome

    def _link_to_parents(self, claims: list[Claim], parents: list[Capsule]) -> list[Claim]:
        """Attach parent claims that share an event reference with each claim."""
        by_event: dict[str, list[str]] = {}
        for parent in parents:
            for parent_claim in parent.claims:
                for event_id in parent_claim.event_ids:
                    by_event.setdefault(event_id, []).append(claim_ref(parent.capsule_id, parent_claim.claim_id))
        linked = []
        for claim in claims:
            refs = sorted({ref for event_id in claim.event_ids for ref in by_event.get(event_id, ())})
            derivation = "NEW" if not refs else ("REFINED" if len(refs) == 1 else "AGGREGATED")
            linked.append(replace(claim, parent_claims=tuple(refs), derivation=derivation))
        return linked

    def _accepted_latest(self, kind: str) -> list[Capsule]:
        return [
            capsule
            for (task_id, capsule_kind), capsule in self._latest.items()
            if capsule_kind == kind and self._status(capsule) == "ACCEPTED"
        ]

    # ---------------------------------------------------------------- Hunter -> Verifier
    def hunter_handoff(self, task_id: str, hunter_output: str) -> HandoffOutcome:
        body, audit = split_tool_audit(hunter_output)
        artifact_ids = register_tool_artifacts(self.ledger, task_id, audit)
        capsule_id, attempt, supersedes = self._next_identity(task_id, "FINDING")
        capsule = Capsule(
            capsule_id=capsule_id,
            kind="FINDING",
            task_id=task_id,
            source="hunter",
            dest="verifier",
            claims=tuple(claims_from_text(body, self.obs_index, artifact_ids)),
            tools_used=tuple(str(a.get("tool", "")) for a in audit),
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "inline", "level_source": "heuristic"},
        )
        return self._check(capsule, "hunter->verifier", action_if_blocked="return_to_hunter")

    def record_verifier(self, task_id: str, passed: bool, verdict: str = "") -> None:
        """Record the Verifier's semantic verdict on the latest gate-accepted FINDING."""
        finding = self._latest.get((task_id, "FINDING"))
        if finding is None or self._status(finding) != "ACCEPTED":
            return
        self.ledger.record_decision(
            finding.capsule_id,
            "ACCEPTED" if passed else "REJECTED",
            "verifier",
            detail={"verdict": str(verdict)[:1000]},
        )

    # ---------------------------------------------------------------- Verifier -> Analyst
    def verifier_handoff(self, task_id: str) -> HandoffOutcome:
        finding = self._latest[(task_id, "FINDING")]
        capsule_id, attempt, supersedes = self._next_identity(task_id, "VERIFIED")
        capsule = Capsule(
            capsule_id=capsule_id,
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
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "inline"},
        )
        return self._check(capsule, "verifier->analyst", action_if_blocked="exclude_from_analyst")

    def accepted_task_ids(self) -> set[str]:
        return {capsule.task_id for capsule in self._accepted_latest("VERIFIED")}

    # ---------------------------------------------------------------- Analyst -> Reporter
    def analyst_handoff(self, analysis_text: str) -> HandoffOutcome:
        parents = sorted(self._accepted_latest("VERIFIED"), key=lambda c: c.capsule_id)
        pairs = claim_lines(analysis_text, self.obs_index, [])
        claims = self._link_to_parents([claim for _, claim in pairs], parents)
        capsule_id, attempt, supersedes = self._next_identity(ANALYSIS_TASK, "ANALYSIS")
        capsule = Capsule(
            capsule_id=capsule_id,
            kind="ANALYSIS",
            task_id=ANALYSIS_TASK,
            source="analyst",
            dest="reporter",
            claims=tuple(claims),
            parent_capsules=tuple(p.capsule_id for p in parents),
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "inline", "level_source": "heuristic", "parent_link": "derived_shared_events"},
        )
        self._line_index[capsule_id] = [line_index for line_index, _ in pairs]
        return self._check(capsule, "analyst->reporter", action_if_blocked="retry_analyst_or_withhold_claims")

    def withhold_blocked_claims(self, analysis_text: str, outcome: HandoffOutcome) -> str:
        """Drop the lines of claims that carry a claim-level violation.

        Capsule-level violations (e.g. no accepted parents) cannot be fixed by
        filtering; they stay recorded in the ledger and the audit.
        """
        flagged = sorted({v["claim_index"] for v in outcome.violations if v["claim_index"] is not None})
        line_index = self._line_index.get(outcome.capsule_id, [])
        drop_lines = {line_index[i] for i in flagged if i < len(line_index)}
        kept = [line for i, line in enumerate(str(analysis_text).splitlines()) if i not in drop_lines]
        self.handoffs.append({
            "edge": outcome.edge,
            "capsule_id": outcome.capsule_id,
            "status": outcome.status,
            "action": "withheld_claims",
            "withheld_claims": [f"{outcome.capsule_id}#c{i + 1}" for i in flagged],
            "capsule_level_violations": [v["code"] for v in outcome.violations if v["claim_index"] is None],
        })
        return "\n".join(kept)

    # ---------------------------------------------------------------- Reporter -> output
    def reporter_handoff(self, report_text: str) -> HandoffOutcome:
        analysis = self._latest.get((ANALYSIS_TASK, "ANALYSIS"))
        parents = [analysis] if analysis is not None else []
        claims = self._link_to_parents(claims_from_text(report_text, self.obs_index, []), parents)
        capsule_id, attempt, supersedes = self._next_identity(REPORT_TASK, "REPORT")
        capsule = Capsule(
            capsule_id=capsule_id,
            kind="REPORT",
            task_id=REPORT_TASK,
            source="reporter",
            dest="output",
            claims=tuple(claims),
            parent_capsules=tuple(p.capsule_id for p in parents),
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "record_only", "level_source": "heuristic", "parent_link": "derived_shared_events"},
        )
        return self._check(capsule, "reporter->output", action_if_blocked="record_only")

    # ---------------------------------------------------------------- output
    def summary(self) -> dict:
        return {
            "mode": "inline",
            "summary": summarize(self.capsules, self.results),
            "handoffs": self.handoffs,
            "ledger_counts": self.ledger.counts(),
        }

    def close_open_findings(self) -> None:
        """FINDINGs that passed the gate but never got a Verifier verdict become UNRESOLVED."""
        for capsule in list(self._latest.values()):
            if self._awaits_verdict(capsule):
                self.ledger.record_decision(
                    capsule.capsule_id,
                    "UNRESOLVED",
                    "policy_orchestrator",
                    detail={"reason": "no_verifier_verdict"},
                )

    def _awaits_verdict(self, capsule: Capsule) -> bool:
        """A FINDING the gate accepted but the Verifier never ruled on."""
        if capsule.kind != "FINDING" or self._status(capsule) not in _OPEN_STATUSES:
            return False
        return not any(
            d["capsule_id"] == capsule.capsule_id and d["actor"] != ContractGate.ACTOR for d in self.ledger.decisions()
        )

    def save(self, run_dir) -> dict:
        self.close_open_findings()
        run_dir = Path(run_dir)
        ledger_path = run_dir / "ech_ledger.jsonl"
        audit_path = run_dir / "ech_inline_audit.json"
        self.ledger.save(ledger_path)
        audit_path.write_text(json.dumps(self.summary(), ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ledger": str(ledger_path), "audit": str(audit_path)}
