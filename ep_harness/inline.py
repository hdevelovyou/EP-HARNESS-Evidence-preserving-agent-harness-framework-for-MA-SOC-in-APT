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

Two claim sources:
  derived - agents write free text; claims are parsed per line with derived
            event references (as in the shadow adapter) and linked to parent
            claims through shared events (metadata.parent_link).
  cited   - the Hunter and the Analyst end their output with an
            ```evidence_claims block (claim_parser); the agent names the
            events, tools and parent claims itself, and the Analyst tags each
            narrative line with its claim ID so a blocked claim can be removed.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from pathlib import Path

from .adapters.masoc import (
    artifacts_by_tool,
    claim_lines,
    claims_from_text,
    ledger_from_evidence_store,
    observable_index,
    register_tool_artifacts,
    split_tool_audit,
    task_contracts_from_catalog,
)
from .capsule import Capsule, Claim, claim_ref
from .claim_parser import (
    FENCE,
    claims_from_records,
    drop_tagged_lines,
    extract_claims_block,
    remove_claims_block,
    strip_claim_tags,
)
from .contracts import TaskContract, default_masoc_registry
from .gate import ContractGate, GateResult
from .metrics import summarize

ANALYSIS_TASK = "ANALYSIS"
REPORT_TASK = "REPORT"
CLAIM_SOURCES = ("derived", "cited")
_OPEN_STATUSES = ("ACCEPTED", "REVIEW_REQUIRED")


@dataclass
class HandoffOutcome:
    edge: str
    capsule_id: str
    status: str
    violations: list[dict] = field(default_factory=list)
    feedback: str = ""
    action: str = ""
    notes: list[str] = field(default_factory=list)

    @property
    def accepted(self) -> bool:
        return self.status == "ACCEPTED"

    @property
    def retryable(self) -> bool:
        """True when the producing agent could fix the problem: a bad claim or an unreadable claims block."""
        return bool(self.notes) or any(v["claim_index"] is not None for v in self.violations)

    def to_dict(self) -> dict:
        return {
            "edge": self.edge,
            "capsule_id": self.capsule_id,
            "status": self.status,
            "violations": self.violations,
            "notes": self.notes,
            "action": self.action,
        }


def gate_feedback(capsule: Capsule, result: GateResult, notes=()) -> str:
    """Deterministic feedback for the producing agent. Never starts with 'OK'."""
    lines = [
        "CONTRACT GATE: the handoff was blocked by the deterministic form/reference check "
        f"(status {result.status}). Problems:",
    ]
    for note in notes:
        lines.append(f"- [format] {note}: end your answer with exactly one ```{FENCE} block as instructed")
    for violation in result.violations:
        line = f"- [{violation.check} {violation.code}] {violation.detail}"
        if violation.claim_index is not None and violation.claim_index < len(capsule.claims):
            claim = capsule.claims[violation.claim_index]
            line += f' (claim {claim.claim_id}: "{claim.text[:160]}")'
        lines.append(line)
    lines.append(
        "Fix only these problems: cite only event IDs that exist in the provided telemetry, "
        "run every mandatory tool, and keep each statement grounded in the events. "
        "Do not add new conclusions to satisfy the gate."
    )
    return "\n".join(lines)


class InlineECH:
    def __init__(self, evidence_store: dict, task_inventory: list[dict] | None = None, claim_source: str = "derived"):
        if claim_source not in CLAIM_SOURCES:
            raise ValueError(f"claim_source must be one of {CLAIM_SOURCES}; got {claim_source!r}")
        self.claim_source = claim_source
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

    @property
    def cited(self) -> bool:
        return self.claim_source == "cited"

    # ---------------------------------------------------------------- helpers
    def _status(self, capsule: Capsule | None) -> str | None:
        return self.ledger.capsule_status(capsule.capsule_id) if capsule else None

    def _next_identity(self, task_id: str, kind: str) -> tuple[str, int, str | None]:
        """ID, attempt and supersedes for the next capsule of (task, kind).

        A previous FINDING that never got a Verifier verdict (e.g. the Verifier
        call raised) is closed as UNRESOLVED first, so the retry can supersede it.
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

    def _check(self, capsule: Capsule, edge: str, action_if_blocked: str, notes=()) -> HandoffOutcome:
        result = self.gate.check(capsule)
        self.capsules.append(capsule)
        self.results.append(result)
        self._latest[(capsule.task_id, capsule.kind)] = capsule
        outcome = HandoffOutcome(
            edge=edge,
            capsule_id=capsule.capsule_id,
            status=result.status,
            violations=[v.to_dict() for v in result.violations],
            feedback="" if result.status == "ACCEPTED" else gate_feedback(capsule, result, notes),
            action="forward" if result.status == "ACCEPTED" else action_if_blocked,
            notes=list(notes),
        )
        self.handoffs.append(outcome.to_dict())
        return outcome

    def _link_to_parents(self, claims: list[Claim], parents: list[Capsule]) -> list[Claim]:
        """Attach parent claims that share an event reference with each claim (derived mode)."""
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
        return sorted(
            (
                capsule
                for (task_id, capsule_kind), capsule in self._latest.items()
                if capsule_kind == kind and self._status(capsule) == "ACCEPTED"
            ),
            key=lambda c: c.capsule_id,
        )

    def _awaits_verdict(self, capsule: Capsule) -> bool:
        """A FINDING the gate accepted but the Verifier never ruled on."""
        if capsule.kind != "FINDING" or self._status(capsule) not in _OPEN_STATUSES:
            return False
        return not any(
            d["capsule_id"] == capsule.capsule_id and d["actor"] != ContractGate.ACTOR for d in self.ledger.decisions()
        )

    # ---------------------------------------------------------------- Hunter -> Verifier
    def hunter_handoff(self, task_id: str, hunter_output: str) -> HandoffOutcome:
        body, audit = split_tool_audit(hunter_output)
        artifact_ids = register_tool_artifacts(self.ledger, task_id, audit)
        notes = []
        if self.cited:
            parsed = extract_claims_block(body)
            claims = claims_from_records(parsed.records, artifacts_by_tool(audit, artifact_ids))
            notes = [parsed.error] if parsed.error else []
        else:
            claims = claims_from_text(body, self.obs_index, artifact_ids)
        capsule_id, attempt, supersedes = self._next_identity(task_id, "FINDING")
        capsule = Capsule(
            capsule_id=capsule_id,
            kind="FINDING",
            task_id=task_id,
            source="hunter",
            dest="verifier",
            claims=tuple(claims),
            tools_used=tuple(str(a.get("tool", "")) for a in audit),
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "inline", "claim_source": self.claim_source,
                      "level_source": "agent" if self.cited else "heuristic"},
        )
        return self._check(capsule, "hunter->verifier", "return_to_hunter", notes)

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
            metadata={"mode": "inline", "claim_source": self.claim_source},
        )
        return self._check(capsule, "verifier->analyst", "exclude_from_analyst")

    def accepted_task_ids(self) -> set[str]:
        return {capsule.task_id for capsule in self._accepted_latest("VERIFIED")}

    def verified_claims(self) -> dict[str, list[dict]]:
        """Accepted VERIFIED claims per task, with the refs the Analyst must cite."""
        return {
            capsule.task_id: [
                {"ref": claim_ref(capsule.capsule_id, c.claim_id), "level": c.level,
                 "text": c.text, "event_ids": list(c.event_ids)}
                for c in capsule.claims
            ]
            for capsule in self._accepted_latest("VERIFIED")
        }

    # ---------------------------------------------------------------- Analyst -> Reporter
    def analyst_handoff(self, analysis_text: str) -> HandoffOutcome:
        parents = self._accepted_latest("VERIFIED")
        capsule_id, attempt, supersedes = self._next_identity(ANALYSIS_TASK, "ANALYSIS")
        notes = []
        if self.cited:
            parsed = extract_claims_block(analysis_text)
            claims = claims_from_records(parsed.records)
            notes = [parsed.error] if parsed.error else []
            parent_link = "cited"
        else:
            pairs = claim_lines(analysis_text, self.obs_index, [])
            claims = self._link_to_parents([claim for _, claim in pairs], parents)
            self._line_index[capsule_id] = [line_index for line_index, _ in pairs]
            parent_link = "derived_shared_events"
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
            metadata={"mode": "inline", "claim_source": self.claim_source,
                      "level_source": "agent" if self.cited else "heuristic", "parent_link": parent_link},
        )
        return self._check(capsule, "analyst->reporter", "retry_analyst_or_withhold_claims", notes)

    def analysis_for_reporter(self, analysis_text: str, outcome: HandoffOutcome) -> str:
        """The analysis text the Reporter may see.

        Lines of claims that carry a claim-level violation are dropped (cited:
        the lines tagged with that claim ID; derived: the claim's own line).
        Capsule-level violations (no accepted parents, no readable claims
        block) cannot be fixed by filtering; they stay recorded in the ledger.
        In cited mode the claims block and the [cN] tags are removed.
        """
        text = str(analysis_text or "")
        if outcome.accepted:
            return strip_claim_tags(remove_claims_block(text)) if self.cited else text
        capsule = self.ledger.capsule(outcome.capsule_id)
        flagged = sorted({v["claim_index"] for v in outcome.violations if v["claim_index"] is not None})
        flagged = [i for i in flagged if i < len(capsule.claims)]
        if self.cited:
            text = strip_claim_tags(
                drop_tagged_lines(remove_claims_block(text), [capsule.claims[i].claim_id for i in flagged])
            )
        else:
            line_index = self._line_index.get(outcome.capsule_id, [])
            drop_lines = {line_index[i] for i in flagged if i < len(line_index)}
            text = "\n".join(line for i, line in enumerate(text.splitlines()) if i not in drop_lines)
        self.handoffs.append({
            "edge": outcome.edge,
            "capsule_id": outcome.capsule_id,
            "status": outcome.status,
            "action": "withheld_claims",
            "withheld_claims": [claim_ref(capsule.capsule_id, capsule.claims[i].claim_id) for i in flagged],
            "capsule_level_violations": [v["code"] for v in outcome.violations if v["claim_index"] is None],
            "notes": outcome.notes,
        })
        return text

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
        return self._check(capsule, "reporter->output", "record_only")

    # ---------------------------------------------------------------- output
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

    def summary(self) -> dict:
        return {
            "mode": "inline",
            "claim_source": self.claim_source,
            "summary": summarize(self.capsules, self.results),
            "handoffs": self.handoffs,
            "ledger_counts": self.ledger.counts(),
        }

    def save(self, run_dir) -> dict:
        self.close_open_findings()
        run_dir = Path(run_dir)
        ledger_path = run_dir / "ech_ledger.jsonl"
        audit_path = run_dir / "ech_inline_audit.json"
        self.ledger.save(ledger_path)
        audit_path.write_text(json.dumps(self.summary(), ensure_ascii=False, indent=2), encoding="utf-8")
        return {"ledger": str(ledger_path), "audit": str(audit_path)}
