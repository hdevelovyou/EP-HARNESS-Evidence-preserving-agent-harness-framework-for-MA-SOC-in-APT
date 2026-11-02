"""Contract Gate: deterministic checks on a proposed capsule.

The gate checks FORM and REFERENCES, never truth:
  C1 schema      - enums, types, IDs, non-empty text, TTP ID format,
                   derivation consistent with parent claims, retry fields
  C2 identity    - the (source, dest, kind) edge exists; task is known
  C3 references  - cited events/artifacts/parents/parent claims exist in the
                   ledger; parents ACCEPTED; a retry supersedes a capsule of
                   the same task that reached a terminal status
  C4 tools       - the task's mandatory tools actually executed
  R1 anchoring   - OBSERVED claims cite >=1 event; INFERRED claims cite
                   events or parent claims
  R2 level       - claim level is allowed on this edge
  R3 observables - every declared observable occurs in a cited event or in
                   a parent claim (lexical anchoring only)
  R4 escalation  - a claim is not stronger than its parent claims unless it
                   cites its own events (CARRIED claims may never escalate)

Semantic sufficiency ("does this evidence support this claim?") is NOT checked
here. It belongs to the Verifier (Hunter->Verifier edge) and the Output
Evidence Guardrail (Analyst/Reporter). Every result says so explicitly.

Decision precedence (first match wins):
  C1, C2, C3 violation          -> REJECTED        (malformed or fabricated)
  C4, R1-R4 violation           -> RETRY_REQUIRED  (recoverable gap)
  otherwise                     -> ACCEPTED
REVIEW_REQUIRED and UNRESOLVED are issued by the Verifier / Policy Orchestrator,
not by this gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .capsule import (
    CAPSULE_ID_PATTERN,
    CLAIM_ID_PATTERN,
    DERIVATIONS,
    DROP_REASONS,
    KINDS,
    LEVEL_RANK,
    LEVELS,
    LINEAGE_SOURCES,
    MIN_PARENT_CLAIMS,
    SUPPORTED_SCHEMA_VERSIONS,
    TERMINAL_STATUSES,
    TTP_PATTERN,
    Capsule,
    parse_claim_ref,
)
from .contracts import ContractRegistry
from .ledger import EvidenceLedger

HARD = {"C1", "C2", "C3"}
SOFT = {"C4", "R1", "R2", "R3", "R4"}


@dataclass
class Violation:
    check: str
    code: str
    detail: str
    claim_index: int | None = None

    def to_dict(self) -> dict:
        return {"check": self.check, "code": self.code, "detail": self.detail, "claim_index": self.claim_index}


@dataclass
class GateResult:
    capsule_id: str
    status: str
    violations: list[Violation] = field(default_factory=list)
    reference_stats: dict = field(default_factory=dict)
    semantic_check: str = "not_performed"

    def to_dict(self) -> dict:
        return {
            "capsule_id": self.capsule_id,
            "status": self.status,
            "violations": [v.to_dict() for v in self.violations],
            "reference_stats": self.reference_stats,
            "semantic_check": self.semantic_check,
        }


class ContractGate:
    ACTOR = "contract_gate"

    def __init__(self, ledger: EvidenceLedger, registry: ContractRegistry, enforce_task_registry: bool = True):
        self.ledger = ledger
        self.registry = registry
        self.enforce_task_registry = enforce_task_registry

    def check(self, capsule: Capsule, record: bool = True) -> GateResult:
        violations: list[Violation] = []
        violations += self._schema(capsule)
        contract = self.registry.handoff(capsule.source, capsule.dest, capsule.kind)
        violations += self._identity(capsule, contract)
        ref_violations, stats = self._references(capsule)
        violations += ref_violations
        violations += self._tools(capsule)
        violations += self._anchoring_and_level(capsule, contract)
        violations += self._observables(capsule)
        violations += self._escalation(capsule)

        checks = {v.check for v in violations}
        if checks & HARD:
            status = "REJECTED"
        elif checks & SOFT:
            status = "RETRY_REQUIRED"
        else:
            status = "ACCEPTED"

        result = GateResult(capsule.capsule_id, status, violations, stats)
        if record:
            self.ledger.add_capsule(capsule)
            self.ledger.record_decision(
                capsule.capsule_id,
                status,
                self.ACTOR,
                [v.to_dict() for v in violations],
                {"reference_stats": stats, "semantic_check": result.semantic_check},
            )
        return result

    # ---------------- helpers ----------------
    def _parent_claim(self, capsule: Capsule, ref: str):
        """Resolve a parent claim ref, only within this capsule's parent capsules."""
        parsed = parse_claim_ref(ref)
        if parsed is None or parsed[0] not in capsule.parent_capsules:
            return None
        parent = self.ledger.capsule(parsed[0])
        return parent.claim(parsed[1]) if parent else None

    # ---------------- C1 ----------------
    def _schema(self, capsule: Capsule) -> list[Violation]:
        out = []
        if capsule.schema_version not in SUPPORTED_SCHEMA_VERSIONS:
            out.append(Violation("C1", "bad_schema_version", f"schema_version={capsule.schema_version!r}"))
        if not CAPSULE_ID_PATTERN.match(capsule.capsule_id or ""):
            out.append(Violation("C1", "bad_capsule_id", f"capsule_id={capsule.capsule_id!r}"))
        if capsule.kind not in KINDS:
            out.append(Violation("C1", "bad_kind", f"kind={capsule.kind!r}"))
        if capsule.status != "PROPOSED":
            out.append(Violation("C1", "self_assigned_status", f"agents may only propose; got {capsule.status!r}"))
        if not isinstance(capsule.attempt, int) or isinstance(capsule.attempt, bool) or capsule.attempt < 1:
            out.append(Violation("C1", "bad_attempt", f"attempt={capsule.attempt!r}"))
        elif (capsule.attempt > 1) != bool(capsule.supersedes):
            out.append(Violation("C1", "bad_retry_fields", "attempt > 1 if and only if supersedes is set"))
        if capsule.supersedes and capsule.supersedes == capsule.capsule_id:
            out.append(Violation("C1", "bad_retry_fields", "a capsule cannot supersede itself"))

        seen_ids = set()
        for index, claim in enumerate(capsule.claims):
            if not CLAIM_ID_PATTERN.match(claim.claim_id or ""):
                out.append(Violation("C1", "bad_claim_id", f"claim_id={claim.claim_id!r}", index))
            elif claim.claim_id in seen_ids:
                out.append(Violation("C1", "duplicate_claim_id", f"claim_id={claim.claim_id!r}", index))
            seen_ids.add(claim.claim_id)
            if not claim.text.strip():
                out.append(Violation("C1", "empty_claim", "claim text is empty", index))
            if claim.level not in LEVELS:
                out.append(Violation("C1", "bad_level", f"level={claim.level!r}", index))
            if claim.lineage not in LINEAGE_SOURCES:
                out.append(Violation("C1", "bad_lineage", f"lineage={claim.lineage!r}", index))
            for ttp in claim.ttp_candidates:
                if not TTP_PATTERN.match(ttp):
                    out.append(Violation("C1", "bad_ttp_id", f"{ttp!r} is not Txxxx[.xxx]", index))
            for ref in claim.parent_claims:
                if parse_claim_ref(ref) is None:
                    out.append(Violation("C1", "bad_claim_ref", f"{ref!r} is not CAP-...#cN", index))
            if any(not str(o).strip() for o in claim.observables):
                out.append(Violation("C1", "empty_observable", "observable is empty", index))
            if claim.derivation not in DERIVATIONS:
                out.append(Violation("C1", "bad_derivation", f"derivation={claim.derivation!r}", index))
            elif claim.derivation == "NEW" and claim.parent_claims:
                out.append(Violation("C1", "derivation_mismatch", "NEW claim lists parent claims", index))
            elif len(set(claim.parent_claims)) < MIN_PARENT_CLAIMS[claim.derivation]:
                out.append(
                    Violation(
                        "C1",
                        "derivation_mismatch",
                        f"{claim.derivation} needs >= {MIN_PARENT_CLAIMS[claim.derivation]} parent claims",
                        index,
                    )
                )

        carried = capsule.all_parent_claims()
        for drop in capsule.dropped_claims:
            if parse_claim_ref(drop.ref) is None:
                out.append(Violation("C1", "bad_claim_ref", f"dropped {drop.ref!r} is not CAP-...#cN"))
            if drop.reason not in DROP_REASONS:
                out.append(Violation("C1", "bad_drop_reason", f"reason={drop.reason!r}"))
            if drop.ref in carried:
                out.append(Violation("C1", "carried_and_dropped", f"{drop.ref} is both used and dropped"))
        return out

    # ---------------- C2 ----------------
    def _identity(self, capsule: Capsule, contract) -> list[Violation]:
        out = []
        if contract is None:
            out.append(
                Violation("C2", "unknown_edge", f"no contract for {capsule.source}->{capsule.dest} ({capsule.kind})")
            )
        elif len(capsule.claims) < contract.min_claims:
            out.append(Violation("C2", "too_few_claims", f"{len(capsule.claims)} < {contract.min_claims}"))
        if self.enforce_task_registry and self.registry.tasks and capsule.task_id not in self.registry.tasks:
            out.append(Violation("C2", "unknown_task", f"task_id={capsule.task_id!r}"))
        return out

    # ---------------- C3 ----------------
    def _references(self, capsule: Capsule):
        out = []
        total = valid = 0
        for index, claim in enumerate(capsule.claims):
            for event_id in claim.event_ids:
                total += 1
                if self.ledger.has_event(event_id):
                    valid += 1
                else:
                    out.append(Violation("C3", "dangling_event", f"{event_id} not in ledger", index))
            for artifact_id in claim.artifact_ids:
                total += 1
                if self.ledger.has_artifact(artifact_id):
                    valid += 1
                else:
                    out.append(Violation("C3", "dangling_artifact", f"{artifact_id} not in ledger", index))
            for ref in claim.parent_claims:
                if parse_claim_ref(ref) is None:
                    continue  # already a C1 violation
                total += 1
                if self._parent_claim(capsule, ref) is not None:
                    valid += 1
                else:
                    out.append(Violation("C3", "unknown_parent_claim", f"{ref} not in a parent capsule", index))
        for drop in capsule.dropped_claims:
            if parse_claim_ref(drop.ref) is not None and self._parent_claim(capsule, drop.ref) is None:
                out.append(Violation("C3", "unknown_parent_claim", f"dropped {drop.ref} not in a parent capsule"))
        for parent in capsule.parent_capsules:
            if not self.ledger.has_capsule(parent):
                out.append(Violation("C3", "unknown_parent", f"parent {parent} not in ledger"))
            elif self.ledger.capsule_status(parent) != "ACCEPTED":
                out.append(
                    Violation("C3", "unaccepted_parent", f"parent {parent} is {self.ledger.capsule_status(parent)}")
                )
        out += self._retry_lineage(capsule)
        stats = {"references": total, "valid": valid, "validity": (valid / total) if total else None}
        return out, stats

    def _retry_lineage(self, capsule: Capsule) -> list[Violation]:
        if not capsule.supersedes:
            return []
        previous = self.ledger.capsule(capsule.supersedes)
        if previous is None:
            return [Violation("C3", "unknown_superseded", f"{capsule.supersedes} not in ledger")]
        out = []
        if (previous.task_id, previous.kind, previous.source) != (capsule.task_id, capsule.kind, capsule.source):
            out.append(Violation("C3", "superseded_mismatch", "a retry must keep task_id, kind and source"))
        if self.ledger.capsule_status(previous.capsule_id) not in TERMINAL_STATUSES:
            out.append(
                Violation(
                    "C3",
                    "superseded_not_retryable",
                    f"{previous.capsule_id} is {self.ledger.capsule_status(previous.capsule_id)}",
                )
            )
        if capsule.attempt != previous.attempt + 1:
            out.append(Violation("C3", "superseded_mismatch", f"attempt {capsule.attempt} != {previous.attempt} + 1"))
        other = self.ledger.superseded_by(previous.capsule_id)
        if other is not None and other != capsule.capsule_id:
            out.append(Violation("C3", "already_superseded", f"{previous.capsule_id} already retried by {other}"))
        return out

    # ---------------- C4 ----------------
    def _tools(self, capsule: Capsule) -> list[Violation]:
        if capsule.kind != "FINDING":
            return []
        task = self.registry.task(capsule.task_id)
        if task is None:
            return []
        executed = {a["tool"] for a in self.ledger.artifacts_for_task(capsule.task_id) if a["status"] == "ok"}
        return [
            Violation("C4", "missing_tool", f"mandatory tool {tool} has no successful artifact")
            for tool in task.required_tools
            if tool not in executed
        ]

    # ---------------- R1 / R2 ----------------
    def _anchoring_and_level(self, capsule: Capsule, contract) -> list[Violation]:
        out = []
        if contract is not None and contract.requires_parents and not capsule.parent_capsules:
            out.append(Violation("R1", "missing_parents", f"{capsule.kind} must build on accepted capsules"))
        for index, claim in enumerate(capsule.claims):
            if claim.level == "OBSERVED" and not claim.event_ids:
                out.append(Violation("R1", "unanchored_observation", "OBSERVED claim cites no event", index))
            if claim.level == "INFERRED" and not claim.event_ids and not claim.parent_claims:
                out.append(
                    Violation("R1", "unanchored_inference", "INFERRED claim has no events and no parent claims", index)
                )
            if contract is not None and claim.level not in contract.allowed_levels:
                out.append(Violation("R2", "level_not_allowed", f"{claim.level} not allowed on this edge", index))
        return out

    # ---------------- R3 ----------------
    def _observables(self, capsule: Capsule) -> list[Violation]:
        """Each observable must occur in a cited event or a parent claim.

        This is lexical anchoring: it shows the value was really seen, not
        that the claim about it is true.
        """
        out = []
        for index, claim in enumerate(capsule.claims):
            if not claim.observables:
                continue
            haystacks = [self.ledger.event_text(e) for e in claim.event_ids if self.ledger.has_event(e)]
            for ref in claim.parent_claims:
                parent = self._parent_claim(capsule, ref)
                if parent is not None:
                    haystacks.append("\n".join((parent.text, *parent.observables)).lower())
            for observable in claim.observables:
                needle = str(observable).strip().lower()
                if needle and not any(needle in h for h in haystacks):
                    out.append(
                        Violation("R3", "observable_not_in_evidence", f"{observable!r} not in cited evidence", index)
                    )
        return out

    # ---------------- R4 ----------------
    def _escalation(self, capsule: Capsule) -> list[Violation]:
        out = []
        for index, claim in enumerate(capsule.claims):
            parents = [self._parent_claim(capsule, ref) for ref in claim.parent_claims]
            parents = [p for p in parents if p is not None and p.level in LEVEL_RANK]
            if not parents or claim.level not in LEVEL_RANK:
                continue
            ceiling = max(LEVEL_RANK[p.level] for p in parents)
            if LEVEL_RANK[claim.level] <= ceiling:
                continue
            if claim.derivation == "CARRIED":
                reason = "a CARRIED claim may not change its level upward"
            elif not claim.event_ids:
                reason = "it cites no events of its own"
            else:
                continue
            out.append(
                Violation("R4", "level_escalation", f"{claim.level} is stronger than its parent claims: {reason}", index)
            )
        return out
