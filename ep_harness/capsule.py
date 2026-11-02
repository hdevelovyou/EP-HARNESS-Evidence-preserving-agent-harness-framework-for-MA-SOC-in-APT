"""Evidence Capsule: the only object allowed to cross an agent boundary.

One schema for every handoff; ``kind`` selects the role-specific contract.
Agents *propose* capsules (status PROPOSED). Only the Contract Gate, the
Verifier, the Output Evidence Guardrail, the Policy Orchestrator or a human
analyst may record a different status, and they do so in the Evidence Ledger,
never by mutating the capsule (see STATUS_TRANSITIONS).

Schema v0.2 adds what is needed to follow a single claim across handoffs:
  - claim_id + claim references "CAP-...#c1" (parent_claims)
  - derivation: how a claim relates to its parent claims
  - observables: literal values the claim rests on (lexical anchors)
  - dropped_claims: parent claims deliberately not carried, with a reason
  - attempt / supersedes: retry lineage (a retry is a new capsule)
The machine-readable form is schemas/evidence_capsule.v0.2.json.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field

SCHEMA_VERSION = "0.2"
SUPPORTED_SCHEMA_VERSIONS = ("0.2",)

KINDS = ("TASK", "FINDING", "VERIFIED", "ANALYSIS", "REPORT")

AGENTS = ("coordinator", "hunter", "verifier", "analyst", "reporter")

# Epistemic level of a single claim.
#   OBSERVED   - directly visible in the cited telemetry events
#   INFERRED   - follows from cited events and/or accepted parent claims,
#                but is not itself visible in any single event
#   HYPOTHESIS - plausible but not yet supported; may travel only as a hypothesis
LEVELS = ("OBSERVED", "INFERRED", "HYPOTHESIS")
LEVEL_RANK = {"HYPOTHESIS": 0, "INFERRED": 1, "OBSERVED": 2}

# How a claim relates to the claims of its parent capsules.
#   NEW        - no parent claim; the claim starts here
#   CARRIED    - the same assertion forwarded unchanged (>=1 parent claim)
#   REFINED    - a narrower or corrected version of one parent claim (>=1)
#   AGGREGATED - a new assertion that combines several parent claims (>=2)
DERIVATIONS = ("NEW", "CARRIED", "REFINED", "AGGREGATED")
MIN_PARENT_CLAIMS = {"NEW": 0, "CARRIED": 1, "REFINED": 1, "AGGREGATED": 2}

# Why a downstream capsule did not carry a parent claim. Declared drops are
# filtering; undeclared drops are evidence loss (metrics.claim_flow).
DROP_REASONS = ("REFUTED", "INSUFFICIENT_EVIDENCE", "DUPLICATE", "OUT_OF_SCOPE")

STATUSES = (
    "PROPOSED",
    "ACCEPTED",
    "RETRY_REQUIRED",
    "REVIEW_REQUIRED",
    "REJECTED",
    "UNRESOLVED",
)

# Who may move a capsule from one status to another (ledger enforces this).
#   PROPOSED -> form decision by the Contract Gate
#   ACCEPTED / REVIEW_REQUIRED -> semantic decision
# RETRY_REQUIRED, REJECTED and UNRESOLVED are terminal: a retry is a new
# capsule with ``supersedes`` pointing at the old one. The Policy Orchestrator
# may stop or escalate a capsule but never accept one.
FORM_ACTORS = ("contract_gate",)
SEMANTIC_ACTORS = ("verifier", "output_guardrail", "policy_orchestrator", "human_analyst")
_SEMANTIC = {
    "ACCEPTED": ("verifier", "output_guardrail", "human_analyst"),
    "REVIEW_REQUIRED": SEMANTIC_ACTORS,
    "REJECTED": SEMANTIC_ACTORS,
    "UNRESOLVED": SEMANTIC_ACTORS,
}
STATUS_TRANSITIONS: dict[str, dict[str, tuple[str, ...]]] = {
    "PROPOSED": {"ACCEPTED": FORM_ACTORS, "RETRY_REQUIRED": FORM_ACTORS, "REJECTED": FORM_ACTORS},
    "ACCEPTED": _SEMANTIC,
    "REVIEW_REQUIRED": _SEMANTIC,
    "RETRY_REQUIRED": {},
    "REJECTED": {},
    "UNRESOLVED": {},
}
TERMINAL_STATUSES = tuple(s for s, nxt in STATUS_TRANSITIONS.items() if not nxt)

# How the event references were obtained.
#   cited   - the agent named the event IDs itself
#   derived - the harness recovered them by matching observables to the ledger
LINEAGE_SOURCES = ("cited", "derived")

TTP_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")
CAPSULE_ID_PATTERN = re.compile(r"^CAP-[A-Za-z0-9_.:-]+$")
CLAIM_ID_PATTERN = re.compile(r"^c\d+$")
CLAIM_REF_PATTERN = re.compile(r"^(CAP-[A-Za-z0-9_.:-]+)#(c\d+)$")


def claim_ref(capsule_id: str, claim_id: str) -> str:
    return f"{capsule_id}#{claim_id}"


def parse_claim_ref(ref: str) -> tuple[str, str] | None:
    match = CLAIM_REF_PATTERN.match(ref)
    return (match.group(1), match.group(2)) if match else None


@dataclass(frozen=True)
class ClaimDrop:
    ref: str
    reason: str
    note: str = ""

    @classmethod
    def from_dict(cls, data: dict) -> "ClaimDrop":
        return cls(ref=str(data.get("ref", "")), reason=str(data.get("reason", "")), note=str(data.get("note", "")))


@dataclass(frozen=True)
class Claim:
    text: str
    level: str = "OBSERVED"
    event_ids: tuple[str, ...] = ()
    artifact_ids: tuple[str, ...] = ()
    ttp_candidates: tuple[str, ...] = ()
    lineage: str = "cited"
    claim_id: str = ""
    parent_claims: tuple[str, ...] = ()
    derivation: str = "NEW"
    observables: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, data: dict, default_id: str = "") -> "Claim":
        return cls(
            text=str(data.get("text", "")),
            level=str(data.get("level", "OBSERVED")),
            event_ids=tuple(data.get("event_ids", ()) or ()),
            artifact_ids=tuple(data.get("artifact_ids", ()) or ()),
            ttp_candidates=tuple(data.get("ttp_candidates", ()) or ()),
            lineage=str(data.get("lineage", "cited")),
            claim_id=str(data.get("claim_id") or default_id),
            parent_claims=tuple(data.get("parent_claims", ()) or ()),
            derivation=str(data.get("derivation", "NEW")),
            observables=tuple(data.get("observables", ()) or ()),
        )


@dataclass(frozen=True)
class Capsule:
    capsule_id: str
    kind: str
    task_id: str
    source: str
    dest: str
    claims: tuple[Claim, ...]
    parent_capsules: tuple[str, ...] = ()
    tools_used: tuple[str, ...] = ()
    status: str = "PROPOSED"
    metadata: dict = field(default_factory=dict)
    schema_version: str = SCHEMA_VERSION
    attempt: int = 1
    supersedes: str | None = None
    dropped_claims: tuple[ClaimDrop, ...] = ()

    def to_dict(self) -> dict:
        data = asdict(self)
        data["claims"] = [asdict(claim) for claim in self.claims]
        data["dropped_claims"] = [asdict(drop) for drop in self.dropped_claims]
        return json.loads(json.dumps(data, default=list))

    @classmethod
    def from_dict(cls, data: dict) -> "Capsule":
        """Parse a capsule. Missing claim IDs are numbered c1..cn by position."""
        return cls(
            capsule_id=str(data["capsule_id"]),
            kind=str(data.get("kind", "")),
            task_id=str(data.get("task_id", "")),
            source=str(data.get("source", "")),
            dest=str(data.get("dest", "")),
            claims=tuple(
                Claim.from_dict(c, default_id=f"c{i}") for i, c in enumerate(data.get("claims", ()) or (), 1)
            ),
            parent_capsules=tuple(data.get("parent_capsules", ()) or ()),
            tools_used=tuple(data.get("tools_used", ()) or ()),
            status=str(data.get("status", "PROPOSED")),
            metadata=dict(data.get("metadata", {}) or {}),
            schema_version=str(data.get("schema_version", SCHEMA_VERSION)),
            attempt=data.get("attempt", 1),
            supersedes=data.get("supersedes") or None,
            dropped_claims=tuple(ClaimDrop.from_dict(d) for d in data.get("dropped_claims", ()) or ()),
        )

    def content_hash(self) -> str:
        """Hash of the claim content, excluding status (status lives in the ledger)."""
        payload = self.to_dict()
        payload.pop("status", None)
        encoded = json.dumps(payload, sort_keys=True, ensure_ascii=False).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def claim(self, claim_id: str) -> Claim | None:
        return next((c for c in self.claims if c.claim_id == claim_id), None)

    def claim_refs(self) -> list[str]:
        return [claim_ref(self.capsule_id, c.claim_id) for c in self.claims]

    def all_event_ids(self) -> set[str]:
        return {eid for claim in self.claims for eid in claim.event_ids}

    def all_artifact_ids(self) -> set[str]:
        return {aid for claim in self.claims for aid in claim.artifact_ids}

    def all_parent_claims(self) -> set[str]:
        return {ref for claim in self.claims for ref in claim.parent_claims}
