"""Adaptive Evidence-Triggered Policy: what to do next with a finding, decided from evidence signals and budget.

After each attempt of a task, the policy reads the signals the harness already
produced (Contract Gate violation codes, semantic verdicts per claim, which
layer decided them, whether the last retry made progress) and the budget left,
and picks one finding-level action:

  ACCEPT           forward the claims that hold; drop, lower or queue the rest
  TARGETED_RETRY   ask for a fix of exactly the failing part:
                     revise - one small LLM call that rewrites only the failing
                              claims, with evidence cards as hints; the claims
                              that already hold are kept by the harness
                     rerun  - run the Hunter again (only when something must be
                              re-executed, e.g. a mandatory tool)
  TARGETED_REVIEW  hold only the disputed claims for a human analyst
                   (layers disagree, or a causal claim lacks a recorded link)
  REJECT           every claim is fabricated, contradicted or unrelated
  UNRESOLVED       budget spent, no progress, or a fault the agent cannot fix

The policy is deterministic, versioned data (SIGNAL_TABLE) plus a budget; it
never calls a model and never accepts on its own: ACCEPT means "forward what
the gate and the Verifier accepted". Claims with fabricated references are
removed by code before any retry (free). Order of preference is cheapest
first: deterministic filter, revise, rerun, review, unresolved.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

POLICY_VERSION = "adaptive-1"
ACTIONS = ("ACCEPT", "TARGETED_RETRY", "TARGETED_REVIEW", "REJECT", "UNRESOLVED")
MODES = ("adaptive", "always_review")

# Claim-level reaction per signal. Versioned with POLICY_VERSION; never changed at runtime.
SIGNAL_TABLE = {
    # Contract Gate: references that do not exist cannot be fixed by asking again -> remove the claim.
    "dangling_event": "reject", "dangling_artifact": "reject", "unknown_parent_claim": "reject",
    "bad_claim_ref": "reject", "empty_claim": "reject",
    # Contract Gate: form problems the agent can fix in the claim itself.
    "unanchored_observation": "revise", "unanchored_inference": "revise", "observable_not_in_evidence": "revise",
    "level_escalation": "revise", "level_not_allowed": "revise", "bad_level": "revise", "bad_claim_id": "revise",
    "duplicate_claim_id": "revise", "bad_ttp_id": "revise", "derivation_mismatch": "revise",
    "empty_observable": "revise", "bad_lineage": "revise",
    # Semantic verdicts.
    "SUPPORTED": "accept", "NOT_APPLICABLE": "accept", "CONTRADICTED": "reject",
    "UNRELATED": "revise", "INSUFFICIENT": "revise",
}
# Capsule-level gate codes (no claim index).
CAPSULE_SIGNALS = {"missing_tool": "rerun", "too_few_claims": "rerun"}
# When a "revise" claim is out of retries: what happens to it instead.
FALLBACK = {"UNRELATED": "reject", "INSUFFICIENT": "hold"}


def _env_int(name: str, default: int) -> int:
    raw = os.getenv(name, "").strip()
    return int(raw) if raw else default


@dataclass
class Budget:
    """Execution budget. llm_calls = 0 means no run-level cap."""

    task_retries: int = 1          # retries per task (revise or rerun); MA-SOC's paper allows one re-call
    reviews: int = 5               # claims a human may be asked to review per run
    llm_calls: int = 0             # LLM calls the policy may spend per run (hunter, revise, judge, verify)
    used_calls: dict = field(default_factory=dict)
    used_reviews: int = 0
    used_retries: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "Budget":
        return cls(task_retries=_env_int("POLICY_TASK_RETRIES", 1), reviews=_env_int("POLICY_REVIEW_BUDGET", 5),
                   llm_calls=_env_int("POLICY_LLM_CALL_BUDGET", 0))

    def calls(self) -> int:
        return sum(self.used_calls.values())

    def can_call(self, n: int = 1) -> bool:
        return self.llm_calls <= 0 or self.calls() + n <= self.llm_calls

    def spend_call(self, kind: str) -> None:
        self.used_calls[kind] = self.used_calls.get(kind, 0) + 1

    def can_retry(self, task_id: str) -> bool:
        return self.used_retries.get(task_id, 0) < self.task_retries and self.can_call()

    def spend_retry(self, task_id: str) -> None:
        self.used_retries[task_id] = self.used_retries.get(task_id, 0) + 1

    def can_review(self, n: int = 1) -> bool:
        return self.used_reviews + n <= self.reviews

    def to_dict(self) -> dict:
        return {"limits": {"task_retries": self.task_retries, "reviews": self.reviews, "llm_calls": self.llm_calls},
                "used": {"llm_calls": dict(self.used_calls), "reviews": self.used_reviews,
                         "retries": dict(self.used_retries)}}


@dataclass
class ClaimSignal:
    claim_id: str
    signal: str                 # a gate code or a semantic verdict
    reason: str = ""
    relation: str = ""
    layer_conflict: bool = False   # rules said SUPPORTED, the judge said otherwise


@dataclass
class Decision:
    action: str
    mode: str = ""                                   # revise | rerun for TARGETED_RETRY
    accept: list[str] = field(default_factory=list)
    reject: list[str] = field(default_factory=list)
    revise: list[str] = field(default_factory=list)
    hold: list[str] = field(default_factory=list)    # kept as HYPOTHESIS
    review: list[str] = field(default_factory=list)  # kept as HYPOTHESIS and queued for a human
    reason: str = ""
    stage: str = ""

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ("", [], None)}


@dataclass
class TaskState:
    """InvestigationState for one task: attempts and the problems each one left."""

    attempts: int = 0
    signatures: list[frozenset] = field(default_factory=list)
    decisions: list[dict] = field(default_factory=list)

    def progressed(self, signature: frozenset) -> bool:
        """False when the last attempt left exactly the same problems as the one before."""
        return not self.signatures or signature != self.signatures[-1]


class AdaptivePolicy:
    def __init__(self, budget: Budget | None = None, mode: str = "adaptive"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}; got {mode!r}")
        self.mode = mode
        self.budget = budget or Budget.from_env()
        self.tasks: dict[str, TaskState] = {}

    def state(self, task_id: str) -> TaskState:
        return self.tasks.setdefault(task_id, TaskState())

    # ------------------------------------------------------------------ signals
    @staticmethod
    def gate_signals(outcome, capsule) -> tuple[list[ClaimSignal], list[str], list[str]]:
        """(claim signals, capsule-level codes, format notes) from a blocked HandoffOutcome and its capsule."""
        claims, capsule_codes = [], []
        for v in outcome.violations:
            index = v["claim_index"]
            if index is None or index >= len(capsule.claims):
                capsule_codes.append(v["code"])
            else:
                claims.append(ClaimSignal(capsule.claims[index].claim_id, v["code"], v["detail"]))
        return claims, capsule_codes, list(outcome.notes)

    @staticmethod
    def semantic_signals(report) -> list[ClaimSignal]:
        out = []
        for v in report.verdicts:
            conflict = v.decided_by == "judge" and v.verdict not in ("SUPPORTED", "NOT_APPLICABLE")
            out.append(ClaimSignal(v.claim_id, v.verdict, "; ".join(v.reasons)[:300], v.relation, conflict))
        return out

    # ------------------------------------------------------------------ decisions
    def decide_gate(self, task_id: str, claim_signals: list[ClaimSignal], capsule_codes: list[str],
                    notes: list[str]) -> Decision:
        """A finding the gate blocked. Claim IDs in claim_signals are resolved by the caller."""
        state = self.state(task_id)
        problems = {(s.claim_id, s.signal) for s in claim_signals} | {("*", c) for c in capsule_codes}
        signature = frozenset(problems | ({("*", "format")} if notes else set()))
        progressed = state.progressed(signature)
        state.signatures.append(signature)
        reject = sorted({s.claim_id for s in claim_signals if SIGNAL_TABLE.get(s.signal) == "reject"})
        revise = sorted({s.claim_id for s in claim_signals if SIGNAL_TABLE.get(s.signal, "revise") == "revise"}
                        - set(reject))
        unknown = [c for c in capsule_codes if c not in CAPSULE_SIGNALS]
        if unknown:
            return self._log(task_id, Decision("UNRESOLVED", reason=f"fault the agent cannot fix: {unknown}",
                                               stage="gate"))
        if notes or "too_few_claims" in capsule_codes:
            mode = "revise" if notes else "rerun"
            return self._retry_or_stop(task_id, Decision("TARGETED_RETRY", mode=mode, reject=reject,
                                                         reason="; ".join(notes) or "no claims"), progressed, "gate")
        if capsule_codes:
            return self._retry_or_stop(task_id, Decision("TARGETED_RETRY", mode="rerun", reject=reject,
                                                         reason=f"capsule-level: {capsule_codes}"), progressed, "gate")
        if revise:
            return self._retry_or_stop(task_id, Decision("TARGETED_RETRY", mode="revise", reject=reject,
                                                         revise=revise, reason="claims need fixing"),
                                       progressed, "gate", fallback_reject=True)
        # Only fabricated references: remove them by code, no retry needed.
        return self._log(task_id, Decision("REJECT" if reject else "UNRESOLVED", reject=reject,
                                           reason="removed claims with references that do not exist",
                                           stage="gate-filter"))

    def decide_semantic(self, task_id: str, signals: list[ClaimSignal]) -> Decision:
        state = self.state(task_id)
        problems = [s for s in signals if SIGNAL_TABLE.get(s.signal) != "accept"]
        signature = frozenset((s.claim_id, s.signal) for s in problems)
        progressed = state.progressed(signature)
        state.signatures.append(signature)
        d = Decision("ACCEPT", stage="semantic")
        for s in signals:
            reaction = SIGNAL_TABLE.get(s.signal, "revise")
            if reaction == "accept":
                d.accept.append(s.claim_id)
            elif s.layer_conflict or (self.mode == "always_review"):
                d.review.append(s.claim_id)
            elif reaction == "reject":
                d.reject.append(s.claim_id)
            else:
                d.revise.append(s.claim_id)
        if d.revise and self.mode == "adaptive" and progressed and self.budget.can_retry(task_id):
            d.action, d.mode, d.reason = "TARGETED_RETRY", "revise", "claims need better evidence"
            return self._log(task_id, d)
        # Out of retries (or no progress): fall back per verdict.
        by_id = {s.claim_id: s for s in signals}
        for claim_id in list(d.revise):
            s = by_id[claim_id]
            fallback = FALLBACK.get(s.signal, "reject")
            if s.signal == "INSUFFICIENT" and s.relation == "CAUSAL":
                fallback = "review"
            d.revise.remove(claim_id)
            getattr(d, fallback).append(claim_id)
        # Reviews beyond the budget become holds (INSUFFICIENT) or rejects.
        while d.review and not self.budget.can_review(len(d.review)):
            claim_id = d.review.pop()
            (d.hold if by_id[claim_id].signal == "INSUFFICIENT" else d.reject).append(claim_id)
        self.budget.used_reviews += len(d.review)
        if d.accept:
            d.action, d.reason = "ACCEPT", "forward the supported claims"
        elif d.review:
            d.action, d.reason = "TARGETED_REVIEW", "only disputed claims remain; held for an analyst"
        elif d.reject and not d.hold:
            d.action, d.reason = "REJECT", "every claim is contradicted, unrelated or fabricated"
        else:
            d.action = "UNRESOLVED"
            d.reason = "no claim is supported" + ("" if progressed else "; the retry made no progress")
        return self._log(task_id, d)

    def decide_verdict(self, task_id: str, passed: bool, feedback: str) -> Decision:
        """Without semantic review: the Verifier's OK/FAIL is the only signal."""
        if passed:
            return self._log(task_id, Decision("ACCEPT", reason="Verifier OK", stage="verifier"))
        state = self.state(task_id)
        signature = frozenset({("*", feedback.strip()[:200])})
        progressed = state.progressed(signature)
        state.signatures.append(signature)
        return self._retry_or_stop(task_id, Decision("TARGETED_RETRY", mode="rerun", reason=feedback[:300]),
                                   progressed, "verifier")

    # ------------------------------------------------------------------ helpers
    def _retry_or_stop(self, task_id, decision: Decision, progressed: bool, stage: str,
                       fallback_reject: bool = False) -> Decision:
        decision.stage = stage
        if self.mode == "adaptive" and progressed and self.budget.can_retry(task_id):
            return self._log(task_id, decision)
        if fallback_reject and decision.revise:
            # Out of retries: claims that still fail the gate are removed; the rest go on.
            decision.reject = sorted(set(decision.reject) | set(decision.revise))
            decision.revise, decision.mode = [], ""
            decision.action = "REJECT"
            decision.reason = "out of retries: failing claims removed" + ("" if progressed else " (no progress)")
            return self._log(task_id, decision)
        decision.action, decision.mode = "UNRESOLVED", ""
        decision.reason = ("no progress since the last attempt; " if not progressed else "out of retries; ") \
            + decision.reason
        return self._log(task_id, decision)

    def _log(self, task_id: str, decision: Decision) -> Decision:
        self.state(task_id).decisions.append(decision.to_dict())
        return decision

    def summary(self) -> dict:
        actions: dict[str, int] = {}
        for state in self.tasks.values():
            for d in state.decisions:
                key = d["action"] + (f":{d['mode']}" if d.get("mode") else "")
                actions[key] = actions.get(key, 0) + 1
        return {"version": POLICY_VERSION, "mode": self.mode, "budget": self.budget.to_dict(), "actions": actions,
                "tasks": {task_id: state.decisions for task_id, state in self.tasks.items()}}
