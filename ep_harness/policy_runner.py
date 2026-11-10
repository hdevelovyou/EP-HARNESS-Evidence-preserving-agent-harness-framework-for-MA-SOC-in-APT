"""Run one Hunter task under the Adaptive Evidence-Triggered Policy.

The loop is: produce a FINDING -> Contract Gate -> (semantic review or the
Verifier's OK/FAIL) -> policy decision -> act. Acting is cheap first:

  gate REJECT of some claims   -> remove them by code and gate the rest again
  TARGETED_RETRY revise        -> one Hunter call that rewrites only the
                                  failing claims; the harness keeps the others
  TARGETED_RETRY rerun         -> run the Hunter again with targeted feedback
  ACCEPT / TARGETED_REVIEW     -> VERIFIED capsule; review claims are queued
  REJECT / UNRESOLVED          -> the task stops; nothing is forced

Agents are passed in as callables so the loop runs the same with real agents
(main.py) and with stubs (tests):

  hunter_run(feedback) -> hunter output text (full Hunter run with tools)
  hunter_revise(request, claims_json) -> text with an evidence_claims block
  judge(task_name, items) -> text with a claim_verdicts block   (semantic mode)
  verify(hunter_output) -> "OK ..." or "FAIL: ..."              (otherwise)
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from .policy import AdaptivePolicy

STATUS_BY_ACTION = {"TARGETED_REVIEW": "Review_Required", "REJECT": "Rejected", "UNRESOLVED": "Unresolved"}


@dataclass
class TaskResult:
    status: str              # Verified | Gate_Blocked | Review_Required | Rejected | Unresolved
    hunter_output: str
    reason: str
    decisions: list = field(default_factory=list)


def _is_ok(text: str) -> bool:
    return bool(re.match(r"^OK(?:\b|[\s:.\-–—])", str(text or "").strip(), flags=re.IGNORECASE))


def _claims_json(finding, claim_ids) -> str:
    chosen = [c for c in finding.claims if not claim_ids or c.claim_id in claim_ids]
    return json.dumps([{"id": c.claim_id, "level": c.level, "evidence": list(c.event_ids),
                        "observables": list(c.observables), "text": c.text} for c in chosen], ensure_ascii=False)


def run_task(task: dict, ech, policy: AdaptivePolicy, *, hunter_run, hunter_revise, judge=None, verify=None,
             semantic: bool = True, max_steps: int = 8) -> TaskResult:
    task_id = task["id"]
    budget = policy.budget
    budget.spend_call("hunter")
    output = hunter_run(None)
    outcome = ech.hunter_handoff(task_id, output)

    for _ in range(max_steps):
        finding = ech.latest_finding(task_id)

        # ---------------- the gate blocked the finding
        if not outcome.accepted:
            signals, codes, notes = policy.gate_signals(outcome, finding)
            decision = policy.decide_gate(task_id, signals, codes, notes)
            if decision.action == "TARGETED_RETRY":
                budget.spend_retry(task_id)
                if decision.mode == "rerun":
                    budget.spend_call("hunter")
                    output = hunter_run(outcome.feedback)
                    outcome = ech.hunter_handoff(task_id, output)
                else:
                    budget.spend_call("revise")
                    request = ech.revision_request(task_id, decision, signals=signals)
                    revision = hunter_revise(request, _claims_json(finding, decision.revise))
                    outcome = ech.revision_handoff(task_id, revision, decision.revise, decision.reject)
                continue
            if decision.action == "REJECT" and len(decision.reject) < len(finding.claims):
                outcome = ech.filter_finding(task_id, decision.reject, decision.reason)
                continue
            ech.record_policy_outcome(task_id, decision)
            return TaskResult(STATUS_BY_ACTION[decision.action], output, decision.reason,
                              policy.state(task_id).decisions)

        # ---------------- the gate accepted: semantic review, or the Verifier's verdict
        if semantic:
            report = ech.semantic_review(task_id)
            if report.pending_judge and budget.can_call():
                budget.spend_call("judge")
                report = ech.apply_judge(report, judge(task["name"], ech.judge_items(task_id, report)))
            ech.record_semantic_verdicts(task_id, report)
            signals = policy.semantic_signals(report)
            decision = policy.decide_semantic(task_id, signals)
            if decision.action == "TARGETED_RETRY":
                budget.spend_retry(task_id)
                budget.spend_call("revise")
                request = ech.revision_request(task_id, decision, report, signals)
                revision = hunter_revise(request, _claims_json(finding, decision.revise))
                outcome = ech.revision_handoff(task_id, revision, decision.revise, decision.reject)
                continue
        else:
            budget.spend_call("verify")
            verdict = verify(output)
            decision = policy.decide_verdict(task_id, _is_ok(verdict), verdict)
            if decision.action == "TARGETED_RETRY":
                ech.record_verifier(task_id, False, verdict)
                budget.spend_retry(task_id)
                budget.spend_call("hunter")
                output = hunter_run(verdict)
                outcome = ech.hunter_handoff(task_id, output)
                continue

        ech.record_policy_outcome(task_id, decision)
        if decision.action == "ACCEPT":
            verified = ech.verifier_handoff(task_id)
            status = "Verified" if verified.accepted else "Gate_Blocked"
            return TaskResult(status, output, decision.reason, policy.state(task_id).decisions)
        return TaskResult(STATUS_BY_ACTION[decision.action], output, decision.reason,
                          policy.state(task_id).decisions)

    return TaskResult("Unresolved", output, "step limit reached", policy.state(task_id).decisions)
