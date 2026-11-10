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
import re
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
from .capsule import Capsule, Claim, ClaimDrop, claim_ref
from .evidence_cards import card, card_line, cards_for_task_view
from .claim_parser import (
    auto_tag_lines,
    FENCE,
    claims_from_records,
    drop_tagged_lines,
    extract_claims_block,
    remove_claims_block,
    strip_claim_tags,
)
from .contracts import TaskContract, default_masoc_registry
from .gate import ContractGate, GateResult
from .metrics import semantic_summary, summarize
from .semantic import SemanticReport, SemanticVerifier, apply_judge, judge_items, parse_judge_verdicts

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
    repairs: list[str] = field(default_factory=list)

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
            "format_repairs": self.repairs,
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
        self.semantic = SemanticVerifier(self.ledger)
        self._semantic_reports: dict[str, SemanticReport] = {}
        self._policy_decisions: dict = {}
        self.review_queue: list[dict] = []
        self.policy = None

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

    def _check(self, capsule: Capsule, edge: str, action_if_blocked: str, notes=(), repairs=()) -> HandoffOutcome:
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
            repairs=list(repairs),
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
        notes, repairs = [], []
        if self.cited:
            parsed = extract_claims_block(body)
            claims = claims_from_records(parsed.records, artifacts_by_tool(audit, artifact_ids))
            notes = [parsed.error] if parsed.error else []
            repairs = parsed.repairs
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
                      "level_source": "agent" if self.cited else "heuristic", "format_repairs": repairs},
        )
        return self._check(capsule, "hunter->verifier", "return_to_hunter", notes, repairs)

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

    def evidence_cards(self, task_view: str) -> str:
        """The ID-first index of a task view's events that the Hunter picks evidence from (cited mode)."""
        return cards_for_task_view(task_view)

    # ---------------------------------------------------------------- semantic evidence verification
    def semantic_review(self, task_id: str) -> SemanticReport:
        """Rule layer on the latest gate-accepted FINDING: one verdict per claim, no LLM call."""
        return self.semantic.check(self._latest[(task_id, "FINDING")])

    def judge_items(self, task_id: str, report: SemanticReport) -> list[dict]:
        """What the Verifier's judge call sees: only the claims the rules found SUPPORTED, with their events."""
        return judge_items(report, self._latest[(task_id, "FINDING")], self.ledger)

    def apply_judge(self, report: SemanticReport, judge_answer: str) -> SemanticReport:
        judgements, error = parse_judge_verdicts(judge_answer)
        return apply_judge(report, judgements, error)

    def finish_semantic_review(self, task_id: str, report: SemanticReport) -> SemanticReport:
        """Record every claim verdict, then the Verifier's decision on the FINDING.

        The FINDING is ACCEPTED when at least one claim is SUPPORTED; the
        VERIFIED capsule then carries only what the verdicts allow
        (verifier_handoff). Otherwise it is REJECTED and the Hunter gets the
        verdicts as feedback.
        """
        finding = self._latest[(task_id, "FINDING")]
        self.record_semantic_verdicts(task_id, report)
        self.ledger.record_decision(
            finding.capsule_id,
            "ACCEPTED" if report.accepted else "REJECTED",
            "verifier",
            detail={"semantic": report.counts()},
        )
        return report

    def record_semantic_verdicts(self, task_id: str, report: SemanticReport) -> None:
        """Append the claim verdicts of the latest FINDING to the ledger (once per FINDING)."""
        finding = self._latest[(task_id, "FINDING")]
        if finding.capsule_id in self._semantic_reports:
            return
        for verdict in report.verdicts:
            self.ledger.record_claim_verdict(verdict.ref, verdict.verdict, "verifier", verdict.to_dict())
        self._semantic_reports[finding.capsule_id] = report
        self.handoffs.append({"edge": "hunter->verifier", "capsule_id": finding.capsule_id,
                              "action": "semantic_review", "counts": report.counts()})

    def _verified_claims(self, finding: Capsule) -> tuple[tuple[Claim, ...], tuple[ClaimDrop, ...]]:
        """Carry SUPPORTED claims, carry INSUFFICIENT ones as HYPOTHESIS, drop UNRELATED and CONTRADICTED.

        A policy decision on the FINDING overrides the default: held and
        review claims travel as HYPOTHESIS, rejected ones are declared drops.
        """
        report = self._semantic_reports.get(finding.capsule_id)
        decision = self._policy_decisions.get(finding.capsule_id)
        claims, drops = [], []
        for c in finding.claims:
            ref = claim_ref(finding.capsule_id, c.claim_id)
            verdict = report.verdict(c.claim_id) if report else None
            carried = replace(c, parent_claims=(ref,), derivation="CARRIED")
            label = verdict.verdict if verdict else None
            if decision is not None:
                if c.claim_id in decision.hold or c.claim_id in decision.review:
                    label = "INSUFFICIENT"
                elif c.claim_id in decision.reject and label in (None, "SUPPORTED", "NOT_APPLICABLE", "INSUFFICIENT"):
                    label = "UNRELATED"
            if label is None or label in ("SUPPORTED", "NOT_APPLICABLE"):
                claims.append(carried)
            elif label == "INSUFFICIENT":
                claims.append(replace(carried, level="HYPOTHESIS"))
            elif label == "UNRELATED":
                drops.append(ClaimDrop(ref, "INSUFFICIENT_EVIDENCE", "cited evidence is unrelated to the claim"
                                       if verdict and verdict.verdict == "UNRELATED" else "removed by the policy"))
            else:
                drops.append(ClaimDrop(ref, "REFUTED", "; ".join(verdict.reasons)[:300] if verdict else "refuted"))
        return tuple(claims), tuple(drops)

    # ---------------------------------------------------------------- adaptive policy support
    def latest_finding(self, task_id: str) -> Capsule | None:
        return self._latest.get((task_id, "FINDING"))

    def task_tool_artifacts(self, task_id: str) -> dict[str, str]:
        """Tool name -> artifact of its latest successful run in this task."""
        return {a["tool"]: a["artifact_id"] for a in self.ledger.artifacts_for_task(task_id) if a["status"] == "ok"}

    def filter_finding(self, task_id: str, drop_ids, reason: str) -> HandoffOutcome:
        """Remove claims with fabricated references by code and gate the rest again (no LLM call).

        The new attempt keeps the Hunter as author: its content is the
        Hunter's, minus the removed claims, as metadata states.
        """
        previous = self._latest[(task_id, "FINDING")]
        capsule_id, attempt, supersedes = self._next_identity(task_id, "FINDING")
        capsule = replace(
            previous, capsule_id=capsule_id, attempt=attempt, supersedes=supersedes, status="PROPOSED",
            claims=tuple(c for c in previous.claims if c.claim_id not in set(drop_ids)),
            metadata=dict(previous.metadata, derived_by="policy_orchestrator", filtered_from=previous.capsule_id,
                          removed_claims=sorted(drop_ids), reason=reason, format_repairs=[]),
        )
        return self._check(capsule, "hunter->verifier", "return_to_hunter")

    def revision_handoff(self, task_id: str, revision_text: str, revise_ids, drop_ids=()) -> HandoffOutcome:
        """Merge a targeted revision into the finding: claims that held are kept, only revise_ids are replaced.

        With no revise_ids the revision replaces every claim (the agent re-emits its claims block).
        """
        previous = self._latest[(task_id, "FINDING")]
        parsed = extract_claims_block(revision_text)
        targets = list(revise_ids)
        records = parsed.records
        if targets:
            chosen = [r for r in records if r.get("id") in targets]
            if not chosen and len(records) == len(targets):
                chosen = [dict(r, id=claim_id) for r, claim_id in zip(records, targets)]
            records = chosen
        kept = [c for c in previous.claims if targets and c.claim_id not in targets and c.claim_id not in drop_ids]
        revised = claims_from_records(records, self.task_tool_artifacts(task_id))
        notes = [parsed.error] if parsed.error else []
        if targets and not revised and not notes:
            notes = [f"the revision contains none of the requested claims {targets}"]
        capsule_id, attempt, supersedes = self._next_identity(task_id, "FINDING")
        capsule = replace(
            previous, capsule_id=capsule_id, attempt=attempt, supersedes=supersedes, status="PROPOSED",
            claims=tuple(kept + revised),
            metadata=dict(previous.metadata, revision_of=previous.capsule_id, kept=[c.claim_id for c in kept],
                          revised=[c.claim_id for c in revised], format_repairs=parsed.repairs),
        )
        return self._check(capsule, "hunter->verifier", "return_to_hunter", notes, parsed.repairs)

    def evidence_hints(self, claim: Claim, missing=(), limit: int = 3) -> list[str]:
        """Card lines of ledger events that mention the claim's entities (or the missing ones first)."""
        wanted = [m for m in missing if m] or sorted(self.semantic.claim_entities(claim), key=len, reverse=True)
        wanted = [w for w in wanted if not self.semantic.is_trivial(w)]
        lines = []
        for event_id in self.ledger.event_ids():
            if any(w in self.ledger.event_text(event_id) for w in wanted):
                lines.append(card_line(card(self.ledger.event(event_id)["payload"])))
            if len(lines) >= limit:
                break
        return lines

    def revision_request(self, task_id: str, decision, report: SemanticReport | None = None,
                         signals=()) -> str:
        """The targeted retry message: per failing claim, its text, what is wrong, and candidate cards."""
        finding = self._latest[(task_id, "FINDING")]
        reasons = {s.claim_id: f"{s.signal}: {s.reason}" for s in signals}
        lines = ["Revise ONLY the claims below; keep their ids. Every other claim is already accepted and kept."]
        for claim_id in decision.revise:
            claim = finding.claim(claim_id)
            if claim is None:
                continue
            verdict = report.verdict(claim_id) if report else None
            problem = reasons.get(claim_id) or (f"{verdict.verdict}: {'; '.join(verdict.reasons)}" if verdict else "")
            lines.append(f"- {claim_id}: \"{claim.text}\" cites {list(claim.event_ids) or 'no event'} -> {problem}")
            hints = self.evidence_hints(claim, verdict.missing if verdict else ())
            lines += [f"    candidate card: {h}" for h in hints] or ["    no card mentions these entities: "
                                                                      "lower the claim to HYPOTHESIS or drop it"]
        if not decision.revise:
            lines = ["Re-emit the claims of your finding as one evidence_claims block, evidence first."]
        return "\n".join(lines)

    def record_policy_outcome(self, task_id: str, decision) -> None:
        """Record the finding-level outcome of a policy decision and queue review claims."""
        finding = self._latest[(task_id, "FINDING")]
        status = self.ledger.capsule_status(finding.capsule_id)
        detail = {"policy": decision.to_dict()}
        target = {"ACCEPT": ("ACCEPTED", "verifier"), "REJECT": ("REJECTED", "verifier"),
                  "TARGETED_REVIEW": ("REVIEW_REQUIRED", "policy_orchestrator"),
                  "UNRESOLVED": ("UNRESOLVED", "policy_orchestrator")}[decision.action]
        if status in ("ACCEPTED", "REVIEW_REQUIRED"):
            self.ledger.record_decision(finding.capsule_id, target[0], target[1], detail=detail)
        self._policy_decisions[finding.capsule_id] = decision
        report = self._semantic_reports.get(finding.capsule_id)
        for claim_id in decision.review:
            verdict = report.verdict(claim_id) if report else None
            self.review_queue.append({
                "ref": claim_ref(finding.capsule_id, claim_id), "task_id": task_id,
                "text": finding.claim(claim_id).text if finding.claim(claim_id) else "",
                "verdict": verdict.verdict if verdict else None,
                "reasons": verdict.reasons if verdict else [], "decided_by": verdict.decided_by if verdict else None,
            })
        self.handoffs.append({"edge": "hunter->verifier", "capsule_id": finding.capsule_id,
                              "action": f"policy:{decision.action}", "policy": decision.to_dict()})

    # ---------------------------------------------------------------- Verifier -> Analyst
    def verifier_handoff(self, task_id: str) -> HandoffOutcome:
        finding = self._latest[(task_id, "FINDING")]
        capsule_id, attempt, supersedes = self._next_identity(task_id, "VERIFIED")
        # Without a semantic review, MA-SOC's Verifier passes the whole finding on unchanged.
        claims, drops = self._verified_claims(finding)
        capsule = Capsule(
            capsule_id=capsule_id,
            kind="VERIFIED",
            task_id=task_id,
            source="verifier",
            dest="analyst",
            claims=claims,
            dropped_claims=drops,
            parent_capsules=(finding.capsule_id,),
            attempt=attempt,
            supersedes=supersedes,
            metadata={"mode": "inline", "claim_source": self.claim_source,
                      "semantic_review": finding.capsule_id in self._semantic_reports},
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
        notes, repairs = [], []
        if self.cited:
            parsed = extract_claims_block(analysis_text)
            claims = claims_from_records(parsed.records)
            notes = [parsed.error] if parsed.error else []
            repairs = parsed.repairs
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
                      "level_source": "agent" if self.cited else "heuristic", "parent_link": parent_link,
                      "format_repairs": repairs},
        )
        return self._check(capsule, "analyst->reporter", "retry_analyst_or_withhold_claims", notes, repairs)

    def analysis_for_reporter(self, analysis_text: str, outcome: HandoffOutcome) -> str:
        """The analysis text the Reporter may see.

        Lines of claims that carry a claim-level violation are dropped (cited:
        the lines tagged with that claim ID; derived: the claim's own line).
        Capsule-level violations (no accepted parents, no readable claims
        block) cannot be fixed by filtering; they stay recorded in the ledger.
        In cited mode the claims block and the [cN] tags are removed; lines the
        Analyst forgot to tag are tagged by the harness first (auto_tag_lines).
        """
        text = str(analysis_text or "")
        if outcome.accepted:
            return strip_claim_tags(remove_claims_block(text)) if self.cited else text
        capsule = self.ledger.capsule(outcome.capsule_id)
        flagged = sorted({v["claim_index"] for v in outcome.violations if v["claim_index"] is not None})
        flagged = [i for i in flagged if i < len(capsule.claims)]
        auto_tagged = 0
        if self.cited:
            narrative, auto_tagged = auto_tag_lines(remove_claims_block(text), capsule.claims)
            text = strip_claim_tags(drop_tagged_lines(narrative, [capsule.claims[i].claim_id for i in flagged]))
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
            "auto_tagged_lines": auto_tagged,
        })
        return text

    # ---------------------------------------------------------------- Analyst edge under the policy
    def latest_analysis(self) -> Capsule | None:
        return self._latest.get((ANALYSIS_TASK, "ANALYSIS"))

    @staticmethod
    def _render_block(records: list[dict]) -> str:
        return f"```{FENCE}\n{json.dumps(records, ensure_ascii=False)}\n```"

    def _tagged_narrative(self, analysis_text: str) -> tuple[list[str], list[dict]]:
        """Narrative lines (untagged ones matched to claims by the harness) and the claim records."""
        parsed = extract_claims_block(analysis_text)
        claims = claims_from_records(parsed.records)
        narrative, _ = auto_tag_lines(remove_claims_block(analysis_text), claims)
        return narrative.splitlines(), parsed.records

    def analysis_without(self, analysis_text: str, drop_ids) -> str:
        """The analysis minus the claims in drop_ids: their tagged lines and their records (no LLM call)."""
        drop = set(drop_ids)
        lines, records = self._tagged_narrative(analysis_text)
        kept_lines = drop_tagged_lines("\n".join(lines), drop)
        kept_records = [r for r in records if str(r.get("id")) not in drop]
        return f"{kept_lines}\n{self._render_block(kept_records)}"

    def analysis_revised(self, analysis_text: str, revision_text: str, revise_ids, drop_ids=()) -> str | None:
        """Merge a targeted Analyst revision: replace only the revised claims, in the block and in the narrative.

        Each revised claim's tagged lines are replaced by its new statement at
        the place of its first line; dropped claims lose their lines; every
        other line and claim stays as the Analyst wrote it. None if the
        revision contains none of the requested claims.
        """
        targets = [str(t) for t in revise_ids]
        parsed = extract_claims_block(revision_text)
        revised = {str(r.get("id")): r for r in parsed.records if str(r.get("id")) in targets}
        if not revised and targets and len(parsed.records) == len(targets):
            revised = {claim_id: dict(r, id=claim_id) for r, claim_id in zip(parsed.records, targets)}
        if not revised and targets:
            return None
        lines, records = self._tagged_narrative(analysis_text)
        drop = set(drop_ids)
        if not targets:  # the Analyst re-emitted its whole claims block
            narrative = drop_tagged_lines("\n".join(lines), drop)
            return f"{narrative}\n{self._render_block([r for r in parsed.records if str(r.get('id')) not in drop])}"
        out, placed = [], set()
        for line in lines:
            tags = set(re.findall(r"\[(c\d+)\]", line))
            if tags & drop:
                continue
            hit = sorted(tags & set(revised))
            if hit:
                claim_id = hit[0]
                if claim_id not in placed:
                    out.append(f"- {revised[claim_id].get('text', '').strip()} [{claim_id}]")
                    placed.add(claim_id)
                continue
            out.append(line)
        out += [f"- {revised[c].get('text', '').strip()} [{c}]" for c in revised if c not in placed]
        merged = [revised.get(str(r.get("id")), r) for r in records if str(r.get("id")) not in drop]
        return "\n".join(out) + "\n" + self._render_block(merged)

    def analysis_revision_request(self, decision, signals) -> str:
        """Targeted retry message for the Analyst: each failing claim, its problem, and parent refs it may cite."""
        capsule = self.latest_analysis()
        reasons = {s.claim_id: f"{s.signal}: {s.reason}" for s in signals}
        refs = [(item["ref"], item["text"]) for claims in self.verified_claims().values() for item in claims]
        lines = ["Revise ONLY the analysis claims below; keep their ids. Every other claim is kept as written."]
        if not decision.revise:
            return "Re-emit the claims of your analysis as one evidence_claims block, parent claims first."
        for claim_id in decision.revise:
            claim = capsule.claim(claim_id) if capsule else None
            if claim is None:
                continue
            lines.append(f"- {claim_id}: \"{claim.text}\" cites parents {list(claim.parent_claims) or 'none'} "
                         f"and events {list(claim.event_ids) or 'none'} -> {reasons.get(claim_id, '')}")
        lines.append("Verified claims you may cite as parent_claims:")
        lines += [f"    {ref}: {text}" for ref, text in refs[:12]] or ["    none: lower the claim to HYPOTHESIS"]
        return "\n".join(lines)

    def analysis_claims_json(self, claim_ids) -> str:
        capsule = self.latest_analysis()
        chosen = [c for c in (capsule.claims if capsule else ()) if not claim_ids or c.claim_id in claim_ids]
        return json.dumps([{"id": c.claim_id, "parent_claims": list(c.parent_claims), "evidence": list(c.event_ids),
                            "observables": list(c.observables), "level": c.level, "text": c.text}
                           for c in chosen], ensure_ascii=False)

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

    def _assist_summary(self) -> dict:
        """What the harness did so the model did not have to: format repairs and lines it tagged itself."""
        repairs: dict[str, int] = {}
        for handoff in self.handoffs:
            for repair in handoff.get("format_repairs", []):
                repairs[repair] = repairs.get(repair, 0) + 1
        return {
            "format_repairs": repairs,
            "handoffs_repaired": sum(1 for h in self.handoffs if h.get("format_repairs")),
            "auto_tagged_lines": sum(h.get("auto_tagged_lines", 0) for h in self.handoffs),
        }

    def summary(self) -> dict:
        return {
            "mode": "inline",
            "claim_source": self.claim_source,
            "summary": summarize(self.capsules, self.results),
            "semantic": semantic_summary(self.ledger),
            "harness_assist": self._assist_summary(),
            "policy": self.policy.summary() if self.policy is not None else None,
            "review_queue": self.review_queue,
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
        paths = {"ledger": str(ledger_path), "audit": str(audit_path)}
        if self.review_queue:
            queue_path = run_dir / "ech_review_queue.json"
            queue_path.write_text(json.dumps(self.review_queue, ensure_ascii=False, indent=2), encoding="utf-8")
            paths["review_queue"] = str(queue_path)
        return paths
