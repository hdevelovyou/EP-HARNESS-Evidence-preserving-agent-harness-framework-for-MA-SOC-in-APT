import json
import time


class DebateStrategy:
    """Debate-based collaboration strategy for SOC multi-agent workflows.

    The strategy changes only agent communication and acceptance flow. It does
    not alter deterministic orchestration layers such as EvidenceExtractor,
    IOCCurator, TTPRelationsGraph, MitreMapper, or evaluators.
    """

    name = "debate_based"

    def __init__(self, timeout_seconds=300, max_revision_rounds=1):
        self.timeout_seconds = timeout_seconds
        self.max_revision_rounds = max_revision_rounds

    def build_debate_roles(self):
        return {
            "proposer": "Construct the strongest evidence-backed interpretation of the incident.",
            "challenger": "Challenge unsupported claims, missing IOCs, weak MITRE mappings, and task drift.",
            "judge": "Resolve disagreements using only raw artifacts, tool outputs, and verified evidence.",
        }

    def build_round_contract(self):
        return {
            "round_input": [
                "stage",
                "previous_agent_output",
                "context",
                "review_focus",
                "previous_arguments",
            ],
            "round_output": [
                "consensus",
                "requires_judge",
                "point_of_concern",
                "summary",
            ],
        }

    def review_and_resolve(
        self,
        stage,
        prior_role,
        reviewer_role,
        prior_output,
        context,
        focus,
        feedback_agent,
        judge_agent,
        started_at=None,
    ):
        """Run a reviewer pass and invoke Judge when consensus is not reached."""
        started_at = started_at or time.time()
        feedback = feedback_agent.review(
            stage=stage,
            reviewer_role=reviewer_role,
            prior_role=prior_role,
            prior_output=prior_output,
            context=context,
            focus=focus,
        )
        consensus = self.has_consensus(feedback)
        blocking = self.has_blocking_concerns(feedback)
        timed_out = (time.time() - started_at) >= self.timeout_seconds
        requires_judge = bool(feedback.get("requires_judge")) or (blocking and timed_out)

        judge_result = None
        accepted_output = prior_output
        if requires_judge:
            judge_result = judge_agent.resolve(
                stage=stage,
                first_role=prior_role,
                second_role=reviewer_role,
                first_output=prior_output,
                second_output=json.dumps(feedback, ensure_ascii=False, indent=2),
                context=context,
            )
            accepted_output = judge_result.get("accepted_output") or prior_output

        return {
            "stage": stage,
            "prior_role": prior_role,
            "reviewer_role": reviewer_role,
            "consensus": consensus,
            "blocking": blocking,
            "timed_out": timed_out,
            "feedback": feedback,
            "judge_result": judge_result,
            "accepted_output": accepted_output,
        }

    def has_consensus(self, feedback):
        concerns = feedback.get("point_of_concern", [])
        return bool(feedback.get("consensus")) and not concerns

    def has_blocking_concerns(self, feedback):
        concerns = feedback.get("point_of_concern", [])
        if not isinstance(concerns, list):
            return False
        return any(
            str(concern.get("severity", "")).strip().lower() == "high"
            for concern in concerns
            if isinstance(concern, dict)
        )

    def can_revise(self, started_at):
        return (time.time() - started_at) < self.timeout_seconds

    def feedback_as_text(self, debate_record):
        feedback = debate_record.get("feedback", {})
        concerns = feedback.get("point_of_concern", [])
        if not concerns:
            return "No debate concerns."
        lines = ["Debate point-of-concern list:"]
        for index, concern in enumerate(concerns, start=1):
            lines.append(
                "{index}. [{severity}] {claim} | issue={issue} | required_fix={required_fix}".format(
                    index=index,
                    severity=concern.get("severity", "medium"),
                    claim=concern.get("claim", ""),
                    issue=concern.get("issue", ""),
                    required_fix=concern.get("required_fix", ""),
                )
            )
        return "\n".join(lines)

    def describe(self):
        return (
            "Debate-based collaboration lets downstream agents critique upstream outputs via "
            "point-of-concern lists. Only high-severity blocking concerns trigger revision; "
            "medium/low concerns are audited without re-running upstream agents. If a blocking "
            "concern cannot be resolved within the debate timeout, a neutral Judge resolves the "
            "disagreement using only supplied evidence."
        )
