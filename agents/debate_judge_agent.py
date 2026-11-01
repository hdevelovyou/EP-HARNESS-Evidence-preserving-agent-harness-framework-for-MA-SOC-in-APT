import json
import os
import re

from agents.llm_config import create_agent_llm
from prompts import (
    build_debate_feedback_prompt,
    build_debate_judge_prompt,
    build_debate_soft_test_prompt,
)

_FENCED_JSON_PATTERN = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)


class DebateFeedbackAgent:
    """Independent reviewer that builds point-of-concern lists for debate rounds."""

    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "debate_feedback",
            temperature=0,
            timeout=int(os.getenv("DEBATE_MODEL_TIMEOUT_SECONDS", "300")),
        )
        self.model = self.llm_settings.model

    def review(self, stage, reviewer_role, prior_role, prior_output, context="", focus=""):
        messages = build_debate_feedback_prompt(
            stage=stage,
            reviewer_role=reviewer_role,
            prior_role=prior_role,
            prior_output=str(prior_output or ""),
            context=str(context or ""),
            focus=str(focus or ""),
        )
        response = self.llm.invoke(messages)
        text = _content_to_text(response.content)
        return _parse_json_or_text(text, fallback_key="raw_feedback")

    def soft_test(self, test_message, expected_answer):
        messages = build_debate_soft_test_prompt(
            test_message=test_message,
            expected_answer=expected_answer,
        )
        response = self.llm.invoke(messages)
        text = _content_to_text(response.content)
        return _parse_json_or_text(text, fallback_key="raw_feedback")


class DebateJudgeAgent:
    """Third-party judge used when two debate roles do not converge in time."""

    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "debate_judge",
            temperature=0,
            timeout=int(os.getenv("DEBATE_MODEL_TIMEOUT_SECONDS", "300")),
        )
        self.model = self.llm_settings.model

    def resolve(self, stage, first_role, second_role, first_output, second_output, context=""):
        messages = build_debate_judge_prompt(
            stage=stage,
            first_role=first_role,
            second_role=second_role,
            first_output=str(first_output or ""),
            second_output=str(second_output or ""),
            context=str(context or ""),
        )
        response = self.llm.invoke(messages)
        text = _content_to_text(response.content)
        return _parse_json_or_text(text, fallback_key="raw_judgment")


def _content_to_text(content):
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, dict):
                if part.get("type") in {"thinking", "reasoning"}:
                    continue
                if "text" in part:
                    parts.append(str(part["text"]))
                elif "content" in part:
                    parts.append(str(part["content"]))
            else:
                parts.append(str(part))
        return "\n".join(parts).strip()
    return str(content).strip()


def _parse_json_or_text(text, fallback_key):
    candidates = [str(text or "").strip()]
    fenced = _FENCED_JSON_PATTERN.search(candidates[0])
    if fenced:
        candidates.insert(0, fenced.group(1).strip())

    extracted = _extract_json_object(candidates[-1])
    if extracted:
        candidates.insert(0, extracted)

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            continue

    return {
        "consensus": False,
        "requires_judge": True,
        "point_of_concern": [
            {
                "severity": "medium",
                "claim": "Feedback was not valid JSON.",
                "issue": str(text or "")[:1200],
                "required_fix": "Re-run debate feedback or escalate to judge.",
            }
        ],
        fallback_key: str(text or ""),
    }


def _extract_json_object(text):
    start = str(text or "").find("{")
    if start == -1:
        return ""

    depth = 0
    in_string = False
    escaped = False
    source = str(text)
    for index in range(start, len(source)):
        char = source[index]
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                in_string = False
            continue

        if char == '"':
            in_string = True
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return source[start:index + 1]
    return ""
