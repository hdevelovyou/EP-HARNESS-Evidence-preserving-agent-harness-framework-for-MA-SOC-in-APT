import json
import re

from agents.llm_config import create_agent_llm
from agents.task_catalog import TASK_BY_ID, TASK_INVENTORY, clone_task
from prompts import build_coordinator_prompt

_FENCED_JSON_PATTERN = re.compile(r"```(?:json)?\s*(.*?)```", re.IGNORECASE | re.DOTALL)
_LEADING_JSON_MARKER_PATTERN = re.compile(r"^\s*`{0,3}\s*json\s*[\r\n]+", re.IGNORECASE)
_TRAILING_FENCE_PATTERN = re.compile(r"\s*`{3}\s*$")
_PLAN_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "selected_tasks": {
            "type": "array",
            "maxItems": 12,
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string"},
                    "reason": {"type": "string"},
                },
                "required": ["id", "reason"],
            },
        },
    },
    "required": ["selected_tasks"],
}
class CoordinatorAgent:
    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "coordinator",
            temperature=0,
            json_mode=True,
            response_schema=_PLAN_RESPONSE_SCHEMA,
        )
        self.model = self.llm_settings.model

        self.task_inventory = [clone_task(task["id"]) for task in TASK_INVENTORY]

    def plan(self, raw_log):
        print(f"[Coordinator] Building an optimized SOC hunting plan with {self.model}...")

        prompt = build_coordinator_prompt()
        chain = prompt | self.llm

        response = chain.invoke({"log": raw_log, "inventory": self.task_inventory})
        result = self._parse_plan_response(response)

        final_plan = []
        seen_task_ids = set()
        for item in result.get("selected_tasks", []):
            task_info = TASK_BY_ID.get(item.get("id"))
            if not task_info or task_info["id"] in seen_task_ids:
                continue

            task_info = clone_task(task_info["id"])
            task_info["coordinator_reason"] = item.get("reason", "")
            final_plan.append(task_info)
            seen_task_ids.add(task_info["id"])

        return final_plan

    def _parse_plan_response(self, response):
        text = self._content_to_text(getattr(response, "content", response)).strip()
        if not text:
            raise ValueError("Coordinator returned an empty response.")

        normalized_text = self._strip_json_markers(text)
        candidates = [normalized_text, text]
        fenced_match = _FENCED_JSON_PATTERN.search(text)
        if fenced_match:
            candidates.insert(0, fenced_match.group(1).strip())

        for source_text in (normalized_text, text):
            object_text = self._extract_json_object(source_text)
            if object_text and object_text not in candidates:
                candidates.append(object_text)

        last_error = None
        for candidate in self._expand_json_candidates(candidates):
            try:
                parsed = json.loads(candidate)
                if isinstance(parsed, dict) and isinstance(parsed.get("selected_tasks"), list):
                    return parsed
            except json.JSONDecodeError as error:
                last_error = error

        raise ValueError(f"Invalid coordinator JSON output: {last_error}; raw={text[:1000]}")

    def _strip_json_markers(self, text):
        clean = text.strip().lstrip("\ufeff")
        if clean.startswith("```"):
            first_newline = clean.find("\n")
            if first_newline != -1:
                clean = clean[first_newline + 1:]
        clean = _LEADING_JSON_MARKER_PATTERN.sub("", clean)
        clean = _TRAILING_FENCE_PATTERN.sub("", clean)
        return clean.strip()

    def _expand_json_candidates(self, candidates):
        expanded = []
        seen = set()
        for candidate in candidates:
            for variant in (candidate, self._repair_common_json_escapes(candidate)):
                if variant and variant not in seen:
                    expanded.append(variant)
                    seen.add(variant)
        return expanded

    def _repair_common_json_escapes(self, text):
        """Repair common LLM JSON slips without changing valid JSON escapes.

        Gemma sometimes returns Windows paths or account names such as
        NT AUTHORITY\\SYSTEM inside JSON strings. Raw backslashes before
        non-JSON escape characters make otherwise valid plans fail parsing.
        """
        return re.sub(r'\\(?!["\\/bfnrtu])', r"\\\\", text)

    def _extract_json_object(self, text):
        start = text.find("{")
        if start == -1:
            return ""

        depth = 0
        in_string = False
        escaped = False
        for index in range(start, len(text)):
            char = text[index]
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
                    return text[start:index + 1]
        return ""

    def _content_to_text(self, content):
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
            return "\n".join(parts)
        return str(content)
