import json
import hashlib
import re

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from agents.llm_config import create_agent_llm
from prompts import (
    build_hunter_final_instruction,
    build_hunter_initial_messages,
    build_hunter_retry_instruction,
    build_hunter_tool_instruction,
)
from agents.task_catalog import TASK_INVENTORY, clone_task
from tools.tools import (
    ner_tool,
    rag_tool,
    sum_tool,
    rex_tool,
    sim_tool,
    map_tool,
    spa_tool,
    cls_tool,
    math_tool,
)

class HunterAgent:
    def __init__(self):
        self.tools = [
            ner_tool,
            rag_tool,
            sum_tool,
            rex_tool,
            sim_tool,
            map_tool,
            spa_tool,
            cls_tool,
            math_tool,
        ]

        self.base_llm, self.llm_settings = create_agent_llm(
            "hunter",
            temperature=0,
        )
        self.model = self.llm_settings.model

        self.task_inventory = [clone_task(task["id"]) for task in TASK_INVENTORY]

        self.history = []
        self.tool_inventory = {
            "ner_tool": ner_tool,
            "rex_tool": rex_tool,
            "rag_tool": rag_tool,
            "sum_tool": sum_tool,
            "sim_tool": sim_tool,
            "map_tool": map_tool,
            "spa_tool": spa_tool,
            "cls_tool": cls_tool,
            "math_tool": math_tool,
        }
        self.tool_cache = {}

    def run(
        self,
        raw_log,
        assigned_tasks,
        upstream_context=None,
        verifier_feedback=None,
        previous_hunter_output=None,
        max_tool_retries=2,
    ):
        print(f"--- START HUNTER WORKFLOW: {len(assigned_tasks)} task(s) ---")
        run_history = []

        for task in assigned_tasks:
            task_desc = f"{task['id']}: {task['name']} (Target: {task['target']})"
            print(f"\n[+] Processing: {task_desc}")

            configured_tool_names = task.get("tools") or []
            allowed_tool_names = []
            for name in configured_tool_names:
                if name in self.tool_inventory and name not in allowed_tool_names:
                    allowed_tool_names.append(name)

            if not allowed_tool_names:
                allowed_tool_names = ["ner_tool"]

            reason = task.get("coordinator_reason", "No coordinator reason provided.")
            task_messages = build_hunter_initial_messages(
                task_desc=task_desc,
                reason=reason,
                allowed_tool_names=allowed_tool_names,
                raw_log=raw_log,
                upstream_context=upstream_context,
                verifier_feedback=verifier_feedback,
                previous_hunter_output=previous_hunter_output,
            )

            tool_results = []
            for tool_name in allowed_tool_names:
                selected_tool = self.tool_inventory[tool_name]
                tool_llm = self.base_llm.bind_tools([selected_tool], tool_choice=tool_name)
                executed = False

                for attempt in range(max_tool_retries + 1):
                    task_messages.append(HumanMessage(content=build_hunter_tool_instruction(tool_name)))
                    ai_msg = tool_llm.invoke(task_messages)

                    # LangChain may preserve malformed provider tool calls in
                    # additional_kwargs/invalid_tool_calls while omitting them from
                    # ai_msg.tool_calls. Do not add such an assistant message to the
                    # conversation: OpenAI would require a ToolMessage for every raw
                    # tool_call_id and reject the next retry with HTTP 400.
                    if self._has_unresolved_tool_calls(ai_msg):
                        task_messages.append(HumanMessage(content=build_hunter_retry_instruction(
                            tool_name,
                            attempt + 1,
                        )))
                        continue

                    task_messages.append(ai_msg)

                    for tool_call in ai_msg.tool_calls or []:
                        called_tool_name = tool_call["name"]
                        if called_tool_name != tool_name:
                            task_messages.append(ToolMessage(
                                content=(
                                    f"Error: expected mandatory tool '{tool_name}', "
                                    f"but model called '{called_tool_name}'."
                                ),
                                tool_call_id=tool_call["id"],
                            ))
                            continue

                        if executed:
                            task_messages.append(ToolMessage(
                                content=(
                                    f"Error: mandatory tool '{tool_name}' was already executed "
                                    "for this task attempt; duplicate tool call ignored."
                                ),
                                tool_call_id=tool_call["id"],
                            ))
                            continue

                        effective_args = self._build_effective_tool_args(
                            tool_name,
                            tool_call.get("args", {}),
                            raw_log,
                        )
                        cache_key = self._tool_cache_key(tool_name, effective_args)
                        cached_output = self.tool_cache.get(cache_key)

                        try:
                            if cached_output is None:
                                print(f"    [!] Running tool: {tool_name}")
                                tool_output = selected_tool.invoke(effective_args)
                                cache_status = "miss"
                                self.tool_cache[cache_key] = tool_output
                            else:
                                print(f"    [=] Using cached tool result: {tool_name}")
                                tool_output = cached_output
                                cache_status = "hit"

                            output_payload = self._build_tool_output_payload(
                                tool_name,
                                tool_output,
                                raw_log,
                            )
                            output_text = json.dumps(output_payload, indent=2, ensure_ascii=False)
                            tool_results.append({
                                "tool": tool_name,
                                "status": "ok",
                                "cache_status": cache_status,
                                "cache_key": cache_key,
                                "output": output_text,
                            })
                            task_messages.append(ToolMessage(
                                content=output_text,
                                tool_call_id=tool_call["id"],
                            ))
                        except Exception as e:
                            output_text = f"Error: {str(e)}"
                            tool_results.append({
                                "tool": tool_name,
                                "status": "error",
                                "output": output_text,
                            })
                            task_messages.append(ToolMessage(
                                content=output_text,
                                tool_call_id=tool_call["id"],
                            ))

                        executed = True

                    if executed:
                        break

                    task_messages.append(HumanMessage(content=build_hunter_retry_instruction(
                        tool_name,
                        attempt + 1,
                    )))

                if not executed:
                    tool_results.append({
                        "tool": tool_name,
                        "status": "not_executed",
                        "output": (
                            "The model failed to issue the required tool call after "
                            f"{max_tool_retries + 1} attempt(s)."
                        ),
                    })

            tool_audit = json.dumps(
                self._build_compact_tool_audit(tool_results),
                indent=2,
                ensure_ascii=False,
            )
            task_messages.append(HumanMessage(content=build_hunter_final_instruction(tool_audit)))
            final_msg = self.base_llm.invoke(task_messages)
            final_content = (
                f"{final_msg.content}\n\n"
                f"Tool Execution Audit:\n{tool_audit}"
            )
            ai_msg = AIMessage(content=final_content)
            task_messages.append(ai_msg)

            run_history.extend(task_messages)
            self.history.extend(task_messages)

            print(f"\n    [TASK RESULT - {task['id']}]")
            print(f"    {ai_msg.content}")
            print("    " + "=" * 30)
            print(f"    [V] Task {task['id']} completed.")

        return run_history

    def _build_effective_tool_args(self, tool_name, tool_args, raw_log):
        text_value = (tool_args or {}).get("text") if isinstance(tool_args, dict) else None
        if tool_name in {"ner_tool", "rex_tool", "sum_tool", "spa_tool"} and not text_value:
            return {"text": raw_log}
        return dict(tool_args or {})

    def _has_unresolved_tool_calls(self, ai_msg):
        invalid_calls = getattr(ai_msg, "invalid_tool_calls", None) or []
        if invalid_calls:
            return True

        parsed_ids = {
            tool_call.get("id")
            for tool_call in (getattr(ai_msg, "tool_calls", None) or [])
            if tool_call.get("id")
        }
        raw_calls = (getattr(ai_msg, "additional_kwargs", None) or {}).get("tool_calls", [])
        raw_ids = {
            tool_call.get("id")
            for tool_call in raw_calls
            if isinstance(tool_call, dict) and tool_call.get("id")
        }
        return bool(raw_ids - parsed_ids)

    def _tool_cache_key(self, tool_name, tool_args):
        normalized_args = json.dumps(tool_args, sort_keys=True, ensure_ascii=False, default=str)
        digest = hashlib.sha256(normalized_args.encode("utf-8")).hexdigest()
        return f"{tool_name}:{digest}"

    def _build_tool_output_payload(self, tool_name, tool_output, raw_log):
        sanitized_output = self._sanitize_tool_output(tool_output)
        payload = {
            "tool_output": sanitized_output,
        }
        if tool_name in {"ner_tool", "rex_tool"}:
            payload["ioc_artifact_validation"] = self._validate_iocs_against_artifact(
                sanitized_output,
                raw_log,
            )
        return payload

    def _sanitize_tool_output(self, value):
        """Remove provider reasoning blocks before they enter prompts or DAG outputs."""
        if isinstance(value, dict):
            if value.get("type") in {"thinking", "reasoning"}:
                return None
            sanitized = {}
            for key, item in value.items():
                if key in {"thinking", "reasoning"}:
                    continue
                clean_item = self._sanitize_tool_output(item)
                if clean_item not in (None, "", [], {}):
                    sanitized[key] = clean_item
            if sanitized.get("type") == "text" and set(sanitized).issubset({"type", "text"}):
                return sanitized.get("text", "")
            return sanitized
        if isinstance(value, (list, tuple, set)):
            sanitized = [self._sanitize_tool_output(item) for item in value]
            return [item for item in sanitized if item not in (None, "", [], {})]
        return value

    def _build_compact_tool_audit(self, tool_results, excerpt_chars=500):
        audit = []
        for result in tool_results:
            output = str(result.get("output", ""))
            item = {
                "tool": result.get("tool"),
                "status": result.get("status"),
                "output_sha256": hashlib.sha256(output.encode("utf-8")).hexdigest(),
            }
            if result.get("cache_status"):
                item["cache_status"] = result["cache_status"]
            if output:
                item["output_excerpt"] = output[:excerpt_chars]
            audit.append(item)
        return audit

    def _validate_iocs_against_artifact(self, tool_output, raw_log):
        candidates = sorted(self._extract_ioc_candidates(tool_output))
        raw_lower = self._defang_to_plain(raw_log).lower()
        supported = []
        unsupported = []

        for candidate in candidates:
            normalized_candidate = self._defang_to_plain(candidate).lower()
            if normalized_candidate in raw_lower:
                supported.append(candidate)
            else:
                unsupported.append(candidate)

        return {
            "policy": "NER/REX IOC candidates must appear in the raw artifact after normalizing common defanged forms.",
            "supported_iocs": supported,
            "unsupported_iocs": unsupported,
        }

    def _defang_to_plain(self, value):
        return (
            str(value)
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _extract_ioc_candidates(self, value):
        text_parts = []
        self._collect_strings(value, text_parts)
        text = "\n".join(text_parts)

        patterns = [
            ("hash", r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b"),
            ("ip", r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?\b"),
            ("url", r"https?://[^\s\"'<>]+"),
            ("domain", r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"),
            ("path", r"[A-Za-z]:\\[^\s\"'<>]+"),
        ]
        candidates = set()
        for kind, pattern in patterns:
            for match in re.findall(pattern, text):
                candidate = match.rstrip(".,;:)")
                if kind == "domain" and self._looks_like_file_extension(candidate):
                    continue
                candidates.add(candidate)
        return candidates

    def _looks_like_file_extension(self, value):
        suffix = value.rsplit(".", 1)[-1].lower() if "." in value else ""
        return suffix in {
            "bat",
            "cmd",
            "dll",
            "doc",
            "docx",
            "exe",
            "json",
            "log",
            "pdf",
            "ps1",
            "tmp",
            "txt",
        }

    def _collect_strings(self, value, output):
        if isinstance(value, str):
            output.append(value)
            return
        if isinstance(value, dict):
            for item in value.values():
                self._collect_strings(item, output)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._collect_strings(item, output)
