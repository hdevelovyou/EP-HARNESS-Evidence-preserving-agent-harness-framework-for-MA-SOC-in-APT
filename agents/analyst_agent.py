from agents.llm_config import create_agent_llm
from prompts import build_analyst_prompt


class AnalystAgent:
    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "analyst",
            temperature=0,
        )
        self.model = self.llm_settings.model

    def analyze_incident(self, hunt_results, raw_log, entity_context=None, ttp_relations_context=None):
        prompt = build_analyst_prompt()
        chain = prompt | self.llm
        analyst_log = raw_log
        if ttp_relations_context:
            analyst_log = (
                f"{raw_log}\n\n"
                "Controlled MITRE ATT&CK relations graph context for horizontal TTP reasoning:\n"
                f"{ttp_relations_context}\n\n"
                "Use the graph context to consider related techniques, but include a Technique ID "
                "only when observed evidence or verified hunter findings support it. If a graph "
                "neighbor is plausible but unsupported, list it under evidence gaps instead of the "
                "MITRE ATT&CK Mapping table. For every evidence-gated checklist item, explicitly "
                "decide Promote, Reject, or Weak; promoted items must be included in the MITRE "
                "ATT&CK Mapping table with evidence. Prefer exact sub-techniques over generic parents."
            )
        content = chain.invoke({
            "results": hunt_results,
            "entities": entity_context or "{}",
            "log": analyst_log,
        }).content
        return self._content_to_text(content)

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
            return "\n".join(parts).strip()
        return str(content).strip()
