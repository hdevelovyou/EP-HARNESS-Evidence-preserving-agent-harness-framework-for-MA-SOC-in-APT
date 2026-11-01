from agents.llm_config import create_agent_llm
from prompts import build_reporter_prompt


class ReporterAgent:
    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "reporter",
            temperature=0,
        )
        self.model = self.llm_settings.model

    def generate_final_report(self, analysis_content, evidence_context=None, entity_context=None):
        prompt = build_reporter_prompt(
            analysis_content,
            evidence_context=evidence_context,
            entity_context=entity_context,
        )
        content = self.llm.invoke(prompt).content
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
