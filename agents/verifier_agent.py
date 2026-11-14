from agents.llm_config import create_agent_llm
import json

from prompts import build_semantic_judge_messages, build_verifier_prompt


class VerifierAgent:
    def __init__(self):
        self.llm, self.llm_settings = create_agent_llm(
            "verifier",
            temperature=0,
        )
        self.model = self.llm_settings.model

    def verify(self, task_description, hunter_output, raw_log):
        prompt = build_verifier_prompt()
        chain = prompt | self.llm
        response = chain.invoke({
            "task_desc": task_description,
            "hunter_out": hunter_output,
            "log": raw_log,
        })
        return response.content

    def judge_claims(self, task_description, items):
        """One LLM call: claim-level verdicts for the claims the rule layer could not reject."""
        messages = build_semantic_judge_messages(task_description, json.dumps(items, ensure_ascii=False, indent=2))
        content = self.llm.invoke(messages).content
        if isinstance(content, list):
            content = "\n".join(str(part.get("text", "")) if isinstance(part, dict) else str(part) for part in content)
        return str(content)
