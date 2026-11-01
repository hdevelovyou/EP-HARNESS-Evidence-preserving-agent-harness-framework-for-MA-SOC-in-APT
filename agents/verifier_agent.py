from agents.llm_config import create_agent_llm
from prompts import build_verifier_prompt


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
