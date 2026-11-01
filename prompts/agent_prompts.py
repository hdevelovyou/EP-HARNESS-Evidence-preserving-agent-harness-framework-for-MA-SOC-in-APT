import os
from pathlib import Path

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_core.prompts import ChatPromptTemplate

ROLE_BASED_ZERO_SHOT = "role_based_zero_shot"
CHAIN_OF_THOUGHT = "chain_of_thought"
EXAMPLE_BASED_FEWSHOT = "example_based_fewshot"

_PROMPTS_DIR = Path(__file__).resolve().parent
_DEFAULT_PROMPT_FAMILY = "techniques"
_DEBATE_PROMPT_FAMILY = "debate_techniques"

_ALIASES = {
    "role": ROLE_BASED_ZERO_SHOT,
    "role_zero_shot": ROLE_BASED_ZERO_SHOT,
    "role-based-zero-shot": ROLE_BASED_ZERO_SHOT,
    "role_based_zeroshot": ROLE_BASED_ZERO_SHOT,
    "role_based_zero_shot": ROLE_BASED_ZERO_SHOT,
    "zero_shot": ROLE_BASED_ZERO_SHOT,
    "cot": CHAIN_OF_THOUGHT,
    "chain-of-thought": CHAIN_OF_THOUGHT,
    "chain_of_thought": CHAIN_OF_THOUGHT,
    "fewshot": EXAMPLE_BASED_FEWSHOT,
    "few_shot": EXAMPLE_BASED_FEWSHOT,
    "example_based_fewshot": EXAMPLE_BASED_FEWSHOT,
    "example-based-fewshot": EXAMPLE_BASED_FEWSHOT,
}


def resolve_prompt_technique(agent_name=None):
    keys = []
    if agent_name:
        keys.append(f"{agent_name.upper()}_PROMPT_TECHNIQUE")
    keys.append("PROMPT_TECHNIQUE")

    for key in keys:
        value = os.getenv(key)
        if value:
            normalized = value.strip().lower().replace(" ", "_")
            return _ALIASES.get(normalized, ROLE_BASED_ZERO_SHOT)

    return ROLE_BASED_ZERO_SHOT


def resolve_prompt_family():
    """Select hierarchical or debate prompt family without changing runtime agents."""
    explicit_family = os.getenv("PROMPT_FAMILY")
    if explicit_family:
        normalized = explicit_family.strip().lower().replace("-", "_")
        if normalized in {"debate", "debate_based", "debate_techniques"}:
            return _DEBATE_PROMPT_FAMILY
        return _DEFAULT_PROMPT_FAMILY

    architecture = os.getenv("PROMPT_ARCHITECTURE", "").strip().lower().replace("-", "_")
    if architecture in {"debate", "debate_based"}:
        return _DEBATE_PROMPT_FAMILY

    return _DEFAULT_PROMPT_FAMILY


def _extract_section(text, heading):
    marker = f"## {heading}"
    start = text.find(marker)
    if start == -1:
        raise ValueError(f"Missing prompt section: {marker}")

    start = text.find("\n", start)
    if start == -1:
        return ""
    start += 1

    end = text.find("\n## ", start)
    if end == -1:
        end = len(text)

    return text[start:end].strip()


def load_prompt_pair(agent_name):
    technique = resolve_prompt_technique(agent_name)
    family = resolve_prompt_family()
    prompt_path = _PROMPTS_DIR / family / technique / f"{agent_name}.md"
    if not prompt_path.exists():
        raise FileNotFoundError(
            f"Prompt file not found for agent='{agent_name}', family='{family}', "
            f"technique='{technique}': {prompt_path}"
        )

    text = prompt_path.read_text(encoding="utf-8")
    return {
        "family": family,
        "technique": technique,
        "path": str(prompt_path),
        "system": _extract_section(text, "System Prompt"),
        "human": _extract_section(text, "Human Prompt"),
    }


def _format(template, **values):
    return template.format(**values)


def build_coordinator_prompt():
    prompt = load_prompt_pair("coordinator")
    return ChatPromptTemplate.from_messages([
        ("system", prompt["system"]),
        ("human", prompt["human"]),
    ])


def build_hunter_initial_messages(
    task_desc,
    reason,
    allowed_tool_names,
    raw_log,
    upstream_context=None,
    verifier_feedback=None,
    previous_hunter_output=None,
):
    prompt = load_prompt_pair("hunter")
    reflexion_context = "No verifier feedback from a previous failed attempt."
    if verifier_feedback:
        reflexion_context = (
            "Reflexion context from the previous failed verification:\n"
            f"- Verifier feedback: {verifier_feedback}\n"
            f"- Previous Hunter output:\n{previous_hunter_output or 'No previous Hunter output captured.'}\n"
            "Repair objective: fix only the verifier-identified gaps or unsupported claims. "
            "Do not repeat unsupported assertions from the previous output."
        )

    human_prompt = _format(
        prompt["human"],
        task_desc=task_desc,
        reason=reason,
        allowed_tools=", ".join(allowed_tool_names),
        reflexion_context=reflexion_context,
        raw_log=raw_log,
    )
    if upstream_context:
        human_prompt += (
            "\n\nVerified upstream DAG context from prerequisite tasks. "
            "Use this to continue reasoning, not to replace raw artifact evidence:\n"
            f"{upstream_context}\n"
        )
    return [
        SystemMessage(content=prompt["system"]),
        HumanMessage(content=human_prompt),
    ]


def build_hunter_tool_instruction(tool_name):
    return (
        f"Call mandatory tool now: {tool_name}.\n"
        "Call exactly this tool once. Use the raw log, task target, coordinator reason, "
        "verified upstream DAG context, and reflexion context as the input basis. "
        "For ner_tool and rex_tool, extract from the supplied task-scoped artifact/log. "
        "Do not produce the final answer yet."
    )


def build_hunter_retry_instruction(tool_name, attempt):
    return (
        f"The mandatory tool '{tool_name}' was not executed on attempt {attempt}. "
        "Retry by calling exactly that tool."
    )


def build_hunter_final_instruction(tool_audit):
    return (
        "All mandatory tool-call attempts for this task are complete. "
        "Produce the final task finding from the raw log, upstream DAG context, reflexion context, and tool outputs. "
        "Be concise and evidence-dense; avoid generic SOC filler. "
        "Treat unsupported NER/REX IOC validation entries as non-evidence unless separately visible in the raw artifact. "
        "Include a concise Tool Execution Audit so the verifier can validate which tools ran.\n\n"
        f"Tool Execution Audit:\n{tool_audit}"
    )


def build_verifier_prompt():
    prompt = load_prompt_pair("verifier")
    return ChatPromptTemplate.from_messages([
        ("system", prompt["system"]),
        ("human", prompt["human"]),
    ])


def build_analyst_prompt():
    prompt = load_prompt_pair("analyst")
    return ChatPromptTemplate.from_messages([
        ("system", prompt["system"]),
        ("human", prompt["human"]),
    ])


def build_reporter_prompt(analysis_content, evidence_context=None, entity_context=None):
    prompt = load_prompt_pair("reporter")
    evidence_block = ""
    if evidence_context:
        evidence_block = (
            "\n\nVerified hunter findings to preserve in the report, especially raw IOCs and hashes:\n"
            f"{evidence_context}\n"
        )
    entity_block = ""
    if entity_context:
        entity_block = (
            "\n\nCurated suspicious/malicious IOC set supplied by the pipeline before report generation. "
            "Use this curated set as the source of truth for the final Indicators of Compromise table. "
            "Do not add contextual benign utilities, private IPs, user accounts, or generic system processes to that IOC table:\n"
            f"{entity_context}\n"
        )

    human_prompt = _format(
        prompt["human"],
        analysis_content=analysis_content,
        evidence_block=evidence_block,
        entity_block=entity_block,
    )
    return [
        SystemMessage(content=prompt["system"]),
        HumanMessage(content=human_prompt),
    ]


def build_debate_feedback_prompt(stage, reviewer_role, prior_role, prior_output, context, focus):
    prompt = load_prompt_pair("feedback")
    human_prompt = _format(
        prompt["human"],
        stage=stage,
        reviewer_role=reviewer_role,
        prior_role=prior_role,
        prior_output=prior_output,
        context=context,
        focus=focus,
    )
    return [
        SystemMessage(content=prompt["system"]),
        HumanMessage(content=human_prompt),
    ]


def build_debate_judge_prompt(stage, first_role, second_role, first_output, second_output, context):
    prompt = load_prompt_pair("judge")
    human_prompt = _format(
        prompt["human"],
        stage=stage,
        first_role=first_role,
        second_role=second_role,
        first_output=first_output,
        second_output=second_output,
        context=context,
    )
    return [
        SystemMessage(content=prompt["system"]),
        HumanMessage(content=human_prompt),
    ]


def build_debate_soft_test_prompt(test_message, expected_answer):
    prompt = load_prompt_pair("soft_test")
    human_prompt = _format(
        prompt["human"],
        test_message=test_message,
        expected_answer=expected_answer,
    )
    return [
        SystemMessage(content=prompt["system"]),
        HumanMessage(content=human_prompt),
    ]
