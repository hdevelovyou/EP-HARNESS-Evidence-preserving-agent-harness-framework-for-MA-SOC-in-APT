import os
from dataclasses import dataclass

from dotenv import load_dotenv


load_dotenv()


_DEFAULT_MODELS = {
    "deepseek": "deepseek-v4-pro",
    "openai": "gpt-4.1-mini",
    "google": "models/gemma-4-26b-a4b-it",
}

_MODEL_ALIASES = {
    "gemma-4-26b-it": "models/gemma-4-26b-a4b-it",
    "models/gemma-4-26b-it": "models/gemma-4-26b-a4b-it",
    "gemma-4-26b-a4b-it": "models/gemma-4-26b-a4b-it",
}

# Homogeneous Gemma-4-26B-IT allocation across all agents. Environment variables
# still take precedence for per-agent or global overrides.
_DEFAULT_PROVIDERS = {
    "coordinator": "google",
    "hunter": "google",
    "verifier": "google",
    "analyst": "google",
    "reporter": "google",
    "tools": "google",
    "debate_feedback": "google",
    "debate_judge": "google",
}


@dataclass(frozen=True)
class AgentLLMSettings:
    agent_name: str
    provider: str
    model: str


def resolve_agent_llm_settings(agent_name):
    """Resolve global agent defaults with optional per-agent overrides."""
    env_prefix = agent_name.strip().upper().replace("-", "_").replace(" ", "_")
    default_provider = _DEFAULT_PROVIDERS.get(env_prefix.lower(), "google")
    provider = (
        os.getenv(f"{env_prefix}_LLM_PROVIDER")
        or os.getenv("AGENT_LLM_PROVIDER")
        or default_provider
    ).strip().lower()

    if provider not in _DEFAULT_MODELS:
        supported = ", ".join(sorted(_DEFAULT_MODELS))
        raise ValueError(
            f"Unsupported LLM provider '{provider}' for {agent_name}. "
            f"Supported providers: {supported}."
        )

    raw_model = (
        os.getenv(f"{env_prefix}_MODEL")
        or os.getenv("AGENT_MODEL")
        or _DEFAULT_MODELS[provider]
    ).strip()
    model = _MODEL_ALIASES.get(raw_model.lower(), raw_model)

    return AgentLLMSettings(
        agent_name=agent_name,
        provider=provider,
        model=model,
    )


def get_llm_config_snapshot(agent_names):
    """Return a secret-free model configuration for benchmark metadata."""
    snapshot = {}
    for agent_name in agent_names:
        settings = resolve_agent_llm_settings(agent_name)
        snapshot[agent_name] = {
            "provider": settings.provider,
            "model": settings.model,
        }
        if settings.provider == "deepseek":
            snapshot[agent_name]["thinking_mode"] = _deepseek_thinking_mode()
    return snapshot


def create_agent_llm(
    agent_name,
    *,
    temperature=0,
    timeout=None,
    json_mode=False,
    response_schema=None,
):
    """Create a LangChain chat model from the shared benchmark toggles."""
    settings = resolve_agent_llm_settings(agent_name)
    timeout = timeout or int(os.getenv("AGENT_MODEL_TIMEOUT_SECONDS", "300"))

    if settings.provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI

        api_key = _required_env("GOOGLE_API_KEY", settings)
        kwargs = {
            "model": settings.model,
            "temperature": temperature,
            "google_api_key": api_key,
        }
        if json_mode:
            kwargs["response_mime_type"] = "application/json"
            if response_schema:
                kwargs["response_schema"] = response_schema
        return ChatGoogleGenerativeAI(**kwargs), settings

    from langchain_openai import ChatOpenAI

    if settings.provider == "deepseek":
        api_key = _required_env("DEEPSEEK_API_KEY", settings)
        llm = ChatOpenAI(
            model=settings.model,
            temperature=temperature,
            timeout=timeout,
            openai_api_key=api_key,
            base_url=os.getenv(
                "DEEPSEEK_BASE_URL",
                "https://api.deepseek.com",
            ),
            # V4 defaults to thinking mode, which rejects the forced
            # tool_choice used by Hunter. Non-thinking mode keeps LangChain's
            # existing deterministic tool workflow compatible with DeepSeek.
            extra_body={
                "thinking": {
                    "type": _deepseek_thinking_mode(),
                },
            },
        )
    else:
        api_key = _required_env("OPENAI_API_KEY", settings)
        llm = ChatOpenAI(
            model=settings.model,
            temperature=temperature,
            timeout=timeout,
            openai_api_key=api_key,
        )

    if json_mode:
        llm = llm.bind(response_format={"type": "json_object"})
    return llm, settings


def _required_env(variable_name, settings):
    value = os.getenv(variable_name)
    if value:
        return value
    raise ValueError(
        f"{variable_name} is required for {settings.agent_name} "
        f"when provider={settings.provider}."
    )


def _deepseek_thinking_mode():
    mode = os.getenv("DEEPSEEK_THINKING_MODE", "disabled").strip().lower()
    if mode not in {"enabled", "disabled"}:
        raise ValueError(
            "DEEPSEEK_THINKING_MODE must be either 'enabled' or 'disabled'."
        )
    return mode
