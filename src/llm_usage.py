"""Count LLM calls and tokens for any provider (Google, OpenAI, DeepSeek).

``get_openai_callback`` only counts OpenAI models, so a run on Gemini/Gemma
reported zero tokens. ``track_usage`` registers a LangChain callback for every
model call made inside the ``with`` block (the same mechanism as
``get_openai_callback``) and reads the provider-neutral ``usage_metadata`` that
LangChain attaches to each AI message, with the OpenAI-style ``token_usage`` as
a fallback. Cost is not estimated here: prices differ per provider and tier.

Without LangChain installed (the stubbed tests), the counter stays at zero.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from contextvars import ContextVar

_ACTIVE: ContextVar = ContextVar("ep_harness_llm_usage", default=None)
_HOOK_READY = False


class UsageCounter:
    def __init__(self):
        self._lock = threading.Lock()
        self.calls = 0
        self.input_tokens = 0
        self.output_tokens = 0
        self.by_model: dict = {}
        self.enabled = False

    def add(self, model: str, input_tokens: int, output_tokens: int) -> None:
        with self._lock:
            self.calls += 1
            self.input_tokens += input_tokens
            self.output_tokens += output_tokens
            entry = self.by_model.setdefault(model or "unknown", {"calls": 0, "input_tokens": 0, "output_tokens": 0})
            entry["calls"] += 1
            entry["input_tokens"] += input_tokens
            entry["output_tokens"] += output_tokens

    def record_result(self, response) -> None:
        """Read one LangChain ``LLMResult``: one count per model response."""
        llm_output = getattr(response, "llm_output", None) or {}
        model = llm_output.get("model_name") or llm_output.get("model") or ""
        fallback = llm_output.get("token_usage") or llm_output.get("usage") or {}
        for generations in getattr(response, "generations", None) or []:
            for generation in generations or []:
                message = getattr(generation, "message", None)
                usage = getattr(message, "usage_metadata", None) or {}
                metadata = getattr(message, "response_metadata", None) or {}
                name = model or metadata.get("model_name") or metadata.get("model") or ""
                if usage:
                    self.add(name, int(usage.get("input_tokens") or 0), int(usage.get("output_tokens") or 0))
                else:
                    self.add(name, int(fallback.get("prompt_tokens") or fallback.get("input_tokens") or 0),
                             int(fallback.get("completion_tokens") or fallback.get("output_tokens") or 0))
                    fallback = {}  # an OpenAI-style total belongs to the whole response, count it once

    def summary(self) -> dict:
        return {"counted": self.enabled, "llm_calls": self.calls, "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens, "by_model": {k: dict(v) for k, v in self.by_model.items()}}


def _handler_for(counter: UsageCounter):
    from langchain_core.callbacks import BaseCallbackHandler

    class _Handler(BaseCallbackHandler):
        def on_llm_end(self, response, **kwargs):
            counter.record_result(response)

    return _Handler()


@contextmanager
def track_usage():
    """Yield a ``UsageCounter`` that counts every LangChain model call made in the block."""
    global _HOOK_READY
    counter = UsageCounter()
    try:
        from langchain_core.tracers.context import register_configure_hook

        if not _HOOK_READY:
            register_configure_hook(_ACTIVE, inheritable=True)
            _HOOK_READY = True
        token = _ACTIVE.set(_handler_for(counter))
        counter.enabled = True
    except (ImportError, AttributeError):
        token = None
    try:
        yield counter
    finally:
        if token is not None:
            _ACTIVE.reset(token)
