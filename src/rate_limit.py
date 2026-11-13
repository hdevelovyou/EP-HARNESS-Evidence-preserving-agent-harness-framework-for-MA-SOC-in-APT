"""Wait and retry when the model provider rate-limits a call (HTTP 429 / RESOURCE_EXHAUSTED).

A rate limit is an infrastructure event, not a model failure, so it must not
consume a task's retry budget (MA-SOC loop or adaptive policy) nor turn a task
into ``Error``. Every agent is wrapped once in ``guarded``: each method call that
hits a per-minute limit waits (the provider's suggested delay when it gives
one) and is called again, transparently to the loop that made it. A daily quota
cannot be waited out within a run, so it stops the run with
``QuotaExhaustedError`` instead of producing a run full of failed tasks.

The module has no LangChain dependency: errors are recognised by type name and
message, which covers the Google, OpenAI and DeepSeek clients.
"""

from __future__ import annotations

import os
import re
import threading
import time

_RATE_LIMIT_TYPES = ("ResourceExhausted", "RateLimitError", "TooManyRequests")
_RATE_LIMIT_TEXT = re.compile(r"\b429\b|RESOURCE_EXHAUSTED|rate[ _-]?limit|too many requests", re.IGNORECASE)
_DAILY_QUOTA_TEXT = re.compile(r"PerDay|per day|daily (?:limit|quota)|RequestsPerDay", re.IGNORECASE)
_RETRY_DELAY = re.compile(
    r"retry[_ ]?delay\W+(\d+(?:\.\d+)?)s|retry in (\d+(?:\.\d+)?)\s*s|retry[- ]after\W+(\d+(?:\.\d+)?)",
    re.IGNORECASE,
)


class QuotaExhaustedError(RuntimeError):
    """The provider's daily quota is used up: the run stops instead of recording failed tasks."""


def _chain(error: BaseException):
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        yield error
        error = error.__cause__ or error.__context__


def is_rate_limit(error: BaseException) -> bool:
    for item in _chain(error):
        if isinstance(item, QuotaExhaustedError):
            return True
        if type(item).__name__ in _RATE_LIMIT_TYPES or getattr(item, "status_code", None) == 429 \
                or getattr(item, "code", None) == 429:
            return True
        if _RATE_LIMIT_TEXT.search(str(item)):
            return True
    return False


def is_daily_quota(error: BaseException) -> bool:
    return is_rate_limit(error) and any(_DAILY_QUOTA_TEXT.search(str(item)) for item in _chain(error))


def suggested_delay(error: BaseException):
    for item in _chain(error):
        match = _RETRY_DELAY.search(str(item))
        if match:
            return float(next(group for group in match.groups() if group))
    return None


class RateLimitGuard:
    """Calls a function, waiting and calling again while the provider rate-limits it."""

    def __init__(self, max_waits=None, default_wait=None, max_wait=None, sleep=time.sleep):
        self.max_waits = int(os.getenv("LLM_RATE_LIMIT_MAX_WAITS", "6") if max_waits is None else max_waits)
        self.default_wait = float(os.getenv("LLM_RATE_LIMIT_WAIT_SECONDS", "60") if default_wait is None
                                  else default_wait)
        self.max_wait = float(os.getenv("LLM_RATE_LIMIT_MAX_WAIT_SECONDS", "300") if max_wait is None else max_wait)
        self._sleep = sleep
        self._lock = threading.Lock()
        self.waits = 0
        self.wait_seconds = 0.0
        self.by_role: dict = {}
        self.gave_up = 0

    def call(self, role: str, fn, *args, **kwargs):
        waits = 0
        while True:
            try:
                return fn(*args, **kwargs)
            except QuotaExhaustedError:
                raise
            except Exception as error:
                if not is_rate_limit(error):
                    raise
                if is_daily_quota(error):
                    raise QuotaExhaustedError(f"{role}: daily quota exhausted: {error}") from error
                if waits >= self.max_waits:
                    with self._lock:
                        self.gave_up += 1
                    raise
                waits += 1
                suggested = suggested_delay(error)
                # The provider's suggested delay (plus a second) when given; otherwise back off linearly.
                delay = min(self.max_wait, suggested + 1.0 if suggested is not None else self.default_wait * waits)
                with self._lock:
                    self.waits += 1
                    self.wait_seconds += delay
                    self.by_role[role] = self.by_role.get(role, 0) + 1
                print(f"    [RATE LIMIT] {role}: waiting {delay:.0f}s ({waits}/{self.max_waits}); "
                      "not counted as a retry.")
                self._sleep(delay)

    def summary(self) -> dict:
        return {"waits": self.waits, "wait_seconds": round(self.wait_seconds, 1), "by_role": dict(self.by_role),
                "gave_up": self.gave_up, "max_waits": self.max_waits}


class guarded:  # noqa: N801 - used like a function: guarded(agent, guard, "hunter")
    """Proxy for an agent: every method call goes through the guard; attributes pass through."""

    def __init__(self, agent, guard: RateLimitGuard, role: str):
        object.__setattr__(self, "_agent", agent)
        object.__setattr__(self, "_guard", guard)
        object.__setattr__(self, "_role", role)

    def __getattr__(self, name):
        value = getattr(self._agent, name)
        if callable(value) and not name.startswith("_") and not isinstance(value, type):
            def call(*args, **kwargs):
                return self._guard.call(f"{self._role}.{name}", value, *args, **kwargs)
            return call
        return value

    def __setattr__(self, name, value):
        setattr(self._agent, name, value)
