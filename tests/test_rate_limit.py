"""Provider rate limits (429) wait instead of failing tasks; calls and tokens are counted for any provider."""

import json
import os
import types
from pathlib import Path

import pytest

from src.llm_usage import UsageCounter
from src.rate_limit import (QuotaExhaustedError, RateLimitGuard, guarded, is_daily_quota, is_rate_limit,
                            suggested_delay)
from test_inline_gate import hunter_output, stubbed_main

REPO = Path(__file__).resolve().parents[1]
S23 = REPO / "extracted_scenarios" / "S23_telemetry.json"
TOOLS = ["ner_tool", "rex_tool", "sum_tool"]
GOOD = {"id": "c1", "evidence": ["event-9"], "observables": ["csc.exe", "tmseiddy.dll"], "tools": ["rex_tool"],
        "level": "OBSERVED", "text": "csc.exe created the file tmseiddy.dll"}

PER_MINUTE = ("429 RESOURCE_EXHAUSTED. Quota exceeded for metric generate_content_free_tier_requests, "
              "quotaId: GenerateRequestsPerMinutePerProjectPerModel-FreeTier. Please retry in 23.4s.")
PER_DAY = ("429 RESOURCE_EXHAUSTED. quotaId: GenerateRequestsPerDayPerProjectPerModel-FreeTier, "
           "'retryDelay': '41s'")


class ResourceExhausted(Exception):
    pass


def block(records):
    return f"csc.exe built a DLL.\n\n```evidence_claims\n{json.dumps(records)}\n```"


# ------------------------------------------------------------ recognising rate limits
def test_rate_limit_errors_are_recognised_by_type_and_message():
    assert is_rate_limit(Exception(PER_MINUTE)) and not is_daily_quota(Exception(PER_MINUTE))
    assert is_rate_limit(ResourceExhausted("quota")) and is_daily_quota(Exception(PER_DAY))
    wrapped = RuntimeError("tool failed")
    wrapped.__cause__ = ResourceExhausted("busy")
    assert is_rate_limit(wrapped)
    assert not is_rate_limit(ValueError("400 invalid argument: tool_call_id"))
    assert suggested_delay(Exception(PER_MINUTE)) == 23.4 and suggested_delay(Exception(PER_DAY)) == 41.0
    assert suggested_delay(Exception("429")) is None


def test_guard_waits_then_succeeds_without_spending_retries():
    slept, attempts = [], []

    def flaky():
        attempts.append(1)
        if len(attempts) < 3:
            raise ResourceExhausted("429 too many requests")
        return "ok"

    guard = RateLimitGuard(max_waits=5, default_wait=10, max_wait=300, sleep=slept.append)
    assert guard.call("hunter.run", flaky) == "ok"
    assert slept == [10, 20] and guard.summary()["waits"] == 2 and guard.summary()["by_role"] == {"hunter.run": 2}

    guard = RateLimitGuard(max_waits=5, default_wait=60, max_wait=300, sleep=slept.append)
    calls = iter([Exception(PER_MINUTE)])

    def once():
        error = next(calls, None)
        if error:
            raise error
        return "ok"

    assert guard.call("verifier.verify", once) == "ok" and round(slept[-1], 1) == 24.4   # suggested 23.4 s + 1


def test_guard_stops_on_daily_quota_and_passes_other_errors_through():
    slept = []
    guard = RateLimitGuard(max_waits=5, default_wait=1, max_wait=5, sleep=slept.append)

    def daily():
        raise Exception(PER_DAY)

    with pytest.raises(QuotaExhaustedError):
        guard.call("hunter.run", daily)

    def broken():
        raise ValueError("bad request")

    with pytest.raises(ValueError):
        guard.call("hunter.run", broken)

    def always_busy():
        raise ResourceExhausted("429")

    with pytest.raises(ResourceExhausted):
        guard.call("hunter.run", always_busy)
    assert slept == [1, 2, 3, 4, 5] and guard.gave_up == 1


def test_guarded_proxy_forwards_attributes_and_guards_methods():
    class Agent:
        def __init__(self):
            self.tool_cache = {}
            self.calls = 0

        def run(self, value):
            self.calls += 1
            if self.calls == 1:
                raise ResourceExhausted("429")
            return value * 2

    agent = Agent()
    proxy = guarded(agent, RateLimitGuard(max_waits=2, default_wait=0, max_wait=0, sleep=lambda s: None), "hunter")
    assert proxy.run(4) == 8 and proxy.calls == 2 and proxy.tool_cache is agent.tool_cache
    proxy.history = ["x"]
    assert agent.history == ["x"]


# ------------------------------------------------------------ token counting for any provider
def test_usage_counter_reads_usage_metadata_and_openai_style_totals():
    counter = UsageCounter()
    gemma = types.SimpleNamespace(
        llm_output={},
        generations=[[types.SimpleNamespace(message=types.SimpleNamespace(
            usage_metadata={"input_tokens": 1200, "output_tokens": 300},
            response_metadata={"model_name": "models/gemma-4-26b-a4b-it"}))]])
    openai = types.SimpleNamespace(
        llm_output={"model_name": "gpt-4.1-mini", "token_usage": {"prompt_tokens": 50, "completion_tokens": 7}},
        generations=[[types.SimpleNamespace(message=types.SimpleNamespace(usage_metadata=None,
                                                                         response_metadata={}))]])
    counter.record_result(gemma)
    counter.record_result(gemma)
    counter.record_result(openai)
    summary = counter.summary()
    assert (summary["llm_calls"], summary["input_tokens"], summary["output_tokens"]) == (3, 2450, 607)
    assert summary["by_model"]["models/gemma-4-26b-a4b-it"] == {"calls": 2, "input_tokens": 2400,
                                                                 "output_tokens": 600}


# ------------------------------------------------------------ main.py: the policy path and the quota stop
def _agents(calls, first_error):
    class Coordinator:
        def plan(self, log):
            return [{"id": "T7"}]

    class Hunter:
        def run(self, task_log, assigned_tasks, **kwargs):
            calls["run"] += 1
            if calls["run"] == 1 and first_error:
                raise first_error
            return [types.SimpleNamespace(content=hunter_output(block([GOOD]), TOOLS))]

        def revise_claims(self, *args):
            raise AssertionError("no revision expected")

    class Verifier:
        def verify(self, *args):
            calls["verify"] += 1
            return "OK"

        def judge_claims(self, task_name, items):
            raise AssertionError("semantic review is off")

    class Analyst:
        def analyze_incident(self, *args, **kwargs):
            return "## Findings\n- csc.exe built tmseiddy.dll [c1]\n```evidence_claims\n" + json.dumps(
                [{"id": "c1", "parent_claims": ["CAP-T7-VERIFIED-a1#c1"], "level": "INFERRED",
                  "text": "csc.exe built tmseiddy.dll"}]) + "\n```"

        def revise_claims(self, request, claims_json):
            return claims_json

    class Reporter:
        def generate_final_report(self, analysis_text, **kwargs):
            return analysis_text

    return Coordinator, Hunter, Verifier, Analyst, Reporter


def _run(tmp_path, first_error):
    calls = {"run": 0, "verify": 0}
    env = {"POLICY_MODE": "adaptive", "ENABLE_SEMANTIC_VERIFIER": "0", "LLM_RATE_LIMIT_WAIT_SECONDS": "0"}
    saved = {k: os.environ.get(k) for k in env}
    with stubbed_main(tmp_path, gate_enabled=True, cited=True) as main:
        os.environ.update(env)
        try:
            (main.CoordinatorAgent, main.HunterAgent, main.VerifierAgent, main.AnalystAgent,
             main.ReporterAgent) = _agents(calls, first_error)
            return main._execute_agent_runtime(S23.read_text(encoding="utf-8"), scenario_name="RL",
                                               strategy="hierarchical"), calls
        finally:
            for k, v in saved.items():
                os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)


def test_rate_limit_in_the_policy_path_waits_instead_of_failing_the_task(tmp_path):
    bundle, calls = _run(tmp_path, ResourceExhausted(PER_MINUTE))
    entry = bundle["final_results"][0]
    assert entry["status"] == "Verified"                        # before: the task became Error
    assert [d["action"] for d in entry["policy_decisions"]] == ["ACCEPT"]
    assert calls == {"run": 2, "verify": 1}
    assert bundle["ech_audit"]["policy"]["budget"]["used"]["llm_calls"]["hunter"] == 1   # the wait cost nothing
    metrics = bundle["openai_metrics"]
    assert metrics["rate_limit"]["waits"] == 1 and metrics["rate_limit"]["by_role"] == {"hunter.run": 1}
    assert "llm_calls" in metrics and metrics["usage_counted"] is False   # no LangChain in the stubbed test


def test_daily_quota_stops_the_run_instead_of_recording_failed_tasks(tmp_path):
    with pytest.raises(QuotaExhaustedError):
        _run(tmp_path, Exception(PER_DAY))


# ------------------------------------------------------------ experiment runner: resume and quota stop
def test_runner_skips_finished_runs_and_stops_on_quota(tmp_path):
    from ep_harness import experiments

    runs = tmp_path / "runs"
    done = runs / "T_B1_structured_capsule_S23_r1_20261113_090000"
    done.mkdir(parents=True)
    (done / "eval_report.json").write_text("{}")
    (runs / "T_B1_structured_capsule_S23_r2_20261113_091000").mkdir()   # stopped half-way: not finished
    launched = []

    def fake_run(command, env=None, check=False):
        launched.append(command[command.index("--run-name") + 1])
        return types.SimpleNamespace(returncode=experiments.QUOTA_EXIT)

    original = experiments.subprocess.run
    experiments.subprocess.run = fake_run
    try:
        code = experiments.main(["run", "--name", "T", "--configs", "B1_structured_capsule", "--scenarios", "S23",
                                 "--repeats", "3", "--execute", "--out", str(tmp_path / "exp"),
                                 "--runs", str(runs)])
    finally:
        experiments.subprocess.run = original
    assert code == experiments.QUOTA_EXIT
    assert launched == ["T_B1_structured_capsule_S23_r2"]          # r1 skipped, stopped after r2
    assert experiments._run_dir(runs, "T_B1_structured_capsule_S23_r2") is None
