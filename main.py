import argparse
import json
import os
import re
import time
from contextlib import contextmanager
from datetime import datetime

from langchain_community.callbacks.manager import get_openai_callback

from agents.analyst_agent import AnalystAgent
from agents.coordinator_agent import CoordinatorAgent
from agents.debate_judge_agent import DebateFeedbackAgent, DebateJudgeAgent
from agents.hunter_agent import HunterAgent
from agents.llm_config import get_llm_config_snapshot
from agents.reporter_agent import ReporterAgent
from agents.summarizer_agent import SummarizerAgent
from agents.task_catalog import TASK_BY_ID, TASK_INVENTORY, clone_task
from agents.verifier_agent import VerifierAgent
from ep_harness.claim_parser import remove_claims_block
from ep_harness.inline import InlineECH
from ep_harness.label_guard import assert_no_labels, mask_labels, unmask_artifacts
from ep_harness.policy import AdaptivePolicy
from ep_harness.policy_runner import run_analysis, run_task
from prompts import build_analyst_claims_contract
from evaluation.evaluator import SOCEvaluator
from evaluation.reasoning_evaluator import ReasoningEvaluator
from src.domain_pack import get_domain_pack_metadata
from src.extractor import EvidenceExtractor
from src.ioc_curator import IOCCurator
from src.mitre_mapper import MitreMapper
from src.orchestration_toggles import (
    disabled_ttp_graph_context,
    load_orchestration_toggles,
)
from src.scenario_loader import (
    infer_scenario_key_from_path,
    list_available_scenarios,
    load_scenario_ground_truth,
    resolve_scenario_runtime,
)
from src.ttp_relations_graph import TTPRelationsGraph
from strategies.cyberteam_dag import (
    build_initial_dag_state,
    build_upstream_context,
    coordinator_only_plan,
    dag_to_mermaid,
    expand_and_sort_plan,
    export_dag,
    record_task_failure,
    record_task_success,
)
from strategies.debate_strategy import DebateStrategy


VALID_STRATEGIES = {"hierarchical", "debate_based"}
IOC_CONTINUITY_CATEGORIES = ["ips", "hosts", "users", "processes", "files", "hashes"]


def resolve_collaboration_strategy(strategy=None):
    raw = (
        strategy
        or os.getenv("COLLABORATION_STRATEGY")
        or os.getenv("PROMPT_ARCHITECTURE")
        or "hierarchical"
    )
    normalized = str(raw).strip().lower().replace("-", "_")
    if normalized in {"debate", "debate_based", "debate_techniques"}:
        return "debate_based"
    if normalized in {"hierarchical", "hier", "default", "techniques"}:
        return "hierarchical"
    raise ValueError(
        f"Unsupported collaboration strategy {raw!r}. "
        f"Expected one of {sorted(VALID_STRATEGIES)}."
    )


@contextmanager
def _scoped_prompt_architecture(strategy):
    previous = os.environ.get("PROMPT_ARCHITECTURE")
    os.environ["PROMPT_ARCHITECTURE"] = strategy
    try:
        yield
    finally:
        if previous is None:
            os.environ.pop("PROMPT_ARCHITECTURE", None)
        else:
            os.environ["PROMPT_ARCHITECTURE"] = previous


def _build_ttp_seed_audit(final_results, ttp_graph_context):
    seeds = [seed.upper() for seed in ttp_graph_context.get("seed_ttps", [])]
    seed_sources = []

    for seed in seeds:
        sources = []
        for item in final_results:
            if item.get("status") != "Verified":
                continue

            artifact = item.get("artifact") or {}
            artifact_candidates = {
                str(candidate).upper()
                for candidate in artifact.get("ttp_candidates", [])
            }
            result_text = str(item.get("result", ""))

            if seed not in artifact_candidates and seed not in result_text.upper():
                continue

            sources.append({
                "task_id": item.get("task_id"),
                "task_name": item.get("task_name"),
                "source": "verified_hunter_artifact_or_result",
                "artifact_ttp_candidates": sorted(artifact_candidates),
                "summary_excerpt": str(artifact.get("summary", ""))[:500],
            })

        seed_sources.append({
            "technique_id": seed,
            "sources": sources,
        })

    return {
        "enabled": ttp_graph_context.get("enabled", True),
        "policy": (
            "TTP seeds are extracted from verified Hunter findings/results_str by technique-ID regex, "
            "filtered to technique IDs present in the local MITRE ATT&CK Enterprise dataset, and used only "
            "to retrieve graph-neighbor mapping guidance. They are not ground truth and are not injected "
            "into IOC scoring."
        ),
        "framing": (
            "The TTP Relations Graph is infrastructure that supports attack-technique mapping with controlled "
            "TTP seeding. Prompting techniques remain agent-prompt variants and do not define total system "
            "performance by themselves."
        ),
        "graph_source": ttp_graph_context.get("source"),
        "seed_count": len(seeds),
        "relation_count": len(ttp_graph_context.get("relations", [])),
        "evidence_hypothesis_count": len(ttp_graph_context.get("evidence_hypotheses", [])),
        "evidence_hypotheses": ttp_graph_context.get("evidence_hypotheses", []),
        "max_neighbors_per_seed": 10,
        "seeds": seed_sources,
    }


def _merge_entity_sets(*entity_maps):
    merged = {}
    for category in IOC_CONTINUITY_CATEGORIES:
        values = set()
        for entity_map in entity_maps:
            values.update(str(value) for value in entity_map.get(category, []) if value)
        merged[category] = sorted(values)
    return merged


def _entity_counts(entity_map):
    return {
        category: len(entity_map.get(category, []))
        for category in IOC_CONTINUITY_CATEGORIES
    }


def _build_ioc_continuity_context(extractor, final_results, analyst_result, baseline_entities):
    """Build runtime IOC continuity context strictly from EvidenceExtractor (no SOCEvaluator)."""
    verified_hunter_items = [
        {
            "task_id": item.get("task_id"),
            "task_name": item.get("task_name"),
            "result": item.get("result", ""),
            "artifact": item.get("artifact", {}),
        }
        for item in final_results
        if item.get("status") == "Verified"
    ]
    verified_hunter_text = json.dumps(verified_hunter_items, ensure_ascii=False)

    hunter_entities = extractor.extract_entities_from_text(verified_hunter_text)
    analyst_entities = extractor.extract_entities_from_text(analyst_result)
    pipeline_supported_entities = _merge_entity_sets(hunter_entities, analyst_entities)
    baseline_reference_entities = {
        category: sorted(str(value) for value in baseline_entities.get(category, []) if value)
        for category in IOC_CONTINUITY_CATEGORIES
    }

    audit = {
        "policy": (
            "IOC continuity context is built deterministically by EvidenceExtractor from verified Hunter "
            "outputs and Analyst synthesis without invoking SOCEvaluator. The raw baseline inventory from "
            "EvidenceExtractor is included only as a coverage guardrail."
        ),
        "pipeline_supported_entities": pipeline_supported_entities,
        "baseline_reference_entities": baseline_reference_entities,
        "counts": {
            "verified_hunter": _entity_counts(hunter_entities),
            "analyst": _entity_counts(analyst_entities),
            "pipeline_supported_union": _entity_counts(pipeline_supported_entities),
            "baseline_reference": _entity_counts(baseline_reference_entities),
        },
    }

    context = (
        "Pipeline IOC Continuity Context\n"
        f"{audit['policy']}\n\n"
        "Reporter instruction:\n"
        "- Enumerate every value from pipeline_supported_entities in the final Indicators of Compromise table.\n"
        "- Do not collapse this inventory with phrases like 'including', 'such as', or 'etc.'.\n"
        "- If maliciousness is uncertain, keep the value and label it Observed/Contextual or Needs Review; do not drop it.\n"
        "- Use baseline_reference_entities only to catch likely omissions from pipeline-supported findings; do not invent values absent from all supplied inputs.\n\n"
        "pipeline_supported_entities:\n"
        f"{json.dumps(pipeline_supported_entities, ensure_ascii=False, indent=2)}\n\n"
        "baseline_reference_entities:\n"
        f"{json.dumps(baseline_reference_entities, ensure_ascii=False, indent=2)}"
    )
    return context, audit


def _compose_scoring_entities(report_entities, ioc_entities):
    return {
        "ips": ioc_entities.get("ips", []),
        "hosts": ioc_entities.get("hosts", []),
        "users": [],
        "processes": ioc_entities.get("processes", []),
        "files": ioc_entities.get("files", []),
        "hashes": ioc_entities.get("hashes", []),
        "techniques": report_entities.get("techniques", []),
    }


def _run_task_with_policy(
    task,
    *,
    ech,
    policy,
    hunter,
    verifier,
    summarizer,
    extractor,
    evidence_store,
    dag_state,
    upstream_context,
    final_results,
    semantic,
):
    """One task under the Adaptive Evidence-Triggered Policy (POLICY_MODE=adaptive / always_review)."""
    task_log = extractor.build_task_view(task, evidence_store)
    evidence_cards = ech.evidence_cards(task_log) if ech.cited else ""
    hunter_log = f"{evidence_cards}\n\n{task_log}" if evidence_cards else task_log
    last = {"output": ""}

    def hunter_run(feedback):
        history = hunter.run(
            hunter_log,
            assigned_tasks=[task],
            upstream_context=upstream_context,
            verifier_feedback=feedback,
            previous_hunter_output=last["output"] or None,
        )
        last["output"] = history[-1].content if history else ""
        return last["output"]

    print(f"\n[+] Policy ({policy.mode}): {task['id']} - {task['name']}")
    decisions = []
    try:
        result = run_task(
            task,
            ech,
            policy,
            hunter_run=hunter_run,
            hunter_revise=lambda request, claims: hunter.revise_claims(task, request, claims, evidence_cards),
            judge=verifier.judge_claims,
            verify=lambda output: verifier.verify(task["name"], output, task_log),
            semantic=semantic,
        )
        status, output, reason, decisions = result.status, result.hunter_output, result.reason, result.decisions
    except Exception as error:  # a model or tool failure must not stop the whole run
        status, output, reason = "Error", last["output"], str(error)
    print(f"    [POLICY] {task['id']}: {status} ({reason})")

    extra = {} if status == "Verified" else {"status": status, "reason": reason}
    artifact = summarizer.summarize(task, remove_claims_block(output), evidence_store=evidence_store, **extra)
    entry = {
        "task_id": task["id"],
        "task_name": task["name"],
        "status": status,
        "depends_on": task.get("depends_on", []),
        "selected_by_coordinator": task.get("selected_by_coordinator", False),
        "result": output,
        "artifact": artifact,
        "policy_decisions": decisions,
    }
    if status != "Verified":
        entry["reason"] = reason
    final_results.append(entry)
    if status == "Verified":
        record_task_success(dag_state, task, output, artifact=artifact)
    else:
        record_task_failure(dag_state, task, output, reason, artifact=artifact)


def _env_flag(name, default=False):
    raw = os.getenv(name, "").strip().lower()
    return default if not raw else raw in {"1", "true", "yes", "on"}


def _scoring_entities(evaluator, source, source_type, label_mapping):
    """Entities for scoring: techniques from the masked source, everything else from restored artifact paths."""
    masked = evaluator._extract_entities(source, source_type=source_type)
    if not label_mapping:
        return masked
    restored = evaluator._extract_entities(unmask_artifacts(source, label_mapping), source_type=source_type)
    restored["techniques"] = masked.get("techniques", [])
    return restored


def _is_verifier_ok(check_result):
    """Accept strict OK and OK-prefixed verifier explanations."""
    check_str = str(check_result or "").strip()
    return bool(re.match(r"^OK(?:\b|[\s:.\-–—])", check_str, flags=re.IGNORECASE))


# --- Debate-branch helpers (kept intact for strategy == "debate_based") ---

def _normalize_concerns(feedback):
    concerns = (feedback or {}).get("point_of_concern", [])
    return concerns if isinstance(concerns, list) else []


def _has_concerns(feedback):
    if not feedback:
        return False
    return (
        bool(_normalize_concerns(feedback))
        or feedback.get("consensus") is False
        or bool(feedback.get("requires_judge"))
    )


def _has_blocking_concerns(feedback):
    return any(
        str(concern.get("severity", "")).strip().lower() == "high"
        for concern in _normalize_concerns(feedback)
        if isinstance(concern, dict)
    )


def _should_revise(feedback, debate_strategy, started_at):
    return (
        _has_blocking_concerns(feedback)
        and not bool((feedback or {}).get("requires_judge"))
        and debate_strategy.can_revise(started_at)
    )


def _should_judge(feedback, debate_strategy, started_at):
    return bool((feedback or {}).get("requires_judge")) or (
        _has_blocking_concerns(feedback)
        and not debate_strategy.can_revise(started_at)
    )


def _feedback_text(feedback):
    concerns = (feedback or {}).get("point_of_concern", [])
    if not concerns:
        return "No debate concerns."
    lines = ["Debate point-of-concern list:"]
    for index, concern in enumerate(concerns, start=1):
        lines.append(
            "{index}. [{severity}] {claim} | issue={issue} | required_fix={required_fix}".format(
                index=index,
                severity=concern.get("severity", "medium"),
                claim=concern.get("claim", ""),
                issue=concern.get("issue", ""),
                required_fix=concern.get("required_fix", ""),
            )
        )
    return "\n".join(lines)


def _run_review(feedback_agent, stage, reviewer_role, prior_role, prior_output, context, focus):
    return feedback_agent.review(
        stage=stage,
        reviewer_role=reviewer_role,
        prior_role=prior_role,
        prior_output=prior_output,
        context=context,
        focus=focus,
    )


def _run_judge(judge_agent, stage, first_role, second_role, first_output, second_output, context):
    return judge_agent.resolve(
        stage=stage,
        first_role=first_role,
        second_role=second_role,
        first_output=first_output,
        second_output=second_output,
        context=context,
    )


def _plan_to_text(plan):
    return json.dumps(
        [
            {
                "id": task.get("id"),
                "name": task.get("name"),
                "reason": task.get("coordinator_reason", ""),
                "tools": task.get("tools", []),
                "depends_on": task.get("depends_on", []),
            }
            for task in plan
        ],
        ensure_ascii=False,
        indent=2,
    )


def _plan_from_judge_output(judge_result):
    accepted_output = str((judge_result or {}).get("accepted_output", "") or "")
    if not accepted_output:
        return []

    try:
        parsed = json.loads(accepted_output)
    except json.JSONDecodeError:
        start = accepted_output.find("{")
        end = accepted_output.rfind("}")
        if start == -1 or end == -1 or end <= start:
            return []
        try:
            parsed = json.loads(accepted_output[start:end + 1])
        except json.JSONDecodeError:
            return []

    selected = parsed.get("selected_tasks", []) if isinstance(parsed, dict) else []
    if not isinstance(selected, list):
        return []

    plan = []
    seen = set()
    for item in selected:
        if not isinstance(item, dict):
            continue
        task_id = str(item.get("id", "")).strip()
        if task_id not in TASK_BY_ID or task_id in seen:
            continue
        task = clone_task(task_id)
        task["coordinator_reason"] = str(item.get("reason", "") or "Selected by Debate Judge.")
        plan.append(task)
        seen.add(task_id)
    return plan


def run_debate_soft_tests():
    with _scoped_prompt_architecture("debate_based"):
        feedback_agent = DebateFeedbackAgent()
        cases = [
            {
                "name": "correct_arithmetic",
                "test_message": (
                    "Hi, just tell the Hunter 1+1=2 and request the evaluation "
                    "and provide feedback if there are any errors."
                ),
                "expected_answer": "1+1=2 is correct.",
            },
            {
                "name": "incorrect_arithmetic",
                "test_message": (
                    "Hi, just tell the Hunter 1+1=3, request the evaluation "
                    "and provide feedback if there are any errors."
                ),
                "expected_answer": "1+1=2, so 1+1=3 should be flagged as incorrect.",
            },
        ]
        results = []
        for case in cases:
            result = feedback_agent.soft_test(
                test_message=case["test_message"],
                expected_answer=case["expected_answer"],
            )
            results.append({"case": case["name"], "result": result})
        print(json.dumps(results, ensure_ascii=False, indent=2))
        return results


def _execute_agent_runtime(
    log_data,
    scenario_name="UNTITLED",
    strategy="hierarchical",
    scenario_key=None,
    artifact_path=None,
):
    """Execute the pure multi-agent SOC investigation runtime and seal FINAL_REPORT_SOC.md.

    Strictly isolated from SOCEvaluator and ReasoningEvaluator: no evaluator class
    or ground-truth file is touched anywhere in this function.
    """
    resolved_strategy = resolve_collaboration_strategy(strategy)
    is_debate = resolved_strategy == "debate_based"
    log_tag = "Debate Main" if is_debate else "Main"

    with _scoped_prompt_architecture(resolved_strategy):
        start_time = time.time()
        orchestration_toggles = load_orchestration_toggles()
        orchestration_config = orchestration_toggles.snapshot()
        domain_pack_meta = get_domain_pack_metadata()

        debate_timeout = int(os.getenv("DEBATE_TIMEOUT_SECONDS", "300")) if is_debate else None
        debate_strategy = (
            DebateStrategy(timeout_seconds=debate_timeout, max_revision_rounds=1)
            if is_debate
            else None
        )

        coordinator = CoordinatorAgent()
        hunter = HunterAgent()
        verifier = VerifierAgent()
        analyst = AnalystAgent()
        reporter = ReporterAgent()
        feedback_agent = DebateFeedbackAgent() if is_debate else None
        judge_agent = DebateJudgeAgent() if is_debate else None

        llm_roles = ["coordinator", "hunter", "verifier", "analyst", "reporter", "tools"]
        if is_debate:
            llm_roles.extend(["debate_feedback", "debate_judge"])
        llm_config = get_llm_config_snapshot(llm_roles)
        print(f"[LLM] Runtime configuration ({resolved_strategy}): {json.dumps(llm_config, ensure_ascii=False)}")

        extractor = EvidenceExtractor()
        ioc_curator = IOCCurator()
        ttp_graph = TTPRelationsGraph() if orchestration_toggles.ttp_relations_graph else None
        summarizer = SummarizerAgent()

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        scenario_id = f"{scenario_name}_{timestamp}"
        run_dir = os.path.join("runs", scenario_id)
        os.makedirs(run_dir, exist_ok=True)

        runtime_manifest = {
            "strategy": resolved_strategy,
            "scenario_key": scenario_key,
            "task_event_limit": extractor.default_event_limit,
            "orchestration_toggles": orchestration_config,
            "domain_pack": domain_pack_meta,
        }
        orchestration_config_path = os.path.join(run_dir, "orchestration_config.json")
        with open(orchestration_config_path, "w", encoding="utf-8") as f:
            json.dump(runtime_manifest, f, ensure_ascii=False, indent=2)
        print(f"[Config] Orchestration toggles: {json.dumps(orchestration_config)}")

        final_results = []
        debate_records = []

        with get_openai_callback() as cb:
            print("\n[Extractor] Sanitizing telemetry and building deterministic evidence ledger...")
            sanitized_log = extractor.sanitize_raw_log(log_data)
            # Invariant: no technique ID (a ground-truth label) reaches the Coordinator, the extractor or any agent.
            label_mask = mask_labels(sanitized_log, markers=_env_flag("MASK_SIMULATION_MARKERS", default=True))
            sanitized_log = label_mask.text
            assert_no_labels(sanitized_log, "sanitized telemetry")
            evidence_store = extractor.extract(sanitized_log)
            assert_no_labels(evidence_store, "evidence store")
            print(
                f"[LabelGuard] Masked {label_mask.to_dict()['technique_ids']} technique ID(s) and "
                f"{label_mask.to_dict()['markers']} simulation marker(s) "
                f"({sum(label_mask.counts.values())} occurrence(s)); no label left in the runtime input."
            )
            evidence_store_path = os.path.join(run_dir, "evidence_store.json")
            with open(evidence_store_path, "w", encoding="utf-8") as f:
                json.dump(evidence_store, f, ensure_ascii=False, indent=2)

            pre_runtime_entities = extractor.build_entity_inventory(evidence_store)
            entity_context = json.dumps(pre_runtime_entities, indent=2, ensure_ascii=False)

            # EP-HARNESS: inline Contract Gate on Hunter->Verifier, Verifier->Analyst, Analyst->Reporter
            ech = (
                InlineECH(
                    evidence_store,
                    TASK_INVENTORY,
                    claim_source="cited" if orchestration_toggles.enable_cited_claims else "derived",
                )
                if orchestration_toggles.enable_contract_gate
                else None
            )
            if ech is not None:
                print("[ECH] Contract Gate enabled inline at Hunter->Verifier, Verifier->Analyst, Analyst->Reporter.")
            policy = (
                AdaptivePolicy(mode=orchestration_toggles.policy_mode)
                if ech is not None and orchestration_toggles.policy_mode in ("adaptive", "always_review")
                else None
            )
            if policy is not None:
                ech.policy = policy
                print(f"[POLICY] {policy.mode}: budget {policy.budget.to_dict()['limits']}")

            coordinator_plan = coordinator.plan(sanitized_log)
            if is_debate:
                plan_debate_started = time.time()
                plan_feedback = _run_review(
                    feedback_agent,
                    stage="coordinator_plan",
                    reviewer_role="Hunter",
                    prior_role="Coordinator",
                    prior_output=_plan_to_text(coordinator_plan),
                    context=sanitized_log[:12000],
                    focus=(
                        "Check whether the selected tasks are evidence-backed, sufficient, "
                        "non-redundant, and within the 8-12 task budget."
                    ),
                )
                plan_debate_record = {
                    "stage": "coordinator_plan",
                    "feedback": plan_feedback,
                    "judge_result": None,
                    "revision_applied": False,
                }
                if _should_revise(plan_feedback, debate_strategy, plan_debate_started):
                    revised_log = (
                        f"{sanitized_log}\n\n"
                        "Coordinator debate feedback from downstream Hunter reviewer:\n"
                        f"{_feedback_text(plan_feedback)}\n"
                        "Revise the task plan only when the concern is supported by the raw artifact."
                    )
                    coordinator_plan = coordinator.plan(revised_log)
                    plan_debate_record["revision_applied"] = True
                elif _should_judge(plan_feedback, debate_strategy, plan_debate_started):
                    plan_debate_record["judge_result"] = _run_judge(
                        judge_agent,
                        stage="coordinator_plan",
                        first_role="Coordinator",
                        second_role="Hunter",
                        first_output=_plan_to_text(coordinator_plan),
                        second_output=json.dumps(plan_feedback, ensure_ascii=False, indent=2),
                        context=sanitized_log[:12000],
                    )
                    judge_plan = _plan_from_judge_output(plan_debate_record["judge_result"])
                    if judge_plan:
                        coordinator_plan = judge_plan
                        plan_debate_record["judge_plan_applied"] = True
                elif _has_concerns(plan_feedback):
                    plan_debate_record["nonblocking_concerns_accepted"] = True
                debate_records.append(plan_debate_record)

            cyber_plan = (
                expand_and_sort_plan(coordinator_plan)
                if orchestration_toggles.dag_orchestrator
                else coordinator_only_plan(coordinator_plan)
            )
            dag_state = build_initial_dag_state(entity_context, evidence_store=evidence_store)

            if orchestration_toggles.dag_orchestrator:
                print(
                    f"\n[{log_tag}] Coordinator selected {len(coordinator_plan)} task(s); "
                    f"DAG-expanded plan has {len(cyber_plan)} task(s)."
                )
            else:
                print(
                    f"\n[{log_tag}] DAG disabled; executing only {len(cyber_plan)} "
                    "Coordinator-selected task(s) without dependency expansion."
                )

            dag_export = export_dag(cyber_plan)
            dag_export["orchestration_enabled"] = orchestration_toggles.dag_orchestrator
            dag_export["mode"] = (
                "dependency_expansion_and_topological_sort"
                if orchestration_toggles.dag_orchestrator
                else "coordinator_selected_tasks_only"
            )
            dag_export["mermaid"] = dag_to_mermaid(cyber_plan)
            dag_path = os.path.join(run_dir, "cyberteam_dag.json")
            with open(dag_path, "w", encoding="utf-8") as f:
                json.dump(dag_export, f, ensure_ascii=False, indent=4)
            print(f"[{log_tag}] CyberTeam DAG saved to: {os.path.abspath(dag_path)}")

            for task in cyber_plan:
                if policy is not None:
                    _run_task_with_policy(
                        task,
                        ech=ech,
                        policy=policy,
                        hunter=hunter,
                        verifier=verifier,
                        summarizer=summarizer,
                        extractor=extractor,
                        evidence_store=evidence_store,
                        dag_state=dag_state,
                        upstream_context=(
                            build_upstream_context(task, dag_state)
                            if orchestration_toggles.dag_orchestrator
                            else ""
                        ),
                        final_results=final_results,
                        semantic=orchestration_toggles.enable_semantic_verifier,
                    )
                    continue
                success = False
                retries = 0
                max_retries = 2
                last_feedback = None
                last_hunter_output = None
                last_artifact = None
                task_log = extractor.build_task_view(task, evidence_store)
                # Cited mode: the harness indexes the evidence so the Hunter picks IDs instead of searching for them.
                evidence_cards = ech.evidence_cards(task_log) if ech is not None and ech.cited else ""
                hunter_log = f"{evidence_cards}\n\n{task_log}" if evidence_cards else task_log

                while not success and retries <= max_retries:
                    stage_prefix = "Debate Processing" if is_debate else "Processing"
                    print(
                        f"\n[+] {stage_prefix}: {task['id']} - {task['name']} "
                        f"(attempt {retries + 1})"
                    )

                    try:
                        upstream_context = (
                            build_upstream_context(task, dag_state)
                            if orchestration_toggles.dag_orchestrator
                            else ""
                        )
                        task_history = hunter.run(
                            hunter_log,
                            assigned_tasks=[task],
                            upstream_context=upstream_context,
                            verifier_feedback=last_feedback,
                            previous_hunter_output=last_hunter_output,
                        )
                        hunter_output = task_history[-1].content if task_history else ""

                        hunter_feedback = None
                        if is_debate:
                            hunter_debate_started = time.time()
                            hunter_feedback = _run_review(
                                feedback_agent,
                                stage=f"hunter_task_{task['id']}",
                                reviewer_role="Verifier",
                                prior_role="Hunter",
                                prior_output=hunter_output,
                                context=task_log,
                                focus=(
                                    "Check unsupported claims, missing task-critical IOCs, "
                                    "weak MITRE mappings, missing tool audit, and task drift."
                                ),
                            )
                            task_debate_record = {
                                "stage": f"hunter_task_{task['id']}",
                                "feedback": hunter_feedback,
                                "judge_result": None,
                                "revision_applied": False,
                            }
                            if _should_revise(hunter_feedback, debate_strategy, hunter_debate_started):
                                debate_feedback_text = _feedback_text(hunter_feedback)
                                task_history = hunter.run(
                                    hunter_log,
                                    assigned_tasks=[task],
                                    upstream_context=upstream_context,
                                    verifier_feedback=debate_feedback_text,
                                    previous_hunter_output=hunter_output,
                                )
                                hunter_output = (
                                    task_history[-1].content if task_history else hunter_output
                                )
                                task_debate_record["revision_applied"] = True
                            elif _should_judge(hunter_feedback, debate_strategy, hunter_debate_started):
                                task_debate_record["judge_result"] = _run_judge(
                                    judge_agent,
                                    stage=f"hunter_task_{task['id']}",
                                    first_role="Hunter",
                                    second_role="Verifier",
                                    first_output=hunter_output,
                                    second_output=json.dumps(
                                        hunter_feedback,
                                        ensure_ascii=False,
                                        indent=2,
                                    ),
                                    context=task_log,
                                )
                                accepted = task_debate_record["judge_result"].get("accepted_output")
                                if accepted:
                                    hunter_output = (
                                        f"{hunter_output}\n\nDebate Judge Resolution:\n{accepted}"
                                    )
                            elif _has_concerns(hunter_feedback):
                                task_debate_record["nonblocking_concerns_accepted"] = True
                            debate_records.append(task_debate_record)

                        last_artifact = summarizer.summarize(
                            task,
                            remove_claims_block(hunter_output),
                            evidence_store=evidence_store,
                        )
                        last_hunter_output = summarizer.compact_for_retry(last_artifact)

                        gate_outcome = ech.hunter_handoff(task["id"], hunter_output) if ech else None
                        gate_blocked = gate_outcome is not None and not gate_outcome.accepted
                        if gate_blocked:
                            print(
                                f"    [GATE] Finding {gate_outcome.capsule_id} is {gate_outcome.status}; "
                                "Verifier not called."
                            )
                            check_result = gate_outcome.feedback
                        elif ech is not None and orchestration_toggles.enable_semantic_verifier:
                            # Claim-level review: rules first, then one judge call only for claims they could not reject.
                            semantic_report = ech.semantic_review(task["id"])
                            if semantic_report.pending_judge:
                                judge_answer = verifier.judge_claims(
                                    task["name"],
                                    ech.judge_items(task["id"], semantic_report),
                                )
                                semantic_report = ech.apply_judge(semantic_report, judge_answer)
                            semantic_report = ech.finish_semantic_review(task["id"], semantic_report)
                            print(f"    [SEMANTIC] {semantic_report.capsule_id}: {semantic_report.counts()}")
                            check_result = semantic_report.feedback()
                        else:
                            check_result = verifier.verify(task["name"], hunter_output, task_log)
                        check_str = str(check_result).strip()

                        verifier_handoff = None
                        if ech is not None and not gate_blocked:
                            if not orchestration_toggles.enable_semantic_verifier:
                                ech.record_verifier(task["id"], _is_verifier_ok(check_str), check_str)
                            if _is_verifier_ok(check_str):
                                verifier_handoff = ech.verifier_handoff(task["id"])

                        if verifier_handoff is not None and not verifier_handoff.accepted:
                            # Blocked at Verifier->Analyst: a Hunter retry cannot fix this edge.
                            print(
                                f"    [GATE] {verifier_handoff.capsule_id} is {verifier_handoff.status}; "
                                f"task {task['id']} excluded from the Analyst."
                            )
                            final_results.append({
                                "task_id": task["id"],
                                "task_name": task["name"],
                                "status": "Gate_Blocked",
                                "depends_on": task.get("depends_on", []),
                                "selected_by_coordinator": task.get("selected_by_coordinator", False),
                                "result": hunter_output,
                                "artifact": last_artifact,
                                "reason": verifier_handoff.feedback,
                            })
                            record_task_failure(
                                dag_state,
                                task,
                                hunter_output,
                                verifier_handoff.feedback,
                                artifact=last_artifact,
                            )
                            break

                        if _is_verifier_ok(check_str):
                            print(f"    [VERIFIED] Task {task['id']} passed.")
                            verified_entry = {
                                "task_id": task["id"],
                                "task_name": task["name"],
                                "status": "Verified",
                                "depends_on": task.get("depends_on", []),
                                "selected_by_coordinator": task.get("selected_by_coordinator", False),
                                "result": hunter_output,
                                "artifact": last_artifact,
                            }
                            if is_debate:
                                verified_entry["debate_feedback"] = hunter_feedback
                            final_results.append(verified_entry)
                            record_task_success(
                                dag_state,
                                task,
                                hunter_output,
                                artifact=last_artifact,
                            )
                            success = True
                        else:
                            retries += 1
                            last_feedback = check_result
                            failure_status = "Gate_Blocked" if gate_blocked else "Failed_Verification"
                            feedback_source = "Contract Gate" if gate_blocked else "Verifier"
                            print(f"    [FAILED] {feedback_source} feedback: {check_result}")

                            if retries <= max_retries:
                                print(f"    [RETRY] Hunter re-working with {feedback_source} feedback...")
                            else:
                                print(f"    [SKIP] {failure_status} after max retries.")
                                failed_artifact = summarizer.summarize(
                                    task,
                                    remove_claims_block(hunter_output),
                                    evidence_store=evidence_store,
                                    status=failure_status,
                                    reason=check_str,
                                )
                                failed_entry = {
                                    "task_id": task["id"],
                                    "task_name": task["name"],
                                    "status": failure_status,
                                    "depends_on": task.get("depends_on", []),
                                    "selected_by_coordinator": task.get("selected_by_coordinator", False),
                                    "result": hunter_output,
                                    "artifact": failed_artifact,
                                    "reason": check_result,
                                }
                                if is_debate:
                                    failed_entry["debate_feedback"] = hunter_feedback
                                final_results.append(failed_entry)
                                record_task_failure(
                                    dag_state,
                                    task,
                                    hunter_output,
                                    check_result,
                                    artifact=failed_artifact,
                                )

                    except Exception as e:
                        error_msg = str(e)
                        retries += 1

                        if "429" in error_msg or "rate_limit" in error_msg.lower():
                            print("    [QUOTA HIT] Sleeping 60s before retry...")
                            last_feedback = f"Previous attempt hit rate limit: {error_msg}"
                            time.sleep(60)
                        else:
                            print(f"    [API ERROR] Attempt failed: {error_msg}")
                            last_feedback = (
                                f"Previous attempt failed before verification: {error_msg}"
                            )
                            time.sleep(5)

                        if retries > max_retries:
                            error_artifact = summarizer.summarize(
                                task,
                                "",
                                evidence_store=evidence_store,
                                status="Error",
                                reason=error_msg,
                            )
                            final_results.append({
                                "task_id": task["id"],
                                "task_name": task["name"],
                                "status": "Error",
                                "depends_on": task.get("depends_on", []),
                                "selected_by_coordinator": task.get("selected_by_coordinator", False),
                                "result": "",
                                "artifact": error_artifact,
                                "reason": error_msg,
                            })
                            record_task_failure(
                                dag_state,
                                task,
                                "",
                                error_msg,
                                artifact=error_artifact,
                            )

            hunt_results_path = os.path.join(run_dir, "soc_hunt_results.json")
            with open(hunt_results_path, "w", encoding="utf-8") as f:
                json.dump(final_results, f, ensure_ascii=False, indent=4)

            analyst_tag = "Analyst Debate" if is_debate else "Analyst"
            print(f"\n[{analyst_tag}] Starting deep incident analysis...")
            lean_results = [
                {"task": item["task_id"], "findings": item["artifact"]}
                for item in final_results
                if item["status"] == "Verified"
            ]
            if ech is not None and ech.cited:
                # The Analyst cites these refs as parent_claims.
                verified_claims = ech.verified_claims()
                for entry in lean_results:
                    entry["claims"] = verified_claims.get(entry["task"], [])
            results_str = json.dumps(lean_results, indent=2, ensure_ascii=False)
            analysis_context = extractor.build_analysis_context(evidence_store)
            if ech is not None and ech.cited:
                analysis_context = f"{analysis_context}\n\n{build_analyst_claims_contract()}"

            # Toggle 1 (decoupled): TTP Relations Graph for Analyst stage ONLY
            ttp_graph_context = (
                ttp_graph.build_context(results_str)
                if orchestration_toggles.ttp_relations_graph
                else disabled_ttp_graph_context()
            )
            ttp_graph_context_path = os.path.join(run_dir, "ttp_relations_context.json")
            with open(ttp_graph_context_path, "w", encoding="utf-8") as f:
                json.dump(ttp_graph_context, f, ensure_ascii=False, indent=2)
            ttp_seed_audit = _build_ttp_seed_audit(final_results, ttp_graph_context)
            ttp_seed_audit_path = os.path.join(run_dir, "ttp_seed_audit.json")
            with open(ttp_seed_audit_path, "w", encoding="utf-8") as f:
                json.dump(ttp_seed_audit, f, ensure_ascii=False, indent=2)

            if orchestration_toggles.ttp_relations_graph:
                print(
                    f"[MITRE] TTP graph seeded with {ttp_seed_audit['seed_count']} "
                    "verified Hunter technique candidate(s)."
                )
                if ttp_seed_audit["seeds"]:
                    print(
                        "[MITRE] Seed TTPs: "
                        + ", ".join(seed["technique_id"] for seed in ttp_seed_audit["seeds"])
                    )
                ttp_graph_prompt_context = ttp_graph.to_prompt_context(ttp_graph_context)
                analyst_review_context = f"{results_str}\n\n{ttp_graph_prompt_context}"
                analyst_review_focus = (
                    "Check chronology, unsupported conclusions, missing promoted TTP evidence, "
                    "IOC/entity discipline, and report-readiness."
                )
            else:
                print("[MITRE] TTP Relations Graph disabled; Analyst receives no graph context.")
                ttp_graph_prompt_context = None
                analyst_review_context = results_str
                analyst_review_focus = (
                    "Check chronology, unsupported conclusions, IOC/entity discipline, and report-readiness. "
                    "Evaluate TTP claims only from verified evidence and Analyst reasoning."
                )

            deep_analysis = analyst.analyze_incident(
                results_str,
                analysis_context,
                entity_context=entity_context,
                ttp_relations_context=ttp_graph_prompt_context,
            )

            if is_debate:
                analyst_debate_started = time.time()
                analyst_feedback = _run_review(
                    feedback_agent,
                    stage="analyst_result",
                    reviewer_role="Reporter",
                    prior_role="Analyst",
                    prior_output=deep_analysis,
                    context=analyst_review_context,
                    focus=analyst_review_focus,
                )
                analyst_debate_record = {
                    "stage": "analyst_result",
                    "feedback": analyst_feedback,
                    "judge_result": None,
                    "revision_applied": False,
                }
                if _should_revise(analyst_feedback, debate_strategy, analyst_debate_started):
                    deep_analysis = analyst.analyze_incident(
                        results_str,
                        f"{analysis_context}\n\nDebate feedback to address:\n{_feedback_text(analyst_feedback)}",
                        entity_context=entity_context,
                        ttp_relations_context=ttp_graph_prompt_context,
                    )
                    analyst_debate_record["revision_applied"] = True
                elif _should_judge(analyst_feedback, debate_strategy, analyst_debate_started):
                    analyst_debate_record["judge_result"] = _run_judge(
                        judge_agent,
                        stage="analyst_result",
                        first_role="Analyst",
                        second_role="Reporter",
                        first_output=deep_analysis,
                        second_output=json.dumps(analyst_feedback, ensure_ascii=False, indent=2),
                        context=analyst_review_context,
                    )
                    accepted = analyst_debate_record["judge_result"].get("accepted_output")
                    if accepted:
                        deep_analysis = f"{deep_analysis}\n\nDebate Judge Resolution:\n{accepted}"
                elif _has_concerns(analyst_feedback):
                    analyst_debate_record["nonblocking_concerns_accepted"] = True
                debate_records.append(analyst_debate_record)

            ungated_analysis = deep_analysis
            if ech is not None and policy is not None:
                # Claim by claim: remove fabricated parents by code, revise only failing claims, withhold the rest.
                analysis_result = run_analysis(
                    ech,
                    policy,
                    deep_analysis,
                    analyst_rerun=lambda feedback: analyst.analyze_incident(
                        results_str,
                        f"{analysis_context}\n\n{feedback}",
                        entity_context=entity_context,
                        ttp_relations_context=ttp_graph_prompt_context,
                    ),
                    analyst_revise=lambda request, claims: analyst.revise_claims(request, claims),
                )
                ungated_analysis, deep_analysis = analysis_result.analysis, analysis_result.for_reporter
                print(
                    f"[POLICY] Analysis {'accepted' if analysis_result.accepted else 'not accepted'}: "
                    f"{[d['action'] for d in analysis_result.decisions]}"
                )
            elif ech is not None:
                analysis_outcome = ech.analyst_handoff(deep_analysis)
                analyst_gate_retries = int(os.getenv("CONTRACT_GATE_ANALYST_RETRIES", "1"))
                while (
                    not analysis_outcome.accepted
                    and analysis_outcome.retryable
                    and analyst_gate_retries > 0
                ):
                    analyst_gate_retries -= 1
                    print(f"[GATE] Analysis {analysis_outcome.capsule_id} is {analysis_outcome.status}; retrying Analyst.")
                    deep_analysis = analyst.analyze_incident(
                        results_str,
                        f"{analysis_context}\n\n{analysis_outcome.feedback}",
                        entity_context=entity_context,
                        ttp_relations_context=ttp_graph_prompt_context,
                    )
                    analysis_outcome = ech.analyst_handoff(deep_analysis)
                ungated_analysis = deep_analysis
                deep_analysis = ech.analysis_for_reporter(deep_analysis, analysis_outcome)
                if not analysis_outcome.accepted:
                    print(
                        f"[GATE] Analysis {analysis_outcome.capsule_id} is {analysis_outcome.status}; "
                        "claims with violations withheld from the Reporter."
                    )

            analyst_result_path = os.path.join(run_dir, "analyst_result.md")
            with open(analyst_result_path, "w", encoding="utf-8") as f:
                f.write(ungated_analysis)
            if deep_analysis != ungated_analysis:
                with open(os.path.join(run_dir, "analyst_result_gated.md"), "w", encoding="utf-8") as f:
                    f.write(deep_analysis)

            ioc_continuity_context, ioc_continuity_audit = _build_ioc_continuity_context(
                extractor,
                final_results,
                deep_analysis,
                pre_runtime_entities,
            )
            ioc_continuity_path = os.path.join(run_dir, "ioc_continuity_audit.json")
            with open(ioc_continuity_path, "w", encoding="utf-8") as f:
                json.dump(ioc_continuity_audit, f, ensure_ascii=False, indent=2)

            curated_iocs = ioc_curator.curate(evidence_store, final_results, deep_analysis)
            curated_iocs_path = os.path.join(run_dir, "curated_iocs.json")
            with open(curated_iocs_path, "w", encoding="utf-8") as f:
                json.dump(curated_iocs, f, ensure_ascii=False, indent=2)
            curated_ioc_context = (
                ioc_curator.to_prompt_context(curated_iocs)
                if orchestration_toggles.ioc_curator
                else None
            )
            reporter_evidence_context = (
                results_str if orchestration_toggles.ioc_curator else None
            )
            if not orchestration_toggles.ioc_curator:
                print(
                    "[IOC] IOC Curator disabled for downstream use; Reporter receives "
                    "only the Analyst-derived analysis and scoring uses final report entities."
                )

            # Toggle 2 (decoupled): MitreMapper candidate retrieval before Reporter stage ONLY
            if orchestration_toggles.mitre_mapper:
                print("[MITRE] Retrieving ATT&CK candidates via MitreMapper for reconstructed behaviors...")
                try:
                    mitre_mapper = MitreMapper()
                    mitre_mapping = mitre_mapper.map_analysis(deep_analysis)
                    mitre_mapping_text = mitre_mapper.to_json(mitre_mapping)
                except Exception as error:
                    mitre_mapping = {
                        "queries": [],
                        "candidates": [],
                        "error": str(error),
                    }
                    mitre_mapping_text = json.dumps(mitre_mapping, ensure_ascii=False, indent=2)
                analysis_with_mitre = (
                    f"{deep_analysis}\n\n"
                    "Local MITRE ATT&CK candidate retrieval for evidence-based validation:\n"
                    f"{mitre_mapping_text}"
                )
            else:
                print("[MITRE] MitreMapper disabled; Reporter receives Analyst narrative without mapper candidates.")
                mitre_mapping = {
                    "enabled": False,
                    "queries": [],
                    "candidates": [],
                    "reason": "MitreMapper layer disabled; use Analyst reasoning only.",
                }
                analysis_with_mitre = deep_analysis

            mitre_mapping_path = os.path.join(run_dir, "mitre_mapping_candidates.json")
            with open(mitre_mapping_path, "w", encoding="utf-8") as f:
                json.dump(mitre_mapping, f, ensure_ascii=False, indent=2)

            final_report = reporter.generate_final_report(
                analysis_with_mitre,
                evidence_context=reporter_evidence_context,
                entity_context=curated_ioc_context,
            )
            report_str = (
                "\n".join([str(x) for x in final_report])
                if isinstance(final_report, list)
                else str(final_report)
            )

            debate_path = None
            if is_debate:
                report_debate_started = time.time()
                report_review_context = (
                    f"{deep_analysis}\n\n{curated_ioc_context}"
                    if orchestration_toggles.ioc_curator
                    else deep_analysis
                )
                report_review_focus = (
                    "Check final report fidelity, unsupported new claims, missing promoted TTPs, and IOC table correctness."
                    if (orchestration_toggles.ttp_relations_graph or orchestration_toggles.mitre_mapper)
                    else "Check final report fidelity, unsupported new claims, evidence-backed Analyst TTPs, and IOC table correctness."
                )
                report_feedback = _run_review(
                    feedback_agent,
                    stage="final_report",
                    reviewer_role="Report Critic",
                    prior_role="Reporter",
                    prior_output=report_str,
                    context=report_review_context,
                    focus=report_review_focus,
                )
                report_debate_record = {
                    "stage": "final_report",
                    "feedback": report_feedback,
                    "judge_result": None,
                    "revision_applied": False,
                }
                if _should_revise(report_feedback, debate_strategy, report_debate_started):
                    revised_analysis = (
                        f"{analysis_with_mitre}\n\n"
                        "Reporter debate feedback to address:\n"
                        f"{_feedback_text(report_feedback)}"
                    )
                    final_report = reporter.generate_final_report(
                        revised_analysis,
                        evidence_context=reporter_evidence_context,
                        entity_context=curated_ioc_context,
                    )
                    report_str = (
                        "\n".join([str(x) for x in final_report])
                        if isinstance(final_report, list)
                        else str(final_report)
                    )
                    report_debate_record["revision_applied"] = True
                elif _should_judge(report_feedback, debate_strategy, report_debate_started):
                    report_debate_record["judge_result"] = _run_judge(
                        judge_agent,
                        stage="final_report",
                        first_role="Reporter",
                        second_role="Report Critic",
                        first_output=report_str,
                        second_output=json.dumps(report_feedback, ensure_ascii=False, indent=2),
                        context=report_review_context,
                    )
                    accepted = report_debate_record["judge_result"].get("accepted_output")
                    if accepted:
                        report_str = str(accepted)
                        report_debate_record["judge_report_applied"] = True
                elif _has_concerns(report_feedback):
                    report_debate_record["nonblocking_concerns_accepted"] = True
                debate_records.append(report_debate_record)

                debate_path = os.path.join(run_dir, "debate_audit.json")
                with open(debate_path, "w", encoding="utf-8") as f:
                    json.dump(debate_records, f, ensure_ascii=False, indent=2)

            ech_audit = None
            if ech is not None:
                ech.reporter_handoff(report_str)
                ech.save(run_dir)
                ech_audit = ech.summary()
                print(f"[ECH] Gate audit saved: {json.dumps(ech_audit['summary']['gate'], ensure_ascii=False)}")

            # SEAL FINAL_REPORT_SOC.md BEFORE ANY EVALUATION CAN RUN
            report_path = os.path.join(run_dir, "FINAL_REPORT_SOC.md")
            with open(report_path, "w", encoding="utf-8") as f:
                f.write(report_str)
            print(f"[Reporter] Final report sealed at: {os.path.abspath(report_path)}")

        latency = time.time() - start_time
        total_input = cb.prompt_tokens
        total_output = cb.completion_tokens
        total_cost = cb.total_cost

        return {
            "scenario_id": scenario_id,
            "scenario_key": scenario_key,
            "artifact_path": artifact_path,
            "strategy": resolved_strategy,
            "timestamp": timestamp,
            "run_dir": run_dir,
            "report_path": report_path,
            "report_str": report_str,
            "sanitized_log": sanitized_log,
            # Post-seal only: pseudonym -> original, to restore artifact paths for IOC scoring.
            "label_mask": label_mask.to_dict(),
            "evidence_store": evidence_store,
            "final_results": final_results,
            "deep_analysis": deep_analysis,
            "curated_iocs": curated_iocs,
            "curated_iocs_path": curated_iocs_path,
            "ioc_continuity_audit": ioc_continuity_audit,
            "ioc_continuity_path": ioc_continuity_path,
            "ttp_graph_context": ttp_graph_context,
            "ttp_seed_audit": ttp_seed_audit,
            "orchestration_toggles": orchestration_toggles,
            "orchestration_config": orchestration_config,
            "orchestration_config_path": orchestration_config_path,
            "domain_pack_meta": domain_pack_meta,
            "llm_config": llm_config,
            "latency": latency,
            "openai_metrics": {
                "input_tokens": total_input,
                "output_tokens": total_output,
                "total_cost_usd": round(total_cost, 6),
            },
            "debate_records": debate_records,
            "debate_path": debate_path,
            "ech_audit": ech_audit,
            "debate_timeout": debate_timeout,
        }


def evaluate_sealed_run(runtime_bundle, ground_truth_path=None, manifest_path=None):
    """Post-seal evaluation stage. Runs ONLY after FINAL_REPORT_SOC.md is written on disk."""
    report_path = runtime_bundle["report_path"]
    if not os.path.isfile(report_path):
        raise RuntimeError(
            f"Cannot run post-seal evaluation before FINAL_REPORT_SOC.md is sealed: {report_path}"
        )

    with open(report_path, "r", encoding="utf-8") as f:
        sealed_report_str = f.read()

    run_dir = runtime_bundle["run_dir"]
    orchestration_toggles = runtime_bundle["orchestration_toggles"]
    curated_iocs = runtime_bundle["curated_iocs"]
    ioc_continuity_audit = runtime_bundle["ioc_continuity_audit"]
    ttp_seed_audit = runtime_bundle["ttp_seed_audit"]
    strategy = runtime_bundle["strategy"]
    is_debate = strategy == "debate_based"

    print("\n[Post-Seal Evaluator] Running offline evaluation on sealed artifacts...")
    evaluator = SOCEvaluator()
    reasoning_evaluator = ReasoningEvaluator()

    # Techniques are scored on the masked texts (no credit for reading a path); IOCs on texts whose
    # artifact paths are restored, so they can match the ground-truth artifacts.
    label_mapping = (runtime_bundle.get("label_mask") or {}).get("mapping", {})
    if label_mapping:
        with open(os.path.join(run_dir, "label_mask.json"), "w", encoding="utf-8") as f:
            json.dump(runtime_bundle["label_mask"], f, ensure_ascii=False, indent=2)
    pre_eval_entities = _scoring_entities(evaluator, runtime_bundle["sanitized_log"], "log", label_mapping)
    report_entities = _scoring_entities(evaluator, sealed_report_str, "report", label_mapping)
    if orchestration_toggles.ioc_curator:
        curated_ioc_entities = _scoring_entities(
            evaluator,
            curated_iocs.get("indicators", {}),
            "curated_iocs",
            label_mapping,
        )
        post_entities = _compose_scoring_entities(report_entities, curated_ioc_entities)
    else:
        post_entities = report_entities

    results_t1 = evaluator.compare_entities(pre_eval_entities, post_entities)

    ground_truth_data = load_scenario_ground_truth(
        scenario_key=runtime_bundle.get("scenario_key"),
        artifact_path=runtime_bundle.get("artifact_path"),
        ground_truth_path=ground_truth_path,
        manifest_path=manifest_path,
    )
    result_t2 = evaluator.calculate_layer_2_jaccard(
        ground_truth_data,
        post_entities,
        w_i=0.7,
        w_j=0.3,
    )

    reasoning_audit = reasoning_evaluator.evaluate(
        runtime_bundle["final_results"],
        runtime_bundle["deep_analysis"],
        sealed_report_str,
        evidence_store=runtime_bundle["evidence_store"],
        graph_context=(
            runtime_bundle["ttp_graph_context"]
            if orchestration_toggles.ttp_relations_graph
            else None
        ),
    )
    reasoning_eval_path = os.path.join(run_dir, "reasoning_eval_report.json")
    with open(reasoning_eval_path, "w", encoding="utf-8") as f:
        json.dump(reasoning_audit, f, indent=4, ensure_ascii=False)

    metadata = {
        "test_date": runtime_bundle["timestamp"],
        "scenario_key": runtime_bundle.get("scenario_key"),
        "artifact_path": runtime_bundle.get("artifact_path"),
        "ground_truth_case": ground_truth_data.get("case_name"),
        "ground_truth_source": ground_truth_data.get("source"),
        "latency_seconds": round(runtime_bundle["latency"], 2),
        "llm_config": runtime_bundle["llm_config"],
        "domain_pack": runtime_bundle["domain_pack_meta"],
        "orchestration_toggles": runtime_bundle["orchestration_config"],
        "orchestration_config_path": runtime_bundle["orchestration_config_path"],
        "openai_metrics": runtime_bundle["openai_metrics"],
        "evaluation_isolation": "post_seal_only",
    }
    if is_debate:
        metadata["debate_timeout_seconds"] = runtime_bundle["debate_timeout"]

    final_eval_data = {
        "scenario_id": runtime_bundle["scenario_id"],
        "strategy": strategy,
        "metadata": metadata,
        "layer_1_metrics": results_t1["layer_1_metrics"],
        "layer_2_audit": result_t2,
        "reasoning_audit": reasoning_audit,
        "ioc_scoring_policy": {
            "source": (
                "curated_iocs"
                if orchestration_toggles.ioc_curator
                else "final_report"
            ),
            "curator_enabled": orchestration_toggles.ioc_curator,
            "fallback_applied": not orchestration_toggles.ioc_curator,
            "curated_iocs_path": runtime_bundle["curated_iocs_path"],
            "curated_ioc_counts": curated_iocs.get("counts", {}),
            "ioc_continuity_audit_path": runtime_bundle["ioc_continuity_path"],
            "ioc_continuity_counts": ioc_continuity_audit.get("counts", {}),
            "policy": (
                "IOC metrics use the curated suspicious/malicious IOC set generated after verified Hunter tasks "
                "and Analyst synthesis; TTP metrics use final-report techniques."
                if orchestration_toggles.ioc_curator
                else "IOC Curator output is not passed to Reporter or Evaluator. IOC and TTP metrics are "
                "extracted entirely from the final report generated from Analyst-derived content."
            ),
        },
        "ttp_seed_audit": ttp_seed_audit,
        "ttp_relations_policy": {
            "enabled": orchestration_toggles.ttp_relations_graph,
            "fallback": (
                None
                if orchestration_toggles.ttp_relations_graph
                else "analyst_reasoning_only_no_graph_context"
            ),
        },
        "mitre_mapper_policy": {
            "enabled": orchestration_toggles.mitre_mapper,
            "fallback": (
                None
                if orchestration_toggles.mitre_mapper
                else "reporter_uses_analyst_narrative_without_mapper_candidates"
            ),
        },
        "dag_policy": {
            "enabled": orchestration_toggles.dag_orchestrator,
            "fallback": (
                None
                if orchestration_toggles.dag_orchestrator
                else "coordinator_selected_tasks_only_no_dependency_expansion"
            ),
        },
    }
    if is_debate and runtime_bundle.get("debate_path"):
        final_eval_data["debate_audit_path"] = runtime_bundle["debate_path"]

    eval_file_path = os.path.join(run_dir, "eval_report.json")
    with open(eval_file_path, "w", encoding="utf-8") as f:
        json.dump(final_eval_data, f, indent=4, ensure_ascii=False)
    print(f"[Post-Seal Evaluator] Eval report saved to: {os.path.abspath(eval_file_path)}")

    _print_benchmark_summary(runtime_bundle, final_eval_data)
    return final_eval_data


def _print_benchmark_summary(runtime_bundle, final_eval_data):
    scenario_id = runtime_bundle["scenario_id"]
    strategy = runtime_bundle["strategy"]
    is_debate = strategy == "debate_based"
    latency = runtime_bundle["latency"]
    openai_metrics = runtime_bundle["openai_metrics"]
    orchestration_toggles = runtime_bundle["orchestration_toggles"]
    curated_iocs = runtime_bundle["curated_iocs"]
    ttp_seed_audit = runtime_bundle["ttp_seed_audit"]

    results_t1 = final_eval_data["layer_1_metrics"]
    result_t2 = final_eval_data["layer_2_audit"]
    reasoning_audit = final_eval_data["reasoning_audit"]

    header_title = "DEBATE BENCHMARK REPORT" if is_debate else "BENCHMARK REPORT"
    print("\n" + "=" * 70)
    print(f"{header_title}: SCENARIO [{scenario_id}] | STRATEGY [{strategy}]")
    print("=" * 70)
    print("[1] PERFORMANCE METRICS (PURE RUNTIME, EXCLUDING EVALUATION)")
    print(f"    - Execution Time:         {latency:.2f} seconds")
    print(f"    - Ground Truth Case:      {final_eval_data['metadata'].get('ground_truth_case')}")
    print("-" * 70)
    print("[2] RESOURCE CONSUMPTION (OPENAI)")
    print(f"    - Input Tokens:           {openai_metrics['input_tokens']:,}")
    print(f"    - Output Tokens:          {openai_metrics['output_tokens']:,}")
    print(f"    - API Cost Estimate:      ${openai_metrics['total_cost_usd']:.6f} USD")
    print("-" * 70)
    print("[3] RELIABILITY METRICS")
    print(f"    - Layer 1 (Recall):       {results_t1['recall']:.4f}")
    print(f"    - Layer 1 (Precision):    {results_t1['precision']:.4f}")
    print(f"    - Layer 1 (F1 Score):     {results_t1['f1_score']:.4f}")
    if result_t2:
        print(f"    - Layer 2 Score (Weighted F1): {result_t2.get('enrichment_quality_score', 0)}/10")
        print(
            f"      + TTPs F1: {result_t2['f1_ttps']:.4f} "
            f"| IOCs F1: {result_t2['f1_iocs']:.4f}"
        )
        print(
            f"      + TTPs Jaccard: {result_t2['jaccard_ttps']:.4f} "
            f"| IOCs Jaccard: {result_t2['jaccard_iocs']:.4f}"
        )
    if reasoning_audit:
        print("-" * 70)
        print("[4] REASONING QUALITY METRICS")
        print(f"    - LLM Judge Enabled:      {reasoning_audit.get('llm_judge_enabled', False)}")
        print(f"    - Overall Reasoning Score: {reasoning_audit['overall_reasoning_score']:.4f}/10")
        for stage_name, stage_data in reasoning_audit.get("stages", {}).items():
            print(f"      + {stage_name}: {stage_data.get('score_10', 0):.4f}/10")
    print("-" * 70)
    print("[5] IOC & MITRE ORCHESTRATION")
    print(
        "    - IOC Source:             "
        + (
            "Curated suspicious/malicious IOC set"
            if orchestration_toggles.ioc_curator
            else "Final report only"
        )
    )
    print(f"    - Curated IOC Counts:     {curated_iocs.get('counts', {})}")
    print(f"    - TTP Graph Enabled:      {orchestration_toggles.ttp_relations_graph}")
    print(f"    - MitreMapper Enabled:    {orchestration_toggles.mitre_mapper}")
    seed_ids = [seed.get("technique_id", "") for seed in ttp_seed_audit.get("seeds", [])]
    print(f"    - TTP Graph Seed IDs:     {', '.join(seed_ids) if seed_ids else 'None'}")
    if is_debate:
        print("-" * 70)
        print("[6] DEBATE AUDIT")
        print(f"    - Debate Records:         {len(runtime_bundle['debate_records'])}")
        print(f"    - Debate Audit Path:      {os.path.abspath(runtime_bundle['debate_path'])}")
        print(f"    - Timeout Seconds:        {runtime_bundle['debate_timeout']}")
    print("=" * 70 + "\n")


def run_cyber_defense_system(
    log_data,
    scenario_name="UNTITLED",
    strategy=None,
    scenario_key=None,
    artifact_path=None,
    ground_truth_path=None,
    manifest_path=None,
    evaluate=True,
):
    """Unified MA-SOC / EP-HARNESS entrypoint supporting hierarchical and debate_based execution."""
    resolved_key = (
        scenario_key
        or infer_scenario_key_from_path(artifact_path)
        or os.getenv("SCENARIO_ID")
        or scenario_name
    )
    runtime_bundle = _execute_agent_runtime(
        log_data,
        scenario_name=scenario_name,
        strategy=strategy,
        scenario_key=resolved_key,
        artifact_path=artifact_path,
    )
    if evaluate:
        evaluate_sealed_run(
            runtime_bundle,
            ground_truth_path=ground_truth_path,
            manifest_path=manifest_path,
        )
    return runtime_bundle["report_str"]


def run_debate_cyber_defense_system(
    log_data,
    scenario_name="UNTITLED_DEBATE",
    scenario_key=None,
    artifact_path=None,
    ground_truth_path=None,
    manifest_path=None,
    evaluate=True,
):
    """Backward-compatible wrapper routing debate_based runs through the unified pipeline."""
    return run_cyber_defense_system(
        log_data,
        scenario_name=scenario_name,
        strategy="debate_based",
        scenario_key=scenario_key,
        artifact_path=artifact_path,
        ground_truth_path=ground_truth_path,
        manifest_path=manifest_path,
        evaluate=evaluate,
    )


def build_cli_parser(default_strategy=None):
    parser = argparse.ArgumentParser(
        description="Unified MA-SOC / EP-HARNESS Cyber Defense Pipeline"
    )
    parser.add_argument(
        "--scenario",
        default=None,
        help="Scenario identifier (e.g., S07, S16, S23, CobaltStrike_Lockbit, Lynx_Ransomware).",
    )
    parser.add_argument(
        "--strategy",
        default=default_strategy,
        help="Collaboration strategy: hierarchical or debate_based.",
    )
    parser.add_argument(
        "--artifact-path",
        default=None,
        help="Explicit telemetry/artifacts JSON path override.",
    )
    parser.add_argument(
        "--ground-truth-path",
        default=None,
        help="Explicit post-seal ground-truth JSON/CSV override.",
    )
    parser.add_argument(
        "--manifest-path",
        default=None,
        help="Explicit scenario_manifest.csv path override for extracted scenarios.",
    )
    parser.add_argument(
        "--run-name",
        default=None,
        help="Optional safe label prefix for runs/<run_name>_<timestamp>.",
    )
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="Skip post-seal evaluation after FINAL_REPORT_SOC.md is written.",
    )
    parser.add_argument(
        "--list-scenarios",
        action="store_true",
        help="List all discovered scenarios and their ground-truth sources, then exit.",
    )
    parser.add_argument(
        "--debate-soft-test",
        action="store_true",
        help="Run DebateFeedbackAgent arithmetic soft tests and exit.",
    )
    return parser


def cli_main(argv=None, default_strategy=None):
    parser = build_cli_parser(default_strategy=default_strategy)
    args = parser.parse_args(argv)

    if args.list_scenarios:
        print(json.dumps(list_available_scenarios(), ensure_ascii=False, indent=2))
        return 0

    if args.debate_soft_test or (
        default_strategy == "debate_based"
        and os.getenv("DEBATE_SOFT_TEST", "0").strip().lower() in {"1", "true", "yes"}
    ):
        run_debate_soft_tests()
        return 0

    strategy = resolve_collaboration_strategy(args.strategy or default_strategy)

    try:
        spec = resolve_scenario_runtime(
            scenario=args.scenario,
            artifact_path=args.artifact_path,
            run_label=args.run_name,
        )
        with open(spec.artifact_path, "r", encoding="utf-8") as f:
            raw_content = f.read()

        print(
            f"[*] Loaded scenario [{spec.scenario_key}] ({spec.source_kind}) "
            f"from: {spec.artifact_path} | strategy={strategy}"
        )
        log_payload = json.dumps(json.loads(raw_content), ensure_ascii=False, indent=2)

        run_name = spec.run_name
        if strategy == "debate_based" and not args.run_name and not os.getenv("SCENARIO_NAME"):
            run_name = f"{spec.scenario_key}_Debate"

        run_cyber_defense_system(
            log_payload,
            scenario_name=run_name,
            strategy=strategy,
            scenario_key=spec.scenario_key,
            artifact_path=spec.artifact_path,
            ground_truth_path=args.ground_truth_path,
            manifest_path=args.manifest_path,
            evaluate=not args.no_eval,
        )
        return 0

    except FileNotFoundError as err:
        print(f"ERROR: {err}")
        return 1
    except json.JSONDecodeError:
        print("ERROR: Scenario telemetry file is not valid JSON.")
        return 1
    except Exception as err:
        print(f"ERROR: Unexpected failure: {err}")
        return 1


if __name__ == "__main__":
    raise SystemExit(cli_main())
