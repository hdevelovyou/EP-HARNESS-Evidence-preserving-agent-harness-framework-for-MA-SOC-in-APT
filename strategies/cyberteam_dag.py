import json
from collections import deque

from agents.task_catalog import TASK_BY_ID, TASK_INVENTORY, clone_task


def expand_and_sort_plan(selected_plan):
    """Expand coordinator-selected tasks with required DAG dependencies."""
    selected_reasons = {
        item["id"]: item.get("coordinator_reason", "")
        for item in selected_plan
        if item.get("id") in TASK_BY_ID
    }
    required_ids = set()

    def add_with_dependencies(task_id):
        if task_id in required_ids:
            return
        if task_id not in TASK_BY_ID:
            return
        for dep_id in TASK_BY_ID[task_id].get("depends_on", []):
            add_with_dependencies(dep_id)
        required_ids.add(task_id)

    for task in selected_plan:
        add_with_dependencies(task.get("id"))

    ordered_ids = topological_sort(required_ids)
    expanded_plan = []
    for task_id in ordered_ids:
        task = clone_task(task_id)
        task["selected_by_coordinator"] = task_id in selected_reasons
        task["coordinator_reason"] = selected_reasons.get(
            task_id,
            f"Required upstream dependency for selected downstream task(s): {', '.join(_downstream_selected(task_id, selected_reasons))}",
        )
        expanded_plan.append(task)

    return expanded_plan


def coordinator_only_plan(selected_plan):
    """Use only Coordinator-selected tasks without DAG expansion or edges."""
    plan = []
    seen_task_ids = set()

    for selected in selected_plan:
        task_id = selected.get("id")
        if task_id not in TASK_BY_ID or task_id in seen_task_ids:
            continue

        task = clone_task(task_id)
        task["catalog_depends_on"] = list(task.get("depends_on", []))
        task["depends_on"] = []
        task["selected_by_coordinator"] = True
        task["coordinator_reason"] = selected.get("coordinator_reason", "")
        plan.append(task)
        seen_task_ids.add(task_id)

    return plan


def topological_sort(task_ids):
    task_ids = set(task_ids)
    indegree = {task_id: 0 for task_id in task_ids}
    children = {task_id: [] for task_id in task_ids}

    for task_id in task_ids:
        for dep_id in TASK_BY_ID[task_id].get("depends_on", []):
            if dep_id not in task_ids:
                continue
            indegree[task_id] += 1
            children[dep_id].append(task_id)

    inventory_order = {task["id"]: index for index, task in enumerate(TASK_INVENTORY)}
    ready = deque(sorted(
        [task_id for task_id, degree in indegree.items() if degree == 0],
        key=lambda task_id: inventory_order[task_id],
    ))
    ordered = []

    while ready:
        task_id = ready.popleft()
        ordered.append(task_id)
        for child_id in sorted(children[task_id], key=lambda item: inventory_order[item]):
            indegree[child_id] -= 1
            if indegree[child_id] == 0:
                ready.append(child_id)

    if len(ordered) != len(task_ids):
        unresolved = sorted(task_ids - set(ordered), key=lambda task_id: inventory_order[task_id])
        raise ValueError(f"Task dependency cycle or unresolved dependency detected: {unresolved}")

    return ordered


def build_initial_dag_state(entity_context, evidence_store=None):
    return {
        "verified_outputs": {},
        "failed_outputs": {},
        "entity_context_available": bool(entity_context),
        "deterministic_evidence_available": bool(evidence_store),
    }


def build_upstream_context(task, dag_state):
    dependency_ids = task.get("depends_on", [])
    verified = []
    failed = []

    for dep_id in dependency_ids:
        if dep_id in dag_state["verified_outputs"]:
            verified.append(dag_state["verified_outputs"][dep_id])
        elif dep_id in dag_state["failed_outputs"]:
            failed.append(dag_state["failed_outputs"][dep_id])

    context = {
        "task_id": task["id"],
        "depends_on": dependency_ids,
        "consumes": task.get("consumes", []),
        "produces": task.get("produces", []),
        "verified_upstream_findings": verified,
        "failed_upstream_dependencies": failed,
        "deterministic_entity_context_available": dag_state.get("entity_context_available", False),
        "deterministic_evidence_available": dag_state.get("deterministic_evidence_available", False),
    }
    return json.dumps(context, ensure_ascii=False, separators=(",", ":"))


def record_task_success(dag_state, task, hunter_output, artifact=None):
    dag_state["verified_outputs"][task["id"]] = {
        "task_id": task["id"],
        "task_name": task["name"],
        "produces": task.get("produces", []),
        "artifact": artifact if artifact is not None else {"summary": str(hunter_output)[:2400]},
    }


def record_task_failure(dag_state, task, hunter_output, reason, artifact=None):
    dag_state["failed_outputs"][task["id"]] = {
        "task_id": task["id"],
        "task_name": task["name"],
        "reason": str(reason)[:800],
        "artifact": artifact if artifact is not None else {"summary": str(hunter_output)[:1200]},
    }


def export_dag(plan):
    plan_ids = {task["id"] for task in plan}
    nodes = []
    edges = []

    for task in plan:
        nodes.append({
            "id": task["id"],
            "name": task["name"],
            "tools": task.get("tools", []),
            "depends_on": task.get("depends_on", []),
            "produces": task.get("produces", []),
            "selected_by_coordinator": task.get("selected_by_coordinator", False),
        })
        for dep_id in task.get("depends_on", []):
            if dep_id in plan_ids:
                edges.append({"from": dep_id, "to": task["id"]})

    return {"nodes": nodes, "edges": edges}


def dag_to_mermaid(plan):
    lines = ["flowchart TD"]
    for task in plan:
        lines.append(f'    {task["id"]}["{task["id"]}: {task["name"]}"]')
    for edge in export_dag(plan)["edges"]:
        lines.append(f'    {edge["from"]} --> {edge["to"]}')
    return "\n".join(lines)


def _downstream_selected(task_id, selected_reasons):
    downstream = []
    for selected_id in selected_reasons:
        if task_id in _all_dependencies(selected_id):
            downstream.append(selected_id)
    return downstream


def _all_dependencies(task_id):
    deps = set()

    def visit(current_id):
        for dep_id in TASK_BY_ID[current_id].get("depends_on", []):
            if dep_id in deps:
                continue
            deps.add(dep_id)
            visit(dep_id)

    visit(task_id)
    return deps
