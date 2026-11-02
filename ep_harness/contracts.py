"""Contract registry: which handoffs are legal and what each task must have done.

Handoff contracts describe agent-boundary edges. Task contracts describe the
tools a task must execute; for MA-SOC they are loaded from task_catalog.py
(see adapters.masoc.task_contracts_from_catalog).
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class HandoffContract:
    source: str
    dest: str
    kind: str
    min_claims: int = 1
    # Claim levels allowed on this edge. A Reporter may not upgrade a
    # HYPOTHESIS into the final report as a finding, for example.
    allowed_levels: tuple[str, ...] = ("OBSERVED", "INFERRED", "HYPOTHESIS")
    # Whether accepted parent capsules are required (downstream of the Hunter).
    requires_parents: bool = False


@dataclass(frozen=True)
class TaskContract:
    task_id: str
    required_tools: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()


@dataclass
class ContractRegistry:
    handoffs: dict[tuple[str, str, str], HandoffContract] = field(default_factory=dict)
    tasks: dict[str, TaskContract] = field(default_factory=dict)

    def add_handoff(self, contract: HandoffContract) -> None:
        self.handoffs[(contract.source, contract.dest, contract.kind)] = contract

    def add_task(self, contract: TaskContract) -> None:
        self.tasks[contract.task_id] = contract

    def handoff(self, source: str, dest: str, kind: str) -> HandoffContract | None:
        return self.handoffs.get((source, dest, kind))

    def task(self, task_id: str) -> TaskContract | None:
        return self.tasks.get(task_id)


def default_masoc_registry() -> ContractRegistry:
    """The five MA-SOC handoff edges. Proposed design; tune per experiment."""
    registry = ContractRegistry()
    registry.add_handoff(HandoffContract("coordinator", "hunter", "TASK", min_claims=0))
    registry.add_handoff(HandoffContract("hunter", "verifier", "FINDING"))
    registry.add_handoff(HandoffContract("verifier", "analyst", "VERIFIED", requires_parents=True))
    registry.add_handoff(HandoffContract("analyst", "reporter", "ANALYSIS", requires_parents=True))
    registry.add_handoff(
        HandoffContract(
            "reporter",
            "output",
            "REPORT",
            requires_parents=True,
            allowed_levels=("OBSERVED", "INFERRED"),
        )
    )
    return registry
