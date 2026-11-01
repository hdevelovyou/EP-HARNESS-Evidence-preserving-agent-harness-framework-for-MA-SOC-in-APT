class HierarchicalStrategy:
    """Marker for the current Coordinator -> Hunter -> Verifier -> Analyst -> Reporter flow.

    This class is intentionally not wired into main.py yet. The current pipeline
    already implements the hierarchical collaboration strategy directly in main.py.
    Keeping this marker makes future strategy selection explicit without changing
    the existing execution or scoring logic.
    """

    name = "hierarchical"

    def describe(self):
        return (
            "Coordinator plans tasks, Hunter executes task-specific tools, Verifier audits "
            "each task, Analyst reconstructs the incident, and Reporter writes the final report."
        )
