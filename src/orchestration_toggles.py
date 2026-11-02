import os
from dataclasses import asdict, dataclass


_TRUE_VALUES = {"1", "true", "yes", "on", "enabled"}
_FALSE_VALUES = {"0", "false", "no", "off", "disabled"}
_VALID_POLICY_MODES = {"fixed", "always_review", "adaptive"}


def _env_toggle(name, default=True):
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    normalized = raw_value.strip().lower()
    if normalized in _TRUE_VALUES:
        return True
    if normalized in _FALSE_VALUES:
        return False
    raise ValueError(
        f"{name} must be one of {sorted(_TRUE_VALUES | _FALSE_VALUES)}; "
        f"received {raw_value!r}."
    )


def _env_policy_mode(name="POLICY_MODE", default="fixed"):
    raw_value = os.getenv(name)
    if raw_value is None or not raw_value.strip():
        return default

    normalized = raw_value.strip().lower().replace("-", "_")
    if normalized in _VALID_POLICY_MODES:
        return normalized
    raise ValueError(
        f"{name} must be one of {sorted(_VALID_POLICY_MODES)}; "
        f"received {raw_value!r}."
    )


@dataclass(frozen=True)
class OrchestrationToggles:
    dag_orchestrator: bool = True
    ioc_curator: bool = True
    ttp_relations_graph: bool = True
    mitre_mapper: bool = True
    # EP-HARNESS: inline Contract Gate (ep_harness.inline); the others are still placeholders
    enable_contract_gate: bool = False
    enable_semantic_verifier: bool = False
    policy_mode: str = "fixed"
    enable_output_guardrail: bool = False

    def snapshot(self):
        return asdict(self)


def load_orchestration_toggles():
    """Load MA-SOC ablation toggles and EP-HARNESS configuration placeholders."""
    return OrchestrationToggles(
        dag_orchestrator=_env_toggle("ENABLE_DAG_ORCHESTRATOR", True),
        ioc_curator=_env_toggle("ENABLE_IOC_CURATOR", True),
        ttp_relations_graph=_env_toggle("ENABLE_TTP_RELATIONS_GRAPH", True),
        mitre_mapper=_env_toggle("ENABLE_MITRE_MAPPER", True),
        enable_contract_gate=_env_toggle("ENABLE_CONTRACT_GATE", False),
        enable_semantic_verifier=_env_toggle("ENABLE_SEMANTIC_VERIFIER", False),
        policy_mode=_env_policy_mode("POLICY_MODE", "fixed"),
        enable_output_guardrail=_env_toggle("ENABLE_OUTPUT_GUARDRAIL", False),
    )


def disabled_ttp_graph_context():
    """Return an explicit empty graph artifact for audit-compatible runs."""
    return {
        "enabled": False,
        "source": "disabled_by_rq2_toggle",
        "policy": (
            "TTP Relations Graph is disabled. No graph seeds, relations, "
            "neighbors, or evidence hypotheses are injected into the pipeline."
        ),
        "seed_ttps": [],
        "relations": [],
        "evidence_hypotheses": [],
    }
