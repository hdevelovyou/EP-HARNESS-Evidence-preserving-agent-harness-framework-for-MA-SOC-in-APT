"""EP-HARNESS: evidence-aware harness for multi-agent SOC threat hunting.

v0.2: Evidence Capsule schema v0.2 (claim IDs, claim lineage, observables,
declared drops, retry lineage, status transitions); ECH core in shadow mode.
"""

from .capsule import SCHEMA_VERSION, Capsule, Claim, ClaimDrop, claim_ref, parse_claim_ref
from .contracts import ContractRegistry, HandoffContract, TaskContract, default_masoc_registry
from .gate import ContractGate, GateResult, Violation
from .ledger import EvidenceLedger, LedgerIntegrityError
from .manifest import HarnessManifest

__version__ = "0.2.0"

__all__ = [
    "SCHEMA_VERSION",
    "Capsule",
    "Claim",
    "ClaimDrop",
    "ContractGate",
    "ContractRegistry",
    "EvidenceLedger",
    "GateResult",
    "HandoffContract",
    "HarnessManifest",
    "LedgerIntegrityError",
    "TaskContract",
    "Violation",
    "claim_ref",
    "default_masoc_registry",
    "parse_claim_ref",
]
