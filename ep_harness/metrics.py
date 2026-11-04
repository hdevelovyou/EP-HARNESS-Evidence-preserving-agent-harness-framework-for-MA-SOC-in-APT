"""Harness-specific metrics computed from gate results and the ledger.

These measure evidence integrity, NOT agreement with ground truth.
Keep them separate from the IOC/TTP Layer-2 scores.
"""

from __future__ import annotations

from collections import Counter

from .capsule import LEVEL_RANK, Capsule, claim_ref
from .gate import GateResult


def evidence_reference_validity(results: list[GateResult]) -> float | None:
    """Valid references / all cited references, pooled over capsules."""
    total = sum(r.reference_stats.get("references", 0) for r in results)
    valid = sum(r.reference_stats.get("valid", 0) for r in results)
    return valid / total if total else None


def provenance_completeness(capsules: list[Capsule]) -> float | None:
    """Share of OBSERVED/INFERRED claims that cite at least one event or artifact."""
    relevant = [c for cap in capsules for c in cap.claims if c.level in ("OBSERVED", "INFERRED")]
    if not relevant:
        return None
    anchored = sum(1 for c in relevant if c.event_ids or c.artifact_ids)
    return anchored / len(relevant)


def anchored_claim_share(capsules: list[Capsule]) -> float | None:
    """Share of ALL claims (any level) that cite at least one event or artifact."""
    claims = [c for cap in capsules for c in cap.claims]
    if not claims:
        return None
    return sum(1 for c in claims if c.event_ids or c.artifact_ids) / len(claims)


def lineage_breakdown(capsules: list[Capsule]) -> dict:
    """How many claims carry agent-cited vs harness-derived event references."""
    counts = Counter(c.lineage for cap in capsules for c in cap.claims if c.event_ids)
    return dict(counts)


def claim_flow(capsules: list[Capsule]) -> dict:
    """What happens to parent claims at each handoff edge, from the schema alone.

    For every parent claim: carried (some child claim cites it), dropped with a
    declared reason, or silently lost. For every child claim: its derivation,
    and whether its level rose above (escalated) or fell below (downgraded) the
    strongest parent claim it cites. Counts are structural; whether a carried
    claim still means the same thing is a semantic question for the Verifier.
    """
    by_id = {cap.capsule_id: cap for cap in capsules}
    edges: dict[str, Counter] = {}
    for child in capsules:
        parents = [by_id[p] for p in child.parent_capsules if p in by_id]
        if not parents:
            continue
        counts = edges.setdefault(f"{child.source}->{child.dest}", Counter())
        parent_levels = {}
        for parent in parents:
            for claim in parent.claims:
                parent_levels[claim_ref(parent.capsule_id, claim.claim_id)] = claim.level
        cited = child.all_parent_claims()
        dropped = {d.ref for d in child.dropped_claims}
        for ref in parent_levels:
            counts["parent_claims"] += 1
            if ref in cited:
                counts["carried"] += 1
            elif ref in dropped:
                counts["dropped_declared"] += 1
            else:
                counts["lost_silently"] += 1
        for claim in child.claims:
            counts["child_claims"] += 1
            counts[f"derivation_{claim.derivation}"] += 1
            levels = [parent_levels[r] for r in claim.parent_claims if parent_levels.get(r) in LEVEL_RANK]
            if not levels or claim.level not in LEVEL_RANK:
                continue
            ceiling = max(LEVEL_RANK[level] for level in levels)
            if LEVEL_RANK[claim.level] > ceiling:
                counts["escalated"] += 1
            elif LEVEL_RANK[claim.level] < ceiling:
                counts["downgraded"] += 1
    return {edge: dict(counts) for edge, counts in edges.items()}


def gate_outcomes(results: list[GateResult]) -> dict:
    statuses = Counter(r.status for r in results)
    codes = Counter(v.code for r in results for v in r.violations)
    n = len(results)
    return {
        "n": n,
        "status_counts": dict(statuses),
        "status_rates": {k: v / n for k, v in statuses.items()} if n else {},
        "violation_codes": dict(codes),
    }


def summarize(capsules: list[Capsule], results: list[GateResult]) -> dict:
    return {
        "evidence_reference_validity": evidence_reference_validity(results),
        "provenance_completeness": provenance_completeness(capsules),
        "anchored_claim_share": anchored_claim_share(capsules),
        "lineage": lineage_breakdown(capsules),
        "claim_flow": claim_flow(capsules),
        "gate": gate_outcomes(results),
    }
