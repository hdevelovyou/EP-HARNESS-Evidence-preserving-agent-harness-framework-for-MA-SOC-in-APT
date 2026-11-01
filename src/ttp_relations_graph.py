import json
import math
import re
from pathlib import Path

from src.domain_pack import load_domain_pack


_TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TOKEN_PATTERN = re.compile(r"[a-z0-9]{3,}", re.IGNORECASE)


class TTPRelationsGraph:
    """Lightweight MITRE ATT&CK technique relation graph built from the local dataset."""

    def __init__(self, dataset_path=None, domain_pack=None):
        default_path = Path(__file__).resolve().parent.parent / "data" / "mitre_attack_dataset.json"
        self.dataset_path = Path(dataset_path or default_path)

        pack = domain_pack if isinstance(domain_pack, dict) else load_domain_pack()
        graph_config = pack.get("ttp_relations_graph", {})

        self.stopwords = {
            str(word).lower() for word in graph_config.get("stopwords", []) if word
        }
        self.thresholds = dict(graph_config.get("thresholds", {}))
        self.weights = dict(graph_config.get("weights", {}))
        self.evidence_hypothesis_rules = [
            rule for rule in graph_config.get("evidence_hypothesis_rules", []) if isinstance(rule, dict)
        ]

        self.techniques = self._load_techniques()

    def extract_ttps(self, text):
        return sorted({match.upper() for match in _TTP_PATTERN.findall(str(text or ""))})

    def build_context(self, seed_text, max_seeds=None, max_neighbors_per_seed=None):
        max_seeds = int(
            max_seeds
            if max_seeds is not None
            else self.thresholds.get("max_seeds", 30)
        )
        max_neighbors_per_seed = int(
            max_neighbors_per_seed
            if max_neighbors_per_seed is not None
            else self.thresholds.get("max_neighbors_per_seed", 10)
        )

        seeds = [
            technique_id
            for technique_id in self.extract_ttps(seed_text)
            if technique_id in self.techniques
        ][:max_seeds]
        seed_entries = []
        for seed_id in seeds:
            technique = self.techniques[seed_id]
            neighbors = self.neighbors(seed_id, limit=max_neighbors_per_seed)
            seed_entries.append({
                "seed": self._public_technique(technique),
                "candidate_relations": neighbors,
            })

        return {
            "policy": (
                "Use graph neighbors and evidence-gated hypotheses as controlled MITRE ATT&CK reasoning guidance. "
                "Promote a candidate only when observed evidence or verified Hunter findings satisfy its promotion rule. "
                "Prefer exact sub-techniques over generic parent techniques; if a sub-technique is promoted, avoid also "
                "asserting the parent unless separate evidence supports the parent itself."
            ),
            "source": str(self.dataset_path),
            "seed_ttps": seeds,
            "evidence_hypotheses": self._evidence_hypotheses(seed_text),
            "relations": seed_entries,
        }

    def to_prompt_context(self, graph_context):
        if not graph_context.get("relations") and not graph_context.get("evidence_hypotheses"):
            return (
                "No MITRE ATT&CK graph seeds were available from verified hunter findings. "
                "Do not expand TTPs without observed behavior."
            )

        lines = [
            "MITRE ATT&CK Relations Graph Context",
            graph_context.get("policy", ""),
        ]
        hypotheses = graph_context.get("evidence_hypotheses", [])
        if hypotheses:
            lines.append("Evidence-gated TTP hypothesis promotion checklist:")
            for item in hypotheses:
                lines.append(
                    "- {id} {name} | confidence_hint={confidence_hint} | evidence={evidence} | promotion_rule={promotion_rule}".format(
                        id=item.get("id", ""),
                        name=item.get("name", ""),
                        confidence_hint=item.get("confidence_hint", ""),
                        evidence=item.get("evidence", ""),
                        promotion_rule=item.get("promotion_rule", ""),
                    )
                )
            lines.append(
                "For each checklist item, decide Promote/Reject/Weak. Promoted items must appear in the MITRE table with evidence; rejected/weak items must not."
            )
        for entry in graph_context.get("relations", []):
            seed = entry.get("seed", {})
            lines.append(
                f"- Seed {seed.get('id')} {seed.get('name')} "
                f"[tactics: {', '.join(seed.get('tactics', [])) or 'unknown'}]"
            )
            for relation in entry.get("candidate_relations", []):
                lines.append(
                    "  -> {id} {name} | relation={relation_type} | weight={weight:.2f} | reason={reason}".format(
                        id=relation.get("id", ""),
                        name=relation.get("name", ""),
                        relation_type=relation.get("relation_type", ""),
                        weight=float(relation.get("weight", 0.0)),
                        reason=relation.get("reason", ""),
                    )
                )
        return "\n".join(lines)

    def _evidence_hypotheses(self, seed_text):
        text = str(seed_text or "").lower()
        hypotheses = []
        seen = set()
        high_conf_min = int(self.thresholds.get("high_confidence_min_matched_terms", 2))
        max_preview = int(self.thresholds.get("max_matched_terms_preview", 8))

        for rule in self.evidence_hypothesis_rules:
            rule_id = str(rule.get("id", "")).upper()
            matched_terms = [
                term
                for term in rule.get("terms_any", ())
                if str(term).lower() in text
            ]
            if not matched_terms:
                continue
            technique = self.techniques.get(rule_id)
            if not technique or rule_id in seen:
                continue
            seen.add(rule_id)
            hypotheses.append({
                **self._public_technique(technique),
                "evidence": rule.get("evidence", ""),
                "matched_terms": matched_terms[:max_preview],
                "promotion_rule": rule.get("promotion_rule", ""),
                "confidence_hint": "high" if len(matched_terms) >= high_conf_min else "medium",
                "source": "evidence_pattern",
            })
        return hypotheses

    def neighbors(self, technique_id, limit=None):
        if limit is None:
            limit = int(self.thresholds.get("default_neighbor_limit", 8))
        technique_id = str(technique_id or "").upper()
        source = self.techniques.get(technique_id)
        if not source:
            return []

        scored = []
        for candidate_id, candidate in self.techniques.items():
            if candidate_id == technique_id:
                continue
            relation = self._relation(source, candidate)
            if relation["weight"] <= 0:
                continue
            scored.append((relation["weight"], candidate_id, candidate, relation))

        scored.sort(key=lambda item: (-item[0], item[1]))
        return [
            {
                **self._public_technique(candidate),
                "relation_type": relation["relation_type"],
                "weight": round(weight, 4),
                "reason": relation["reason"],
            }
            for weight, _, candidate, relation in scored[:limit]
        ]

    def relation_supported(self, source_ids, target_id, min_weight=None):
        if min_weight is None:
            min_weight = float(self.thresholds.get("min_relation_weight", 0.35))
        target_id = str(target_id or "").upper()
        for source_id in source_ids:
            source = self.techniques.get(str(source_id or "").upper())
            target = self.techniques.get(target_id)
            if not source or not target or source["id"] == target["id"]:
                continue
            if self._relation(source, target)["weight"] >= min_weight:
                return True
        return False

    def _load_techniques(self):
        if not self.dataset_path.exists():
            return {}
        with open(self.dataset_path, "r", encoding="utf-8") as handle:
            raw_items = json.load(handle)

        techniques = {}
        for item in raw_items if isinstance(raw_items, list) else []:
            technique_id = str(item.get("id", "")).upper()
            if not _TTP_PATTERN.fullmatch(technique_id):
                continue
            text = str(item.get("text", ""))
            name = str(item.get("name", ""))
            tactics = [str(value).lower() for value in item.get("tactics", []) if value]
            platforms = [str(value).lower() for value in item.get("platforms", []) if value]
            techniques[technique_id] = {
                "id": technique_id,
                "name": name,
                "tactics": tactics,
                "platforms": platforms,
                "text": text,
                "is_subtechnique": bool(item.get("is_subtechnique")),
                "parent_id": technique_id.split(".", 1)[0] if "." in technique_id else "",
                "tokens": self._tokens(f"{technique_id} {name} {text}"),
            }
        return techniques

    def _relation(self, source, candidate):
        if candidate["parent_id"] and candidate["parent_id"] == source["id"]:
            return {
                "relation_type": "parent_to_subtechnique",
                "weight": float(self.weights.get("parent_to_subtechnique", 1.0)),
                "reason": "candidate is a sub-technique of the seed technique",
            }
        if source["parent_id"] and source["parent_id"] == candidate["id"]:
            return {
                "relation_type": "subtechnique_to_parent",
                "weight": float(self.weights.get("subtechnique_to_parent", 0.95)),
                "reason": "candidate is the parent technique of the seed sub-technique",
            }
        if source["parent_id"] and source["parent_id"] == candidate["parent_id"]:
            return {
                "relation_type": "sibling_subtechnique",
                "weight": float(self.weights.get("sibling_subtechnique", 0.75)),
                "reason": "candidate shares the same parent technique",
            }

        shared_tactics = sorted(set(source["tactics"]) & set(candidate["tactics"]))
        shared_platforms = sorted(set(source["platforms"]) & set(candidate["platforms"]))
        token_similarity = self._jaccard(source["tokens"], candidate["tokens"])

        tactic_base = float(self.weights.get("shared_tactic_base", 0.24))
        tactic_step = float(self.weights.get("shared_tactic_per_item", 0.04))
        tactic_max = float(self.weights.get("shared_tactic_max_bonus", 0.16))
        platform_weight = float(self.weights.get("shared_platform", 0.08))
        min_token_sim = float(self.thresholds.get("min_token_similarity", 0.08))
        token_mult = float(self.weights.get("token_similarity_multiplier", 0.55))
        token_max = float(self.weights.get("token_similarity_max_bonus", 0.35))
        min_rel_weight = float(self.thresholds.get("min_relation_weight", 0.35))
        max_sem_weight = float(self.weights.get("max_semantic_neighbor", 0.9))

        weight = 0.0
        relation_bits = []
        if shared_tactics:
            weight += tactic_base + min(tactic_max, tactic_step * len(shared_tactics))
            relation_bits.append(f"shared tactic(s): {', '.join(shared_tactics[:3])}")
        if shared_platforms:
            weight += platform_weight
            relation_bits.append("shared platform scope")
        if token_similarity >= min_token_sim:
            weight += min(token_max, math.sqrt(token_similarity) * token_mult)
            relation_bits.append(f"procedure/description token overlap {token_similarity:.2f}")

        if weight < min_rel_weight:
            return {"relation_type": "weak_or_unrelated", "weight": 0.0, "reason": ""}

        return {
            "relation_type": "semantic_tactic_neighbor",
            "weight": min(weight, max_sem_weight),
            "reason": "; ".join(relation_bits),
        }

    def _tokens(self, value):
        return {
            token.lower()
            for token in _TOKEN_PATTERN.findall(str(value or ""))
            if token.lower() not in self.stopwords
        }

    def _jaccard(self, left, right):
        if not left or not right:
            return 0.0
        return len(left & right) / len(left | right)

    def _public_technique(self, technique):
        return {
            "id": technique.get("id", ""),
            "name": technique.get("name", ""),
            "tactics": technique.get("tactics", []),
            "is_subtechnique": technique.get("is_subtechnique", False),
        }
