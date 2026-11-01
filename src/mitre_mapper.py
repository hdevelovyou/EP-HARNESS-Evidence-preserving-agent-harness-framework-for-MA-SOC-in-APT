import json
import re

from src.domain_pack import load_domain_pack
from src.retriever import Retriever


_TECHNIQUE_ID_PATTERN = re.compile(r"Technique ID:\s*(T\d{4}(?:\.\d{3})?)", re.IGNORECASE)
_TECHNIQUE_NAME_PATTERN = re.compile(r"Name:\s*([^\n]+)", re.IGNORECASE)


class MitreMapper:
    """Retrieve ATT&CK candidates for compact kill-chain behaviors in one batch."""

    def __init__(self, retriever=None, max_queries=None, candidates_per_query=None, domain_pack=None):
        pack = domain_pack if isinstance(domain_pack, dict) else load_domain_pack()
        mapper_config = pack.get("mitre_mapper", {})

        self.retriever = retriever or Retriever()
        self.max_queries = int(
            max_queries
            if max_queries is not None
            else mapper_config.get("max_queries", 24)
        )
        self.candidates_per_query = int(
            candidates_per_query
            if candidates_per_query is not None
            else mapper_config.get("candidates_per_query", 5)
        )
        self.max_ranked_candidates = int(mapper_config.get("max_ranked_candidates", 20))
        self.min_line_length = int(mapper_config.get("min_line_length", 20))
        self.max_line_chars = int(mapper_config.get("max_line_chars", 600))
        self.behavior_terms = tuple(
            str(term).lower() for term in mapper_config.get("behavior_terms", []) if term
        )
        self.high_signal_tokens = tuple(
            str(token).lower() for token in mapper_config.get("high_signal_tokens", []) if token
        )
        self.ignored_line_prefixes = tuple(
            str(prefix).lower() for prefix in mapper_config.get("ignored_line_prefixes", []) if prefix
        )
        self.penalty_terms = tuple(
            str(term).lower() for term in mapper_config.get("penalty_terms", []) if term
        )
        self.weights = dict(mapper_config.get("weights", {}))

    def map_analysis(self, analysis_text):
        queries = self._behavior_queries(str(analysis_text or ""))
        if not queries:
            return {"queries": [], "candidates": []}

        results = self.retriever.search_batch(
            queries,
            n_results=self.candidates_per_query,
            where={"type": "attack"},
        )
        candidates = {}
        documents = results.get("documents", [])
        metadatas = results.get("metadatas", [])
        distances = results.get("distances", [])

        for query_index, query in enumerate(queries):
            query_documents = documents[query_index] if query_index < len(documents) else []
            query_metadatas = metadatas[query_index] if query_index < len(metadatas) else []
            query_distances = distances[query_index] if query_index < len(distances) else []
            for result_index, document in enumerate(query_documents):
                metadata = query_metadatas[result_index] if result_index < len(query_metadatas) else {}
                distance = query_distances[result_index] if result_index < len(query_distances) else None
                technique_id = metadata.get("technique_id") or self._match(
                    _TECHNIQUE_ID_PATTERN,
                    document,
                )
                if not technique_id:
                    continue
                candidate = {
                    "technique_id": technique_id.upper(),
                    "name": metadata.get("name") or self._match(_TECHNIQUE_NAME_PATTERN, document),
                    "tactics": metadata.get("tactics", ""),
                    "matched_behavior": query,
                    "distance": distance,
                }
                previous = candidates.get(candidate["technique_id"])
                if previous is None or self._is_better_distance(distance, previous.get("distance")):
                    candidates[candidate["technique_id"]] = candidate

        ranked = sorted(
            candidates.values(),
            key=lambda item: float("inf") if item.get("distance") is None else item["distance"],
        )
        return {
            "queries": queries,
            "candidates": ranked[: self.max_ranked_candidates],
            "policy": "Candidates are retrieved from the local MITRE ATT&CK collection and require evidence-based validation.",
        }

    def to_json(self, mapping):
        return json.dumps(mapping, ensure_ascii=False, indent=2)

    def _behavior_queries(self, text):
        scored_candidates = []
        seen = set()
        for raw_line in text.splitlines():
            line = " ".join(raw_line.strip(" -*#\t").split())
            lowered = line.lower()
            score = self._behavior_score(lowered)
            if len(line) < self.min_line_length or score == 0:
                continue
            normalized = lowered[: self.max_line_chars]
            if normalized in seen:
                continue
            seen.add(normalized)
            scored_candidates.append((score, len(scored_candidates), line[: self.max_line_chars]))
        candidates = [
            item[2]
            for item in sorted(scored_candidates, key=lambda item: (-item[0], item[1]))
        ][: self.max_queries]
        if not candidates and text.strip():
            candidates.append(" ".join(text.split())[: self.max_line_chars])
        return candidates

    def _behavior_score(self, lowered):
        if not lowered:
            return 0
        if self.ignored_line_prefixes and lowered.startswith(self.ignored_line_prefixes):
            return 0

        score = 0
        if self.behavior_terms and any(term in lowered for term in self.behavior_terms):
            score += int(self.weights.get("behavior_term", 1))
        if re.search(r"\b20\d{2}-\d{2}-\d{2}[t\s]\d{2}:\d{2}:\d{2}", lowered):
            score += int(self.weights.get("timestamp", 3))
        if self.high_signal_tokens and any(token in lowered for token in self.high_signal_tokens):
            score += int(self.weights.get("high_signal_token", 3))
        if "|" in lowered and "`" in lowered:
            score += int(self.weights.get("markdown_table_code", 2))
        if self.penalty_terms and any(term in lowered for term in self.penalty_terms):
            score += int(self.weights.get("penalty_term", -1))
        return max(score, 0)

    def _match(self, pattern, text):
        match = pattern.search(str(text or ""))
        return match.group(1).strip() if match else ""

    def _is_better_distance(self, candidate, previous):
        if candidate is None:
            return False
        if previous is None:
            return True
        return candidate < previous
