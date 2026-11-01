import json
import os
import re

from dotenv import load_dotenv
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI

from src.ttp_relations_graph import TTPRelationsGraph

load_dotenv()


_TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TIMESTAMP_PATTERN = re.compile(r"\b20\d{2}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")
_EVENT_PATTERN = re.compile(r"\bevent-\d+\b", re.IGNORECASE)
_HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>`]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|vn|io|ru|xyz)\b",
    re.IGNORECASE,
)
_FILE_PATTERN = re.compile(
    r"\b[^\s\\/:*?\"<>|`]+\.(?:exe|dll|bat|ps1|vbs|txt|bin|cab|js|sh|docx|pdf|doc|xlsx|xls|zip|rar)\b",
    re.IGNORECASE,
)
_WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\r\n\"'<>|`,;)]*")


class ReasoningEvaluator:
    """Hybrid rule-based + LLM-as-judge audit for pipeline reasoning quality."""

    def __init__(
        self,
        ttp_graph=None,
        judge_model="gpt-4.1-mini",
        enable_llm_judge=None,
        artifact_char_limit=None,
        context_char_limit=None,
    ):
        self.ttp_graph = ttp_graph or TTPRelationsGraph()
        self.parser = JsonOutputParser()
        self.judge_model = judge_model
        self.enable_llm_judge = (
            self._env_flag("ENABLE_LLM_REASONING_JUDGE", default=False)
            if enable_llm_judge is None
            else bool(enable_llm_judge)
        )
        self.artifact_char_limit = artifact_char_limit or self._env_int(
            "REASONING_JUDGE_ARTIFACT_CHARS",
            default=6000,
        )
        self.context_char_limit = context_char_limit or self._env_int(
            "REASONING_JUDGE_CONTEXT_CHARS",
            default=4000,
        )
        self.llm = None
        if self.enable_llm_judge:
            self.llm = ChatOpenAI(
                model=judge_model,
                temperature=0,
            )

    def evaluate(self, hunt_results, analyst_result, final_report, evidence_store=None, graph_context=None):
        evidence_summary = self._evidence_summary(evidence_store)
        hunt_text = self._to_text(hunt_results)
        analyst_text = self._to_text(analyst_result)
        final_text = self._to_text(final_report)

        stages = {
            "hunt_results": self._evaluate_hunt_results(hunt_results, hunt_text, evidence_summary),
            "analyst_result": self._evaluate_analyst_result(
                hunt_text,
                analyst_text,
                evidence_summary,
                graph_context,
            ),
            "final_report": self._evaluate_final_report(hunt_text, analyst_text, final_text),
        }

        overall = round(
            (
                stages["hunt_results"]["score_10"]
                + stages["analyst_result"]["score_10"]
                + stages["final_report"]["score_10"]
            ) / 3,
            4,
        )

        return {
            "overall_reasoning_score": overall,
            "llm_judge_enabled": self.enable_llm_judge,
            "llm_judge_model": self.judge_model if self.enable_llm_judge else None,
            "llm_judge_limits": {
                "artifact_chars": self.artifact_char_limit,
                "context_chars": self.context_char_limit,
            },
            "stages": stages,
            "policy": (
                "Reasoning scores audit evidence grounding, causal coherence, horizontal TTP reasoning, "
                "and report fidelity. They are separate from IOC/TTP factual overlap metrics."
            ),
        }

    def _evaluate_hunt_results(self, hunt_results, hunt_text, evidence_summary):
        rule = self._hunt_rule_score(hunt_results, hunt_text)
        judge = self._judge_stage(
            stage="hunt_results",
            artifact=hunt_text,
            context=evidence_summary,
            rubric=(
                "Score verified Hunter task outputs for local evidence reasoning. Reward direct event/timestamp/IOC support, "
                "mandatory tool faithfulness, task focus, and explicit evidence gaps. Penalize unsupported TTP/IOC claims, "
                "task drift, and vague conclusions."
            ),
        )
        return self._merge_rule_and_judge("hunt_results", rule, judge)

    def _evaluate_analyst_result(self, hunt_text, analyst_text, evidence_summary, graph_context):
        seed_ttps = self._extract_ttps(hunt_text)
        analyst_ttps = self._extract_ttps(analyst_text)
        graph_rule = self._analyst_graph_rule_score(seed_ttps, analyst_ttps, graph_context)
        rule = {
            **graph_rule,
            "evidence_grounding_score": self._ratio_score(
                len(_EVENT_PATTERN.findall(analyst_text)) + len(_TIMESTAMP_PATTERN.findall(analyst_text)),
                max(len(analyst_ttps), 1),
                cap=2.0,
            ),
            "causal_language_score": self._causal_language_score(analyst_text),
            "inference_discipline_score": self._keyword_presence_score(
                analyst_text,
                ("observed", "evidence", "inferred", "confidence", "gap", "uncertain"),
            ),
        }
        rule["score_10"] = round(
            10
            * (
                0.25 * rule["evidence_grounding_score"]
                + 0.25 * rule["causal_language_score"]
                + 0.30 * rule["ttp_reasoning_score"]
                + 0.20 * rule["inference_discipline_score"]
            ),
            4,
        )
        judge = self._judge_stage(
            stage="analyst_result",
            artifact=analyst_text,
            context=(
                f"Evidence summary:\n{evidence_summary}\n\n"
                f"Verified Hunter TTP seeds:\n{', '.join(seed_ttps) or 'None'}\n\n"
                f"MITRE graph context:\n{json.dumps(graph_context or {}, ensure_ascii=False)[:self.context_char_limit]}"
            ),
            rubric=(
                "Score Analyst macro-reasoning. Reward chronological kill-chain reconstruction, claim->evidence->reasoning "
                "structure, observed-vs-inferred discipline, and horizontal TTP expansion that is both MITRE-graph-supported "
                "and evidence-supported. Penalize graph-neighbor over-expansion without evidence."
            ),
        )
        return self._merge_rule_and_judge("analyst_result", rule, judge)

    def _evaluate_final_report(self, hunt_text, analyst_text, final_text):
        rule = self._final_report_rule_score(hunt_text, analyst_text, final_text)
        judge = self._judge_stage(
            stage="final_report",
            artifact=final_text,
            context=(
                f"Verified Hunter summary:\n{hunt_text[:self.context_char_limit]}\n\n"
                f"Analyst result summary:\n{analyst_text[:self.context_char_limit]}"
            ),
            rubric=(
                "Score final report fidelity and communication quality. Reward preservation of core Analyst/Hunter conclusions, "
                "IOCs, TTPs, timeline consistency, evidence-backed major conclusions, and clear SOC reporting. Penalize unsupported "
                "new claims, dropped critical evidence, contradictions, and poor section completeness."
            ),
        )
        return self._merge_rule_and_judge("final_report", rule, judge)

    def _hunt_rule_score(self, hunt_results, hunt_text):
        items = hunt_results if isinstance(hunt_results, list) else []
        verified = sum(1 for item in items if item.get("status") == "Verified")
        total = max(len(items), 1)
        ttp_count = len(self._extract_ttps(hunt_text))
        evidence_markers = len(_EVENT_PATTERN.findall(hunt_text)) + len(_TIMESTAMP_PATTERN.findall(hunt_text))
        ioc_markers = len(_HASH_PATTERN.findall(hunt_text)) + len(_IP_PATTERN.findall(hunt_text))
        tool_audit_count = hunt_text.lower().count("tool execution audit")

        return {
            "verified_task_ratio": round(verified / total, 4),
            "evidence_grounding_score": self._ratio_score(evidence_markers, max(ttp_count, 1), cap=2.0),
            "ioc_preservation_score": self._ratio_score(ioc_markers, total, cap=8.0),
            "tool_faithfulness_score": self._ratio_score(tool_audit_count, total, cap=1.0),
            "task_focus_score": self._keyword_presence_score(
                hunt_text,
                ("task verdict", "evidence chain", "observed iocs", "reasoning summary", "evidence gaps"),
            ),
            "score_10": round(
                10
                * (
                    0.20 * (verified / total)
                    + 0.30 * self._ratio_score(evidence_markers, max(ttp_count, 1), cap=2.0)
                    + 0.20 * self._ratio_score(ioc_markers, total, cap=8.0)
                    + 0.15 * self._ratio_score(tool_audit_count, total, cap=1.0)
                    + 0.15 * self._keyword_presence_score(
                        hunt_text,
                        ("task verdict", "evidence chain", "observed iocs", "reasoning summary", "evidence gaps"),
                    )
                ),
                4,
            ),
        }

    def _analyst_graph_rule_score(self, seed_ttps, analyst_ttps, graph_context):
        seed_set = set(seed_ttps)
        analyst_set = set(analyst_ttps)
        expanded = sorted(analyst_set - seed_set)
        if not expanded:
            supported_expansions = []
            unsupported_expansions = []
        else:
            supported_expansions = [
                technique_id
                for technique_id in expanded
                if self.ttp_graph.relation_supported(seed_set, technique_id)
            ]
            unsupported_expansions = sorted(set(expanded) - set(supported_expansions))

        candidate_ids = set()
        for relation in (graph_context or {}).get("relations", []):
            for candidate in relation.get("candidate_relations", []):
                candidate_id = candidate.get("id")
                if candidate_id:
                    candidate_ids.add(candidate_id)

        candidate_hits = sorted(candidate_ids & analyst_set)
        candidate_recall = len(candidate_hits) / len(candidate_ids) if candidate_ids else 1.0
        support_precision = (
            len(supported_expansions) / len(expanded)
            if expanded else 1.0
        )
        seed_retention = len(seed_set & analyst_set) / len(seed_set) if seed_set else 1.0
        ttp_reasoning_score = (0.55 * seed_retention) + (0.35 * support_precision) + (0.10 * min(candidate_recall * 3, 1.0))

        return {
            "seed_ttp_count": len(seed_set),
            "analyst_ttp_count": len(analyst_set),
            "expanded_ttp_count": len(expanded),
            "graph_candidate_count": len(candidate_ids),
            "graph_candidate_hits": candidate_hits,
            "supported_expansions": sorted(supported_expansions),
            "unsupported_expansions": unsupported_expansions,
            "seed_ttp_retention": round(seed_retention, 4),
            "graph_candidate_recall": round(candidate_recall, 4),
            "graph_expansion_precision": round(support_precision, 4),
            "graph_supported_expansion_score": round((0.55 * support_precision) + (0.45 * candidate_recall), 4),
            "ttp_reasoning_score": round(ttp_reasoning_score, 4),
        }

    def _final_report_rule_score(self, hunt_text, analyst_text, final_text):
        analyst_ttps = set(self._extract_ttps(analyst_text))
        final_ttps = set(self._extract_ttps(final_text))
        hunt_iocs = self._extract_ioc_set(hunt_text)
        final_iocs = self._extract_ioc_set(final_text)

        ttp_fidelity = len(analyst_ttps & final_ttps) / len(analyst_ttps) if analyst_ttps else 1.0
        ioc_fidelity = len(hunt_iocs & final_iocs) / len(hunt_iocs) if hunt_iocs else 1.0
        unsupported_ttp_ratio = (
            len(final_ttps - analyst_ttps) / len(final_ttps)
            if final_ttps else 0.0
        )
        section_score = self._keyword_presence_score(
            final_text,
            ("executive", "kill chain", "mitre", "ioc", "impact", "recommend", "evidence"),
        )
        evidence_score = self._ratio_score(
            len(_EVENT_PATTERN.findall(final_text)) + len(_TIMESTAMP_PATTERN.findall(final_text)),
            max(len(final_ttps), 1),
            cap=1.5,
        )

        return {
            "ttp_fidelity_to_analyst": round(ttp_fidelity, 4),
            "ioc_fidelity_to_hunt": round(ioc_fidelity, 4),
            "unsupported_ttp_addition_ratio": round(unsupported_ttp_ratio, 4),
            "section_completeness_score": section_score,
            "evidence_reference_score": evidence_score,
            "score_10": round(
                10
                * (
                    0.25 * ttp_fidelity
                    + 0.25 * ioc_fidelity
                    + 0.20 * (1 - unsupported_ttp_ratio)
                    + 0.15 * section_score
                    + 0.15 * evidence_score
                ),
                4,
            ),
        }

    def _merge_rule_and_judge(self, stage, rule, judge):
        rule_score = float(rule.get("score_10", 0.0))
        judge_score = judge.get("score_10") if isinstance(judge, dict) else None
        if isinstance(judge_score, (int, float)):
            score = round((0.55 * rule_score) + (0.45 * float(judge_score)), 4)
        else:
            score = round(rule_score, 4)
        return {
            "stage": stage,
            "score_10": score,
            "rule_based": rule,
            "llm_judge": judge,
        }

    def _judge_stage(self, stage, artifact, context, rubric):
        if not self.enable_llm_judge:
            return {
                "status": "skipped",
                "reason": "ENABLE_LLM_REASONING_JUDGE is not enabled; using rule-based reasoning score only.",
                "score_10": None,
            }

        prompt = (
            "You are an independent SOC reasoning evaluator. Return ONLY valid JSON.\n"
            "Do not grade based on hidden ground truth. Use only the supplied artifact and context.\n\n"
            f"Stage: {stage}\n"
            f"Rubric: {rubric}\n\n"
            "Return schema:\n"
            "{"
            "\"score_10\": number, "
            "\"evidence_grounding\": number, "
            "\"causal_coherence\": number, "
            "\"inference_discipline\": number, "
            "\"horizontal_ttp_reasoning\": number, "
            "\"fidelity_or_task_focus\": number, "
            "\"strengths\": [string], "
            "\"weaknesses\": [string]"
            "}\n\n"
            f"Context:\n{str(context)[:self.context_char_limit]}\n\n"
            f"Artifact:\n{str(artifact)[:self.artifact_char_limit]}"
        )
        try:
            result = self.llm.invoke(prompt).content
            parsed = self.parser.parse(result)
            if isinstance(parsed, dict):
                parsed["status"] = "ok"
                return parsed
        except Exception as error:
            return {
                "status": "error",
                "error": str(error),
                "score_10": None,
            }
        return {"status": "error", "error": "Judge did not return a JSON object.", "score_10": None}

    def _evidence_summary(self, evidence_store):
        if not isinstance(evidence_store, dict):
            return "{}"
        compact = {
            "dataset": evidence_store.get("dataset", {}),
            "observable_types": {
                key: len(value)
                for key, value in (evidence_store.get("observables") or {}).items()
            },
            "event_count": len(evidence_store.get("events", [])),
        }
        return json.dumps(compact, ensure_ascii=False, indent=2)

    def _extract_ttps(self, text):
        return sorted({match.upper() for match in _TTP_PATTERN.findall(str(text or ""))})

    def _extract_ioc_set(self, text):
        value = str(text or "").lower()
        iocs = set(_HASH_PATTERN.findall(value)) | set(_IP_PATTERN.findall(value))
        iocs.update(match.rstrip(".,;:)`").lower() for match in _URL_PATTERN.findall(value))
        iocs.update(match.rstrip(".,;:)`").lower() for match in _DOMAIN_PATTERN.findall(value))
        iocs.update(match.rstrip(".,;:)`").lower() for match in _FILE_PATTERN.findall(value))
        for match in _WINDOWS_PATH_PATTERN.findall(str(text or "")):
            normalized = match.strip().strip("`\"'").rstrip(".,;:)")
            while "\\\\" in normalized:
                normalized = normalized.replace("\\\\", "\\")
            if normalized:
                iocs.add(normalized.lower())
        return iocs

    def _to_text(self, value):
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, default=str)

    def _ratio_score(self, numerator, denominator, cap=1.0):
        if denominator <= 0:
            return 1.0
        return round(min(float(numerator) / (float(denominator) * cap), 1.0), 4)

    def _keyword_presence_score(self, text, keywords):
        lowered = str(text or "").lower()
        if not keywords:
            return 1.0
        hits = sum(1 for keyword in keywords if keyword.lower() in lowered)
        return round(hits / len(keywords), 4)

    def _causal_language_score(self, text):
        return self._keyword_presence_score(
            text,
            ("because", "therefore", "followed", "led to", "after", "using", "chain", "sequence"),
        )

    def _env_flag(self, name, default=False):
        value = os.getenv(name)
        if value is None:
            return default
        return value.strip().lower() in {"1", "true", "yes", "y", "on", "enabled"}

    def _env_int(self, name, default):
        value = os.getenv(name)
        if not value:
            return default
        try:
            return max(500, int(value))
        except ValueError:
            return default
