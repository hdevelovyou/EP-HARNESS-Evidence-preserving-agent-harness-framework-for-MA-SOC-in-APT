import ipaddress
import json
import os
import re

from dotenv import load_dotenv
from langchain_core.output_parsers import JsonOutputParser
from langchain_openai import ChatOpenAI

from src.domain_pack import load_domain_pack

load_dotenv()

_DEFAULT_FILE_EXTENSIONS = (
    "7z", "aspx", "bat", "bin", "cab", "cmd", "db", "dit", "dll", "dmp",
    "doc", "docm", "docx", "exe", "hta", "js", "jse", "lnk", "log", "msi",
    "pdf", "ps1", "py", "rar", "sh", "sys", "tmp", "txt", "url", "vbs",
    "xls", "xlsx", "xml", "zip",
)
_DEFAULT_DOMAIN_TLDS = (
    "com", "net", "org", "info", "biz", "vn", "io", "ru", "xyz",
    "top", "cc", "cn", "gov", "edu", "mil", "uk", "de", "fr", "jp",
    "kr", "cloud", "online", "site", "tech", "dev", "app", "me", "co",
    "us", "in", "br", "au", "ca",
)


class SOCEvaluator:
    """Post-seal evaluation engine. Must ONLY be invoked after FINAL_REPORT_SOC.md is sealed."""

    def __init__(self, domain_pack=None):
        self._llm = None
        self.parser = JsonOutputParser()
        self.openai_input_tokens = 0
        self.openai_output_tokens = 0

        pack = domain_pack if isinstance(domain_pack, dict) else load_domain_pack()
        curator_cfg = pack.get("ioc_curator", {})
        tools_cfg = pack.get("tools", {})

        raw_exts = (
            curator_cfg.get("file_pattern_extensions")
            or tools_cfg.get("pattern_file_suffixes")
            or list(_DEFAULT_FILE_EXTENSIONS)
        )
        exts = sorted({str(ext).lower().lstrip(".") for ext in raw_exts if ext} | set(_DEFAULT_FILE_EXTENSIONS))
        ext_union = "|".join(re.escape(ext) for ext in exts)
        self._entity_file_pattern = re.compile(
            rf"\b(?:[a-zA-Z]:\\[\\\w\.-]+)?\\?[\w\.-]+\.(?:{ext_union})\b",
            re.IGNORECASE,
        )
        self._ioc_file_pattern = re.compile(
            rf"\b[\w\.-]+\.(?:{ext_union})\b",
            re.IGNORECASE,
        )

        raw_tlds = curator_cfg.get("domain_tlds") or list(_DEFAULT_DOMAIN_TLDS)
        tlds = sorted({str(tld).lower().lstrip(".") for tld in raw_tlds if tld} | set(_DEFAULT_DOMAIN_TLDS))
        tld_union = "|".join(re.escape(tld) for tld in tlds)
        self._domain_pattern = re.compile(
            rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{tld_union})\b",
            re.IGNORECASE,
        )
        self._file_suffix_set = set(exts)

    @property
    def llm(self):
        if self._llm is None:
            self._llm = ChatOpenAI(
                model="gpt-4o",
                api_key=os.getenv("OPENAI_API_KEY"),
                temperature=0,
            )
        return self._llm

    def _extract_entities(self, text, source_type="log"):
        """Rule-based entity extraction used strictly for post-seal evaluation metrics."""
        if isinstance(text, dict):
            text = json.dumps(text)
        elif isinstance(text, list):
            text = "\n".join(str(item) for item in text)
        else:
            text = str(text)

        normalized_text = self._defang_to_plain(text)
        entities = {
            "ips": [],
            "hosts": [],
            "users": [],
            "processes": [],
            "files": [],
            "techniques": [],
            "hashes": [],
        }

        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        entities["ips"] = sorted(set(re.findall(ip_pattern, normalized_text)))

        tech_pattern = r"\bT\d{4}(?:\.\d{3})?\b"
        entities["techniques"] = sorted(set(re.findall(tech_pattern, normalized_text)))

        found_files = sorted(set(self._entity_file_pattern.findall(normalized_text)))
        for file_name in found_files:
            if file_name.lower().endswith(".exe"):
                entities["processes"].append(file_name)
            else:
                entities["files"].append(file_name)

        found_domains = set()
        for domain in self._domain_pattern.findall(normalized_text):
            suffix = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
            if suffix in self._file_suffix_set:
                continue
            found_domains.add(domain)
        entities["hosts"] = sorted(found_domains)

        user_pattern = r"\b[A-Za-z0-9_ -]+\\[A-Za-z0-9_-]+\b"
        found_users = re.findall(user_pattern, normalized_text)
        entities["users"] = sorted(set(
            user for user in found_users
            if not user.lower().endswith((".exe", ".dll", ".sys"))
        ))

        hash_pattern = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"
        text_without_imphash = re.sub(r"\bIMPHASH=[0-9a-fA-F]{32}\b", "", normalized_text, flags=re.IGNORECASE)
        entities["hashes"] = sorted(set(re.findall(hash_pattern, text_without_imphash)))

        return entities

    def compare_entities(self, pre_json, post_json):
        metrics = {}
        all_categories = [
            "ips",
            "hosts",
            "users",
            "processes",
            "files",
            "techniques",
            "hashes",
        ]

        total_g_log = 0
        total_p_agent = 0
        total_intersection = 0
        enrichment_entities = []

        for cat in all_categories:
            g_log_set = set(pre_json.get(cat, []))
            p_agent_set = set(post_json.get(cat, []))
            intersection = g_log_set.intersection(p_agent_set)
            extras = p_agent_set - g_log_set

            for entity in extras:
                enrichment_entities.append({"type": cat, "value": entity})

            total_g_log += len(g_log_set)
            total_p_agent += len(p_agent_set)
            total_intersection += len(intersection)

            metrics[cat] = {
                "needed": sorted(g_log_set),
                "found": sorted(intersection),
                "missing": sorted(g_log_set - p_agent_set),
                "extra_enrichment": sorted(extras),
            }

        precision = (total_intersection / total_p_agent) if total_p_agent > 0 else 0.0
        recall = (total_intersection / total_g_log) if total_g_log > 0 else 1.0
        f1_score = (
            2 * (precision * recall) / (precision + recall)
            if precision + recall > 0
            else 0.0
        )

        return {
            "layer_1_metrics": {
                "precision": round(precision, 4),
                "recall": round(recall, 4),
                "f1_score": round(f1_score, 4),
            },
            "enrichment_list": enrichment_entities,
            "details": metrics,
        }

    def _flatten_to_strings(self, data_list):
        result = []
        for item in data_list:
            if isinstance(item, dict):
                result.extend(self._flatten_to_strings(item.values()))
            elif isinstance(item, list) or isinstance(item, tuple):
                result.extend(self._flatten_to_strings(item))
            else:
                result.append(str(item).strip())
        return result

    def _defang_to_plain(self, value):
        return (
            str(value)
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _normalize_techniques(self, values):
        techniques = set()
        for value in self._flatten_to_strings(values):
            for match in re.findall(r"\bT\d{4}(?:\.\d{3})?\b", value, re.IGNORECASE):
                techniques.add(match.upper())
        return techniques

    def _normalize_iocs(self, values):
        normalized = set()
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"
        hash_pattern = r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b"

        for raw_value in self._flatten_to_strings(values):
            value = self._defang_to_plain(raw_value).strip().lower()
            if not value:
                continue

            extracted = set()
            for match in re.findall(ip_pattern, value):
                if self._is_public_ip(match):
                    extracted.add(match.lower())
            for domain in self._domain_pattern.findall(value):
                suffix = domain.rsplit(".", 1)[-1].lower() if "." in domain else ""
                if suffix not in self._file_suffix_set:
                    extracted.add(domain.lower())
            extracted.update(match.lower() for match in self._ioc_file_pattern.findall(value))
            text_without_imphash = re.sub(r"\bimphash=[0-9a-f]{32}\b", "", value, flags=re.IGNORECASE)
            extracted.update(match.lower() for match in re.findall(hash_pattern, text_without_imphash))

            normalized.update(extracted)

        return normalized

    def _is_public_ip(self, value):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
        )

    def _set_metrics(self, expected, found):
        intersection = expected.intersection(found)
        union = expected.union(found)
        precision = len(intersection) / len(found) if found else 0.0
        recall = len(intersection) / len(expected) if expected else 1.0
        f1 = (
            2 * precision * recall / (precision + recall)
            if precision + recall > 0
            else 0.0
        )
        jaccard = len(intersection) / len(union) if union else 0.0
        return {
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "jaccard": jaccard,
            "matched": intersection,
        }

    def calculate_layer_2_jaccard(self, ground_truth, ma_entities, w_i=0.7, w_j=0.3):
        t_expert = self._normalize_techniques(ground_truth.get("T_expert", []))

        i_expert_dict = ground_truth.get("I_expert", {})
        i_expert_raw = (
            i_expert_dict.get("atomic", [])
            + i_expert_dict.get("computed", [])
        )
        i_expert = self._normalize_iocs(i_expert_raw)

        t_ma = self._normalize_techniques(ma_entities.get("techniques", []))

        ma_ioc_values = []
        for cat in ["ips", "hosts", "processes", "files", "hashes"]:
            ma_ioc_values.extend(ma_entities.get(cat, []))
        i_ma = self._normalize_iocs(ma_ioc_values)

        t_metrics = self._set_metrics(t_expert, t_ma)
        i_metrics = self._set_metrics(i_expert, i_ma)

        score_l2 = (w_i * t_metrics["f1"]) + (w_j * i_metrics["f1"])
        jaccard_l2 = (w_i * t_metrics["jaccard"]) + (w_j * i_metrics["jaccard"])
        score_10 = round(score_l2 * 10, 2)

        return {
            "enrichment_quality_score": score_10,
            "weighted_f1_score": round(score_l2, 4),
            "weighted_jaccard_score": round(jaccard_l2, 4),
            "jaccard_ttps": round(t_metrics["jaccard"], 4),
            "jaccard_iocs": round(i_metrics["jaccard"], 4),
            "f1_ttps": round(t_metrics["f1"], 4),
            "f1_iocs": round(i_metrics["f1"], 4),
            "precision_ttps": round(t_metrics["precision"], 4),
            "precision_iocs": round(i_metrics["precision"], 4),
            "recall_ttps": round(t_metrics["recall"], 4),
            "recall_iocs": round(i_metrics["recall"], 4),
            "weights_used": {"w_i (TTPs)": w_i, "w_j (IOCs)": w_j},
            "details": {
                "TTPs": {
                    "expert_expected": sorted(t_expert),
                    "agent_found": sorted(t_ma),
                    "matched": sorted(t_metrics["matched"]),
                },
                "IOCs": {
                    "expert_expected": sorted(i_expert),
                    "agent_found": sorted(i_ma),
                    "matched": sorted(i_metrics["matched"]),
                },
            },
        }
