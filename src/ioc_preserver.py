import json
import re
from collections import defaultdict


_HASH_PATTERN = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|info|biz|vn|io|ru|xyz)\b"
)
_FILE_PATTERN = re.compile(
    r"\b[^\s\\/:*?\"<>|]+\.(?:exe|dll|bat|ps1|vbs|txt|bin|cab|js|sh|docx|pdf|doc|xlsx|xls|zip|rar)\b",
    re.IGNORECASE,
)
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\r\n\"'<>|]+")


class IOCPreservationVerifier:
    """Preserve IOC values inferred/extracted by the Hunter stage across downstream stages."""

    def build_hunter_baseline(self, hunt_results):
        baseline = defaultdict(set)
        for item in hunt_results or []:
            if item.get("status") != "Verified":
                continue
            artifact = item.get("artifact") or {}
            observables = artifact.get("observables") or {}
            for observable_type, values in observables.items():
                category = self._category(observable_type)
                for value in values or []:
                    self._add_value(baseline, category, value)

        return self._freeze(baseline)

    def extract_iocs(self, value):
        text = self._to_text(value)
        extracted = defaultdict(set)

        for url in _URL_PATTERN.findall(text):
            self._add_value(extracted, "urls", url)
        for ip in _IP_PATTERN.findall(text):
            self._add_value(extracted, "ips", ip)
        for domain in _DOMAIN_PATTERN.findall(text):
            if not self._looks_like_file(domain):
                self._add_value(extracted, "domains", domain.lower())
        for file_name in _FILE_PATTERN.findall(text):
            category = "processes" if file_name.lower().endswith(".exe") else "files"
            self._add_value(extracted, category, file_name)
        for path in _WINDOWS_PATH_PATTERN.findall(text):
            self._add_value(extracted, "paths", path)
        for digest in _HASH_PATTERN.findall(text):
            self._add_value(extracted, "hashes", digest.lower())

        return self._freeze(extracted)

    def verify_stage(self, expected, stage_output):
        found = self.extract_iocs(stage_output)
        missing = {}
        retained = {}

        for category, values in (expected or {}).items():
            expected_set = set(values)
            found_set = self._equivalent_found_set(found, category)
            retained_set = expected_set & found_set
            missing_set = expected_set - found_set
            if retained_set:
                retained[category] = sorted(retained_set)
            if missing_set:
                missing[category] = sorted(missing_set)

        total_expected = sum(len(values) for values in (expected or {}).values())
        total_missing = sum(len(values) for values in missing.values())
        retention = 1.0 if total_expected == 0 else (total_expected - total_missing) / total_expected

        return {
            "expected_count": total_expected,
            "missing_count": total_missing,
            "retention": round(retention, 4),
            "missing": missing,
            "retained": retained,
        }

    def merge_missing_into_expected(self, expected, missing):
        merged = defaultdict(set)
        for category, values in (expected or {}).items():
            merged[category].update(values or [])
        for category, values in (missing or {}).items():
            merged[category].update(values or [])
        return self._freeze(merged)

    def format_context(self, iocs, title="Verified IOC preservation context"):
        if not iocs:
            return ""
        lines = [
            title,
            "These IOCs were extracted and preserved from verified Hunter-stage findings. Preserve them verbatim downstream unless explicitly contradicted by evidence.",
        ]
        for category in ("ips", "domains", "urls", "hashes", "processes", "files", "paths", "other"):
            values = sorted(set(iocs.get(category, [])))
            if values:
                lines.append(f"- {category}: " + ", ".join(f"`{value}`" for value in values))
        return "\n".join(lines)

    def format_fallback_section(self, missing, source_stage):
        if not missing:
            return ""
        return self.format_context(
            missing,
            title=f"Verified IOC Preservation Fallback from {source_stage}",
        )

    def _merge_extracted(self, target, extracted):
        for category, values in (extracted or {}).items():
            target[category].update(values or [])

    def _add_value(self, target, category, value):
        value = self._clean_value(category, value)
        if not value:
            return
        target[category].add(value)
        if category == "files" and self._is_executable_like(value):
            target["processes"].add(value)
        elif category == "processes" and self._looks_like_file(value):
            target["files"].add(value)

    def _equivalent_found_set(self, found, category):
        values = set(found.get(category, []))
        if category == "files":
            values |= {value for value in found.get("processes", []) if self._looks_like_file(value)}
        elif category == "processes":
            values |= {value for value in found.get("files", []) if self._is_executable_like(value)}
        return values

    def _clean_value(self, category, value):
        value = str(value or "").strip().strip("`\"'").rstrip(".,;:)")
        if not value:
            return ""
        while "\\\\" in value:
            value = value.replace("\\\\", "\\")
        if category == "hashes":
            return value.lower()
        if category == "domains":
            lowered = value.lower()
            if lowered in {"mitre.org", "attack.mitre.org"}:
                return ""
            return lowered
        if category == "paths":
            return self._clean_path(value)
        return value

    def _clean_path(self, value):
        value = value.strip().strip("`\"'")
        for marker in ("`", " (", ";", ",", " with ", " and ", " flagged ", " executed ", " are "):
            index = value.find(marker)
            if index > 0:
                value = value[:index]
        value = re.sub(r"\s+-[A-Za-z].*$", "", value)

        file_match = re.match(
            r"^[A-Za-z]:\\.*?\.(?:exe|dll|bat|ps1|vbs|js|docx?|xlsx?|zip|rar|7z|txt|cab|bin)\b",
            value,
            re.IGNORECASE,
        )
        if file_match:
            return file_match.group(0).rstrip("\\")

        dir_match = re.match(r"^[A-Za-z]:\\[^\r\n\"'<>|,;`)]*", value)
        if dir_match:
            return dir_match.group(0).strip().rstrip(" .")
        return value.rstrip(" .")

    def _category(self, observable_type):
        key = str(observable_type or "").lower()
        if key in {"ip", "ips", "ip_addresses"}:
            return "ips"
        if key in {"domain", "domains", "host", "hosts"}:
            return "domains"
        if key in {"url", "urls"}:
            return "urls"
        if key in {"md5", "sha1", "sha256", "hash", "hashes"}:
            return "hashes"
        if key in {"file", "files"}:
            return "files"
        if key in {"process", "processes"}:
            return "processes"
        if key in {"path", "paths"}:
            return "paths"
        return "other"

    def _looks_like_file(self, value):
        return bool(_FILE_PATTERN.fullmatch(str(value or "")))

    def _is_executable_like(self, value):
        return str(value or "").lower().endswith((".exe", ".dll", ".bat", ".ps1", ".vbs", ".js"))

    def _to_text(self, value):
        if isinstance(value, str):
            return value
        return json.dumps(value, ensure_ascii=False, default=str)

    def _freeze(self, mapping):
        return {
            category: sorted({str(value) for value in values if str(value).strip()})
            for category, values in sorted((mapping or {}).items())
            if values
        }
