import re


_TTP_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_TIMESTAMP_PATTERN = re.compile(r"\b\d{4}-\d{2}-\d{2}T[^\s,;]+")
_SIGNAL_TERMS = (
    "evidence", "observed", "execut", "created", "deleted", "access", "connect",
    "credential", "persist", "inject", "encrypt", "exfiltrat", "disable", "malicious",
    "suspicious", "confidence", "gap", "verdict", "supported", "unsupported",
)


class SummarizerAgent:
    """Deterministically compress verified task output into a bounded DAG artifact."""

    def __init__(self, max_summary_chars=2400, max_observables=120):
        self.max_summary_chars = max_summary_chars
        self.max_observables = max_observables

    def summarize(self, task, hunter_output, evidence_store=None, status="Verified", reason=None):
        clean_output = self._strip_tool_audit(str(hunter_output or ""))
        summary = self._evidence_dense_summary(clean_output)
        artifact = {
            "task_id": task.get("id"),
            "task_name": task.get("name"),
            "status": status,
            "produces": list(task.get("produces", [])),
            "summary": summary,
            "ttp_candidates": sorted({value.upper() for value in _TTP_PATTERN.findall(clean_output)}),
            "timestamps": sorted(set(_TIMESTAMP_PATTERN.findall(clean_output)))[:40],
            "observables": self._observables_in_output(clean_output, evidence_store),
            "source_chars": len(str(hunter_output or "")),
            "summary_chars": len(summary),
        }
        if reason:
            artifact["reason"] = str(reason)[:800]
        return artifact

    def compact_for_retry(self, artifact):
        parts = [
            f"Task: {artifact.get('task_id')} - {artifact.get('task_name')}",
            f"Status: {artifact.get('status')}",
            f"Summary: {artifact.get('summary', '')}",
        ]
        if artifact.get("ttp_candidates"):
            parts.append("TTP candidates: " + ", ".join(artifact["ttp_candidates"]))
        if artifact.get("observables"):
            flattened = []
            for observable_type, values in artifact["observables"].items():
                flattened.append(f"{observable_type}: {', '.join(values)}")
            parts.append("Observed values: " + "; ".join(flattened))
        return "\n".join(parts)

    def _strip_tool_audit(self, text):
        marker = text.find("Tool Execution Audit:")
        return text[:marker].strip() if marker >= 0 else text.strip()

    def _evidence_dense_summary(self, text):
        lines = []
        seen = set()
        for raw_line in text.splitlines():
            line = " ".join(raw_line.strip().split())
            if not line or line.lower() in seen:
                continue
            lowered = line.lower()
            if line.startswith(("#", "-", "*")) or any(term in lowered for term in _SIGNAL_TERMS):
                lines.append(line)
                seen.add(lowered)

        if not lines:
            lines = [" ".join(text.split())]

        summary_parts = []
        current_length = 0
        for line in lines:
            addition = len(line) + (1 if summary_parts else 0)
            if current_length + addition > self.max_summary_chars:
                remaining = self.max_summary_chars - current_length
                if remaining > 80:
                    summary_parts.append(line[:remaining].rstrip())
                break
            summary_parts.append(line)
            current_length += addition
        return "\n".join(summary_parts).strip()

    def _observables_in_output(self, text, evidence_store):
        if not evidence_store:
            return {}
        lowered = text.lower()
        matches = {}
        remaining = self.max_observables
        for observable_type, entries in evidence_store.get("observables", {}).items():
            values = []
            for entry in entries:
                value = str(entry.get("value", ""))
                if value and value.lower() in lowered:
                    values.append(value)
                    remaining -= 1
                    if remaining <= 0:
                        break
            if values:
                matches[observable_type] = values
            if remaining <= 0:
                break
        return matches
