import ipaddress
import json
import os
import re
from collections import defaultdict

from src.domain_pack import load_domain_pack


DEFAULT_TASK_EVENT_LIMIT = 120

_HASH_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\(?:\\)?[^\r\n\"'<>|]+")
_WINDOWS_USER_PATTERN = re.compile(r"\b[A-Za-z0-9_ -]+\\[A-Za-z0-9_$-]+\b")
_TTP_LEAK_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)

_FORBIDDEN_KEY_NAMES = {
    "mitre",
    "mitre_id",
    "mitre_ids",
    "mitre_technique",
    "mitre_techniques",
    "mitre_tactic",
    "mitre_tactics",
    "mitre_groups",
    "threat",
    "scenario_id",
    "scenrario_id",
    "scenario_name",
    "case_name",
    "ground_truth",
    "simulated_techniques",
    "simulated_tactics",
    "simiulated_tactics",
    "expected_artifacts",
}

_FORBIDDEN_DOTTED_PREFIXES = (
    "rule.mitre",
    "_source.rule.mitre",
    "threat.",
    "_source.threat.",
)

_TASK_HINTS = {
    "T1": ("malware", "process", "executable", "image", "dll", "script", "originalfilename"),
    "T2": ("signature", "hash", "hashes", "malware", "process", "image"),
    "T3": ("timestamp", "time", "sequence", "utctime", "systemtime"),
    "T4": ("organization", "domain", "user", "actor", "company"),
    "T5": ("country", "region", "language", "timezone"),
    "T6": ("victim", "host", "computer", "user", "organization"),
    "T7": ("ip", "ipaddress", "domain", "queryname", "url", "hash", "hashes", "file", "targetfilename", "path", "network", "dns"),
    "T8": ("actor", "malware", "signature", "infrastructure"),
    "T9": ("campaign", "actor", "malware", "infrastructure"),
    "T10": ("file", "targetfilename", "create", "creationutctime", "delete", "write", "path", "registry", "targetobject"),
    "T11": ("network", "dns", "queryname", "source", "destination", "ipaddress", "ipport", "connect", "port", "url"),
    "T12": ("credential", "lsass", "grantedaccess", "targetimage", "password", "token", "ntds", "sam", "security"),
    "T13": ("process", "image", "user", "parent", "parentimage", "command_line", "commandline", "execution"),
    "T14": ("command", "commandline", "parentcommandline", "powershell", "script", "cmd.exe", "arguments"),
    "T15": ("privilege", "integritylevel", "elevatedtoken", "admin", "system", "elevat", "token"),
    "T16": ("disable", "defender", "evasion", "obfuscat", "clear", "logfilecleared", "delete", "masquerad"),
    "T17": ("timestamp", "sequence", "event", "process", "network", "file"),
    "T18": ("process", "command", "commandline", "file", "network", "credential", "persistence"),
    "T19": ("initial", "access", "network", "execution"),
    "T20": ("complexity", "condition", "prerequisite", "access"),
    "T21": ("privilege", "user", "integritylevel", "admin", "system"),
    "T22": ("user", "document", "download", "click", "execution"),
    "T23": ("host", "computer", "network", "remote", "lateral", "component"),
    "T24": ("impact", "encrypt", "delete", "exfiltrat", "credential"),
    "T25": ("impact", "privilege", "scope", "complexity", "access"),
    "T26": ("contain", "respond", "host", "process", "network"),
    "T27": ("control", "firewall", "edr", "defender", "policy"),
    "T28": ("vulnerability", "code", "patch", "exploit"),
    "T29": ("tool", "patch", "mitigat", "technique"),
    "T30": ("cve", "advisory", "vulnerability", "technique"),
}


def _resolve_default_event_limit(default_event_limit=None):
    if default_event_limit is not None:
        return int(default_event_limit)
    env_val = os.getenv("TASK_EVENT_LIMIT")
    if env_val and env_val.strip():
        try:
            return max(1, int(env_val.strip()))
        except ValueError:
            pass
    return DEFAULT_TASK_EVENT_LIMIT


class EvidenceExtractor:
    """Build a leakage-free observable inventory and compact, task-scoped event views."""

    def __init__(self, default_event_limit=None, domain_pack=None):
        self.default_event_limit = _resolve_default_event_limit(default_event_limit)
        pack = domain_pack if isinstance(domain_pack, dict) else load_domain_pack()
        tools_cfg = pack.get("tools", {})
        curator_cfg = pack.get("ioc_curator", {})

        suffixes = tools_cfg.get("file_suffixes") or [
            "7z", "bat", "bin", "cab", "cmd", "db", "dll", "dmp", "doc", "docx",
            "exe", "hta", "js", "jse", "json", "lnk", "log", "msi", "pdf", "ps1",
            "py", "rar", "sh", "sys", "tmp", "txt", "url", "vbs", "xls", "xlsx",
            "xml", "zip",
        ]
        self.file_suffixes = {str(s).lower().lstrip(".") for s in suffixes if s}

        pattern_suffixes = tools_cfg.get("pattern_file_suffixes") or suffixes
        escaped_exts = "|".join(
            re.escape(str(s).lower().lstrip(".")) for s in pattern_suffixes if s
        )
        self.file_pattern = re.compile(
            rf"\b[^\s\\/:*?\"<>|`]+\.(?:{escaped_exts})\b",
            re.IGNORECASE,
        )

        tlds = [re.escape(str(tld).lower().lstrip(".")) for tld in curator_cfg.get("domain_tlds", []) if tld]
        if tlds:
            self.domain_pattern = re.compile(
                rf"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{{0,61}}[a-zA-Z0-9])?\.)+(?:{'|'.join(tlds)})\b",
                re.IGNORECASE,
            )
        else:
            self.domain_pattern = re.compile(
                r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b"
            )

    def sanitize_payload(self, raw_log):
        """Recursively strip rule.mitre.*, threat.*, and scenario IDs from raw payload."""
        payload = self._parse_payload(raw_log)
        return self._strip_forbidden(payload)

    def sanitize_raw_log(self, raw_log):
        """Return a JSON string of the scenario with all forbidden label fields removed."""
        sanitized = self.sanitize_payload(raw_log)
        return json.dumps(sanitized, ensure_ascii=False, indent=2)

    def extract(self, raw_log):
        payload = self.sanitize_payload(raw_log)
        events = self._get_events(payload)
        normalized_events = []
        observables = defaultdict(lambda: defaultdict(set))
        seen_event_ids = set()

        for index, event in enumerate(events):
            normalized = self._normalize_event(event, index, seen_event_ids)
            normalized_events.append(normalized)
            string_parts = []
            self._collect_strings(normalized, string_parts)
            event_text = "\n".join(string_parts)
            for observable_type, values in self._extract_observables(event_text).items():
                for value in values:
                    observables[observable_type][value].add(normalized["event_id"])

        inventory = {}
        for observable_type, values in sorted(observables.items()):
            inventory[observable_type] = [
                {
                    "value": value,
                    "event_ids": sorted(event_ids),
                    "occurrences": len(event_ids),
                }
                for value, event_ids in sorted(values.items())
            ]

        return {
            "dataset": self._dataset_metadata(payload, len(events)),
            "observables": inventory,
            "events": normalized_events,
        }

    def build_entity_inventory(self, evidence_store):
        """Build runtime entity inventory strictly from EvidenceExtractor (no Evaluator, no TTP labels)."""
        observables = (evidence_store or {}).get("observables", {})
        events = (evidence_store or {}).get("events", [])

        ips = {str(entry["value"]) for entry in observables.get("ip", []) if entry.get("value")}
        domains = {str(entry["value"]) for entry in observables.get("domain", []) if entry.get("value")}
        hosts = set(domains)
        users = set()
        processes = set()
        files = set()
        hashes = set()

        for hash_key in ("md5", "sha1", "sha256"):
            for entry in observables.get(hash_key, []):
                if entry.get("value"):
                    hashes.add(str(entry["value"]).lower())

        for obs_key in ("file", "path"):
            for entry in observables.get(obs_key, []):
                val = str(entry.get("value", "")).strip()
                if not val:
                    continue
                if val.lower().endswith(".exe"):
                    processes.add(val)
                else:
                    files.add(val)

        for event in events:
            if not isinstance(event, dict):
                continue
            host_obj = event.get("host")
            if isinstance(host_obj, dict) and host_obj.get("name"):
                hosts.add(str(host_obj["name"]))
            winlog_obj = event.get("winlog")
            if isinstance(winlog_obj, dict) and winlog_obj.get("computer"):
                hosts.add(str(winlog_obj["computer"]))

            user_obj = event.get("user")
            if isinstance(user_obj, dict):
                domain_part = user_obj.get("domain")
                name_part = user_obj.get("name")
                if domain_part and name_part:
                    users.add(f"{domain_part}\\{name_part}")
                elif name_part:
                    users.add(str(name_part))
            elif isinstance(user_obj, str) and user_obj.strip():
                users.add(user_obj.strip())

            eventdata = event.get("eventdata")
            if isinstance(eventdata, dict):
                for ukey in ("user", "parentUser"):
                    uval = str(eventdata.get(ukey, "")).strip().replace("\\\\", "\\")
                    if uval and uval != "-":
                        users.add(uval)
                subj_dom = str(eventdata.get("subjectDomainName", "")).strip()
                subj_usr = str(eventdata.get("subjectUserName", "")).strip()
                if subj_dom and subj_usr and subj_usr != "-":
                    users.add(f"{subj_dom}\\{subj_usr}")
                tgt_dom = str(eventdata.get("targetDomainName", "")).strip()
                tgt_usr = str(eventdata.get("targetUserName", "")).strip()
                if tgt_dom and tgt_usr and tgt_usr != "-":
                    users.add(f"{tgt_dom}\\{tgt_usr}")

        return {
            "ips": sorted(ips),
            "hosts": sorted(hosts),
            "users": sorted(users),
            "processes": sorted(processes),
            "files": sorted(files),
            "hashes": sorted(hashes),
        }

    def extract_entities_from_text(self, text):
        """Deterministic runtime observable parser for continuity audits (replaces SOCEvaluator in runtime)."""
        if isinstance(text, (dict, list)):
            raw_text = json.dumps(text, ensure_ascii=False)
        else:
            raw_text = str(text or "")

        normalized_text = self._defang_to_plain(raw_text).replace("\\\\", "\\")
        obs = self._extract_observables(normalized_text)

        processes = set()
        files = set()
        for item in obs.get("file", set()) | obs.get("path", set()):
            if str(item).lower().endswith(".exe"):
                processes.add(item)
            else:
                files.add(item)

        found_users = {
            user
            for user in _WINDOWS_USER_PATTERN.findall(normalized_text)
            if not user.lower().endswith((".exe", ".dll", ".sys", ".bat", ".ps1"))
        }

        hashes = set()
        for htype in ("md5", "sha1", "sha256"):
            hashes.update(obs.get(htype, set()))

        return {
            "ips": sorted(obs.get("ip", set())),
            "hosts": sorted(obs.get("domain", set())),
            "users": sorted(found_users),
            "processes": sorted(processes),
            "files": sorted(files),
            "hashes": sorted(hashes),
        }

    def build_task_view(self, task, evidence_store):
        task_id = task.get("id", "")
        events = evidence_store.get("events", [])
        hints = self._task_hints(task)
        scored = []

        for index, event in enumerate(events):
            text = json.dumps(event, ensure_ascii=False, default=str).lower()
            score = sum(1 for hint in hints if hint and hint in text)
            scored.append((score, index, event))

        broad_timeline_task = task_id in {"T17", "T18"}
        event_limit = len(events) if broad_timeline_task else self.default_event_limit
        ranked = sorted(scored, key=lambda item: (-item[0], item[1]))
        selected = [item[2] for item in ranked[:event_limit]]
        selected.sort(key=lambda event: (event.get("timestamp", ""), self._event_sort_num(event.get("event_id", ""))))

        selected_ids = {event["event_id"] for event in selected}
        include_all_observables = task_id in {"T7", "T17", "T18"}
        observables = self._filter_observables(
            evidence_store.get("observables", {}),
            selected_ids,
            include_all=include_all_observables,
        )

        view = {
            "evidence_view": {
                "task_id": task_id,
                "task_name": task.get("name", ""),
                "target": task.get("target", ""),
                "source_event_count": evidence_store.get("dataset", {}).get("event_count", len(events)),
                "selected_event_count": len(selected),
            },
            "observable_inventory": observables,
            "events": selected,
        }
        return json.dumps(view, ensure_ascii=False, indent=2)

    def build_analysis_context(self, evidence_store):
        return json.dumps({
            "dataset": evidence_store.get("dataset", {}),
            "observable_inventory": evidence_store.get("observables", {}),
            "events": evidence_store.get("events", []),
        }, ensure_ascii=False, indent=2)

    def _event_sort_num(self, event_id):
        match = re.search(r"\d+", str(event_id or ""))
        return int(match.group(0)) if match else 0

    def _is_forbidden_key(self, key_str, dotted_path=""):
        norm_key = str(key_str or "").strip().lower()
        norm_path = str(dotted_path or norm_key).strip().lower()

        if norm_key in _FORBIDDEN_KEY_NAMES:
            return True
        if any(norm_path == prefix.rstrip(".") or norm_path.startswith(prefix) for prefix in _FORBIDDEN_DOTTED_PREFIXES):
            return True
        if ".rule.mitre" in norm_path or norm_path.startswith("rule.mitre"):
            return True
        if ".threat." in norm_path or norm_path.endswith(".threat") or norm_path.startswith("threat."):
            return True
        if "mitre" in norm_key or "scenario_id" in norm_key or "scenrario_id" in norm_key:
            return True
        return False

    def _strip_forbidden(self, value, path_prefix=""):
        if isinstance(value, dict):
            cleaned = {}
            for key, item in value.items():
                key_str = str(key)
                dotted = f"{path_prefix}.{key_str}" if path_prefix else key_str
                if self._is_forbidden_key(key_str, dotted):
                    continue
                if key_str.lower().endswith("rulename") and isinstance(item, str):
                    if _TTP_LEAK_PATTERN.search(item) or "technique_id" in item.lower():
                        continue
                cleaned[key] = self._strip_forbidden(item, dotted)
            return cleaned
        if isinstance(value, list):
            return [self._strip_forbidden(item, path_prefix) for item in value]
        return value

    def _parse_payload(self, raw_log):
        if isinstance(raw_log, (dict, list)):
            return raw_log
        try:
            return json.loads(raw_log)
        except (TypeError, json.JSONDecodeError):
            return {"events": [{"message": str(raw_log)}]}

    def _get_events(self, payload):
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict) and isinstance(payload.get("events"), list):
            return payload["events"]
        return [payload]

    def _dataset_metadata(self, payload, event_count):
        if not isinstance(payload, dict):
            return {"event_count": event_count}
        metadata = {
            key: value
            for key, value in payload.items()
            if key != "events"
            and not self._is_forbidden_key(key)
            and isinstance(value, (str, int, float, bool, list))
        }
        metadata["event_count"] = event_count
        return metadata

    def _is_flat_wazuh_event(self, event):
        return any(str(key).startswith("_source.") for key in event.keys())

    def _allocate_event_id(self, candidate_num, index, seen_event_ids):
        try:
            num = int(candidate_num)
            if num <= 0:
                num = index + 1
        except (TypeError, ValueError):
            num = index + 1

        event_id = f"event-{num}"
        if event_id in seen_event_ids:
            event_id = f"event-{index + 1}"
            counter = index + 2
            while event_id in seen_event_ids:
                event_id = f"event-{counter}"
                counter += 1
        seen_event_ids.add(event_id)
        return event_id

    def _normalize_wazuh_flat_event(self, event, index, seen_event_ids):
        event_id = self._allocate_event_id(index + 1, index, seen_event_ids)
        timestamp = (
            event.get("@timestamp")
            or event.get("_source.data.win.system.systemTime")
            or event.get("_source.@timestamp")
            or event.get("_source.timestamp")
            or ""
        )

        agent_info = {}
        winlog_system = {}
        eventdata = {}
        extra_win = {}
        other_fields = {}

        ignored_system_keys = {
            "keywords", "opcode", "providerGuid", "threadID", "version", "task", "level", "processID",
        }
        ignored_rule_compliance = {
            "pci_dss", "hipaa", "tsc", "nist_800_53", "gpg13", "gdpr", "mail", "firedtimes",
        }

        raw_system_message = None

        for raw_key, raw_val in event.items():
            key = str(raw_key)
            if raw_val in (None, "", [], {}, "-"):
                continue
            if self._is_forbidden_key(key, key):
                continue
            if key in {"_index", "_id", "_version", "_score", "@timestamp", "_source.@timestamp", "_source.timestamp", "_source.id"}:
                continue

            val = raw_val.replace("\\\\", "\\") if isinstance(raw_val, str) else raw_val

            if key.startswith("_source.agent."):
                subkey = key[len("_source.agent."):]
                agent_info[subkey] = self._compact(val)
            elif key.startswith("_source.data.win.eventdata."):
                subkey = key[len("_source.data.win.eventdata."):]
                if subkey.lower() == "rulename" and isinstance(val, str):
                    if val.strip() == "-" or _TTP_LEAK_PATTERN.search(val) or "technique_id" in val.lower():
                        continue
                eventdata[subkey] = self._compact(val)
            elif key.startswith("_source.data.win.system."):
                subkey = key[len("_source.data.win.system."):]
                if subkey == "message":
                    raw_system_message = val
                    continue
                if subkey in ignored_system_keys:
                    continue
                winlog_system[subkey] = self._compact(val)
            elif key.startswith("_source.data.win."):
                subkey = key[len("_source.data.win."):]
                extra_win[subkey] = self._compact(val)
            elif key.startswith("_source.rule."):
                subkey = key[len("_source.rule."):]
                if subkey in ignored_rule_compliance or subkey.startswith("mitre"):
                    continue
                # Keep only generic non-leaking channel group/level tags if needed, never description/mitre
                if subkey in {"level", "groups"}:
                    other_fields[f"wazuh_rule_{subkey}"] = self._compact(val)
            elif key.startswith("_source."):
                subkey = key[len("_source."):]
                if subkey in {"manager.name", "input.type", "decoder.name", "location"}:
                    continue
                other_fields[subkey] = self._compact(val)

        # Keep system.message only when structured eventdata is absent/sparse
        if raw_system_message and len(eventdata) <= 2:
            winlog_system["message"] = self._compact(raw_system_message)

        normalized = {
            "event_id": event_id,
            "timestamp": str(timestamp),
        }
        computer = winlog_system.get("computer") or agent_info.get("name")
        if computer or agent_info.get("ip"):
            host_dict = {}
            if computer:
                host_dict["name"] = computer
            if agent_info.get("ip"):
                host_dict["ip"] = agent_info["ip"]
            normalized["host"] = host_dict
        if winlog_system:
            normalized["winlog"] = winlog_system
        if eventdata:
            normalized["eventdata"] = eventdata
        if extra_win:
            normalized["win_extra"] = extra_win
        if other_fields:
            normalized.update(other_fields)
        return normalized

    def _normalize_event(self, event, index, seen_event_ids=None):
        if seen_event_ids is None:
            seen_event_ids = set()

        if not isinstance(event, dict):
            event_id = self._allocate_event_id(index + 1, index, seen_event_ids)
            return {
                "event_id": event_id,
                "message": str(event)[:4000],
            }

        if self._is_flat_wazuh_event(event):
            return self._normalize_wazuh_flat_event(event, index, seen_event_ids)

        sequence = self._nested(event, "event", "sequence")
        record_id = self._nested(event, "winlog", "record_id")
        candidate_id = sequence or record_id or (index + 1)
        event_id = self._allocate_event_id(candidate_id, index, seen_event_ids)

        normalized = {
            "event_id": event_id,
            "timestamp": event.get("@timestamp") or event.get("timestamp") or "",
        }

        # Note: 'threat' and 'rule' are deliberately excluded to prevent label/MITRE leakage
        retained_fields = (
            "event", "winlog", "host", "user", "process", "file", "source",
            "destination", "network", "dns", "url", "registry", "powershell",
            "related", "message",
        )
        for key in retained_fields:
            if key not in event:
                continue
            compacted = self._compact(self._strip_forbidden(event[key], key))
            if compacted not in (None, "", [], {}):
                normalized[key] = compacted
        return normalized

    def _compact(self, value, depth=0):
        if depth > 6:
            return str(value)[:1000]
        if isinstance(value, dict):
            return {
                key: compacted
                for key, item in value.items()
                if (compacted := self._compact(item, depth + 1)) not in (None, "", [], {})
            }
        if isinstance(value, list):
            return [
                compacted
                for item in value
                if (compacted := self._compact(item, depth + 1)) not in (None, "", [], {})
            ]
        if isinstance(value, str):
            return value[:4000]
        return value

    def _extract_observables(self, text):
        normalized_text = self._defang_to_plain(text).replace("\\\\", "\\")
        urls = {value.rstrip(".,;:)\"'") for value in _URL_PATTERN.findall(normalized_text)}
        ips = set()
        for candidate in _IP_PATTERN.findall(normalized_text):
            try:
                ips.add(str(ipaddress.ip_address(candidate)))
            except ValueError:
                continue

        domains = set()
        for candidate in self.domain_pattern.findall(normalized_text):
            candidate = candidate.lower().rstrip(".,;:)\"'")
            if candidate in ips or self._looks_like_file(candidate):
                continue
            domains.add(candidate)

        hashes = defaultdict(set)
        # Exclude Sysmon IMPHASH=... values from being misclassified as file MD5s
        text_without_imphash = re.sub(r"\bIMPHASH=[0-9a-fA-F]{32}\b", "", normalized_text, flags=re.IGNORECASE)
        for value in _HASH_PATTERN.findall(text_without_imphash):
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
            hashes[hash_type].add(value.lower())

        observables = {
            "ip": ips,
            "domain": domains,
            "url": urls,
            "file": {value.rstrip(".,;:)\"'") for value in self.file_pattern.findall(normalized_text)},
            "path": {value.rstrip(".,;:)\"'") for value in _WINDOWS_PATH_PATTERN.findall(normalized_text)},
        }
        observables.update(hashes)
        return {key: values for key, values in observables.items() if values}

    def _defang_to_plain(self, value):
        return (
            str(value)
            .replace("[.]", ".")
            .replace("(.)", ".")
            .replace("hxxps://", "https://")
            .replace("hxxp://", "http://")
        )

    def _looks_like_file(self, value):
        suffix = value.rsplit(".", 1)[-1].lower() if "." in value else ""
        return suffix in self.file_suffixes

    def _task_hints(self, task):
        hints = set(_TASK_HINTS.get(task.get("id", ""), ()))
        for field in ("target", "consumes", "produces"):
            value = task.get(field, "")
            if isinstance(value, list):
                value = " ".join(value)
            hints.update(re.findall(r"[a-z0-9_.-]+", str(value).lower().replace("_", " ")))
        return tuple(hint for hint in hints if len(hint) > 2)

    def _filter_observables(self, inventory, selected_ids, include_all=False):
        filtered = {}
        for observable_type, entries in inventory.items():
            selected_entries = []
            for entry in entries:
                matching_ids = sorted(set(entry.get("event_ids", [])) & selected_ids)
                if include_all or matching_ids:
                    selected_entries.append({
                        "value": entry["value"],
                        "event_ids": entry.get("event_ids", []) if include_all else matching_ids,
                        "occurrences": entry.get("occurrences", len(entry.get("event_ids", []))),
                    })
            if selected_entries:
                filtered[observable_type] = selected_entries
        return filtered

    def _nested(self, value, *path):
        current = value
        for key in path:
            if not isinstance(current, dict):
                return None
            current = current.get(key)
        return current

    def _collect_strings(self, value, output):
        if isinstance(value, str):
            output.append(value)
            return
        if isinstance(value, dict):
            for item in value.values():
                self._collect_strings(item, output)
            return
        if isinstance(value, (list, tuple, set)):
            for item in value:
                self._collect_strings(item, output)
