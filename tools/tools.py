from langchain_core.prompts import ChatPromptTemplate
from langchain_core.output_parsers import JsonOutputParser
from langchain.tools import tool
from agents.llm_config import create_agent_llm
from src.domain_pack import load_domain_pack
from src.retriever import Retriever
from functools import lru_cache
from collections import defaultdict
import ipaddress
import json
import os
import re

shared_llm, shared_llm_settings = create_agent_llm(
    "tools",
    temperature=0,
)
json_shared_llm = shared_llm.bind(response_format={"type": "json_object"})


@lru_cache(maxsize=1)
def _get_retriever():
    """Reuse the embedding model and Chroma collection for the whole process."""
    return Retriever()


def _tools_domain_config():
    return load_domain_pack().get("tools", {})


def _build_tools_file_pattern():
    suffixes = _tools_domain_config().get("pattern_file_suffixes", [])
    escaped = "|".join(re.escape(str(item).lstrip(".")) for item in suffixes if item)
    if not escaped:
        escaped = "exe|dll|bat|cmd|ps1|txt"
    return re.compile(rf"\b[^\s\\/:*?\"<>|]+\.(?:{escaped})\b", re.IGNORECASE)


_HASH_PATTERN = re.compile(r"\b(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})\b")
_IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
_WINDOWS_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\r\n\"'<>|]+")
_FILE_PATTERN = _build_tools_file_pattern()

_FILE_SUFFIXES = {
    str(item).lower().lstrip(".")
    for item in _tools_domain_config().get("file_suffixes", [])
    if item
}


def _parse_tool_text(text):
    if isinstance(text, (dict, list)):
        return text
    try:
        return json.loads(str(text))
    except (TypeError, json.JSONDecodeError):
        return {"raw_text": str(text)}


def _flatten_strings(value, output):
    if isinstance(value, str):
        output.append(value)
        return
    if isinstance(value, dict):
        for item in value.values():
            _flatten_strings(item, output)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _flatten_strings(item, output)


def _looks_like_file(value):
    suffix = value.rsplit(".", 1)[-1].lower() if "." in value else ""
    return suffix in _FILE_SUFFIXES


def _defang_to_plain(value):
    return (
        str(value)
        .replace("[.]", ".")
        .replace("(.)", ".")
        .replace("hxxps://", "https://")
        .replace("hxxp://", "http://")
    )


def _normalize_inventory_entries(entries):
    values = set()
    for entry in entries or []:
        if isinstance(entry, dict):
            value = entry.get("value")
        else:
            value = entry
        if value not in (None, "", [], {}):
            values.add(str(value).strip())
    return values


def _embedded_observable_inventory(payload):
    if isinstance(payload, dict):
        inventory = payload.get("observable_inventory")
        if isinstance(inventory, dict):
            return {
                key: _normalize_inventory_entries(entries)
                for key, entries in inventory.items()
            }
    return {}


def _events_from_payload(payload):
    if isinstance(payload, dict):
        if isinstance(payload.get("events"), list):
            return payload["events"]
        if isinstance(payload.get("evidence_view"), dict):
            return []
    if isinstance(payload, list):
        return payload
    return []


def _extract_observables_from_text(text):
    normalized_text = _defang_to_plain(text)
    urls = {value.rstrip(".,;:)") for value in _URL_PATTERN.findall(normalized_text)}
    ips = set()
    for candidate in _IP_PATTERN.findall(normalized_text):
        try:
            ips.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue

    domains = set()
    for candidate in _DOMAIN_PATTERN.findall(normalized_text):
        candidate = candidate.lower().rstrip(".,;:)")
        if candidate in ips or _looks_like_file(candidate):
            continue
        domains.add(candidate)

    hashes = defaultdict(set)
    for value in _HASH_PATTERN.findall(normalized_text):
        hash_type = {32: "md5", 40: "sha1", 64: "sha256"}[len(value)]
        hashes[hash_type].add(value.lower())

    observables = {
        "ip": ips,
        "domain": domains,
        "url": urls,
        "file": {value.rstrip(".,;:)") for value in _FILE_PATTERN.findall(normalized_text)},
        "path": {value.rstrip(".,;:)") for value in _WINDOWS_PATH_PATTERN.findall(normalized_text)},
    }
    observables.update(hashes)
    return {key: values for key, values in observables.items() if values}


def _collect_event_entities(event, entities):
    if not isinstance(event, dict):
        return

    host_name = (((event.get("host") or {}).get("name")) if isinstance(event.get("host"), dict) else None)
    if host_name:
        entities["hosts"].add(str(host_name))

    user_value = event.get("user")
    if isinstance(user_value, dict):
        for key in ("name", "domain"):
            if user_value.get(key):
                entities["users"].add(str(user_value[key]))
        if user_value.get("domain") and user_value.get("name"):
            entities["users"].add(f"{user_value['domain']}\\{user_value['name']}")
    elif user_value:
        entities["users"].add(str(user_value))

    process_value = event.get("process")
    if isinstance(process_value, dict):
        for key in ("name", "executable", "parent.name", "parent.executable"):
            current = process_value
            for part in key.split("."):
                if not isinstance(current, dict):
                    current = None
                    break
                current = current.get(part)
            if current:
                entities["processes"].add(str(current))
        if process_value.get("command_line"):
            entities["commands"].add(str(process_value["command_line"]))

    file_value = event.get("file")
    if isinstance(file_value, dict):
        for key in ("name", "path"):
            if file_value.get(key):
                entities["files"].add(str(file_value[key]))

    registry_value = event.get("registry")
    if isinstance(registry_value, dict):
        for key in ("path", "key", "value"):
            if registry_value.get(key):
                entities["registry"].add(str(registry_value[key]))


def _deterministic_rex(text):
    payload = _parse_tool_text(text)
    inventory = _embedded_observable_inventory(payload)

    string_parts = []
    _flatten_strings(payload, string_parts)
    fallback = _extract_observables_from_text("\n".join(string_parts))

    merged = defaultdict(set)
    for source in (fallback, inventory):
        for key, values in source.items():
            merged[key].update(str(value).strip() for value in values if str(value).strip())

    timestamps = set()
    for event in _events_from_payload(payload):
        if isinstance(event, dict) and event.get("timestamp"):
            timestamps.add(str(event["timestamp"]))
    timestamps.update(re.findall(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\b", "\n".join(string_parts)))

    return {
        "ip_addresses": sorted(merged.get("ip", set())),
        "domains": sorted(merged.get("domain", set())),
        "urls": sorted(merged.get("url", set())),
        "file_hashes": {
            "md5": sorted(merged.get("md5", set())),
            "sha1": sorted(merged.get("sha1", set())),
            "sha256": sorted(merged.get("sha256", set())),
        },
        "files": sorted(merged.get("file", set())),
        "paths": sorted(merged.get("path", set())),
        "timestamps": sorted(timestamps),
        "extraction_mode": "deterministic_local",
    }


def _deterministic_ner(text):
    payload = _parse_tool_text(text)
    rex = _deterministic_rex(text)
    entities = defaultdict(set)

    for event in _events_from_payload(payload):
        _collect_event_entities(event, entities)

    executable_exts = tuple(
        str(ext).lower()
        for ext in _tools_domain_config().get("executable_extensions", [])
        if ext
    )
    for value in rex["files"]:
        lowered = value.lower()
        if executable_exts and lowered.endswith(executable_exts):
            entities["malware_tool"].add(value)
        else:
            entities["files"].add(value)
    for value in rex["paths"]:
        entities["files"].add(value)

    infrastructure = {
        "ips": rex["ip_addresses"],
        "domains": rex["domains"],
        "urls": rex["urls"],
        "hashes": rex["file_hashes"],
    }

    return {
        "threat_actor": [],
        "malware_tool": sorted(entities["malware_tool"] | entities["processes"]),
        "vulnerability": [],
        "infrastructure": infrastructure,
        "hosts": sorted(entities["hosts"]),
        "users": sorted(entities["users"]),
        "processes": sorted(entities["processes"]),
        "commands": sorted(entities["commands"]),
        "files": sorted(entities["files"]),
        "registry": sorted(entities["registry"]),
        "extraction_mode": "deterministic_local",
    }


_SECURITY_LINE_KEYWORDS = tuple(
    str(keyword).lower()
    for keyword in _tools_domain_config().get("security_line_keywords", [])
    if keyword
)


def _event_to_summary_line(event):
    if not isinstance(event, dict):
        return str(event)

    parts = []
    for key in ("timestamp", "event.action", "message"):
        current = event
        for part in key.split("."):
            if not isinstance(current, dict):
                current = None
                break
            current = current.get(part)
        if current:
            parts.append(str(current))

    host = event.get("host")
    if isinstance(host, dict) and host.get("name"):
        parts.append(f"host={host['name']}")

    process_value = event.get("process")
    if isinstance(process_value, dict):
        if process_value.get("name"):
            parts.append(f"process={process_value['name']}")
        if process_value.get("command_line"):
            parts.append(f"cmd={process_value['command_line']}")

    file_value = event.get("file")
    if isinstance(file_value, dict):
        file_bits = [str(file_value.get(key)) for key in ("path", "name") if file_value.get(key)]
        if file_bits:
            parts.append(f"file={' | '.join(file_bits)}")

    destination = event.get("destination")
    if isinstance(destination, dict):
        dest_bits = [str(destination.get(key)) for key in ("ip", "domain", "port") if destination.get(key)]
        if dest_bits:
            parts.append(f"dest={' | '.join(dest_bits)}")

    return " ; ".join(parts)


def _security_relevant_lines(text, max_lines=12):
    payload = _parse_tool_text(text)
    events = _events_from_payload(payload)
    if events:
        lines = [_event_to_summary_line(event) for event in events]
    else:
        string_parts = []
        _flatten_strings(payload, string_parts)
        lines = []
        for part in string_parts:
            lines.extend(str(part).splitlines())

    scored = []
    for index, line in enumerate(lines):
        clean = re.sub(r"\s+", " ", str(line)).strip()
        if not clean:
            continue
        lowered = clean.lower()
        score = sum(1 for keyword in _SECURITY_LINE_KEYWORDS if keyword in lowered)
        score += len(_HASH_PATTERN.findall(clean))
        score += len(_IP_PATTERN.findall(clean))
        if score > 0:
            scored.append((score, index, clean))

    if not scored:
        return [re.sub(r"\s+", " ", str(line)).strip() for line in lines[:max_lines] if str(line).strip()]

    scored.sort(key=lambda item: (-item[0], item[1]))
    selected = sorted(scored[:max_lines], key=lambda item: item[1])
    return [line for _, _, line in selected]


def _deterministic_sum(text):
    payload = _parse_tool_text(text)
    rex = _deterministic_rex(text)
    highlights = _security_relevant_lines(text, max_lines=10)

    observable_counts = {
        "ips": len(rex.get("ip_addresses", [])),
        "domains": len(rex.get("domains", [])),
        "urls": len(rex.get("urls", [])),
        "files": len(rex.get("files", [])),
        "paths": len(rex.get("paths", [])),
        "hashes": sum(len(values) for values in rex.get("file_hashes", {}).values()),
    }
    nonzero_counts = ", ".join(
        f"{key}={value}" for key, value in observable_counts.items() if value
    ) or "no explicit observables extracted"

    timeline = rex.get("timestamps", [])
    timeline_text = ""
    if timeline:
        timeline_text = f" Timeline spans {timeline[0]} to {timeline[-1]}."

    highlights_text = " Key evidence: " + " | ".join(highlights[:5]) if highlights else ""
    event_count = len(_events_from_payload(payload))
    event_text = f"{event_count} event(s)" if event_count else "the supplied text"

    return (
        f"Local evidence summary over {event_text}: extracted {nonzero_counts}."
        f"{timeline_text}{highlights_text}"
    )


def _deterministic_spa(text):
    lines = _security_relevant_lines(text, max_lines=8)
    if not lines:
        return "No explicit attack-technique span was found in the supplied text."
    return "\n".join(f"- {line}" for line in lines)

@tool
def ner_tool(text: str):
    """
    Extracting cybersecurity entities (Threat Actor, Malware, Vulnerability, Infrastructure) 
    according to the CyberTeam framework for threat identification.
    """
    # Sử dụng Gemini Flash để xử lý nhanh các tác vụ trích xuất thực thể
    
    # 1. System Prompt
    system_prompt = (
        "You are a cybersecurity threat intelligence assistant specialized in named entity recognition. "
        "This is a role-based zero-shot tool task: use only the supplied text. "
        "Your task is to extract and categorize all named entities relevant to threat attribution from the provided text. "
        "Focus on answering: 'Who is responsible for the attack?', 'How was the attack carried out?'."
    )
    
    # 2. Instructions: Định nghĩa chi tiết các nhãn thực thể (Entity Labels)
    instructions = (
        "Given a cybersecurity-related document or report excerpt, extract all relevant named entities and classify them into:\n"
        "- Threat Actor: Individual(s) or groups suspected or known to conduct the activity.\n"
        "- Malware/Tool: Names of malicious software, exploits, or hacking tools.\n"
        "- Vulnerability: CVE identifiers or technical flaws exploited.\n"
        "- Infrastructure: IPs, domains, file hashes, or URLs used.\n\n"
        "Output: Return results as a structured JSON object.\n\n"
        "TEXT TO ANALYZE:\n{text}"
    )
    
    # 3. Thiết lập Chain
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Sử dụng JsonOutputParser để đảm bảo đầu ra là JSON sạch, không lẫn text thừa
    chain = prompt | json_shared_llm | JsonOutputParser()
    
    try:
        return chain.invoke({"text": text})
    except Exception as e:
        return {"error": f"Lỗi xử lý NER: {str(e)}"}
    
@tool
def rex_tool(text: str):
    """
    Trích xuất các chỉ dấu đe dọa tiêu chuẩn (IP, Hash, Domain, Timestamp) 
    bằng cơ chế khớp mẫu định sẵn (Regex Pattern Matching) của CyberTeam.
    """
    
    # System Prompt: Bê nguyên xi vai trò trợ lý parsing
    system_prompt = (
        "You are a cybersecurity parsing assistant. "
        "This is a role-based zero-shot tool task: use only the supplied document. "
        "Your task is to extract standard "
        "threat indicators from raw incident reports using predefined regex patterns."
    )
    
    # Instructions: Danh sách các đối tượng cần trích xuất
    instructions = (
        "Parse the following document and extract any matches for:\n"
        "- IP addresses\n"
        "- File hashes (MD5, SHA1, SHA256)\n"
        "- Domain names\n"
        "- Timestamps\n\n"
        "Output: Return all matches grouped by type in structured JSON format.\n\n"
        "DOCUMENT TO PARSE:\n{text}"
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    chain = prompt | json_shared_llm | JsonOutputParser()
    return chain.invoke({"text": text})

@tool
def rag_tool(topic: str):
    """
    Truy xuất tri thức an ninh mạng nâng cao. 
    Sử dụng LLM để sinh truy vấn có cấu trúc trước khi tìm kiếm trong Vector DB (MITRE/NVD).
    """
    
    # System Prompt 
    system_prompt = (
        "You are a cybersecurity retrieval planner. "
        "This is a role-based zero-shot tool task: use only the supplied topic. "
        "Formulate a concise search query to retrieve relevant threat intelligence."
    )
    
    # Instructions 
    instructions = (
        "Based on the topic '{topic}', generate a concise search query. "
        "Example format: 'APT29 phishing campaign 2024 indicators, tools, and targets site:mitre.org OR site:virustotal.com'\n"
        "Return ONLY the final query string."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Bước A: LLM sinh ra Query (Structured Query for Retrieval)
    query_chain = prompt | shared_llm
    structured_query = query_chain.invoke({"topic": topic}).content
    print(f"    [RAG] CyberTeam Query: {structured_query}")
    
    # Bước B: Nạp Query đó vào Retriever
    # Retriever sẽ tìm trong database (MITRE ATT&CK, NVD, Exploit-DB).
    retriever = _get_retriever()
    search_results = retriever.search(structured_query)
    
    # Trả về cả query và kết quả truy xuất
    return {
        "final_query": structured_query,
        "evidence_passages": search_results
    }

@tool
def sum_tool(text: str):
    """
    Tóm tắt báo cáo đe dọa hoặc dữ liệu log dài, giữ lại các chi tiết quan trọng 
    như TTPs, IOCs và dòng thời gian sự cố theo khung CyberTeam.
    """

    # System Prompt: Bê nguyên xi vai trò trợ lý phân tích an ninh mạng
    system_prompt = (
        "You are a cybersecurity analyst assistant. "
        "This is a role-based zero-shot tool task: use only the supplied text. "
        "Your task is to summarize the following "
        "threat report in 3-4 sentences, preserving the attack vector, affected systems, "
        "timeline, and any mentioned threat actors or IOCs."
    )

    # Instructions: Yêu cầu trích lọc thông tin tình báo thiết yếu, tránh dùng từ ngữ chung chung
    instructions = (
        "Summarize only the essential intelligence. Avoid generic phrases. "
        "Include dates, names, and tools where available.\n\n"
        "REPORT TO SUMMARIZE:\n{text}"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Output yêu cầu trả về là một đoạn văn bản (plain-text summary paragraph)
    # Ta sử dụng trực tiếp kết quả content từ LLM
    return shared_llm.invoke(prompt.format(text=text)).content

@tool
def sim_tool(phrase1: str, phrase2: str):
    """
    So khớp độ tương đồng văn bản dựa trên ngữ cảnh địa lý và văn hóa 
    để xác định xem hai chỉ dấu có trỏ về cùng một nguồn gốc đe dọa hay không.
    """

    # System Prompt
    system_prompt = (
        "You are a cybersecurity assistant that helps analysts determine whether two "
        "phrases refer to the same threat context. This is a role-based zero-shot tool task: "
        "use only the two supplied phrases. "
        "Use contextual reasoning to decide if the two phrases describe the same "
        "group or region in a cyber threat context."
    )

    # Instructions: Yêu cầu so sánh ngữ nghĩa và khả năng dùng thay thế trong CTI
    instructions = (
        "Given two input phrases describing threat origin (e.g., 'Russian-affiliated' "
        "vs. 'Eastern Bloc actor'), determine whether they semantically refer to the "
        "same group or geopolitical background.\n\n"
        "Answer the following questions:\n"
        "1. Do both descriptions point to the same cultural, linguistic, or geopolitical region?\n"
        "2. Are the expressions used interchangeably in threat intelligence contexts?\n\n"
        "Input Phrase 1: {phrase1}\n"
        "Input Phrase 2: {phrase2}\n"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Sử dụng JsonOutputParser để lấy đúng cấu trúc: match, confidence, justification
    chain = prompt | json_shared_llm | JsonOutputParser()
    
    return chain.invoke({"phrase1": phrase1, "phrase2": phrase2})

@tool
def map_tool(text: str):
    """
    Xây dựng bản đồ tri thức bằng cách trích xuất các bộ ba quan hệ (Subject-Predicate-Object) 
    từ báo cáo đe dọa để làm rõ mối liên hệ giữa các thực thể.
    """

    # System Prompt: Trợ lý xây dựng đồ thị tri thức an ninh mạng
    system_prompt = (
        "You are a cybersecurity knowledge graph assistant. "
        "This is a role-based zero-shot tool task: use only the supplied report excerpt. "
        "Extract and relate key "
        "entities from the given threat report to form subject-predicate-object triples."
    )

    # Instructions: Nhận diện thực thể và quan hệ giữa chúng (e.g., uses, targets)
    instructions = (
        "Identify entities (e.g., threat actors, tools, organizations, IP addresses) "
        "and the relationships between them (e.g., 'uses', 'targets', 'associated with').\n\n"
        "Output: Return a list of triples in the format: [subject, predicate, object]. "
        "Include a confidence score (0-1) for each triple.\n\n"
        "REPORT EXCERPT:\n{text}"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Trả về danh sách JSON chứa các triples và điểm tin cậy
    chain = prompt | json_shared_llm | JsonOutputParser()
    
    return chain.invoke({"text": text})

@tool
def spa_tool(text: str):
    """
    Định vị và trích xuất đoạn văn bản (text span) mô tả trực tiếp kỹ thuật 
    mà kẻ tấn công sử dụng để xâm nhập hệ thống (ví dụ: phishing, lateral movement).
    """
    
    # System Prompt: Vai trò trợ lý định vị vùng văn bản
    system_prompt = (
        "You are a cybersecurity span identification assistant. "
        "This is a role-based zero-shot tool task: use only the supplied report excerpt. "
        "Extract the text span that describes the primary technique used in the attack."
    )
    
    # Instructions: Tìm câu hoặc cụm từ mô tả cách hệ thống bị xâm nhập
    instructions = (
        "Given a report excerpt, locate and return the sentence or phrase that directly "
        "describes how the attacker compromised the system (e.g., phishing, lateral movement, privilege escalation).\n\n"
        "REPORT EXCERPT:\n{text}"
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    # Output: Trả về đoạn văn bản thuần (plain text)
    return shared_llm.invoke(prompt.format(text=text)).content

@tool
def cls_tool(text: str, category: str):
    """
    Phân loại các đầu vào văn bản liên quan đến an ninh mạng (cảnh báo, log, lỗ hổng) 
    vào các nhãn định sẵn như loại tấn công, mức độ phức tạp, hoặc mức độ ảnh hưởng.
    """
    
    # Xây dựng System Prompt dựa trên mô tả B.8
    system_prompt = (
        "You are a cybersecurity classification assistant. "
        "This is a role-based zero-shot tool task: use only the supplied text and category. "
        "Your task is to categorize "
        "cybersecurity-relevant textual inputs into predefined classes."
    )
    
    # Instructions: Dựa trên Analytical Target trong Table 2
    instructions = (
        "Classify the following input based on the specified category: {category}\n\n"
        "Input text: {text}\n\n"
        "Common Categories from CyberTeam:\n"
        "- Attack Vector (Network, Local, Physical)\n"
        "- Attack Complexity (Level of hurdles)\n"
        "- Privileges Required (None, Low, High)\n"
        "- Impact Level (Confidentiality, Integrity, Availability)\n\n"
        "Output: Return a JSON object with 'category', 'label', and 'confidence_score' (0-1)."
    )
    
    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])
    
    chain = prompt | json_shared_llm | JsonOutputParser()
    return chain.invoke({"text": text, "category": category})

@tool
def math_tool(vulnerability_description: str, metrics_values: str):
    """
    Tính toán điểm số mức độ nghiêm trọng (CVSS v3.1 Base Score) dựa trên 
    mô tả lỗ hổng và các chỉ số kỹ thuật (Confidentiality, Integrity, Availability, v.v.).
    """

    # System Prompt: Vai trò trợ lý tính điểm bảo mật
    system_prompt = (
        "You are a cybersecurity scoring assistant. Given a vulnerability description "
        "and metric values, this is a role-based zero-shot tool task: use only those supplied inputs. "
        "Metric values may include Confidentiality, Integrity, Availability, Scope, "
        "Attack Vector, etc.), compute the CVSS v3.1 Base Score."
    )

    # Instructions: Yêu cầu sử dụng công thức chính thức và quy tắc làm tròn chuẩn
    instructions = (
        "Use the official CVSS equations and apply the rounding rules specified in the standard. "
        "Return both the numeric score and a textual explanation of the computation steps.\n\n"
        "Vulnerability Description: {description}\n"
        "Metric Values: {metrics}\n"
    )

    prompt = ChatPromptTemplate.from_messages([
        ("system", system_prompt),
        ("human", instructions)
    ])

    # Output: Trả về điểm số (float 1 chữ số thập phân) và giải thích từng bước
    return shared_llm.invoke(prompt.format(
        description=vulnerability_description, 
        metrics=metrics_values
    )).content
