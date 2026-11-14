"""Parse the evidence-claims block that agents append to their output.

With cited claims enabled, the Hunter and the Analyst end their answer with
one fenced block:

    ```evidence_claims
    [{"id": "c1", "text": "...", "level": "OBSERVED", "event_ids": ["event-12"],
      "tools": ["rex_tool"], "observables": ["compdatasystems.com"]}]
    ```

The parser is lenient about shape and strict about nothing: it turns records
into Claim objects (lineage "cited") and leaves every judgement to the
Contract Gate. A missing or unreadable block yields no claims plus an error
string, so the gate refuses the handoff and the agent is told why.
"""

from __future__ import annotations

import ast
import json
import re
from dataclasses import dataclass, field

from .capsule import Claim

FENCE = "evidence_claims"
_BLOCK = re.compile(r"```[ \t]*(?:json[ \t]+)?" + FENCE + r"[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)
# Fallbacks a model commonly produces instead of the asked-for fence.
_JSON_FENCE = re.compile(r"```[ \t]*json[ \t]*\r?\n(.*?)```", re.DOTALL | re.IGNORECASE)
_LABELLED = re.compile(FENCE + r"\s*[:=]?\s*(\[.*\])", re.DOTALL | re.IGNORECASE)
_TAG = re.compile(r"[ \t]*\[(c\d+)\]")

# Field names models use for the same thing -> the schema's name.
_ALIASES = {
    "claim_id": "id", "claim": "text", "statement": "text", "description": "text",
    "evidence": "event_ids", "events": "event_ids", "event": "event_ids", "event_id": "event_ids",
    "evidence_ids": "event_ids", "cards": "event_ids",
    "tool": "tools", "values": "observables", "iocs": "observables", "observable": "observables",
    "parents": "parent_claims", "based_on": "parent_claims", "parent_claim": "parent_claims",
    "confidence": "level", "epistemic_level": "level", "ttps": "ttp_candidates", "ttp": "ttp_candidates",
}
_LEVEL_ALIASES = {
    "observed": "OBSERVED", "observation": "OBSERVED", "seen": "OBSERVED", "direct": "OBSERVED",
    "inferred": "INFERRED", "inference": "INFERRED", "derived": "INFERRED",
    "hypothesis": "HYPOTHESIS", "hypothetical": "HYPOTHESIS", "suspected": "HYPOTHESIS", "possible": "HYPOTHESIS",
}
_EVENT_ID = re.compile(r"^event[\s_-]*(\d+)$", re.IGNORECASE)
_SCHEMA_FIELDS = ("id", "text", "level", "event_ids", "tools", "observables", "parent_claims", "derivation",
                  "ttp_candidates", "lineage")


@dataclass
class ParsedClaims:
    body: str
    records: list[dict] = field(default_factory=list)
    error: str = ""
    found: bool = False
    repairs: list[str] = field(default_factory=list)


def _locate(text: str):
    """(match, how) for the claims block, trying the asked-for fence first."""
    matches = list(_BLOCK.finditer(text))
    if matches:
        return matches[-1], ""
    for match in reversed(list(_JSON_FENCE.finditer(text))):
        if re.search(r"[\"'](text|statement|claim)[\"']", match.group(1), re.IGNORECASE):
            return match, "read a ```json block as the claims block"
    match = _LABELLED.search(text)
    if match:
        return match, "read an unfenced claims list"
    return None, ""


def _loads_lenient(raw: str) -> tuple[object, list[str]]:
    """json.loads, then the fixes for the slips models make most often. Raises ValueError if nothing works."""
    try:
        return json.loads(raw), []
    except json.JSONDecodeError:
        pass
    repairs = []
    fixed = raw.strip()
    curly = fixed.translate(str.maketrans({"“": '"', "”": '"', "‘": "'", "’": "'"}))
    if curly != fixed:
        fixed = curly
        repairs.append("replaced typographic quotes")
    if re.search(r",\s*[\]}]", fixed):
        fixed = re.sub(r",\s*([\]}])", r"\1", fixed)
        repairs.append("removed trailing commas")
    if fixed.startswith("{") and re.search(r"}\s*,?\s*{", fixed):
        fixed = "[" + re.sub(r"}\s*,?\s*{", "},{", fixed) + "]"
        repairs.append("wrapped separate objects in a list")
    try:
        return json.loads(fixed), repairs
    except json.JSONDecodeError:
        pass
    try:
        pythonish = re.sub(r"\btrue\b", "True", re.sub(r"\bfalse\b", "False", re.sub(r"\bnull\b", "None", fixed)))
        return ast.literal_eval(pythonish), repairs + ["read single-quoted JSON"]
    except (ValueError, SyntaxError) as error:
        raise ValueError(str(error)) from error


def _canonical(record: dict) -> dict:
    """Schema field names, list fields as lists, level and event IDs in their canonical spelling."""
    out = {}
    for key, value in record.items():
        name = str(key).strip().lower().replace(" ", "_")
        name = _ALIASES.get(name, name)
        if name in out and isinstance(out[name], list) and isinstance(value, list):
            out[name] = out[name] + value
        else:
            out[name] = value
    if out.get("id") not in (None, ""):
        out["id"] = _claim_id(out["id"], 0)
    level = str(out.get("level", "")).strip().lower()
    if level in _LEVEL_ALIASES:
        out["level"] = _LEVEL_ALIASES[level]
    if "event_ids" in out:
        out["event_ids"] = [
            f"event-{m.group(1)}" if (m := _EVENT_ID.match(str(e).strip())) else str(e).strip()
            for e in (out["event_ids"] if isinstance(out["event_ids"], list) else [out["event_ids"]])
        ]
    return out


def extract_claims_block(text: str) -> ParsedClaims:
    """Split ``text`` into the narrative and the records of its last claims block.

    Format slips are repaired deterministically and listed in ``repairs``
    (they are measured, not hidden); only a block that cannot be read at all
    is an error, which the gate then reports to the agent.
    """
    text = str(text or "")
    match, how = _locate(text)
    if match is None:
        return ParsedClaims(body=text.strip(), error=f"no ```{FENCE} block found")
    body = (text[: match.start()] + text[match.end():]).strip()
    repairs = [how] if how else []
    try:
        data, fixes = _loads_lenient(match.group(1))
    except ValueError as error:
        return ParsedClaims(body=body, error=f"{FENCE} block is not valid JSON: {error}", found=True, repairs=repairs)
    repairs += fixes
    if isinstance(data, dict):
        data = data.get("claims", [data] if ("text" in data or "statement" in data) else [])
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        return ParsedClaims(body=body, error=f"{FENCE} block must be a JSON list of objects", found=True,
                            repairs=repairs)
    records = [_canonical(r) for r in data]
    asked_for = set(_SCHEMA_FIELDS) | {"evidence"}  # "evidence" is the name the contracts ask for
    if any(str(key) not in asked_for for r in data for key in r):
        repairs.append("mapped field names to the schema")
    return ParsedClaims(body=body, records=records, found=True, repairs=repairs)


def _strings(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, int)):
        value = [value]
    return tuple(str(v).strip() for v in value if str(v).strip()) if isinstance(value, (list, tuple)) else ()


def _claim_id(value, index: int) -> str:
    """'C3', 'c3' and 3 all mean c3; a missing ID is numbered by position."""
    claim_id = str(value if value is not None else "").strip().lower()
    if not claim_id:
        return f"c{index}"
    return f"c{claim_id}" if claim_id.isdigit() else claim_id


def claims_from_records(records: list[dict], artifact_by_tool: dict[str, str] | None = None) -> list[Claim]:
    """Records -> Claims. Cited tool names become the task's artifact IDs.

    A tool the task never ran maps to an ID the ledger does not hold, so the
    gate rejects it as a dangling artifact (C3) instead of trusting the name.
    """
    artifact_by_tool = artifact_by_tool or {}
    claims = []
    for index, record in enumerate((_canonical(r) for r in records), 1):
        parents = _strings(record.get("parent_claims"))
        default_derivation = "NEW" if not parents else ("REFINED" if len(parents) == 1 else "AGGREGATED")
        tools = _strings(record.get("tools"))
        claims.append(
            Claim(
                text=" ".join(str(record.get("text", "")).split())[:500],
                level=str(record.get("level", "")).strip().upper(),
                event_ids=_strings(record.get("event_ids")),
                artifact_ids=tuple(artifact_by_tool.get(t, f"tool:unexecuted:{t}") for t in tools),
                ttp_candidates=tuple(t.upper() for t in _strings(record.get("ttp_candidates"))),
                lineage="cited",
                claim_id=_claim_id(record.get("id"), index),
                parent_claims=parents,
                derivation=str(record.get("derivation") or default_derivation).strip().upper(),
                observables=_strings(record.get("observables")),
            )
        )
    return claims


def drop_tagged_lines(text: str, claim_ids) -> str:
    """Remove the narrative lines tagged with any of ``claim_ids`` (e.g. "... [c3]")."""
    blocked = set(claim_ids)
    if not blocked:
        return str(text or "")
    kept = [line for line in str(text or "").splitlines() if not blocked & set(_TAG.findall(line))]
    return "\n".join(kept)


def strip_claim_tags(text: str) -> str:
    return _TAG.sub("", str(text or ""))


def remove_claims_block(text: str) -> str:
    text = str(text or "")
    match, _ = _locate(text)
    return (text[: match.start()] + text[match.end():]).strip() if match else text.strip()


_WORD = re.compile(r"[a-z0-9][a-z0-9._\-]{2,}")


def auto_tag_lines(text: str, claims) -> tuple[str, int]:
    """Tag untagged narrative lines with the claim they state, so a blocked claim can still be removed.

    A line gets claim cN when it contains the claim's text, or at least 60% of
    the claim's words (3+ letters). Lines the agent tagged itself are kept.
    Returns the tagged text and how many lines the harness tagged.
    """
    vocab = []
    for claim in claims:
        words = set(_WORD.findall(claim.text.lower()))
        if len(words) >= 3:
            vocab.append((claim.claim_id, claim.text.lower().strip(" ."), words))
    out, tagged = [], 0
    for line in str(text or "").splitlines():
        lowered = line.lower()
        if _TAG.search(line) or not lowered.strip():
            out.append(line)
            continue
        line_words = set(_WORD.findall(lowered))
        best, best_score = None, 0.0
        for claim_id, claim_text, words in vocab:
            score = 1.0 if claim_text and claim_text in lowered else len(words & line_words) / len(words)
            if score > best_score:
                best, best_score = claim_id, score
        if best and best_score >= 0.6:
            out.append(f"{line} [{best}]")
            tagged += 1
        else:
            out.append(line)
    return "\n".join(out), tagged
