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

import json
import re
from dataclasses import dataclass, field

from .capsule import Claim

FENCE = "evidence_claims"
_BLOCK = re.compile(r"```" + FENCE + r"[ \t]*\r?\n(.*?)```", re.DOTALL)
_TAG = re.compile(r"[ \t]*\[(c\d+)\]")


@dataclass
class ParsedClaims:
    body: str
    records: list[dict] = field(default_factory=list)
    error: str = ""
    found: bool = False


def extract_claims_block(text: str) -> ParsedClaims:
    """Split ``text`` into the narrative and the records of its last claims block."""
    text = str(text or "")
    matches = list(_BLOCK.finditer(text))
    if not matches:
        return ParsedClaims(body=text.strip(), error=f"no ```{FENCE} block found")
    match = matches[-1]
    body = (text[: match.start()] + text[match.end():]).strip()
    try:
        data = json.loads(match.group(1))
    except json.JSONDecodeError as error:
        return ParsedClaims(body=body, error=f"{FENCE} block is not valid JSON: {error.msg}", found=True)
    if isinstance(data, dict):
        data = data.get("claims", [])
    if not isinstance(data, list) or not all(isinstance(r, dict) for r in data):
        return ParsedClaims(body=body, error=f"{FENCE} block must be a JSON list of objects", found=True)
    return ParsedClaims(body=body, records=data, found=True)


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
    for index, record in enumerate(records, 1):
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
    return _BLOCK.sub("", str(text or "")).strip()
