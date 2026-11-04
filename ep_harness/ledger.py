"""Evidence Ledger: append-only record of what evidence exists and where it came from.

Three record types:
  event     - original telemetry, content-hashed; never modified
  artifact  - a tool execution (tool name, task, output hash)
  capsule   - a proposed handoff (content hash)
plus ``decision`` records that carry every status change of a capsule.

Re-adding an identical record is idempotent; re-adding an ID with different
content raises LedgerIntegrityError. That is how fabricated or silently edited
evidence becomes detectable. Decisions must follow STATUS_TRANSITIONS, and no
actor may decide on a capsule it authored.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .capsule import STATUS_TRANSITIONS, STATUSES, Capsule


class LedgerIntegrityError(ValueError):
    pass


def canonical_hash(value) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _string_leaves(value):
    if isinstance(value, dict):
        for item in value.values():
            yield from _string_leaves(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _string_leaves(item)
    elif value is not None:
        yield str(value)


class EvidenceLedger:
    def __init__(self):
        self._journal: list[dict] = []
        self._events: dict[str, dict] = {}
        self._artifacts: dict[str, dict] = {}
        self._capsules: dict[str, dict] = {}
        self._capsule_status: dict[str, str] = {}
        self._superseded_by: dict[str, str] = {}
        self._event_text: dict[str, str] = {}

    # ---------- writes (append-only) ----------
    def add_event(self, event_id: str, payload: dict, source: str = "", timestamp: str = "") -> dict:
        record = {
            "event_id": event_id,
            "sha256": canonical_hash(payload),
            "source": source,
            "timestamp": timestamp,
            "payload": payload,
        }
        return self._append("event", self._events, event_id, record, compare_key="sha256")

    def add_artifact(self, artifact_id: str, task_id: str, tool: str, status: str, output_sha256: str) -> dict:
        record = {
            "artifact_id": artifact_id,
            "task_id": task_id,
            "tool": tool,
            "status": status,
            "output_sha256": output_sha256,
        }
        return self._append("artifact", self._artifacts, artifact_id, record, compare_key=None)

    def add_capsule(self, capsule: Capsule) -> dict:
        record = {"capsule_id": capsule.capsule_id, "sha256": capsule.content_hash(), "capsule": capsule.to_dict()}
        stored = self._append("capsule", self._capsules, capsule.capsule_id, record, compare_key="sha256")
        self._capsule_status.setdefault(capsule.capsule_id, "PROPOSED")
        return stored

    def record_decision(self, capsule_id: str, status: str, actor: str, violations=(), detail: dict | None = None):
        if status not in STATUSES:
            raise ValueError(f"unknown status {status!r}")
        if capsule_id not in self._capsules:
            raise LedgerIntegrityError(f"decision for unknown capsule {capsule_id!r}")
        current = self._capsule_status[capsule_id]
        allowed_actors = STATUS_TRANSITIONS[current].get(status, ())
        if actor not in allowed_actors:
            raise LedgerIntegrityError(
                f"{actor!r} may not move {capsule_id!r} from {current} to {status} (allowed: {list(allowed_actors)})"
            )
        if actor == self._capsules[capsule_id]["capsule"]["source"]:
            raise LedgerIntegrityError(f"{actor!r} may not decide on its own capsule {capsule_id!r}")
        record = {
            "capsule_id": capsule_id,
            "from": current,
            "to": status,
            "actor": actor,
            "violations": list(violations),
            "detail": detail or {},
        }
        self._journal.append({"seq": len(self._journal), "type": "decision", "record": record})
        self._capsule_status[capsule_id] = status
        return record

    def _append(self, record_type, store, key, record, compare_key):
        existing = store.get(key)
        if existing is not None:
            same = existing == record if compare_key is None else existing[compare_key] == record[compare_key]
            if not same:
                raise LedgerIntegrityError(f"{record_type} {key!r} already exists with different content")
            return existing
        store[key] = record
        self._journal.append({"seq": len(self._journal), "type": record_type, "id": key})
        if record_type == "capsule" and record["capsule"].get("supersedes"):
            self._superseded_by.setdefault(record["capsule"]["supersedes"], key)
        return record

    # ---------- reads ----------
    def has_event(self, event_id: str) -> bool:
        return event_id in self._events

    def has_artifact(self, artifact_id: str) -> bool:
        return artifact_id in self._artifacts

    def has_capsule(self, capsule_id: str) -> bool:
        return capsule_id in self._capsules

    def event(self, event_id: str) -> dict | None:
        return self._events.get(event_id)

    def event_text(self, event_id: str) -> str:
        """Lower-cased string leaves of an event payload, for observable matching."""
        if event_id not in self._event_text:
            record = self._events.get(event_id)
            self._event_text[event_id] = "\n".join(_string_leaves(record["payload"])).lower() if record else ""
        return self._event_text[event_id]

    def capsule(self, capsule_id: str) -> Capsule | None:
        record = self._capsules.get(capsule_id)
        return Capsule.from_dict(record["capsule"]) if record else None

    def superseded_by(self, capsule_id: str) -> str | None:
        return self._superseded_by.get(capsule_id)

    def artifacts_for_task(self, task_id: str) -> list[dict]:
        return [a for a in self._artifacts.values() if a["task_id"] == task_id]

    def capsule_status(self, capsule_id: str) -> str | None:
        return self._capsule_status.get(capsule_id)

    def decisions(self) -> list[dict]:
        return [entry["record"] for entry in self._journal if entry["type"] == "decision"]

    def counts(self) -> dict:
        return {
            "events": len(self._events),
            "artifacts": len(self._artifacts),
            "capsules": len(self._capsules),
            "decisions": len(self.decisions()),
        }

    # ---------- persistence ----------
    def save(self, path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            for entry in self._journal:
                line = dict(entry)
                if entry["type"] == "event":
                    line["record"] = self._events[entry["id"]]
                elif entry["type"] == "artifact":
                    line["record"] = self._artifacts[entry["id"]]
                elif entry["type"] == "capsule":
                    line["record"] = self._capsules[entry["id"]]
                handle.write(json.dumps(line, ensure_ascii=False) + "\n")

    @classmethod
    def load(cls, path) -> "EvidenceLedger":
        ledger = cls()
        with open(path, encoding="utf-8") as handle:
            for raw in handle:
                entry = json.loads(raw)
                record = entry["record"]
                if entry["type"] == "event":
                    ledger.add_event(record["event_id"], record["payload"], record["source"], record["timestamp"])
                elif entry["type"] == "artifact":
                    ledger.add_artifact(**record)
                elif entry["type"] == "capsule":
                    ledger.add_capsule(Capsule.from_dict(record["capsule"]))
                elif entry["type"] == "decision":
                    ledger.record_decision(
                        record["capsule_id"], record["to"], record["actor"], record["violations"], record["detail"]
                    )
        return ledger
