"""Evidence cards: a compact, ID-first index of the events an agent may cite.

The task view an agent receives is a long JSON dump (about 110 000 characters
for one S23 task). Finding and copying the right event ID out of it is exactly
the step weaker models get wrong. The harness therefore does that step itself:
one line per event, its ID first, then time, activity, actor -> object and the
command line, all read from the event's own fields.

    event-9 | 2024-11-09 11:19:58 | file (11) | csc.exe -> tmseiddy.dll

Agents are asked to pick cards first and write the claim second, so the claim
is built from evidence rather than evidence looked up for a claim.
"""

from __future__ import annotations

import json
import re

from .semantic import _flatten, event_behaviour, event_time

_ACTIVITY_ORDER = ("process", "network", "dns", "file", "registry", "auth", "scheduled_task", "service")
_PROCESS_KEYS = ("process.name", "process.executable", "eventdata.image", "eventdata.processname")
_PARENT_KEYS = ("process.parent.name", "process.parent.executable", "eventdata.parentimage")
_OBJECT_KEYS = {
    "network": ("destination.ip", "destination.domain", "eventdata.destinationip", "eventdata.destinationhostname"),
    "dns": ("dns.question.name", "eventdata.queryname"),
    "file": ("file.path", "file.name", "eventdata.targetfilename"),
    "registry": ("registry.path", "eventdata.targetobject"),
    "auth": ("eventdata.targetusername", "user.name"),
    "scheduled_task": ("eventdata.taskname",),
    "service": ("eventdata.servicename",),
}
_PORT_KEYS = ("destination.port", "eventdata.destinationport")
_COMMAND_KEYS = ("process.command_line", "eventdata.commandline")
_CODE_KEYS = ("event.code", "winlog.event_id", "winlog.eventid")
_MAX_COMMAND = 140


def _first(flat: dict, keys) -> str:
    for key in keys:
        value = str(flat.get(key) or "").strip()
        if value:
            return value
    return ""


def _short(value: str) -> str:
    """Basename of a path, defanged indicators restored."""
    value = value.replace("[.]", ".").replace("[:]", ":")
    return re.split(r"[\\/]", value.rstrip("\\/"))[-1] if ("\\" in value or "/" in value) else value


def card(payload: dict) -> dict:
    flat = dict(_flatten(payload))
    kinds = event_behaviour(payload)
    kind = next((k for k in _ACTIVITY_ORDER if k in kinds), "")
    process = _short(_first(flat, _PROCESS_KEYS))
    if kind == "process":
        actor, obj = _short(_first(flat, _PARENT_KEYS)), process
    else:
        actor, obj = process, _short(_first(flat, _OBJECT_KEYS.get(kind, ())))
        port = _first(flat, _PORT_KEYS)
        if kind == "network" and obj and port:
            obj = f"{obj}:{port}"
    command = " ".join(_first(flat, _COMMAND_KEYS).split())
    when = event_time(payload)
    return {
        "event_id": str(payload.get("event_id", "")),
        "time": when.strftime("%Y-%m-%d %H:%M:%S") if when else "",
        "activity": kind or "other",
        "code": _first(flat, _CODE_KEYS),
        "actor": actor,
        "object": obj,
        "command": command[:_MAX_COMMAND] + ("..." if len(command) > _MAX_COMMAND else ""),
    }


def card_line(c: dict) -> str:
    activity = f"{c['activity']} ({c['code']})" if c["code"] else c["activity"]
    link = " -> ".join(part for part in (c["actor"], c["object"]) if part) or "-"
    line = f"{c['event_id']} | {c['time'] or '-'} | {activity} | {link}"
    return f"{line} | {c['command']}" if c["command"] else line


def render(cards: list[dict]) -> str:
    lines = [
        "Evidence cards (one per event you may cite: ID | time | activity (event code) | actor -> object | command):",
    ]
    lines += [card_line(c) for c in cards]
    return "\n".join(lines)


def cards_for_task_view(task_view: str) -> str:
    """Cards for the events of a task view (the JSON string the extractor builds); '' if it cannot be read."""
    try:
        events = json.loads(task_view).get("events", [])
    except (json.JSONDecodeError, AttributeError, TypeError):
        return ""
    cards = [card(e) for e in events if isinstance(e, dict) and e.get("event_id")]
    return render(cards) if cards else ""
