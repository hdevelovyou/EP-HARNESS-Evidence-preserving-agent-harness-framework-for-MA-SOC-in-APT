"""Semantic Evidence Verification: does the cited evidence actually back the claim?

The Contract Gate only checks that cited events exist. This module asks the
next question, claim by claim, and answers with one of four verdicts:

  SUPPORTED     the cited events are about what the claim is about, nothing
                in them conflicts with it, and they cover every entity and the
                behaviour it asserts
  UNRELATED     no cited event is about the claim: they share no specific
                entity with it (only ubiquitous ones such as the host name,
                and then not even the kind of activity)
  INSUFFICIENT  the events are about the claim but do not establish it: an
                entity or the asserted behaviour is missing, or a causal claim
                rests on co-occurrence only
  CONTRADICTED  a cited event states the opposite of the claim: outcome,
                network direction, time of day, or order of two activities

plus NOT_APPLICABLE for claims with nothing to check (a HYPOTHESIS, or an
inference that rests only on parent claims).

Two layers, cheapest first:
  1. Rules (this module, deterministic, no LLM). UNRELATED, INSUFFICIENT and
     CONTRADICTED found here are final.
  2. A judge (the Verifier's single LLM call) sees only the claims the rules
     found SUPPORTED, with their cited events, and may make a verdict
     stricter, never looser (apply_judge).

Entities are read from entity-like fields of the event payload (hosts, users,
processes, files, addresses, domains, hashes, registry keys, command lines).
An entity found in more than TRIVIAL_DF of the ledger's events (typically the
host and the user) is "trivial": sharing only trivial entities does not make
an event relevant to a claim.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime

from .capsule import CLAIM_VERDICTS, Capsule, Claim, claim_ref
from .ledger import EvidenceLedger

VERDICTS = CLAIM_VERDICTS
# Strictness used when a judge disagrees with the rules: a verdict only moves right.
_STRICTNESS = {"NOT_APPLICABLE": -1, "SUPPORTED": 0, "INSUFFICIENT": 1, "UNRELATED": 2, "CONTRADICTED": 3}
RELATIONS = ("ATTRIBUTE", "CORRELATION", "TEMPORAL", "CAUSAL")

TRIVIAL_DF = 0.3
_MIN_EVENTS_FOR_DF = 10
_MIN_ANCHOR_LEN = 4
_TIME_TOLERANCE_MIN = 10
_JUDGE_FENCE = "claim_verdicts"

# ------------------------------------------------------------------ entities
_ENTITY_KEYS = ("host", "computer", "user", "process", "image", "command", "parent", "file", "target", "path",
                "hash", "ip", "address", "domain", "dns", "query", "url", "registry", "guid")
_NON_ENTITY_KEYS = ("event.", "provider", "channel", "outcome", "category", "type", "action", "kind", "direction",
                    "protocol", "transport", "integrity", "severity", "rule", "wazuh", "description", "company",
                    "product", "version", "logontype", "terminalsession", "currentdirectory", "os.", "port",
                    "sequence", "record", "time", "length", "level")
_FILE_EXT = ("exe", "dll", "ps1", "bat", "cmd", "vbs", "js", "hta", "lnk", "docm", "docx", "doc", "xlsm", "xlsx",
             "xls", "zip", "rar", "7z", "iso", "msi", "scr", "sys", "tmp", "dat", "bin", "py", "sh")
_TLD = ("com", "net", "org", "info", "io", "ru", "cn", "biz", "xyz", "top", "online", "site", "club", "co", "me",
        "cc", "tk", "pw", "in", "us", "uk", "de", "fr", "vn", "local")
_CLAIM_PATTERNS = [
    re.compile(r"\b\d{1,3}(?:\[?\.\]?\d{1,3}){3}\b"),                                       # IPv4, defanged too
    re.compile(r"\b(?:[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b"),                           # hashes
    re.compile(r"[a-z]:\\[^\s\"'<>|,;]+"),                                                   # windows paths
    re.compile(r"\bhk(?:lm|cu|ey_local_machine|ey_current_user)\\[^\s\"',;]+"),              # registry keys
    re.compile(r"[\w$.-]+\.(?:" + "|".join(_FILE_EXT) + r")\b"),                             # file names
    re.compile(r"\b(?:[a-z0-9-]+\[?\.\]?)+(?:" + "|".join(_TLD) + r")\b"),                   # domains
    re.compile(r"\b(?=[a-z0-9-]*\d)[a-z]{2,}[a-z0-9]*-[a-z0-9-]{2,}\b"),                     # host-like: ws-fin-014
]

# ------------------------------------------------------------------ behaviour
_CLAIM_BEHAVIOUR = {
    "process": r"spawn|launch|execut|\bran\b|started|process creat|child process|command line|invok",
    "network": r"connect|beacon|\bc2\b|outbound|inbound|egress|ingress|traffic|\bport\b|\btcp\b|\bhttps?\b",
    "dns": r"\bdns\b|resolv|lookup|quer(y|ied)",
    "file": r"dropp|\bwr(ote|itten|ites)\b|file creat|creat\w* (a |the )?file|saved|staged|deleted file|modified file",
    "registry": r"registry|run key|\bhklm\b|\bhkcu\b|reg add",
    "auth": r"logon|log(ged)? ?in\b|authenticat|credential|kerberos|\bntlm\b",
    "scheduled_task": r"scheduled task|schtasks|task scheduler",
    "service": r"service install|new service|sc create|installed (a |the )?service",
}
_EVENT_CODE_BEHAVIOUR = {
    "1": {"process"}, "3": {"network"}, "5": {"process"}, "7": {"process"}, "8": {"process"}, "10": {"process"},
    "11": {"file"}, "12": {"registry"}, "13": {"registry"}, "14": {"registry"}, "15": {"file"}, "22": {"dns", "network"},
    "23": {"file"}, "26": {"file"}, "4624": {"auth"}, "4625": {"auth"}, "4648": {"auth"}, "4672": {"auth"},
    "4768": {"auth"}, "4769": {"auth"}, "4776": {"auth"}, "4688": {"process"}, "4698": {"scheduled_task"},
    "4699": {"scheduled_task"}, "4702": {"scheduled_task"}, "4697": {"service"}, "7045": {"service"},
    "4103": {"process"}, "4104": {"process"}, "5156": {"network"},
}
_CATEGORY_BEHAVIOUR = {"process": "process", "network": "network", "file": "file", "registry": "registry",
                       "authentication": "auth"}
_FAILURE_CODES = {"4625"}

# ------------------------------------------------------------------ relations and assertions
_CAUSAL = re.compile(r"\b(spawn(?:ed|s)?|launched by|executed by|started by|child of|parent of|caused|led to|"
                     r"resulted in|dropped by|injected into|created by|written by)\b")
_ORDER = re.compile(r"\b(before|prior to|then|followed by|after|preceded by)\b")
_CORRELATION = re.compile(r"\b(associated with|linked to|related to|correlat\w*|same host|together with)\b")
_SUCCESS = re.compile(r"\b(succeed(?:ed|s)?|successful(?:ly)?)\b")
_FAILURE = re.compile(r"\b(fail(?:ed|s|ure)?|unsuccessful|denied|rejected)\b")
_INBOUND = re.compile(r"\b(inbound|ingress|incoming)\b")
_OUTBOUND = re.compile(r"\b(outbound|egress|outgoing)\b")
_TIME_OF_DAY = re.compile(r"(?<![\d.:])([01]?\d|2[0-3]):([0-5]\d)(?::[0-5]\d)?(?![\d:])")


def _flatten(value, prefix=""):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _flatten(item, f"{prefix}.{key}" if prefix else str(key))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _flatten(item, prefix)
    elif value is not None:
        yield prefix.lower(), str(value)


def _normalise(value: str) -> str:
    return value.strip().strip("\"'").lower().replace("[.]", ".").replace("[:]", ":")


def _anchor_variants(key: str, value: str) -> set[str]:
    """A field value plus the parts a claim would name: basename, executable stem, command-line tokens, hashes."""
    value = _normalise(value)
    out = {value}
    pieces = [value]
    if "command" in key:
        pieces += [_normalise(token) for token in re.split(r"[\s\"']+", value)]
    if "hash" in key:
        pieces += [p.split("=", 1)[-1] for p in re.split(r"[,;\s]+", value)]
    for piece in pieces:
        out.add(piece)
        base = re.split(r"[\\/]", piece)[-1]
        out.add(base)
        stem, dot, ext = base.rpartition(".")
        if dot and ext in _FILE_EXT:
            out.add(stem)
    return {a for a in out if len(a) >= _MIN_ANCHOR_LEN and not a.isdigit()}


def event_entities(payload: dict) -> dict[str, set[str]]:
    """Entity-like field -> anchors. Event metadata (codes, outcome, timestamps) is not an entity."""
    entities: dict[str, set[str]] = {}
    for key, value in _flatten(payload):
        if any(hint in key for hint in _NON_ENTITY_KEYS) or not any(hint in key for hint in _ENTITY_KEYS):
            continue
        anchors = _anchor_variants(key, value)
        if anchors:
            entities.setdefault(key, set()).update(anchors)
    return entities


def event_behaviour(payload: dict) -> set[str]:
    flat = dict(_flatten(payload))
    behaviour = set()
    for key, value in flat.items():
        if key.endswith("event.category"):
            behaviour |= {_CATEGORY_BEHAVIOUR[v] for v in [value.lower()] if v in _CATEGORY_BEHAVIOUR}
        if key in ("event.code", "winlog.event_id", "winlog.eventid"):
            behaviour |= _EVENT_CODE_BEHAVIOUR.get(value.strip(), set())
        if key.startswith("dns.") or "queryname" in key:
            behaviour.add("dns")
        if key.startswith("destination.ip") or key.endswith("destinationip"):
            behaviour.add("network")
        if key.startswith("registry."):
            behaviour.add("registry")
        if key.startswith("file.path") or "targetfilename" in key:
            behaviour.add("file")
    return behaviour


def event_time(payload: dict) -> datetime | None:
    raw = str(payload.get("timestamp") or "").strip().replace("Z", "+00:00")
    if not raw:
        return None
    raw = re.sub(r"(\.\d{6})\d+", r"\1", raw.replace(" ", "T", 1))
    try:
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    except ValueError:
        return None


def _outcome(payload: dict) -> str | None:
    flat = dict(_flatten(payload))
    if flat.get("event.outcome") in ("success", "failure"):
        return flat["event.outcome"]
    code = flat.get("event.code") or flat.get("winlog.event_id") or flat.get("winlog.eventid")
    return "failure" if code in _FAILURE_CODES else None


def _direction(payload: dict) -> str | None:
    value = dict(_flatten(payload)).get("network.direction", "").lower()
    return {"egress": "out", "outbound": "out", "ingress": "in", "inbound": "in"}.get(value)


_ENTITY_SHAPE = re.compile(r"[\d.\\/_@:-]")


def mentions(text: str, anchor: str) -> bool:
    """``anchor`` occurs in ``text`` as a whole token, not inside a longer word ("chrome" is not in "chromebook")."""
    return re.search(r"(?<![\w])" + re.escape(anchor) + r"(?![\w])", text) is not None


_NOT_ANCHORS = {"sha-256", "sha-1", "md-5", "utf-8", "base-64", "x86-64", "win-32", "win-64", "ipv-4", "ipv-6"}


def claim_anchors(claim: Claim) -> set[str]:
    text = claim.text.lower()
    anchors = {_normalise(o) for o in claim.observables if o.strip()}
    for pattern in _CLAIM_PATTERNS:
        anchors |= {_normalise(m.group(0)) for m in pattern.finditer(text)}
    return {a for a in anchors if len(a) >= _MIN_ANCHOR_LEN and a not in _NOT_ANCHORS}


def claim_behaviour(text: str) -> set[str]:
    text = text.lower()
    return {name for name, pattern in _CLAIM_BEHAVIOUR.items() if re.search(pattern, text)}


def claim_relation(text: str) -> str:
    text = text.lower()
    if _CAUSAL.search(text):
        return "CAUSAL"
    if _ORDER.search(text) or _TIME_OF_DAY.search(text):
        return "TEMPORAL"
    if _CORRELATION.search(text):
        return "CORRELATION"
    return "ATTRIBUTE"


# ------------------------------------------------------------------ results
@dataclass
class ClaimVerdict:
    ref: str
    claim_id: str
    verdict: str
    relation: str = "ATTRIBUTE"
    decided_by: str = "rules"
    reasons: list[str] = field(default_factory=list)
    relevant_events: list[str] = field(default_factory=list)
    irrelevant_events: list[str] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)

    @property
    def needs_judge(self) -> bool:
        return self.verdict == "SUPPORTED" and self.decided_by == "rules"

    def to_dict(self) -> dict:
        return {
            "ref": self.ref, "verdict": self.verdict, "relation": self.relation, "decided_by": self.decided_by,
            "reasons": self.reasons, "relevant_events": self.relevant_events,
            "irrelevant_events": self.irrelevant_events, "missing": self.missing,
        }


@dataclass
class SemanticReport:
    capsule_id: str
    verdicts: list[ClaimVerdict]

    def verdict(self, claim_id: str) -> ClaimVerdict | None:
        return next((v for v in self.verdicts if v.claim_id == claim_id), None)

    @property
    def pending_judge(self) -> list[ClaimVerdict]:
        return [v for v in self.verdicts if v.needs_judge]

    @property
    def accepted(self) -> bool:
        """A finding passes semantic review when at least one claim is SUPPORTED."""
        return any(v.verdict == "SUPPORTED" for v in self.verdicts)

    def counts(self) -> dict:
        out: dict[str, int] = {}
        for v in self.verdicts:
            out[v.verdict] = out.get(v.verdict, 0) + 1
        return out

    def feedback(self) -> str:
        """Plain-text verdicts for the producing agent; starts with OK only when accepted."""
        head = "OK" if self.accepted else "FAIL: no claim is supported by the evidence it cites"
        lines = [f"{head}. Semantic evidence review of {self.capsule_id}:"]
        for v in self.verdicts:
            if v.verdict == "NOT_APPLICABLE":
                continue
            reason = "; ".join(v.reasons) if v.reasons else "evidence covers the claim"
            lines.append(f"- {v.claim_id} {v.verdict} ({v.decided_by}): {reason}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {"capsule_id": self.capsule_id, "counts": self.counts(), "verdicts": [v.to_dict() for v in self.verdicts]}


# ------------------------------------------------------------------ rule layer
class SemanticVerifier:
    def __init__(self, ledger: EvidenceLedger, trivial_df: float = TRIVIAL_DF):
        self.ledger = ledger
        self.trivial_df = trivial_df
        self._entities: dict[str, dict[str, set[str]]] = {}
        self._df: dict[str, float] = {}
        self._vocabulary: set[str] | None = None

    # ---- ledger views
    def _payload(self, event_id: str) -> dict:
        record = self.ledger.event(event_id)
        return record["payload"] if record else {}

    def entities(self, event_id: str) -> dict[str, set[str]]:
        if event_id not in self._entities:
            self._entities[event_id] = event_entities(self._payload(event_id))
        return self._entities[event_id]

    def vocabulary(self) -> set[str]:
        """Every entity anchor of every ledger event: what a claim can name that the telemetry knows about."""
        if self._vocabulary is None:
            self._vocabulary = set()
            for event_id in self.ledger.event_ids():
                for values in self.entities(event_id).values():
                    self._vocabulary |= values
        return self._vocabulary

    def claim_entities(self, claim: Claim) -> set[str]:
        """Entities the claim asserts: pattern matches, declared observables, and known telemetry entities it names."""
        text = claim.text.lower()
        # Only entity-shaped values: a plain word ("file", "system") in a field is not something a claim names.
        known = {a for a in self.vocabulary() if len(a) <= 200 and _ENTITY_SHAPE.search(a) and mentions(text, a)}
        # Keep the longest form: "csc.exe" makes the bare stem "csc" redundant.
        known = {a for a in known if not any(a != b and a in b for b in known)}
        return claim_anchors(claim) | known

    def is_trivial(self, anchor: str) -> bool:
        event_ids = self.ledger.event_ids()
        if len(event_ids) < _MIN_EVENTS_FOR_DF:
            return False
        if anchor not in self._df:
            hits = sum(1 for e in event_ids if anchor in self.ledger.event_text(e))
            self._df[anchor] = hits / len(event_ids)
        return self._df[anchor] > self.trivial_df

    # ---- per claim
    def check_claim(self, capsule: Capsule, claim: Claim) -> ClaimVerdict:
        ref = claim_ref(capsule.capsule_id, claim.claim_id)
        relation = claim_relation(claim.text)
        verdict = ClaimVerdict(ref=ref, claim_id=claim.claim_id, verdict="SUPPORTED", relation=relation)
        cited = [e for e in claim.event_ids if self.ledger.has_event(e)]
        if not cited:
            if claim.level == "HYPOTHESIS" or claim.parent_claims:
                verdict.verdict = "NOT_APPLICABLE"
                verdict.reasons.append("no cited event to check (hypothesis or inference from parent claims)")
            else:
                verdict.verdict = "INSUFFICIENT"
                verdict.reasons.append("the claim cites no event")
            return verdict

        text = claim.text.lower()
        anchors = self.claim_entities(claim)
        specific = {a for a in anchors if not self.is_trivial(a)}
        behaviour = claim_behaviour(text)

        matched: dict[str, set[str]] = {}
        for event_id in cited:
            event_text = self.ledger.event_text(event_id)
            event_anchors = set().union(*self.entities(event_id).values()) if self.entities(event_id) else set()
            shared = {a for a in anchors if a in event_text} | {a for a in event_anchors if mentions(text, a)}
            shared_specific = {a for a in shared if not self.is_trivial(a)}
            same_kind = bool(behaviour & event_behaviour(self._payload(event_id)))
            if shared_specific or (same_kind and (shared or not anchors)):
                verdict.relevant_events.append(event_id)
                matched[event_id] = shared
            else:
                verdict.irrelevant_events.append(event_id)

        if not anchors and not behaviour:
            verdict.verdict = "INSUFFICIENT"
            verdict.reasons.append("the claim names no entity or activity the evidence could be checked against")
            return verdict
        if not verdict.relevant_events:
            verdict.verdict = "UNRELATED"
            verdict.reasons.append(
                "no cited event shares a specific entity or the asserted activity with the claim"
            )
            return verdict
        if verdict.irrelevant_events:
            verdict.reasons.append(f"cited but unrelated: {', '.join(verdict.irrelevant_events)}")

        relevant = verdict.relevant_events
        contradiction = self._contradiction(text, relevant, matched)
        if contradiction:
            verdict.verdict = "CONTRADICTED"
            verdict.reasons.insert(0, contradiction)
            return verdict

        covered = "\n".join(self.ledger.event_text(e) for e in relevant)
        verdict.missing = sorted(a for a in specific if a not in covered)
        gaps = []
        if verdict.missing:
            gaps.append(f"not in the relevant events: {', '.join(verdict.missing)}")
        kinds = set().union(*(event_behaviour(self._payload(e)) for e in relevant))
        if behaviour and kinds and not behaviour & kinds:
            gaps.append(f"claim asserts {'/'.join(sorted(behaviour))} activity, events show {'/'.join(sorted(kinds))}")
        if relation == "CAUSAL" and not self._linked(relevant, anchors | set().union(*matched.values())):
            gaps.append("causal claim rests on co-occurrence: no event records a link between the entities")
        if relation == "CORRELATION" and len(relevant) > 1 and not self._share_entity(relevant):
            gaps.append("correlated events share no entity")
        if gaps:
            verdict.verdict = "INSUFFICIENT"
            verdict.reasons[:0] = gaps
        return verdict

    def check(self, capsule: Capsule) -> SemanticReport:
        return SemanticReport(capsule.capsule_id, [self.check_claim(capsule, c) for c in capsule.claims])

    # ---- assertion checks
    def _contradiction(self, text: str, relevant: list[str], matched: dict[str, set[str]]) -> str:
        payloads = {e: self._payload(e) for e in relevant}
        outcomes = {o for o in (_outcome(p) for p in payloads.values()) if o}
        if _SUCCESS.search(text) and outcomes == {"failure"}:
            return "claim says the activity succeeded; the events record a failure"
        if _FAILURE.search(text) and outcomes == {"success"}:
            return "claim says the activity failed; the events record success"
        directions = {d for d in (_direction(p) for p in payloads.values()) if d}
        if _INBOUND.search(text) and directions == {"out"}:
            return "claim says inbound; the events record egress traffic"
        if _OUTBOUND.search(text) and directions == {"in"}:
            return "claim says outbound; the events record ingress traffic"

        times = {e: event_time(p) for e, p in payloads.items()}
        stated = [int(h) * 60 + int(m) for h, m in _TIME_OF_DAY.findall(text)]
        if stated and all(times.values()):
            def near(t):
                minutes = t.hour * 60 + t.minute
                return any(min(abs(minutes - s), 1440 - abs(minutes - s)) <= _TIME_TOLERANCE_MIN for s in stated)
            if not any(near(t) for t in times.values()):
                shown = ", ".join(sorted({t.strftime("%H:%M") for t in times.values()}))
                return f"claim states a time the cited events do not show (events at {shown})"

        order = _ORDER.search(text)
        if order:
            left, right = text[: order.start()], text[order.end():]
            left_events = [e for e in relevant if any(a in left for a in matched[e])]
            right_events = [e for e in relevant if any(a in right for a in matched[e])]
            if order.group(1) in ("after", "preceded by"):
                left_events, right_events = right_events, left_events
            left_times = [times[e] for e in left_events if times[e] and e not in right_events]
            right_times = [times[e] for e in right_events if times[e] and e not in left_events]
            if left_times and right_times and min(left_times) > max(right_times):
                return "claim states an order of activities that the event timestamps reverse"
        return ""

    def _linked(self, relevant: list[str], anchors: set[str]) -> bool:
        """Does an event record the relationship itself?

        Either one event names two distinct entities of the claim in different
        fields (process and parent process, process and the file it wrote,
        process and the address it reached), or two events are tied by a
        process id / parent process id.
        """
        named = {a for a in anchors if not self.is_trivial(a)}
        for event_id in relevant:
            entities = self.entities(event_id)
            hits = {a: {key for key, values in entities.items() if a in values} for a in named}
            hits = {a: keys for a, keys in hits.items() if keys}
            for a in hits:
                for b in hits:
                    if a < b and a not in b and b not in a and hits[a] - hits[b] and hits[b] - hits[a]:
                        return True
        ids = {e: dict(_flatten(self._payload(e))) for e in relevant}
        for a, fa in ids.items():
            own = {fa.get(k) for k in ("process.entity_id", "eventdata.processguid", "eventdata.processid") if fa.get(k)}
            for b, fb in ids.items():
                parents = {fb.get(k) for k in ("process.parent.entity_id", "eventdata.parentprocessguid",
                                               "eventdata.parentprocessid") if fb.get(k)}
                if a != b and own & parents:
                    return True
        return False

    def _share_entity(self, relevant: list[str]) -> bool:
        sets = [set().union(*self.entities(e).values()) if self.entities(e) else set() for e in relevant]
        return bool(set.intersection(*sets)) if sets else False


# ------------------------------------------------------------------ judge layer
def judge_items(report: SemanticReport, capsule: Capsule, ledger: EvidenceLedger, max_chars: int = 1500) -> list[dict]:
    """What the judge sees: only rule-SUPPORTED claims, each with its relevant events (trimmed)."""
    items = []
    for verdict in report.pending_judge:
        claim = capsule.claim(verdict.claim_id)
        events = []
        for event_id in verdict.relevant_events:
            payload = json.dumps(ledger.event(event_id)["payload"], ensure_ascii=False)
            events.append({"event_id": event_id, "event": payload[:max_chars]})
        items.append({"id": claim.claim_id, "text": claim.text, "level": claim.level, "events": events})
    return items


def parse_judge_verdicts(text: str) -> tuple[dict[str, tuple[str, str]], str]:
    """Read ```claim_verdicts [{"id","verdict","reason"}] from the judge's answer."""
    match = list(re.finditer(r"```" + _JUDGE_FENCE + r"[ \t]*\r?\n(.*?)```", str(text or ""), re.DOTALL))
    if not match:
        return {}, f"no ```{_JUDGE_FENCE} block found"
    try:
        records = json.loads(match[-1].group(1))
    except json.JSONDecodeError as error:
        return {}, f"{_JUDGE_FENCE} block is not valid JSON: {error.msg}"
    out = {}
    for record in records if isinstance(records, list) else []:
        if not isinstance(record, dict):
            continue
        claim_id = str(record.get("id", "")).strip().lower()
        verdict = str(record.get("verdict", "")).strip().upper()
        if claim_id and verdict in VERDICTS:
            out[claim_id] = (verdict, str(record.get("reason", ""))[:300])
    return out, ""


def apply_judge(report: SemanticReport, judgements: dict[str, tuple[str, str]], judge_error: str = "") -> SemanticReport:
    """Merge judge verdicts. The judge may only make a verdict stricter; a claim it skipped is INSUFFICIENT."""
    merged = []
    for verdict in report.verdicts:
        if not verdict.needs_judge:
            merged.append(verdict)
            continue
        judged, reason = judgements.get(verdict.claim_id, ("INSUFFICIENT", judge_error or "the judge gave no verdict"))
        if _STRICTNESS.get(judged, 0) > _STRICTNESS["SUPPORTED"]:
            merged.append(replace(verdict, verdict=judged, decided_by="judge", reasons=[reason] + verdict.reasons))
        else:
            merged.append(replace(verdict, decided_by="judge"))
    return SemanticReport(report.capsule_id, merged)
