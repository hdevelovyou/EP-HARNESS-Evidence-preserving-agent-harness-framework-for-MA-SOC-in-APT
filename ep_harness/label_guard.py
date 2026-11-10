"""Label guard: keep ATT&CK technique IDs (the ground-truth labels) out of everything agents see.

Windows-APT telemetry is produced with Atomic Red Team, whose paths carry the
technique under test (`...\\atomics\\T1566.001\\bin\\...`). Left in, an agent can
"detect" a technique by reading a folder name. Before any agent or the
evidence extractor sees the telemetry:

  mask_labels      replaces every technique ID with a stable pseudonym
                   (T1566.001 -> XTID03), the same ID always the same pseudonym,
                   so paths stay distinct and consistent across events;
                   optionally also the simulation markers (atomic-red-team, ...)
  assert_no_labels stops the run if any technique ID is still present

After the report is sealed, evaluation needs the real paths to match the
ground-truth artifacts, but must not hand out technique credit:

  unmask_artifacts restores a pseudonym only inside a path-like token
                   (backslash, slash or file name around it). A pseudonym that
                   stands alone, e.g. a bare "XTID03", is never restored, so a
                   report cannot score a technique it did not infer.

Technique scoring therefore runs on the masked report, IOC scoring on the
unmasked one (main.evaluate_sealed_run).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

TECHNIQUE_ID = re.compile(r"(?<![0-9A-Za-z])T\d{4}(?:\.\d{3})?(?![0-9])", re.IGNORECASE)
PSEUDONYM = re.compile(r"X(?:TID|SIM)\d{2,}")
# Simulation-framework markers: not labels, but they reveal that the telemetry is an emulation.
MARKERS = re.compile(r"atomic[-_ ]?red[-_ ]?team|pathtoatomicsfolder|invoke-atomictest|redcanaryco|"
                     r"red[-_ ]?canary|(?<![0-9A-Za-z])atomics(?![0-9A-Za-z])", re.IGNORECASE)
_TOKEN = re.compile(r"[^\s\"'<>|,;()\[\]{}]+")


class LabelLeakError(RuntimeError):
    """A technique ID would reach the runtime: the run must not start."""


@dataclass
class LabelMask:
    text: str
    mapping: dict[str, str] = field(default_factory=dict)   # pseudonym -> original
    counts: dict[str, int] = field(default_factory=dict)    # original -> occurrences

    def to_dict(self) -> dict:
        return {"mapping": self.mapping, "counts": self.counts,
                "technique_ids": sum(1 for p in self.mapping if p.startswith("XTID")),
                "markers": sum(1 for p in self.mapping if p.startswith("XSIM"))}


def mask_labels(text: str, markers: bool = False) -> LabelMask:
    """Replace technique IDs (and, if asked, simulation markers) with stable pseudonyms."""
    text = str(text or "")
    if PSEUDONYM.search(text):
        raise LabelLeakError("telemetry already contains pseudonym-shaped tokens (XTIDnn/XSIMnn); refusing to mask")
    by_original: dict[str, str] = {}    # normalised original -> pseudonym
    first_seen: dict[str, str] = {}     # pseudonym -> original as first written (restored on unmask)
    counts: dict[str, int] = {}
    issued = {"XTID": 0, "XSIM": 0}

    def replacer(prefix, normalise):
        def replace(match):
            raw = match.group(0)
            original = normalise(raw)
            if original not in by_original:
                issued[prefix] += 1
                by_original[original] = f"{prefix}{issued[prefix]:02d}"
                first_seen[by_original[original]] = raw
            counts[original] = counts.get(original, 0) + 1
            return by_original[original]
        return replace

    masked = TECHNIQUE_ID.sub(replacer("XTID", str.upper), text)
    if markers:
        masked = MARKERS.sub(replacer("XSIM", lambda s: s), masked)
    return LabelMask(masked, first_seen, counts)


def find_labels(value) -> list[str]:
    """Technique IDs found in any string of value (str, dict, list, ...)."""
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False, default=str)
    return sorted({m.group(0).upper() for m in TECHNIQUE_ID.finditer(text)})


def assert_no_labels(value, where: str) -> None:
    found = find_labels(value)
    if found:
        raise LabelLeakError(f"technique IDs still present in {where}: {found[:10]}")


def _is_path_like(token: str, pseudonym: str) -> bool:
    rest = token.replace(pseudonym, "")
    return "\\" in token or "/" in token or bool(re.search(r"[A-Za-z0-9]", rest))


def unmask_artifacts(value, mapping: dict[str, str]):
    """Restore pseudonyms inside path-like tokens only; works on str, dict and list."""
    if not mapping:
        return value
    if isinstance(value, dict):
        return {k: unmask_artifacts(v, mapping) for k, v in value.items()}
    if isinstance(value, list):
        return [unmask_artifacts(v, mapping) for v in value]
    if not isinstance(value, str):
        return value

    def restore(match):
        token = match.group(0)
        for pseudonym in sorted(set(PSEUDONYM.findall(token)), key=len, reverse=True):
            if pseudonym in mapping and _is_path_like(token, pseudonym):
                token = token.replace(pseudonym, mapping[pseudonym])
        return token

    return _TOKEN.sub(restore, value)
