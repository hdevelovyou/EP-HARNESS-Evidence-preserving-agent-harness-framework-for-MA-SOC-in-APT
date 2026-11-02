"""Harness manifest and fingerprint.

The manifest declares every harness component in the 8 categories
(5 standard + 3 SOC-specific). The fingerprint hashes the manifest plus the
package source, so a result can always be tied to the exact harness that
produced it. Never compare scores across different fingerprints.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path

CATEGORIES = (
    "system_prompts",
    "tools_skills",
    "infrastructure",
    "orchestration",
    "hooks_middleware",
    "trust_boundary",
    "evidence_provenance",
    "observability_evaluation",
)

PACKAGE_DIR = Path(__file__).resolve().parent


@dataclass(frozen=True)
class Component:
    name: str
    category: str
    version: str
    enabled: bool = True
    config: dict = field(default_factory=dict)


@dataclass
class HarnessManifest:
    name: str
    version: str
    components: list[Component]

    @classmethod
    def load(cls, path) -> "HarnessManifest":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        components = [Component(**c) for c in data.get("components", [])]
        manifest = cls(data["name"], data["version"], components)
        manifest.validate()
        return manifest

    def validate(self) -> None:
        names = set()
        for component in self.components:
            if component.category not in CATEGORIES:
                raise ValueError(f"{component.name}: unknown category {component.category!r}")
            if component.name in names:
                raise ValueError(f"duplicate component {component.name!r}")
            names.add(component.name)

    def enabled(self, name: str) -> bool:
        return any(c.name == name and c.enabled for c in self.components)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "version": self.version,
            "components": [c.__dict__ for c in self.components],
        }

    def fingerprint(self) -> dict:
        sources = {
            str(p.relative_to(PACKAGE_DIR)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted([*PACKAGE_DIR.rglob("*.py"), *PACKAGE_DIR.glob("schemas/*.json")])
        }
        manifest_hash = hashlib.sha256(
            json.dumps(self.to_dict(), sort_keys=True).encode("utf-8")
        ).hexdigest()
        combined = hashlib.sha256(
            json.dumps({"manifest": manifest_hash, "sources": sources}, sort_keys=True).encode("utf-8")
        ).hexdigest()
        return {"harness_sha256": combined, "manifest_sha256": manifest_hash, "sources": sources}
