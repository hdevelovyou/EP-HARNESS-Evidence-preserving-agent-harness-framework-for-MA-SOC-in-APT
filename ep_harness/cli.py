"""Command line.

    python -m ep_harness.cli audit runs/<scenario_id> --masoc-repo PATH --out report.json
    python -m ep_harness.cli preflight --scenario S23 --masoc-repo .

audit      shadow-mode audit of a finished MA-SOC run directory
preflight  model-free dry run of the runtime input: sanitize, mask labels, extract,
           check that no technique ID is left; exit code 1 on a leak
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from .adapters.masoc import audit_run_dir
from .label_guard import MARKERS, find_labels, mask_labels
from .manifest import HarnessManifest

DEFAULT_MANIFEST = Path(__file__).resolve().parent / "harness.json"


def load_task_inventory(masoc_repo: str | None):
    if not masoc_repo:
        return None
    path = Path(masoc_repo) / "agents" / "task_catalog.py"
    spec = importlib.util.spec_from_file_location("masoc_task_catalog", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.TASK_INVENTORY


def preflight(telemetry: Path, masoc_repo: Path, markers: bool = False) -> dict:
    """What the runtime would hand to the agents, checked for labels, without calling any model."""
    sys.path.insert(0, str(masoc_repo))
    from src.extractor import EvidenceExtractor  # MA-SOC's own extractor, unchanged

    extractor = EvidenceExtractor()
    sanitized = extractor.sanitize_raw_log(telemetry.read_text(encoding="utf-8"))
    mask = mask_labels(sanitized, markers=markers)
    evidence = extractor.extract(mask.text)
    leaks = {"sanitized_log": find_labels(mask.text), "evidence_store": find_labels(evidence)}
    return {
        "telemetry": str(telemetry),
        "events": len(evidence.get("events", [])),
        "technique_ids_before_masking": find_labels(sanitized),
        "masked": mask.to_dict(),
        "simulation_markers_left": len(MARKERS.findall(mask.text)),
        "leaks_after_masking": leaks,
        "ok": not any(leaks.values()),
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ep_harness")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit an MA-SOC run directory")
    audit.add_argument("run_dir")
    audit.add_argument("--masoc-repo", help="MA-SOC repo root, to load task contracts")
    audit.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    audit.add_argument("--out", help="write JSON report here")
    audit.add_argument("--ledger-out", help="write ledger JSONL here")
    check = sub.add_parser("preflight", help="model-free check that no label reaches the runtime")
    source = check.add_mutually_exclusive_group(required=True)
    source.add_argument("--scenario", help="scenario id, read from extracted_scenarios/<id>_telemetry.json")
    source.add_argument("--telemetry", help="explicit telemetry JSON path")
    check.add_argument("--masoc-repo", default=".", help="repo root holding src/extractor.py")
    check.add_argument("--mask-markers", action="store_true", help="also mask simulation markers")
    args = parser.parse_args(argv)

    if args.command == "preflight":
        repo = Path(args.masoc_repo)
        telemetry = Path(args.telemetry) if args.telemetry else repo / "extracted_scenarios" / f"{args.scenario}_telemetry.json"
        report = preflight(telemetry, repo, markers=args.mask_markers)
        report["masked"].pop("mapping")  # pseudonym -> label stays out of the console
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["ok"] else 1

    manifest = HarnessManifest.load(args.manifest)
    report = audit_run_dir(args.run_dir, load_task_inventory(args.masoc_repo))
    ledger = report.pop("_ledger")
    report.pop("_capsules")
    report["harness"] = {"name": manifest.name, "version": manifest.version,
                         "fingerprint": manifest.fingerprint()["harness_sha256"]}
    if args.ledger_out:
        ledger.save(args.ledger_out)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    print(json.dumps({"summary": report["summary"], "gate_vs_verifier": report["gate_vs_verifier"],
                      "harness": report["harness"]}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
