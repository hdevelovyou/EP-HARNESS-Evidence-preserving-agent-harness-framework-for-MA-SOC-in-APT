"""Command line: audit an existing MA-SOC run directory in shadow mode.

    python -m ep_harness.cli audit runs/<scenario_id> --masoc-repo PATH --out report.json
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from .adapters.masoc import audit_run_dir
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


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ep_harness")
    sub = parser.add_subparsers(dest="command", required=True)
    audit = sub.add_parser("audit", help="audit an MA-SOC run directory")
    audit.add_argument("run_dir")
    audit.add_argument("--masoc-repo", help="MA-SOC repo root, to load task contracts")
    audit.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    audit.add_argument("--out", help="write JSON report here")
    audit.add_argument("--ledger-out", help="write ledger JSONL here")
    args = parser.parse_args(argv)

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
