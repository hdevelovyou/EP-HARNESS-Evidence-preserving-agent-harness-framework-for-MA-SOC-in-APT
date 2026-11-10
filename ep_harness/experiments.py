"""Experiment matrix: configurations x scenarios x repeats, and the comparison table.

    python -m ep_harness.experiments plan    --repeats 5                    # print the runs, call nothing
    python -m ep_harness.experiments run     --repeats 5 --execute          # calls the LLM: only when asked
    python -m ep_harness.experiments summarize --name <experiment>          # table from finished runs

The ladder adds one enforcement layer at a time over the Structured Capsule
baseline, so the gain of each layer can be read off on its own:

  B0_masoc                      MA-SOC as is (reference point, free-text handoffs)
  B1_structured_capsule         agents emit evidence capsules; nothing enforced (gate in shadow mode)
  B1c_structured_capsule_cards  + evidence cards (guidance only, still nothing enforced)
  L1_gate                       + Contract Gate inline at the three handoffs
  L2_semantic                   + semantic evidence verification
  Full_ep_harness               + adaptive evidence-triggered policy

Every configuration sets every switch explicitly (nothing leaks from the
shell), uses the same retry budget (one re-call) and masks labels; every run
is measured by the same instrument (ech_measurement.json) and scored by the
post-seal evaluator (eval_report.json).
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
from datetime import datetime
from pathlib import Path

SCENARIOS = ("S07", "S16", "S23")
OFF = {
    "ENABLE_CONTRACT_GATE": "0", "CONTRACT_GATE_MODE": "inline", "ENABLE_CITED_CLAIMS": "0",
    "ENABLE_EVIDENCE_CARDS": "0", "ENABLE_SEMANTIC_VERIFIER": "0", "POLICY_MODE": "fixed",
    "ENABLE_OUTPUT_GUARDRAIL": "0",
}
COMMON = {"MASOC_MAX_RETRIES": "1", "POLICY_TASK_RETRIES": "1", "MASK_SIMULATION_MARKERS": "1",
          "COLLABORATION_STRATEGY": "hierarchical"}
CAPSULE = {"ENABLE_CONTRACT_GATE": "1", "ENABLE_CITED_CLAIMS": "1"}
CONFIGS = {
    "B0_masoc": {},
    "B1_structured_capsule": dict(CAPSULE, CONTRACT_GATE_MODE="shadow"),
    "B1c_structured_capsule_cards": dict(CAPSULE, CONTRACT_GATE_MODE="shadow", ENABLE_EVIDENCE_CARDS="1"),
    "L1_gate": dict(CAPSULE, ENABLE_EVIDENCE_CARDS="1"),
    "L2_semantic": dict(CAPSULE, ENABLE_EVIDENCE_CARDS="1", ENABLE_SEMANTIC_VERIFIER="1"),
    "Full_ep_harness": dict(CAPSULE, ENABLE_EVIDENCE_CARDS="1", ENABLE_SEMANTIC_VERIFIER="1", POLICY_MODE="adaptive"),
}
# Values read from each finished run: (file, path in the JSON).
METRICS = {
    "f1_ttps": ("eval_report.json", ("layer_2_audit", "f1_ttps")),
    "f1_iocs": ("eval_report.json", ("layer_2_audit", "f1_iocs")),
    "tokens_in": ("eval_report.json", ("metadata", "openai_metrics", "input_tokens")),
    "tokens_out": ("eval_report.json", ("metadata", "openai_metrics", "output_tokens")),
    "cost_usd": ("eval_report.json", ("metadata", "openai_metrics", "total_cost_usd")),
    "latency_s": ("eval_report.json", ("metadata", "latency_seconds")),
    "ucr_findings": ("ech_measurement.json", ("findings", "unsupported_claim_rate")),
    "ucr_forwarded": ("ech_measurement.json", ("forwarded_findings", "unsupported_claim_rate")),
    "ucr_analysis": ("ech_measurement.json", ("analysis", "unsupported_claim_rate")),
    "ucr_report": ("ech_measurement.json", ("report", "unsupported_claim_rate")),
    "ref_validity_findings": ("ech_measurement.json", ("findings", "reference_validity")),
    "provenance_findings": ("ech_measurement.json", ("findings", "provenance_completeness")),
    "irrelevant_citations": ("ech_measurement.json", ("findings", "irrelevant_citation_rate")),
}


def config_env(name: str) -> dict:
    return dict(OFF, **COMMON, **CONFIGS[name])


def plan(name: str, configs=None, scenarios=SCENARIOS, repeats: int = 5) -> dict:
    runs = []
    for config in configs or list(CONFIGS):
        for scenario in scenarios:
            for repeat in range(1, repeats + 1):
                run_name = f"{name}_{config}_{scenario}_r{repeat}"
                runs.append({"config": config, "scenario": scenario, "repeat": repeat, "run_name": run_name,
                             "env": config_env(config),
                             "command": [sys.executable, "main.py", "--scenario", scenario, "--run-name", run_name]})
    return {"name": name, "created": datetime.now().isoformat(timespec="seconds"), "runs": runs}


def _run_dir(runs_root: Path, run_name: str) -> Path | None:
    found = sorted(runs_root.glob(f"{run_name}_*"))
    return found[-1] if found else None


def _get(data, path):
    for key in path:
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    return data


def collect(experiment: dict, runs_root: Path) -> list[dict]:
    rows = []
    for run in experiment["runs"]:
        folder = _run_dir(runs_root, run["run_name"])
        row = {"config": run["config"], "scenario": run["scenario"], "repeat": run["repeat"],
               "run_dir": str(folder) if folder else None}
        cache = {}
        for metric, (file_name, path) in METRICS.items():
            if folder and file_name not in cache:
                target = folder / file_name
                cache[file_name] = json.loads(target.read_text(encoding="utf-8")) if target.exists() else None
            row[metric] = _get(cache.get(file_name), path) if folder else None
        rows.append(row)
    return rows


def summarize(rows: list[dict]) -> list[dict]:
    """Mean and standard deviation per configuration x scenario, over the repeats that finished."""
    groups: dict[tuple, list] = {}
    for row in rows:
        groups.setdefault((row["config"], row["scenario"]), []).append(row)
    order = {c: i for i, c in enumerate(CONFIGS)}
    table = []
    for (config, scenario), group in sorted(groups.items(), key=lambda kv: (order.get(kv[0][0], 99), kv[0][1])):
        entry = {"config": config, "scenario": scenario, "runs": len(group),
                 "finished": sum(1 for r in group if r["run_dir"])}
        for metric in METRICS:
            values = [r[metric] for r in group if isinstance(r[metric], (int, float))]
            entry[metric] = {"mean": round(statistics.mean(values), 4) if values else None,
                             "std": round(statistics.stdev(values), 4) if len(values) > 1 else None,
                             "n": len(values)}
        table.append(entry)
    return table


def to_markdown(table: list[dict], metrics=("f1_ttps", "f1_iocs", "ucr_findings", "ucr_report", "tokens_in")) -> str:
    head = "| config | scenario | finished | " + " | ".join(metrics) + " |"
    lines = [head, "|" + " --- |" * (3 + len(metrics))]
    for e in table:
        cells = [f"{e[m]['mean']} ± {e[m]['std']}" if e[m]["std"] is not None else str(e[m]["mean"]) for m in metrics]
        lines.append(f"| {e['config']} | {e['scenario']} | {e['finished']}/{e['runs']} | " + " | ".join(cells) + " |")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ep_harness.experiments")
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "run"):
        cmd = sub.add_parser(name)
        cmd.add_argument("--name", default=f"EXP{datetime.now():%Y%m%d}")
        cmd.add_argument("--configs", nargs="*", choices=list(CONFIGS))
        cmd.add_argument("--scenarios", nargs="*", default=list(SCENARIOS))
        cmd.add_argument("--repeats", type=int, default=5)
        cmd.add_argument("--out", default="experiments")
        if name == "run":
            cmd.add_argument("--execute", action="store_true", help="actually run main.py (calls the LLM)")
    summ = sub.add_parser("summarize")
    summ.add_argument("--name", required=True)
    summ.add_argument("--out", default="experiments")
    summ.add_argument("--runs", default="runs")
    args = parser.parse_args(argv)

    if args.command == "summarize":
        folder = Path(args.out) / args.name
        experiment = json.loads((folder / "plan.json").read_text(encoding="utf-8"))
        table = summarize(collect(experiment, Path(args.runs)))
        (folder / "summary.json").write_text(json.dumps(table, indent=2), encoding="utf-8")
        (folder / "summary.md").write_text(to_markdown(table) + "\n", encoding="utf-8")
        print(to_markdown(table))
        return 0

    experiment = plan(args.name, args.configs, args.scenarios, args.repeats)
    folder = Path(args.out) / args.name
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "plan.json").write_text(json.dumps(experiment, indent=2), encoding="utf-8")
    print(f"{len(experiment['runs'])} runs planned -> {folder / 'plan.json'}")
    if args.command == "plan" or not args.execute:
        if args.command == "run":
            print("Dry run: add --execute to call the LLM.")
        for run in experiment["runs"][:6]:
            print(" ", run["config"], run["scenario"], f"r{run['repeat']}")
        return 0
    for run in experiment["runs"]:
        print(f"[experiment] {run['run_name']}")
        subprocess.run(run["command"], env=dict(os.environ, **run["env"]), check=False)
    print(f"Done. Summarize with: python -m ep_harness.experiments summarize --name {args.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
