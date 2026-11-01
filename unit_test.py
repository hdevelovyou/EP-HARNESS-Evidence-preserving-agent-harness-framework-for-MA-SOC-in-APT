import json
import os
from datetime import datetime

from evaluation.evaluator import SOCEvaluator


def _latest_run_report():
    runs_dir = "runs"
    if not os.path.isdir(runs_dir):
        return None

    candidates = []
    for run_name in os.listdir(runs_dir):
        report_path = os.path.join(runs_dir, run_name, "FINAL_REPORT_SOC.md")
        if os.path.isfile(report_path):
            candidates.append(report_path)

    if not candidates:
        return None

    return max(candidates, key=os.path.getmtime)


def test_independent_evaluator(scenario_name="MIMIKATZ_TEST"):
    evaluator = SOCEvaluator()

    raw_log = (
        "[2026-05-13 08:17:55] [CRITICAL] [IDS-Snort]\n"
        "Sensor=DMZ-IDS-01\n"
        "Signature=\"ET EXPLOIT Apache Struts RCE Attempt\"\n"
        "SourceIP=45.227.255.201\n"
        "DestinationIP=10.10.20.8\n"
        "DestinationPort=443\n"
        "Protocol=HTTPS\n"
        "Priority=1\n"
        "Classification=Web Application Attack"
    )

    report_path = _latest_run_report()
    if report_path is None:
        report_path = "FINAL_REPORT_SOC.md"
    ground_truth_path = os.path.join(
        "datasets",
        "CobaltStrike_Lockbit",
        "ground_truth.json",
    )

    if not os.path.exists(report_path):
        print(f"ERROR: File not found: {report_path}")
        return

    if not os.path.exists(ground_truth_path):
        print(f"ERROR: File not found: {ground_truth_path}")
        return

    with open(report_path, "r", encoding="utf-8") as f:
        final_report_content = f.read()

    with open(ground_truth_path, "r", encoding="utf-8") as f:
        ground_truth_data = json.load(f)

    print(f"--- INDEPENDENT EVALUATOR: {scenario_name} ---")

    pre_json = evaluator._extract_entities(raw_log, source_type="log")
    post_json = evaluator._extract_entities(final_report_content, source_type="report")

    t1_results = evaluator.compare_entities(pre_json, post_json)
    t2_results = evaluator.calculate_layer_2_jaccard(
        ground_truth_data,
        post_json,
        w_i=0.7,
        w_j=0.3,
    )

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    scenario_id = f"{scenario_name}_{timestamp}"

    final_eval_data = {
        "scenario_id": scenario_id,
        "metadata": {
            "test_date": datetime.now().isoformat(),
            "raw_log": raw_log,
        },
        "layer_1_metrics": t1_results["layer_1_metrics"],
        "layer_1_details": t1_results["details"],
        "layer_2_audit": t2_results,
    }

    print("\n" + "=" * 50)
    print(f"EVALUATION RESULT: {scenario_id}")
    print(f"Layer 1 Recall:    {t1_results['layer_1_metrics']['recall']}")
    print(f"Layer 1 Precision: {t1_results['layer_1_metrics']['precision']}")
    print(f"Layer 1 F1 Score:  {t1_results['layer_1_metrics']['f1_score']}")
    print(f"Layer 2 Score:     {t2_results.get('enrichment_quality_score', 'N/A')}/10")
    print(f"Layer 2 TTP F1:    {t2_results.get('f1_ttps', 'N/A')}")
    print(f"Layer 2 IOC F1:    {t2_results.get('f1_iocs', 'N/A')}")

    return final_eval_data


if __name__ == "__main__":
    test_independent_evaluator(scenario_name="UNIT_TEST_MIMIKATZ")
