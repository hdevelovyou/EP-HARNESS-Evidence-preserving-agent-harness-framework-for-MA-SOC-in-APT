import json

INPUT_FILE = "nvdcve-2.0-2026.json"
OUTPUT_FILE = "clean_cve.json"


def get_english_description(desc_list):
    for d in desc_list:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def get_primary_cvss(metrics):
    if "cvssMetricV31" not in metrics:
        return None, None, {}

    for metric in metrics["cvssMetricV31"]:
        if metric.get("type") == "Primary":
            data = metric.get("cvssData", {})
            return (
                data.get("baseScore"),
                data.get("baseSeverity"),
                data
            )

    return None, None, {}


def get_cwe(weaknesses):
    for w in weaknesses:
        if w.get("type") == "Primary":
            for d in w.get("description", []):
                if "CWE" in d.get("value", ""):
                    return d["value"]
    return None


def extract_features(cvss_data):
    return {
        "attack_vector": cvss_data.get("attackVector"),
        "attack_complexity": cvss_data.get("attackComplexity"),
        "privileges_required": cvss_data.get("privilegesRequired"),
        "user_interaction": cvss_data.get("userInteraction")
    }


def clean_nvd():
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw = json.load(f)

    clean_data = []

    for item in raw.get("vulnerabilities", []):
        cve = item.get("cve", {})

        cve_id = cve.get("id")
        if not cve_id:
            continue

        description = get_english_description(cve.get("descriptions", []))
        if len(description) < 20:
            continue  # bỏ CVE rác

        metrics = cve.get("metrics", {})
        cvss, severity, cvss_data = get_primary_cvss(metrics)

        cwe = get_cwe(cve.get("weaknesses", []))

        features = extract_features(cvss_data)

        clean_item = {
            "id": cve_id,
            "text": description.strip(),
            "cwe": cwe,
            "cvss": cvss,
            "severity": severity,
            **features
        }

        clean_data.append(clean_item)

    # save file mới
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(clean_data, f, indent=2, ensure_ascii=False)

    print(f"Done! Saved {len(clean_data)} CVEs to {OUTPUT_FILE}")


if __name__ == "__main__":
    clean_nvd()