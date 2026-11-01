import os
import json

INPUT_FOLDER = "attack-pattern"
OUTPUT_FILE = "attack_dataset.json"


def extract_external_id(obj):
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            return ref.get("external_id")
    return None


def extract_tactics(obj):
    return [
        phase.get("phase_name")
        for phase in obj.get("kill_chain_phases", [])
        if phase.get("kill_chain_name") == "mitre-attack"
    ]


def clean_text(text):
    if not text:
        return ""
    return " ".join(text.replace("\n", " ").split())


def parse_attack_pattern(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            # bỏ deprecated
            if obj.get("x_mitre_deprecated"):
                continue

            technique_id = extract_external_id(obj)
            if not technique_id:
                continue

            return {
                "id": technique_id,
                "name": obj.get("name"),
                "tactics": extract_tactics(obj),
                "text": clean_text(obj.get("description")),
                "platforms": obj.get("x_mitre_platforms", []),
                "is_subtechnique": obj.get("x_mitre_is_subtechnique", False)
            }

    except Exception as e:
        print(f"Error reading {file_path}: {e}")

    return None


def build_dataset():
    dataset = []

    for filename in os.listdir(INPUT_FOLDER):
        if not filename.endswith(".json"):
            continue

        file_path = os.path.join(INPUT_FOLDER, filename)

        item = parse_attack_pattern(file_path)
        if item:
            dataset.append(item)

    # save file
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2, ensure_ascii=False)

    print(f"Done! Extracted {len(dataset)} techniques → {OUTPUT_FILE}")


if __name__ == "__main__":
    build_dataset()