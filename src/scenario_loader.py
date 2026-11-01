import csv
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path


_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SCENARIO_ID_PATTERN = re.compile(r"^(S\d{1,3})$", re.IGNORECASE)
_TELEMETRY_FILENAME_PATTERN = re.compile(r"^(S\d{1,3})_telemetry\.json$", re.IGNORECASE)
_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_ARTIFACT_SECTION_PATTERN = re.compile(
    r"(?:^|;\s*)(proc|net|file|reg|host|user)\s*:\s*",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class ScenarioRuntimeSpec:
    """Leakage-free runtime descriptor for an input scenario.

    Contains only the opaque scenario_key, source_kind, telemetry artifact_path,
    and safe run_name prefix. Ground truth and threat-actor names from
    scenario_manifest.csv are intentionally excluded during runtime.
    """

    scenario_key: str
    source_kind: str
    artifact_path: str
    run_name: str

    def to_dict(self):
        return asdict(self)


def _resolve_root(base_dir=None):
    return Path(base_dir).resolve() if base_dir else _PROJECT_ROOT


def list_available_scenarios(base_dir=None):
    """Discover all available extracted scenarios and legacy dataset folders."""
    root = _resolve_root(base_dir)
    catalog = []

    extracted_dir = root / "extracted_scenarios"
    manifest_file = extracted_dir / "scenario_manifest.csv"
    if extracted_dir.is_dir():
        for file_path in sorted(extracted_dir.glob("*_telemetry.json")):
            match = _TELEMETRY_FILENAME_PATTERN.match(file_path.name)
            scenario_key = match.group(1).upper() if match else file_path.stem
            catalog.append({
                "scenario_key": scenario_key,
                "source_kind": "extracted_scenario",
                "artifact_path": str(file_path),
                "ground_truth_source": str(manifest_file) if manifest_file.is_file() else None,
            })

    datasets_dir = root / "datasets"
    if datasets_dir.is_dir():
        for child in sorted(datasets_dir.iterdir()):
            if not child.is_dir():
                continue
            artifact_file = child / "artifacts.json"
            gt_file = child / "ground_truth.json"
            if artifact_file.is_file():
                catalog.append({
                    "scenario_key": child.name,
                    "source_kind": "legacy_dataset",
                    "artifact_path": str(artifact_file),
                    "ground_truth_source": str(gt_file) if gt_file.is_file() else None,
                })

    return catalog


def infer_scenario_key_from_path(artifact_path, base_dir=None):
    """Infer canonical scenario_key (e.g. 'S23' or 'CobaltStrike_Lockbit') from an artifact file path."""
    if not artifact_path:
        return None
    root = _resolve_root(base_dir)
    path = Path(artifact_path)
    if not path.is_absolute():
        path = (root / path).resolve()
    else:
        path = path.resolve()

    match = _TELEMETRY_FILENAME_PATTERN.match(path.name)
    if match:
        return match.group(1).upper()

    parent_name = path.parent.name
    datasets_dir = (root / "datasets").resolve()
    if path.parent.parent.resolve() == datasets_dir and parent_name:
        return parent_name

    id_match = _SCENARIO_ID_PATTERN.match(path.stem)
    if id_match:
        return id_match.group(1).upper()

    return path.stem


def _match_known_scenario(selector, available):
    if not selector:
        return None
    cleaned = str(selector).strip()
    if not cleaned:
        return None

    lowered = cleaned.lower()
    for entry in available:
        if entry["scenario_key"].lower() == lowered:
            return entry

    # Also support selectors like 'S07_telemetry' or 'S07_ablation_test'
    prefix_match = re.match(r"^(S\d{1,3})(?:$|[_-])", cleaned, flags=re.IGNORECASE)
    if prefix_match:
        sid = prefix_match.group(1).upper()
        for entry in available:
            if entry["scenario_key"].upper() == sid:
                return entry

    for entry in available:
        key_lower = entry["scenario_key"].lower()
        if lowered.startswith(key_lower + "_") or lowered.startswith(key_lower + "-"):
            return entry

    return None


def resolve_scenario_runtime(
    scenario=None,
    artifact_path=None,
    run_label=None,
    base_dir=None,
):
    """Resolve scenario telemetry path and opaque runtime identifier without touching ground truth."""
    root = _resolve_root(base_dir)
    available = list_available_scenarios(root)

    explicit_artifact = artifact_path or os.getenv("ARTIFACT_PATH")
    explicit_scenario = scenario or os.getenv("SCENARIO_ID")
    env_scenario_name = run_label or os.getenv("SCENARIO_NAME")

    chosen_entry = None
    resolved_path = None
    scenario_key = None
    source_kind = "custom_artifact"

    # 1. Explicit scenario parameter or SCENARIO_ID takes highest priority unless artifact_path arg was passed directly
    if artifact_path:
        candidate_path = Path(artifact_path)
        if not candidate_path.is_absolute():
            candidate_path = (root / candidate_path).resolve()
        resolved_path = candidate_path
        scenario_key = (
            _match_known_scenario(scenario, available)["scenario_key"]
            if scenario and _match_known_scenario(scenario, available)
            else infer_scenario_key_from_path(candidate_path, root)
        )
        matched = _match_known_scenario(scenario_key, available)
        if matched:
            source_kind = matched["source_kind"]
    elif explicit_scenario:
        matched = _match_known_scenario(explicit_scenario, available)
        if matched:
            chosen_entry = matched
        else:
            candidate_path = Path(explicit_scenario)
            if not candidate_path.is_absolute():
                candidate_path = (root / candidate_path).resolve()
            if candidate_path.is_file():
                resolved_path = candidate_path
                scenario_key = infer_scenario_key_from_path(candidate_path, root)
            else:
                known_keys = [item["scenario_key"] for item in available]
                raise FileNotFoundError(
                    f"Unknown scenario {explicit_scenario!r}. "
                    f"Available scenarios: {known_keys}"
                )
    elif explicit_artifact:
        candidate_path = Path(explicit_artifact)
        if not candidate_path.is_absolute():
            candidate_path = (root / candidate_path).resolve()
        resolved_path = candidate_path
        scenario_key = infer_scenario_key_from_path(candidate_path, root)
        matched = _match_known_scenario(scenario_key, available)
        if matched:
            source_kind = matched["source_kind"]
    elif env_scenario_name:
        matched = _match_known_scenario(env_scenario_name, available)
        if matched:
            chosen_entry = matched

    # Default selection when no CLI arg or env override was provided:
    # Prefer extracted scenarios (defaulting to S23 as compact smoke-ready APT telemetry, then first extracted),
    # falling back to legacy datasets only if extracted_scenarios is empty.
    if chosen_entry is None and resolved_path is None:
        extracted_entries = [e for e in available if e["source_kind"] == "extracted_scenario"]
        s23_entry = next((e for e in extracted_entries if e["scenario_key"].upper() == "S23"), None)
        if s23_entry:
            chosen_entry = s23_entry
        elif extracted_entries:
            chosen_entry = extracted_entries[0]
        elif available:
            chosen_entry = available[0]
        else:
            raise FileNotFoundError(
                f"No scenarios found under {root / 'extracted_scenarios'} or {root / 'datasets'}."
            )

    if chosen_entry is not None:
        scenario_key = chosen_entry["scenario_key"]
        source_kind = chosen_entry["source_kind"]
        resolved_path = Path(chosen_entry["artifact_path"]).resolve()

    if not resolved_path.is_file():
        raise FileNotFoundError(f"Scenario telemetry file not found: {resolved_path}")

    safe_run_name = (
        str(env_scenario_name).strip()
        if env_scenario_name and str(env_scenario_name).strip()
        else str(scenario_key)
    )

    return ScenarioRuntimeSpec(
        scenario_key=str(scenario_key),
        source_kind=source_kind,
        artifact_path=str(resolved_path),
        run_name=safe_run_name,
    )


def _clean_manifest_artifact_token(raw_token):
    token = str(raw_token or "").strip()
    if not token:
        return ""

    # Strip leading/trailing quotes, backticks, stray braces, and semicolons from CSV formatting
    token = token.strip(" \t\r\n`\"';{}")
    while token.endswith((";", "`", "}", "{", "\"", "'")):
        token = token[:-1].strip()
    if token.endswith(")") and "(" not in token:
        token = token[:-1].strip()
    return token


def parse_manifest_expected_artifacts(raw_expected_artifacts):
    """Parse Expected_artifacts column from scenario_manifest.csv into structured categories and atomic IOCs."""
    text = str(raw_expected_artifacts or "").strip()
    by_category = {
        "proc": [],
        "net": [],
        "file": [],
        "reg": [],
        "host": [],
        "user": [],
    }
    if not text:
        return by_category, []

    matches = list(_ARTIFACT_SECTION_PATTERN.finditer(text))
    if not matches:
        tokens = [
            cleaned
            for part in text.split(",")
            if (cleaned := _clean_manifest_artifact_token(part))
        ]
        by_category["file"] = tokens
    else:
        for idx, match in enumerate(matches):
            category = match.group(1).lower()
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(text)
            segment = text[start:end].strip()
            seen_in_cat = set()
            for raw_item in segment.split(","):
                cleaned = _clean_manifest_artifact_token(raw_item)
                if not cleaned:
                    continue
                dedup_key = cleaned.lower()
                if dedup_key in seen_in_cat:
                    continue
                seen_in_cat.add(dedup_key)
                by_category.setdefault(category, []).append(cleaned)

    atomic_iocs = []
    seen_atomic = set()
    for category in ("proc", "file", "net", "host"):
        for item in by_category.get(category, []):
            key = item.lower()
            if key not in seen_atomic:
                seen_atomic.add(key)
                atomic_iocs.append(item)

    return by_category, atomic_iocs


def _load_manifest_ground_truth(scenario_key, manifest_path):
    if not manifest_path.is_file():
        raise FileNotFoundError(
            f"Scenario manifest CSV not found for scenario {scenario_key!r}: {manifest_path}"
        )

    target_id = str(scenario_key).strip().upper()
    with open(manifest_path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            row_id = (
                row.get("Scenario_ID")
                or row.get("Scenrario_ID")
                or ""
            ).strip().upper()
            if row_id != target_id:
                continue

            raw_techniques = row.get("Simulated Techniques") or row.get("Simulated_Techniques") or ""
            t_expert = sorted({
                match.upper()
                for match in _TECHNIQUE_PATTERN.findall(raw_techniques)
            })

            raw_tactics = (
                row.get("Simulated Tactics")
                or row.get("Simiulated Tactics")
                or row.get("Simulated_Tactics")
                or ""
            )
            tactics = [
                part.strip()
                for part in raw_tactics.split(";")
                if part.strip()
            ]

            raw_artifacts = row.get("Expected_artifacts") or row.get("Expected_Artifacts") or ""
            artifacts_by_category, atomic_iocs = parse_manifest_expected_artifacts(raw_artifacts)

            return {
                "scenario_id": target_id,
                "case_name": f"{target_id}_{row.get('Scenario_Name', '').strip()}".rstrip("_"),
                "scenario_name": row.get("Scenario_Name", "").strip(),
                "mitre_groups": row.get("Mitre_Groups", "").strip(),
                "reported_origin": row.get("Reported_Origin", "").strip(),
                "simulated_tactics": tactics,
                "reference": row.get("Reference", "").strip(),
                "source": str(manifest_path),
                "T_expert": t_expert,
                "I_expert": {
                    "atomic": atomic_iocs,
                    "computed": [],
                },
                "expected_artifacts_by_category": artifacts_by_category,
            }

    raise KeyError(
        f"Scenario ID {target_id!r} was not found in manifest {manifest_path}."
    )


def _validate_ground_truth_alignment(scenario_key, gt_path, root):
    """Prevent accidental evaluation of scenario X against scenario Y's ground_truth.json."""
    if not scenario_key:
        return
    gt_resolved = Path(gt_path).resolve()
    datasets_dir = (root / "datasets").resolve()

    if gt_resolved.parent.parent.resolve() == datasets_dir:
        gt_dataset_name = gt_resolved.parent.name
        if gt_dataset_name.lower() != str(scenario_key).strip().lower():
            raise ValueError(
                f"Ground-truth mismatch detected: scenario_key is {scenario_key!r}, "
                f"but ground_truth_path points to dataset {gt_dataset_name!r} ({gt_resolved})."
            )


def load_scenario_ground_truth(
    scenario_key=None,
    artifact_path=None,
    ground_truth_path=None,
    manifest_path=None,
    base_dir=None,
):
    """Load the exact ground truth matching the executed scenario.

    Must ONLY be called post-runtime after FINAL_REPORT_SOC.md has been sealed.
    """
    root = _resolve_root(base_dir)
    resolved_key = scenario_key or infer_scenario_key_from_path(artifact_path, root)

    explicit_gt = ground_truth_path or os.getenv("GROUND_TRUTH_PATH")
    if explicit_gt and str(explicit_gt).strip():
        gt_candidate = Path(explicit_gt)
        if not gt_candidate.is_absolute():
            gt_candidate = (root / gt_candidate).resolve()
        else:
            gt_candidate = gt_candidate.resolve()

        if gt_candidate.suffix.lower() == ".csv":
            if not resolved_key:
                raise ValueError(
                    f"scenario_key is required when loading ground truth from CSV manifest {gt_candidate}."
                )
            return _load_manifest_ground_truth(resolved_key, gt_candidate)

        _validate_ground_truth_alignment(resolved_key, gt_candidate, root)
        with open(gt_candidate, "r", encoding="utf-8") as f:
            data = json.load(f)
        data.setdefault("scenario_id", resolved_key or gt_candidate.parent.name)
        data.setdefault("source", str(gt_candidate))
        return data

    if resolved_key and _SCENARIO_ID_PATTERN.match(str(resolved_key).strip()):
        resolved_manifest = Path(
            manifest_path
            or os.getenv("SCENARIO_MANIFEST_PATH")
            or (root / "extracted_scenarios" / "scenario_manifest.csv")
        )
        if not resolved_manifest.is_absolute():
            resolved_manifest = (root / resolved_manifest).resolve()
        return _load_manifest_ground_truth(resolved_key, resolved_manifest)

    # Legacy dataset resolution (datasets/<scenario_key>/ground_truth.json or sibling of artifact_path)
    candidate_paths = []
    if artifact_path:
        art_path = Path(artifact_path)
        if not art_path.is_absolute():
            art_path = (root / art_path).resolve()
        candidate_paths.append(art_path.parent / "ground_truth.json")
    if resolved_key:
        candidate_paths.append(root / "datasets" / str(resolved_key) / "ground_truth.json")
        for entry in list_available_scenarios(root):
            if entry["scenario_key"].lower() == str(resolved_key).lower() and entry.get("ground_truth_source"):
                candidate_paths.append(Path(entry["ground_truth_source"]))

    for candidate in candidate_paths:
        if candidate.is_file():
            if candidate.suffix.lower() == ".csv":
                return _load_manifest_ground_truth(resolved_key, candidate)
            _validate_ground_truth_alignment(resolved_key, candidate, root)
            with open(candidate, "r", encoding="utf-8") as f:
                data = json.load(f)
            data.setdefault("scenario_id", resolved_key or candidate.parent.name)
            data.setdefault("source", str(candidate.resolve()))
            return data

    raise FileNotFoundError(
        f"Could not locate ground truth for scenario_key={resolved_key!r} "
        f"(artifact_path={artifact_path!r})."
    )
