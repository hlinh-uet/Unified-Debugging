from __future__ import annotations

import glob
import json
import os
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence


PASS_OUTCOMES = {"PASS", "PASSED", "SUCCESS"}
FAIL_OUTCOMES = {"FAIL", "FAILED"}


@dataclass
class Defects4CLoadConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    bug_id_filter: str = ""
    exclude_fixed_fail_tests: bool = True


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _workspace_root() -> str:
    return os.path.abspath(os.path.join(_project_root(), ".."))


def default_defects4c_root() -> str:
    return os.path.join(_workspace_root(), "defects4c")


def _metadata_base_dir(defects4c_root: str) -> str:
    return os.path.join(defects4c_root, "out_tmp_dirs", "unified_debugging")


def default_metadata_dir(dataset: str = "fmt", defects4c_root: str = "") -> str:
    root = defects4c_root or default_defects4c_root()
    return os.path.join(_metadata_base_dir(root), dataset, "metadata")


def list_available_datasets(defects4c_root: str = "") -> List[str]:
    root = defects4c_root or default_defects4c_root()
    base = _metadata_base_dir(root)
    if not os.path.isdir(base):
        return []
    datasets = []
    for name in sorted(os.listdir(base)):
        metadata_dir = os.path.join(base, name, "metadata")
        if glob.glob(os.path.join(metadata_dir, "*_meta.json")):
            datasets.append(name)
    return datasets


def _bug_filter(value: str) -> set:
    return {item.strip() for item in str(value or "").split(",") if item.strip()}


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _covered_functions(test: dict) -> List[str]:
    covered = test.get("covered_functions")
    if covered is None:
        covered = test.get("covered_methods", [])
    if not isinstance(covered, list):
        return []
    return [str(item) for item in covered if item]


def _source_basename(metadata: dict) -> str:
    basename = metadata.get("source_basename")
    if basename:
        return os.path.basename(str(basename))
    source_file = metadata.get("source_file")
    return os.path.basename(str(source_file or ""))


def normalize_function_key(function_key: object, source_basename: str = "") -> str:
    raw = str(function_key or "").strip()
    if not raw:
        return ""

    normalized = raw.replace("\\", "/")

    if source_basename:
        for marker in (f"{source_basename}::", f"{source_basename}:"):
            if marker in normalized:
                return f"{source_basename}:{normalized.split(marker, 1)[1]}"

    match = re.match(
        r"(?P<file>.*\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx))(?:::|:)(?P<func>.+)$",
        normalized,
    )
    if match:
        basename = os.path.basename(match.group("file"))
        func_part = match.group("func")
        if basename and func_part:
            return f"{basename}:{func_part}"

    if ":" in normalized and "::" not in normalized:
        file_part, func_part = normalized.split(":", 1)
        basename = os.path.basename(file_part)
        if basename and func_part:
            return f"{basename}:{func_part}"

    if source_basename:
        return f"{source_basename}:{normalized}"
    return normalized


def _normalize_ground_truth(metadata: dict) -> List[str]:
    basename = _source_basename(metadata)
    ground_truth = metadata.get("ground_truth") or []
    normalized = [
        normalize_function_key(item, basename)
        for item in ground_truth
        if normalize_function_key(item, basename)
    ]
    if normalized:
        return sorted(dict.fromkeys(normalized))

    functions = metadata.get("ground_truth_functions") or []
    return sorted(
        dict.fromkeys(
            normalize_function_key(item, basename)
            for item in functions
            if normalize_function_key(item, basename)
        )
    )


def _filtered_tests(tests: Sequence[dict], exclude_fixed_fail_tests: bool) -> tuple:
    kept = []
    excluded = []
    for test in tests:
        if not isinstance(test, dict):
            continue
        outcome_fixed = _outcome(test.get("outcome_fixed"))
        if exclude_fixed_fail_tests and outcome_fixed in FAIL_OUTCOMES:
            excluded.append(str(test.get("test_id") or ""))
            continue
        item = dict(test)
        item["covered_functions"] = _covered_functions(test)
        kept.append(item)
    return kept, excluded


def _metadata_paths_for_config(config: Defects4CLoadConfig) -> List[str]:
    if config.metadata_dir:
        metadata_dirs = [config.metadata_dir]
    elif str(config.dataset).lower() == "all":
        root = config.defects4c_root or default_defects4c_root()
        metadata_dirs = [
            default_metadata_dir(dataset, root)
            for dataset in list_available_datasets(root)
        ]
    else:
        metadata_dirs = [
            default_metadata_dir(config.dataset, config.defects4c_root)
        ]

    paths: List[str] = []
    for metadata_dir in metadata_dirs:
        paths.extend(glob.glob(os.path.join(metadata_dir, "*_meta.json")))
    return sorted(paths)


def _dataset_from_path(path: str) -> str:
    metadata_dir = os.path.basename(os.path.dirname(path))
    if metadata_dir == "metadata":
        return os.path.basename(os.path.dirname(os.path.dirname(path)))
    return ""


def load_defects4c_bugs(config: Optional[Defects4CLoadConfig] = None) -> List[dict]:
    config = config or Defects4CLoadConfig()
    filters = _bug_filter(config.bug_id_filter)
    bugs = []

    for path in _metadata_paths_for_config(config):
        bug_id = os.path.basename(path).removesuffix("_meta.json")
        try:
            with open(path, "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception as exc:
            print(f"Error loading Defects4C metadata {path}: {exc}")
            continue

        metadata_bug_id = str(metadata.get("bug_id") or "")
        if filters and bug_id not in filters and metadata_bug_id not in filters:
            continue

        raw_tests = metadata.get("tests") or []
        if not isinstance(raw_tests, list):
            raw_tests = []
        tests, excluded = _filtered_tests(raw_tests, config.exclude_fixed_fail_tests)
        bugs.append(
            {
                "bug_id": bug_id,
                "metadata_bug_id": metadata_bug_id,
                "dataset": _dataset_from_path(path) or config.dataset,
                "metadata_path": path,
                "project": metadata.get("project", ""),
                "source_file": metadata.get("source_file", ""),
                "source_basename": _source_basename(metadata),
                "ground_truth": _normalize_ground_truth(metadata),
                "ground_truth_functions": metadata.get("ground_truth_functions") or [],
                "tests": tests,
                "test_filter": {
                    "exclude_fixed_fail_tests": config.exclude_fixed_fail_tests,
                    "excluded_fixed_fail_count": len(excluded),
                    "excluded_fixed_fail_tests": excluded,
                },
            }
        )

    return bugs


def summarize_loaded_bugs(bugs: Iterable[dict]) -> Dict[str, int]:
    summary = {
        "bugs": 0,
        "tests": 0,
        "passing_tests": 0,
        "failing_tests": 0,
        "covered_test_records": 0,
    }
    for bug in bugs:
        summary["bugs"] += 1
        for test in bug.get("tests", []):
            summary["tests"] += 1
            outcome = _outcome(test.get("outcome"))
            if outcome in PASS_OUTCOMES:
                summary["passing_tests"] += 1
            elif outcome in FAIL_OUTCOMES:
                summary["failing_tests"] += 1
            if _covered_functions(test):
                summary["covered_test_records"] += 1
    return summary
