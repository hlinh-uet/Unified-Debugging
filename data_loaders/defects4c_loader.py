"""
Defects4C loader.

Input convention:
    defects4c/out_tmp_dirs/unified_debugging/<data_folder>/metadata/*_meta.json

`<data_folder>` is the only selector used by Unified-Debugging.  The actual
Defects4C project name, commit ids, compile command, and test command are read
from each metadata JSON file.
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Dict, List, Optional, Tuple

from configs.path import DEFECTS4C_CACHE_DIR, DEFECTS4C_OUT_DIR, DEFECTS4C_UNIFIED_DIR
from core.utils import parse_sbfl_qualified_name
from data_loaders.base_loader import BugLoader, BugRecord


class Defects4CLoader(BugLoader):
    """Load Defects4C records by metadata folder slug."""

    def __init__(self, data_folder: Optional[str] = None, project: Optional[str] = None):
        # `project` is accepted only for backward compatibility with older calls.
        requested = data_folder or project
        self.data_folder = self._resolve_data_folder(requested)
        self.cache_dir = os.path.join(DEFECTS4C_CACHE_DIR, self.data_folder or "all")
        self._records: Optional[List[BugRecord]] = None
        self._bug_info_cache: Dict[str, List[dict]] = {}

    def load_all(self) -> List[BugRecord]:
        if self._records is not None:
            return self._records

        records: List[BugRecord] = []
        for folder, metadata_dir in self._metadata_dirs():
            for filename in sorted(os.listdir(metadata_dir)):
                if not filename.endswith("_meta.json"):
                    continue
                record = self._record_from_meta_file(
                    os.path.join(metadata_dir, filename),
                    data_folder=folder,
                )
                if record:
                    records.append(record)

        self._deduplicate_bug_ids(records)
        self._records = records
        return records

    def load_one(self, bug_id: str) -> Optional[BugRecord]:
        for record in self.load_all():
            raw = record.raw or {}
            candidates = {
                record.bug_id,
                raw.get("original_bug_id", ""),
                raw.get("metadata_stem", ""),
                raw.get("commit_after", ""),
            }
            project = raw.get("project", "")
            commit_after = raw.get("commit_after", "")
            if project and commit_after:
                candidates.add(f"{project}@{commit_after}")
            if bug_id in candidates:
                return record
        return None

    def _resolve_data_folder(self, requested: Optional[str]) -> Optional[str]:
        if not requested:
            return None
        key = requested.strip()
        if key.lower().startswith("defects4c-"):
            key = key[len("defects4c-"):]

        direct = os.path.join(DEFECTS4C_UNIFIED_DIR, key, "metadata")
        if os.path.isdir(direct):
            return key

        if os.path.isdir(DEFECTS4C_UNIFIED_DIR):
            for folder in sorted(os.listdir(DEFECTS4C_UNIFIED_DIR)):
                if folder.lower() == key.lower():
                    return folder

        raise ValueError(
            f"Không tìm thấy Defects4C data folder '{requested}' tại "
            f"{DEFECTS4C_UNIFIED_DIR}/<folder>/metadata"
        )

    def _metadata_dirs(self) -> List[Tuple[str, str]]:
        if self.data_folder:
            path = os.path.join(DEFECTS4C_UNIFIED_DIR, self.data_folder, "metadata")
            return [(self.data_folder, path)] if os.path.isdir(path) else []

        if not os.path.isdir(DEFECTS4C_UNIFIED_DIR):
            return []
        out = []
        for folder in sorted(os.listdir(DEFECTS4C_UNIFIED_DIR)):
            path = os.path.join(DEFECTS4C_UNIFIED_DIR, folder, "metadata")
            if os.path.isdir(path):
                out.append((folder, path))
        return out

    def _record_from_meta_file(self, path: str, data_folder: str) -> Optional[BugRecord]:
        try:
            with open(path, "r") as f:
                raw = json.load(f)
        except Exception as exc:
            print(f"[Defects4CLoader] Lỗi đọc metadata {path}: {exc}")
            return None

        metadata_stem = os.path.basename(path).replace("_meta.json", "")
        bug_info = self._match_bug_info(data_folder, raw, metadata_stem)
        bug_files = bug_info.get("files", {}) if isinstance(bug_info.get("files"), dict) else {}
        src_files = _normalize_path_list(bug_files.get("src", []))
        test_files = _normalize_path_list(bug_files.get("test", []))
        raw_source_file = raw.get("source_file", "")
        host_source_file = _container_to_host_path(raw_source_file)
        repo_dir = _find_git_root(host_source_file)
        source_relpath = _relpath_or_basename(host_source_file, repo_dir)
        source_basename = raw.get("source_basename") or os.path.basename(source_relpath)

        safe_id = metadata_stem.replace("@", "__").replace("/", "__")
        record_cache_dir = os.path.join(DEFECTS4C_CACHE_DIR, data_folder, safe_id)
        source_file, accepted_file = self._ensure_source_cache(
            raw=raw,
            host_source_file=host_source_file,
            repo_dir=repo_dir,
            source_relpath=source_relpath,
            source_basename=source_basename,
            cache_dir=record_cache_dir,
        )

        tests = _normalize_tests(raw.get("tests", []))
        ground_truth = _normalize_ground_truth(raw, source_basename)
        original_bug_id = raw.get("bug_id", metadata_stem)

        enriched_raw = {
            **raw,
            "bug_id": original_bug_id,
            "original_bug_id": original_bug_id,
            "metadata_file": path,
            "metadata_stem": metadata_stem,
            "data_folder": data_folder,
            "metadata_slug": data_folder,
            "source_file": source_file,
            "accepted_file": accepted_file,
            "source_basename": source_basename,
            "source_cache_dir": record_cache_dir,
            "source_repo_dir": repo_dir,
            "source_relpath": source_relpath,
            "original_source_file": raw_source_file,
            "host_source_file": host_source_file,
            "container_repo_dir": _container_repo_dir(raw_source_file, repo_dir),
            "defects4c_bug_info": bug_info,
            "src_files": src_files or ([source_relpath] if source_relpath else []),
            "test_files": test_files,
        }

        return BugRecord(
            bug_id=original_bug_id,
            dataset="defects4c",
            tests=tests,
            ground_truth=ground_truth,
            source_file=source_file,
            compile_cmd=raw.get("compile_cmd"),
            test_cmd_template=raw.get("test_cmd_template"),
            raw=enriched_raw,
        )

    def _match_bug_info(self, data_folder: str, raw: dict, metadata_stem: str) -> dict:
        candidates = self._load_bug_infos(data_folder)
        if not candidates:
            return {}

        commit_after = str(raw.get("commit_after") or "").strip()
        commit_before = str(raw.get("commit_before") or "").strip()
        bug_id = str(raw.get("bug_id") or metadata_stem).strip()

        def type_id(item: dict) -> str:
            bug_type = item.get("type", {})
            return str(bug_type.get("id") or bug_type.get("name") or "").strip() if isinstance(bug_type, dict) else ""

        exact = [
            item for item in candidates
            if commit_after and item.get("commit_after") == commit_after
            and (not commit_before or item.get("commit_before") == commit_before)
            and (not bug_id or type_id(item) in ("", bug_id) or bug_id.startswith(type_id(item)))
        ]
        if exact:
            return exact[0]

        by_after = [item for item in candidates if commit_after and item.get("commit_after") == commit_after]
        if len(by_after) == 1:
            return by_after[0]

        by_type = [item for item in candidates if bug_id and type_id(item) == bug_id]
        if len(by_type) == 1:
            return by_type[0]
        return {}

    def _load_bug_infos(self, data_folder: str) -> List[dict]:
        if data_folder in self._bug_info_cache:
            return self._bug_info_cache[data_folder]

        path = os.path.join(DEFECTS4C_UNIFIED_DIR, data_folder, "metadata", "bugs_list_new.json")
        try:
            with open(path, "r") as f:
                data = json.load(f)
        except FileNotFoundError:
            data = []
        except Exception as exc:
            print(f"[Defects4CLoader] Lỗi đọc bugs_list_new.json cho {data_folder}: {exc}")
            data = []

        if not isinstance(data, list):
            data = []
        self._bug_info_cache[data_folder] = [x for x in data if isinstance(x, dict)]
        return self._bug_info_cache[data_folder]

    def _ensure_source_cache(
        self,
        raw: dict,
        host_source_file: str,
        repo_dir: str,
        source_relpath: str,
        source_basename: str,
        cache_dir: str,
    ) -> Tuple[str, str]:
        os.makedirs(cache_dir, exist_ok=True)
        buggy_path = os.path.join(cache_dir, source_basename)
        accepted_path = os.path.join(cache_dir, f"{source_basename}.accepted")

        buggy_content = _git_show(repo_dir, raw.get("commit_before", ""), source_relpath)
        accepted_content = _git_show(repo_dir, raw.get("commit_after", ""), source_relpath)

        if buggy_content is None:
            buggy_content = _read_file(host_source_file)
        if accepted_content is None:
            accepted_content = _read_file(host_source_file)

        if buggy_content is not None:
            with open(buggy_path, "w") as f:
                f.write(buggy_content)
        else:
            buggy_path = host_source_file

        if accepted_content is not None:
            with open(accepted_path, "w") as f:
                f.write(accepted_content)
        else:
            accepted_path = raw.get("accepted_file", "")

        return buggy_path, accepted_path

    @staticmethod
    def _deduplicate_bug_ids(records: List[BugRecord]) -> None:
        counts: Dict[str, int] = {}
        for record in records:
            counts[record.bug_id] = counts.get(record.bug_id, 0) + 1

        for record in records:
            if counts.get(record.bug_id, 0) <= 1:
                continue
            raw = record.raw or {}
            record.bug_id = raw.get("metadata_stem") or record.bug_id
            raw["bug_id"] = record.bug_id


def get_defects4c_accepted_path(bug_id: str) -> str:
    record = Defects4CLoader().load_one(bug_id)
    if not record or not record.raw:
        return ""
    return record.raw.get("accepted_file", "")


def get_defects4c_source_path(bug_id: str) -> str:
    record = Defects4CLoader().load_one(bug_id)
    return record.source_file if record else ""


def get_defects4c_raw_record(bug_id: str) -> Optional[dict]:
    record = Defects4CLoader().load_one(bug_id)
    return record.raw if record else None


def parse_defects4c_bug_id(bug_id: str, default_project: str = "") -> Tuple[str, str]:
    if "@" in bug_id:
        return tuple(bug_id.split("@", 1))  # type: ignore[return-value]
    return default_project, bug_id


def _normalize_tests(tests: List[dict]) -> List[dict]:
    out = []
    for test in tests:
        covered = test.get("covered_functions")
        if covered is None:
            covered = test.get("covered_methods", [])
        normalized = [_normalize_coverage_key(x) for x in covered if isinstance(x, str)]
        out.append({**test, "covered_functions": normalized, "covered_methods": normalized})
    return out


def _normalize_ground_truth(raw: dict, source_basename: str) -> List[str]:
    out = []
    for item in raw.get("ground_truth", []) or []:
        if isinstance(item, str):
            normalized = _normalize_coverage_key(item)
            if normalized:
                out.append(normalized)

    if not out:
        for fn in raw.get("ground_truth_functions", []) or []:
            if isinstance(fn, str) and fn:
                out.append(f"{source_basename}:{fn}")
    return sorted(set(out))


def _normalize_path_list(values) -> List[str]:
    if not isinstance(values, list):
        return []
    out = []
    for value in values:
        if not isinstance(value, str):
            continue
        cleaned = value.strip().replace("\\", "/")
        if cleaned:
            out.append(cleaned)
    return sorted(dict.fromkeys(out))


def _normalize_coverage_key(value: str) -> str:
    if not value:
        return ""
    if "::" in value:
        file_hint, func = value.rsplit("::", 1)
        return f"{os.path.basename(file_hint)}:{func}"
    file_hint, func = parse_sbfl_qualified_name(value)
    if file_hint and func:
        return f"{os.path.basename(file_hint)}:{func}"
    return value


def _container_to_host_path(path: str) -> str:
    if not path or not isinstance(path, str):
        return path
    if os.path.exists(path):
        return path
    if path.startswith("/out/"):
        mapped = os.path.join(DEFECTS4C_OUT_DIR, path[len("/out/"):])
        if os.path.exists(mapped):
            return mapped
    return path


def _container_repo_dir(raw_source_file: str, repo_dir: str) -> str:
    if raw_source_file.startswith("/out/"):
        rel = raw_source_file[len("/out/"):]
        parts = rel.split("/")
        if len(parts) >= 2:
            return "/out/" + "/".join(parts[:2])
    if repo_dir.startswith(DEFECTS4C_OUT_DIR):
        rel = os.path.relpath(repo_dir, DEFECTS4C_OUT_DIR).replace(os.sep, "/")
        return f"/out/{rel}"
    return ""


def _find_git_root(path: str) -> str:
    cur = path if os.path.isdir(path) else os.path.dirname(path)
    while cur and cur != os.path.dirname(cur):
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        cur = os.path.dirname(cur)
    return ""


def _relpath_or_basename(path: str, root: str) -> str:
    if root:
        try:
            return os.path.relpath(path, root).replace(os.sep, "/")
        except ValueError:
            pass
    return os.path.basename(path)


def _git_show(repo_dir: str, commit: str, relpath: str) -> Optional[str]:
    if not repo_dir or not commit or not relpath:
        return None
    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "show", f"{commit}:{relpath}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return None
    if result.returncode != 0:
        return None
    return result.stdout


def _read_file(path: str) -> Optional[str]:
    if not path or not os.path.exists(path):
        return None
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except Exception:
        return None
