"""
data_loaders/defects4c_loader.py
--------------------------------
Loader tối thiểu cho Defects4C project tcpdump.

Defects4C không lưu sẵn JSON theo schema của Unified-Debugging như Codeflaws.
Loader này đọc metadata gốc của Defects4C và tạo cache source trong
experiments/defects4c_cache để các bước FL/APR đọc được file nguồn ổn định.
"""

from __future__ import annotations

import csv
import glob
import json
import os
import re
from typing import Dict, List, Optional, Tuple

from configs.path import (
    DEFECTS4C_CACHE_DIR,
    DEFECTS4C_OUT_DIR,
    DEFECTS4C_RAW_INFO_CSV,
    DEFECTS4C_SRC_CONTENT_JSONL,
    DEFECTS4C_TCPDUMP_METADATA_DIR,
    DEFECTS4C_TCPDUMP_PROJECT,
    DEFECTS4C_TCPDUMP_PROJECT_DIR,
)
from core.utils import qualify_func
from data_loaders.base_loader import BugLoader, BugRecord


class Defects4CLoader(BugLoader):
    """Load Defects4C tcpdump records into the common BugRecord format."""

    def __init__(self, project: str = "tcpdump"):
        if project not in ("tcpdump", DEFECTS4C_TCPDUMP_PROJECT):
            raise ValueError("Defects4CLoader hiện chỉ hỗ trợ project tcpdump")

        self.project = DEFECTS4C_TCPDUMP_PROJECT
        self.project_dir = DEFECTS4C_TCPDUMP_PROJECT_DIR
        self.metadata_dir = DEFECTS4C_TCPDUMP_METADATA_DIR
        self.cache_dir = os.path.join(DEFECTS4C_CACHE_DIR, self.project)

        self._bugs: Optional[List[dict]] = None
        self._raw_info: Optional[Dict[str, dict]] = None
        self._accepted_content: Optional[Dict[str, str]] = None
        self._buggy_functions: Optional[Dict[str, dict]] = None

    def load_all(self) -> List[BugRecord]:
        standardized = self._load_standardized_records()
        if standardized:
            return standardized

        records = []
        for bug_meta in self._load_bug_list():
            record = self._build_record(bug_meta)
            if record:
                records.append(record)
        return records

    def load_one(self, bug_id: str) -> Optional[BugRecord]:
        standardized = self._load_standardized_record(bug_id)
        if standardized:
            return standardized

        project, sha = parse_defects4c_bug_id(bug_id, default_project=self.project)
        if project != self.project:
            return None

        for bug_meta in self._load_bug_list():
            if bug_meta.get("commit_after") == sha:
                return self._build_record(bug_meta)
        return None

    def _load_standardized_records(self) -> List[BugRecord]:
        if not os.path.isdir(self.metadata_dir):
            return []

        records: List[BugRecord] = []
        for filename in sorted(os.listdir(self.metadata_dir)):
            if not filename.endswith("_meta.json"):
                continue
            record = self._record_from_meta_file(os.path.join(self.metadata_dir, filename))
            if record:
                records.append(record)
        return records

    def _load_standardized_record(self, bug_id: str) -> Optional[BugRecord]:
        if not os.path.isdir(self.metadata_dir):
            return None

        safe_id = bug_id.replace("@", "__").replace("/", "__")
        path = os.path.join(self.metadata_dir, f"{safe_id}_meta.json")
        if os.path.exists(path):
            return self._record_from_meta_file(path)

        _, sha = parse_defects4c_bug_id(bug_id, default_project=self.project)
        for filename in os.listdir(self.metadata_dir):
            if sha in filename and filename.endswith("_meta.json"):
                return self._record_from_meta_file(os.path.join(self.metadata_dir, filename))
        return None

    def _record_from_meta_file(self, path: str) -> Optional[BugRecord]:
        try:
            with open(path, "r") as f:
                raw = json.load(f)
        except Exception as e:
            print(f"[Defects4CLoader] Lỗi đọc metadata chuẩn {path}: {e}")
            return None

        source_file = self._normalize_host_path(raw.get("source_file", ""))

        # Suy ra accepted_file nếu meta file không có sẵn trường này.
        # Convention: _ensure_source_cache tạo ra "<source_file>.accepted"
        accepted_file = raw.get("accepted_file", "")
        if not accepted_file or not os.path.exists(accepted_file):
            # Thử "source_file.accepted" (path đã được normalize sang host path)
            candidate = source_file + ".accepted" if source_file else ""
            if candidate and os.path.exists(candidate):
                accepted_file = candidate
            else:
                # Fallback: tìm trong cache_dir/<bug_id>/<src_basename>.accepted
                bug_id_raw = raw.get("bug_id", "")
                src_basename = raw.get("source_basename") or (
                    os.path.basename(source_file) if source_file else ""
                )
                if bug_id_raw and src_basename:
                    alt = os.path.join(
                        self.cache_dir,
                        bug_id_raw.replace("@", "__"),
                        f"{src_basename}.accepted",
                    )
                    if os.path.exists(alt):
                        accepted_file = alt
        raw = {**raw, "accepted_file": accepted_file, "source_file": source_file}

        tests = self._requalify_tests(raw.get("tests", []), source_file)
        ground_truth = raw.get("ground_truth") or self._qualify_names(
            raw.get("ground_truth_functions", []),
            source_file,
        )

        return BugRecord(
            bug_id=raw.get("bug_id", os.path.basename(path).replace("_meta.json", "")),
            dataset=raw.get("dataset_name", "defects4c"),
            tests=tests,
            ground_truth=ground_truth,
            source_file=source_file,
            compile_cmd=raw.get("compile_cmd"),
            test_cmd_template=raw.get("test_cmd_template"),
            raw=raw,
        )

    def _normalize_host_path(self, maybe_path: str) -> str:
        """Map container paths (/out/...) to host paths when running APR/FL on host."""
        if not maybe_path or not isinstance(maybe_path, str):
            return maybe_path
        if os.path.exists(maybe_path):
            return maybe_path
        if maybe_path.startswith("/out/"):
            mapped = os.path.join(DEFECTS4C_OUT_DIR, maybe_path[len("/out/"):])
            if os.path.exists(mapped):
                return mapped
        return maybe_path

    def _requalify_tests(self, tests: List[dict], source_file: str) -> List[dict]:
        """Normalize coverage symbols for FL across metadata versions.

        New format stores `covered_functions` as `file:function`.
        Legacy format stores only function names or absolute_path::function.
        """
        result = []
        source_name = os.path.basename(source_file) if source_file else ""
        for test in tests:
            covered_functions = test.get("covered_functions")
            if covered_functions is not None:
                result.append({**test, "covered_methods": covered_functions})
                continue

            func_names = test.get("covered_function_names")
            if func_names is None:
                # Legacy metadata: extract function name from qualified string
                func_names = [
                    m.split("::")[-1] for m in test.get("covered_methods", []) if "::" in m
                ]

            if source_name:
                covered_functions = [f"{source_name}:{fn}" for fn in func_names]
                result.append({**test, "covered_functions": covered_functions, "covered_methods": covered_functions})
            else:
                requalified = self._qualify_names(func_names, source_file)
                result.append({**test, "covered_methods": requalified})
        return result

    def _qualify_names(self, names: List[str], source_file: str) -> List[str]:
        return [
            fn if "::" in fn else qualify_func(source_file, fn)
            for fn in names
        ]

    def _load_bug_list(self) -> List[dict]:
        if self._bugs is None:
            path = os.path.join(self.project_dir, "bugs_list_new.json")
            if not os.path.exists(path):
                print(f"[Defects4CLoader] Không tìm thấy {path}")
                self._bugs = []
            else:
                with open(path, "r") as f:
                    self._bugs = json.load(f)
        return self._bugs

    def _load_raw_info(self) -> Dict[str, dict]:
        if self._raw_info is not None:
            return self._raw_info

        result: Dict[str, dict] = {}
        if not os.path.exists(DEFECTS4C_RAW_INFO_CSV):
            self._raw_info = result
            return result

        with open(DEFECTS4C_RAW_INFO_CSV, newline="") as f:
            for row in csv.DictReader(f):
                github = row.get("github", "")
                if "the-tcpdump-group/tcpdump" not in github:
                    continue
                sha = _sha_from_github_url(github)
                if sha:
                    result[sha] = row

        self._raw_info = result
        return result

    def _load_accepted_content(self) -> Dict[str, str]:
        if self._accepted_content is not None:
            return self._accepted_content

        shas = {b.get("commit_after") for b in self._load_bug_list()}
        result: Dict[str, str] = {}
        if os.path.exists(DEFECTS4C_SRC_CONTENT_JSONL):
            with open(DEFECTS4C_SRC_CONTENT_JSONL, "r") as f:
                for line in f:
                    rec = json.loads(line)
                    src_id = rec.get("id", "")
                    sha = _sha_from_src_id(src_id)
                    if sha in shas and rec.get("content") is not None:
                        result[sha] = rec["content"]

        self._accepted_content = result
        return result

    def _load_buggy_functions(self) -> Dict[str, dict]:
        if self._buggy_functions is not None:
            return self._buggy_functions

        result: Dict[str, dict] = {}
        patterns = [
            "buggy_errmsg/*.json",
            "buggy_errmsg_cve/*.json",
        ]
        for pattern in patterns:
            for path in glob.glob(os.path.join(os.path.dirname(DEFECTS4C_SRC_CONTENT_JSONL), pattern)):
                try:
                    with open(path, "r") as f:
                        data = json.load(f)
                except Exception:
                    continue
                for key, value in data.items():
                    sha = _sha_from_src_id(key)
                    if sha and isinstance(value, dict) and value.get("buggy"):
                        result[sha] = value

        self._buggy_functions = result
        return result

    def _build_record(self, bug_meta: dict) -> Optional[BugRecord]:
        sha = bug_meta.get("commit_after")
        if not sha:
            return None

        raw_info = self._load_raw_info().get(sha, {})
        accepted = self._load_accepted_content().get(sha)
        buggy_func_meta = self._load_buggy_functions().get(sha, {})
        buggy_func = buggy_func_meta.get("buggy")
        if accepted is None or not buggy_func:
            print(f"[Defects4CLoader] Thiếu source/function metadata cho {sha}, bỏ qua.")
            return None

        src_rel = _first_src_file(bug_meta)
        src_basename = os.path.basename(src_rel or raw_info.get("src_path", f"{sha}.c"))
        bug_id = format_defects4c_bug_id(self.project, sha)

        source_file, accepted_file = self._ensure_source_cache(
            bug_id=bug_id,
            sha=sha,
            src_basename=src_basename,
            accepted_content=accepted,
            buggy_func=buggy_func,
            raw_info=raw_info,
        )

        func_name = _extract_c_function_name(buggy_func) or _func_name_from_prompt(buggy_func_meta)
        covered = [qualify_func(source_file, func_name)] if func_name else []

        test_ids = _test_ids_from_meta(bug_meta)
        tests = [
            {
                "test_id": test_id,
                "outcome": "FAIL",
                "covered_methods": covered,
                "fail_reason": bug_meta.get("type", {}).get("name", "Defects4C regression test fails"),
            }
            for test_id in test_ids
        ]
        if not tests:
            tests = [{
                "test_id": "defects4c_regression",
                "outcome": "FAIL",
                "covered_methods": covered,
                "fail_reason": bug_meta.get("type", {}).get("name", "Defects4C regression test fails"),
            }]

        return BugRecord(
            bug_id=bug_id,
            dataset="defects4c",
            tests=tests,
            ground_truth=covered,
            source_file=source_file,
            compile_cmd="bash inplace_rebuild.sh <build_dir> <log>",
            test_cmd_template="bash inplace_test.sh <build_dir> <log>",
            raw={
                **bug_meta,
                "defects4c_project": self.project,
                "source_file": source_file,
                "accepted_file": accepted_file,
                "func_name": func_name,
                "raw_info": raw_info,
            },
        )

    def _ensure_source_cache(
        self,
        bug_id: str,
        sha: str,
        src_basename: str,
        accepted_content: str,
        buggy_func: str,
        raw_info: dict,
    ) -> Tuple[str, str]:
        bug_dir = os.path.join(self.cache_dir, bug_id.replace("@", "__"))
        os.makedirs(bug_dir, exist_ok=True)

        buggy_path = os.path.join(bug_dir, src_basename)
        accepted_path = os.path.join(bug_dir, f"{src_basename}.accepted")

        with open(accepted_path, "w") as f:
            f.write(accepted_content)

        patched_buggy = _replace_function_by_offsets(accepted_content, buggy_func, raw_info)
        with open(buggy_path, "w") as f:
            f.write(patched_buggy)

        return buggy_path, accepted_path


def format_defects4c_bug_id(project: str, sha: str) -> str:
    return f"{project}@{sha}"


def parse_defects4c_bug_id(bug_id: str, default_project: str = DEFECTS4C_TCPDUMP_PROJECT) -> Tuple[str, str]:
    if "@" in bug_id:
        project, sha = bug_id.split("@", 1)
    else:
        project, sha = default_project, bug_id
    return project, sha


def get_defects4c_accepted_path(bug_id: str) -> str:
    loader = Defects4CLoader(project="tcpdump")
    record = loader.load_one(bug_id)
    if not record or not record.raw:
        return ""
    return record.raw.get("accepted_file", "")


def get_defects4c_source_path(bug_id: str) -> str:
    loader = Defects4CLoader(project="tcpdump")
    record = loader.load_one(bug_id)
    return record.source_file if record else ""


def get_defects4c_raw_record(bug_id: str) -> Optional[dict]:
    loader = Defects4CLoader(project="tcpdump")
    record = loader.load_one(bug_id)
    return record.raw if record else None


def _replace_function_by_offsets(accepted: str, buggy_func: str, raw_info: dict) -> str:
    try:
        start = int(raw_info.get("func_start_byte", -1))
        end = int(raw_info.get("func_end_byte", -1))
    except (TypeError, ValueError):
        start, end = -1, -1

    if 0 <= start < end <= len(accepted):
        return accepted[:start] + buggy_func.rstrip() + "\n" + accepted[end:]

    return accepted


def _extract_c_function_name(function_code: str) -> str:
    match = re.search(r'\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{', function_code, re.MULTILINE)
    return match.group(1) if match else ""


def _func_name_from_prompt(meta: dict) -> str:
    prefix = meta.get("prefix", "")
    return _extract_c_function_name(prefix)


def _first_src_file(bug_meta: dict) -> str:
    src_files = bug_meta.get("files", {}).get("src", [])
    return src_files[0] if src_files else ""


def _test_ids_from_meta(bug_meta: dict) -> List[str]:
    tests = []
    for path in bug_meta.get("files", {}).get("test", []):
        if path.endswith(".pcap"):
            tests.append(os.path.basename(path))
    return tests


def _sha_from_github_url(url: str) -> str:
    return url.rstrip("/").split("/")[-1] if url else ""


def _sha_from_src_id(src_id: str) -> str:
    base = os.path.basename(src_id)
    if "___" not in base:
        return ""
    sha = base.split("___", 1)[0]
    return sha if re.fullmatch(r"[0-9a-f]{40}", sha) else ""
