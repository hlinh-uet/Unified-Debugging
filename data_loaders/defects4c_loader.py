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
import re
import shutil
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
        # Avoid load_all() here. APR/evaluation commonly need only a few bugs;
        # scanning every metadata file would also create/reset every cached
        # worktree and can fail because of unrelated stale worktrees.
        requested = str(bug_id or "").strip()
        if not requested:
            return None

        metadata_files = []
        for folder, metadata_dir in self._metadata_dirs():
            direct = os.path.join(metadata_dir, f"{requested}_meta.json")
            if os.path.isfile(direct):
                record = self._record_from_meta_file(direct, data_folder=folder)
                if record:
                    self._prefer_unique_metadata_id(record, requested)
                return record
            for filename in sorted(os.listdir(metadata_dir)):
                if filename.endswith("_meta.json"):
                    metadata_files.append((folder, os.path.join(metadata_dir, filename)))

        for folder, path in metadata_files:
            try:
                with open(path, "r") as f:
                    raw = json.load(f)
            except Exception:
                continue

            metadata_stem = os.path.basename(path).replace("_meta.json", "")
            candidates = {
                metadata_stem,
                str(raw.get("bug_id") or ""),
                str(raw.get("original_bug_id") or ""),
                str(raw.get("commit_after") or ""),
            }
            project = str(raw.get("project") or "")
            commit_after = str(raw.get("commit_after") or "")
            if project and commit_after:
                candidates.add(f"{project}@{commit_after}")
            if requested in candidates:
                record = self._record_from_meta_file(path, data_folder=folder)
                if record and requested in {metadata_stem, commit_after, f"{project}@{commit_after}"}:
                    self._prefer_unique_metadata_id(record, metadata_stem)
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
        source_relpath = _defects4c_source_relpath(raw_source_file, host_source_file, repo_dir)
        source_basename = raw.get("source_basename") or os.path.basename(source_relpath)
        normalized_src_files = src_files or ([source_relpath] if source_relpath else [])
        cache_raw = {
            **raw,
            "src_files": normalized_src_files,
            "source_relpath": source_relpath,
        }

        safe_id = metadata_stem.replace("@", "__").replace("/", "__")
        record_cache_dir = os.path.join(DEFECTS4C_CACHE_DIR, data_folder, safe_id)
        buggy_tree_dir, fixed_tree_dir = self._ensure_version_workspaces(
            raw=cache_raw,
            repo_dir=repo_dir,
            src_files=normalized_src_files,
            cache_dir=record_cache_dir,
        )
        if not buggy_tree_dir or not fixed_tree_dir:
            print(f"[Defects4CLoader] Không tạo được buggy/fixed workspace cho {path}")
            return None

        source_file = os.path.join(buggy_tree_dir, source_relpath)
        accepted_file = os.path.join(fixed_tree_dir, source_relpath)
        if not os.path.isfile(source_file):
            print(f"[Defects4CLoader] Buggy source không tồn tại: {source_file}")
            return None
        if not os.path.isfile(accepted_file):
            print(f"[Defects4CLoader] Fixed source không tồn tại: {accepted_file}")
            return None

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
            "buggy_tree_dir": buggy_tree_dir,
            "fixed_tree_dir": fixed_tree_dir,
            "source_basename": source_basename,
            "source_cache_dir": record_cache_dir,
            "source_repo_dir": repo_dir,
            "source_relpath": source_relpath,
            "original_source_file": raw_source_file,
            "host_source_file": host_source_file,
            "container_repo_dir": _container_repo_dir(raw_source_file, repo_dir),
            "defects4c_bug_info": bug_info,
            "src_files": normalized_src_files,
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

    def _ensure_version_workspaces(
        self,
        raw: dict,
        repo_dir: str,
        src_files: List[str],
        cache_dir: str,
    ) -> Tuple[str, str]:
        os.makedirs(cache_dir, exist_ok=True)
        commit_after = str(raw.get("commit_after") or "").strip()
        commit_before = str(raw.get("commit_before") or "").strip()
        if not commit_after or not commit_before:
            return "", ""

        fixed_dir = os.path.join(cache_dir, "fixed_ver")
        buggy_dir = os.path.join(cache_dir, "buggy_ver")
        project_key = _defects4c_project_cache_key(raw, repo_dir)
        shared_cache_repo = os.path.join(DEFECTS4C_CACHE_DIR, "_repos", project_key, "_repo")
        worktree_repo = _select_cached_repo(shared_cache_repo)
        if worktree_repo and not _ensure_cached_commits(
            worktree_repo,
            repo_dir,
            [commit_after, commit_before],
        ):
            worktree_repo = ""
        if not worktree_repo and repo_dir and os.path.isdir(repo_dir):
            worktree_repo = _ensure_worktree_source_repo(repo_dir, shared_cache_repo)
            if worktree_repo and not _ensure_cached_commits(
                worktree_repo,
                repo_dir,
                [commit_after, commit_before],
            ):
                worktree_repo = ""
        if not worktree_repo:
            # Backward compatibility for caches created before project-level repos.
            worktree_repo = _select_cached_repo(os.path.join(cache_dir, "_repo"))
        if not worktree_repo:
            return "", ""

        if not _ensure_worktree(worktree_repo, fixed_dir, commit_after):
            return "", ""
        if not _verify_worktree_head(fixed_dir, commit_after, "fixed_ver"):
            return "", ""
        if not _ensure_worktree(worktree_repo, buggy_dir, commit_after):
            return "", ""
        if not _verify_worktree_head(buggy_dir, commit_after, "buggy_ver"):
            return "", ""

        overlay_files = [
            rel for rel in src_files
            if isinstance(rel, str)
            and rel.strip()
            and not rel.strip().startswith("/")
            and ".." not in rel.strip().replace("\\", "/").split("/")
        ]
        if overlay_files:
            result = subprocess.run(
                ["git", "-C", buggy_dir, "checkout", "--force", commit_before, "--", *overlay_files],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=60,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip().splitlines()
                tail = detail[-1] if detail else "unknown"
                print(f"[Defects4CLoader] Overlay buggy src_files lỗi: {tail}")
                return "", ""

        return buggy_dir, fixed_dir

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

    @staticmethod
    def _prefer_unique_metadata_id(record: BugRecord, unique_id: str) -> None:
        """Make load_one() use the same unique IDs that load_all() uses."""
        if not record or not unique_id:
            return
        raw = record.raw or {}
        original = record.bug_id
        if original == unique_id:
            return
        raw.setdefault("original_bug_id", original)
        raw["bug_id"] = unique_id
        record.bug_id = unique_id


def get_defects4c_accepted_path(bug_id: str, data_folder: Optional[str] = None) -> str:
    record = Defects4CLoader(data_folder=data_folder).load_one(bug_id)
    if not record or not record.raw:
        return ""
    return record.raw.get("accepted_file", "")


def get_defects4c_source_path(bug_id: str, data_folder: Optional[str] = None) -> str:
    record = Defects4CLoader(data_folder=data_folder).load_one(bug_id)
    return record.source_file if record else ""


def get_defects4c_raw_record(bug_id: str, data_folder: Optional[str] = None) -> Optional[dict]:
    record = Defects4CLoader(data_folder=data_folder).load_one(bug_id)
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
    value = value.strip()

    path_func = re.match(
        r"^(?P<file>.+\.(?:c|cc|cpp|cxx|h|hh|hpp))::(?P<func>.+)$",
        value,
    )
    if path_func:
        return f"{os.path.basename(path_func.group('file'))}:{path_func.group('func')}"

    first_colon = value.find(":")
    if first_colon >= 0 and not value.startswith("::", first_colon):
        file_hint = value[:first_colon]
        func = value[first_colon + 1:]
        if file_hint and func:
            return f"{os.path.basename(file_hint)}:{func}"

    file_hint, func = parse_sbfl_qualified_name(value)
    if file_hint and func:
        return f"{os.path.basename(file_hint)}:{func}"
    return value


def _defects4c_source_relpath(raw_source_file: str, host_source_file: str, repo_dir: str) -> str:
    """Resolve the source path inside a Defects4C git_repo_dir_* tree."""
    for path in (raw_source_file, host_source_file):
        relpath = _relpath_after_git_repo_dir(path)
        if relpath:
            return relpath
    return _relpath_or_basename(host_source_file, repo_dir)


def _relpath_after_git_repo_dir(path: str) -> str:
    if not path or not isinstance(path, str):
        return ""
    parts = path.strip().replace("\\", "/").split("/")
    for idx, part in enumerate(parts):
        if part.startswith("git_repo_dir") and idx + 1 < len(parts):
            return "/".join(parts[idx + 1:])
    return ""


def _defects4c_project_cache_key(raw: dict, repo_dir: str) -> str:
    project = str(raw.get("project") or "").strip()
    if not project:
        project = _project_from_defects4c_path(str(raw.get("source_file") or ""))
    if not project:
        project = _project_from_defects4c_path(repo_dir)
    if not project:
        project = os.path.basename(repo_dir.rstrip(os.sep)) or "unknown"
    return _safe_cache_key(project)


def _project_from_defects4c_path(path: str) -> str:
    if not path or not isinstance(path, str):
        return ""
    parts = path.strip().replace("\\", "/").split("/")
    for idx, part in enumerate(parts):
        if part.startswith("git_repo_dir") and idx > 0:
            return parts[idx - 1]
    return ""


def _safe_cache_key(value: str) -> str:
    safe = str(value or "").strip().replace("\\", "/")
    safe = safe.replace("@", "__").replace("/", "__")
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", safe)
    return safe or "unknown"


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


def _git_cmd(repo_dir: str, *args: str) -> List[str]:
    cmd = ["git"]
    if repo_dir:
        cmd.extend(["-c", f"safe.directory={repo_dir}"])
        git_dir = os.path.join(repo_dir, ".git")
        if os.path.isdir(git_dir):
            cmd.extend(["-c", f"safe.directory={git_dir}"])
    cmd.extend(args)
    return cmd


def _git_error_tail(result: subprocess.CompletedProcess) -> str:
    detail = (result.stderr or result.stdout or "").strip().splitlines()
    return detail[-1] if detail else "unknown"


def _select_cached_repo(cache_repo: str) -> str:
    if cache_repo and os.path.isdir(os.path.join(cache_repo, ".git")):
        return cache_repo
    return ""


def _ensure_cached_commits(cache_repo: str, source_repo: str, commits: List[str]) -> bool:
    missing = _missing_commits(cache_repo, commits)
    if not missing:
        return True
    if not source_repo or not os.path.isdir(source_repo):
        return False

    cmd = ["git"]
    for safe_repo in _git_safe_directories(cache_repo) + _git_safe_directories(source_repo):
        cmd.extend(["-c", f"safe.directory={safe_repo}"])
    cmd.extend(["-C", cache_repo, "fetch", "--no-tags", source_repo, *missing])
    fetch = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    if fetch.returncode != 0:
        _merge_git_objects_cache(source_repo, cache_repo)
    missing_after = _missing_commits(cache_repo, commits)
    if missing_after:
        print(
            f"[Defects4CLoader] cache repo thiếu commit ({cache_repo}): "
            f"{', '.join(missing_after)}; fetch: {_git_error_tail(fetch)}"
        )
        return False
    return True


def _missing_commits(repo_dir: str, commits: List[str]) -> List[str]:
    missing = []
    for commit in commits:
        commit = str(commit or "").strip()
        if not commit:
            continue
        check = subprocess.run(
            _git_cmd(repo_dir, "-C", repo_dir, "cat-file", "-e", f"{commit}^{{commit}}"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if check.returncode != 0:
            missing.append(commit)
    return missing


def _verify_worktree_head(worktree_dir: str, expected_commit: str, label: str) -> bool:
    expected = str(expected_commit or "").strip().lower()
    if not worktree_dir or not expected:
        return False
    result = subprocess.run(
        _git_cmd(worktree_dir, "-C", worktree_dir, "rev-parse", "HEAD"),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    actual = (result.stdout or "").strip().lower()
    if result.returncode == 0 and actual == expected:
        return True
    detail = _git_error_tail(result) if result.returncode != 0 else f"HEAD={actual or '<empty>'}"
    print(f"[Defects4CLoader] Verify {label} HEAD lỗi ({worktree_dir}): expected {expected}, {detail}")
    return False


def _git_safe_directories(repo_dir: str) -> List[str]:
    if not repo_dir:
        return []
    out = [repo_dir]
    git_dir = os.path.join(repo_dir, ".git")
    if os.path.isdir(git_dir):
        out.append(git_dir)
    return out


def _merge_git_objects_cache(source_repo: str, cache_repo: str) -> bool:
    source_git = _git_dir_path(source_repo)
    cache_git = _git_dir_path(cache_repo)
    if not source_git or not cache_git:
        return False
    source_objects = os.path.join(source_git, "objects")
    cache_objects = os.path.join(cache_git, "objects")
    if not os.path.isdir(source_objects) or not os.path.isdir(cache_objects):
        return False
    try:
        shutil.copytree(source_objects, cache_objects, symlinks=True, dirs_exist_ok=True)
    except OSError:
        return False
    return True


def _git_dir_path(repo_dir: str) -> str:
    marker = os.path.join(repo_dir, ".git")
    if os.path.isdir(marker):
        return marker
    if not os.path.isfile(marker):
        return ""
    try:
        with open(marker, "r") as f:
            content = f.read().strip()
    except OSError:
        return ""
    prefix = "gitdir:"
    if not content.lower().startswith(prefix):
        return ""
    gitdir = content[len(prefix):].strip()
    if not os.path.isabs(gitdir):
        gitdir = os.path.normpath(os.path.join(repo_dir, gitdir))
    return gitdir if os.path.isdir(gitdir) else ""


def _ensure_worktree_source_repo(source_repo: str, cache_repo: str) -> str:
    """Return a project-level cache repo suitable as the owner of worktrees.

    Defects4C source repos may be created by Docker and owned by root/nobody.
    Keep those trees read-only from this loader and create worktrees from a
    single user-owned cache repo per Defects4C project.
    """
    selected = _select_cached_repo(cache_repo)
    if selected:
        return selected
    if not source_repo or not os.path.isdir(source_repo):
        return ""

    if os.path.exists(cache_repo):
        shutil.rmtree(cache_repo)
    os.makedirs(os.path.dirname(cache_repo), exist_ok=True)
    clone = subprocess.run(
        _git_cmd(source_repo, "clone", "--no-checkout", source_repo, cache_repo),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=180,
    )
    if clone.returncode != 0:
        if not _copy_git_dir_cache(source_repo, cache_repo):
            print(f"[Defects4CLoader] git clone cache lỗi ({cache_repo}): {_git_error_tail(clone)}")
            return ""
    return _select_cached_repo(cache_repo)


def _copy_git_dir_cache(source_repo: str, cache_repo: str) -> bool:
    source_git = os.path.join(source_repo, ".git")
    cache_git = os.path.join(cache_repo, ".git")
    if not os.path.isdir(source_git):
        return False
    try:
        if os.path.exists(cache_repo):
            shutil.rmtree(cache_repo)
        os.makedirs(cache_repo, exist_ok=True)
        shutil.copytree(source_git, cache_git, symlinks=True)
    except OSError:
        return False
    return os.path.isdir(cache_git)


def _ensure_worktree(repo_dir: str, worktree_dir: str, commit: str) -> bool:
    """Create or reset a detached git worktree at ``commit``."""
    if not repo_dir or not os.path.isdir(repo_dir) or not commit:
        return False

    git_marker = os.path.join(worktree_dir, ".git")
    if not os.path.exists(git_marker):
        if os.path.exists(worktree_dir):
            shutil.rmtree(worktree_dir)
        os.makedirs(os.path.dirname(worktree_dir), exist_ok=True)
        subprocess.run(
            _git_cmd(repo_dir, "-C", repo_dir, "worktree", "prune"),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        add = subprocess.run(
            _git_cmd(repo_dir, "-C", repo_dir, "worktree", "add", "--detach", "--force", worktree_dir, commit),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=120,
        )
        if add.returncode != 0:
            print(f"[Defects4CLoader] git worktree add lỗi ({worktree_dir}): {_git_error_tail(add)}")
            return False

    reset = subprocess.run(
        [
            "bash",
            "-lc",
            "git -C \"$wt\" reset --hard && git -C \"$wt\" clean -ffdx && git -C \"$wt\" checkout -f \"$commit\"",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
        env={**os.environ, "wt": worktree_dir, "commit": commit},
    )
    if reset.returncode != 0:
        detail = (reset.stderr or reset.stdout or "").strip().splitlines()
        tail = detail[-1] if detail else "unknown"
        print(f"[Defects4CLoader] git worktree reset lỗi ({worktree_dir}): {tail}")
        return False
    return True
