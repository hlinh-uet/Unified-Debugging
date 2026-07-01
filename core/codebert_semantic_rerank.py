"""CodeBERT embedding reranking for function-level fault localization."""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.dynamic_failure_rerank import parse_structured_failure
from core.llm_semantic_rerank import (
    _brace_match,
    _extract_function_code,
    _split_function_key,
)


DEFAULT_MODEL = "microsoft/codebert-base"
TOPK_VALUES = (1, 3, 5, 10, 20, 30)


@dataclass
class CodeBertSemanticConfig:
    dataset: str = "fmt"
    experiments_dir: str = ""
    results_file: str = ""
    metadata_dir: str = ""
    output_file: str = ""
    evidence_output_dir: str = ""
    source_root: str = ""
    source_cache_file: str = ""
    cache_dir: str = ""
    bug_id_filter: str = ""
    score_field: str = "scores"
    candidate_limit: int = 30
    alpha: float = 0.35
    backend: str = "codebert"
    model_name: str = DEFAULT_MODEL
    local_files_only: bool = False
    device: str = ""
    max_length: int = 512
    max_query_chars: int = 20000
    max_candidate_chars: int = 12000
    max_test_chars: int = 12000
    max_test_cases: int = 3
    max_chunks: int = 8
    chunk_chars: int = 2600
    include_test_output: bool = True
    keep_evidence: bool = True
    batch_size: int = 4


def _project_root() -> str:
    return os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _workspace_root() -> str:
    return os.path.abspath(os.path.join(_project_root(), ".."))


def _default_experiments_dir() -> str:
    return os.path.join(_project_root(), "experiments")


def _default_defects4c_root() -> str:
    return os.path.join(_workspace_root(), "defects4c")


def _default_source_root() -> str:
    return os.path.join(_default_defects4c_root(), "out_tmp_dirs")


def _default_source_cache_file() -> str:
    return os.path.join(
        _default_defects4c_root(),
        "defectsc_tpl",
        "data",
        "github_src_path.jsonl",
    )


def _default_model_cache_dir() -> str:
    return os.path.join(_workspace_root(), ".hf_cache")


def _resolve_config(config: CodeBertSemanticConfig) -> CodeBertSemanticConfig:
    if not config.experiments_dir:
        config.experiments_dir = _default_experiments_dir()
    dataset_dir = os.path.join(config.experiments_dir, config.dataset)
    if not config.results_file:
        config.results_file = os.path.join(dataset_dir, "fault_localization_function_results.json")
    if not config.metadata_dir:
        config.metadata_dir = os.path.join(
            _default_source_root(),
            "unified_debugging",
            config.dataset,
            "metadata",
        )
    if not config.output_file:
        config.output_file = os.path.join(dataset_dir, "codebert_semantic_function_results.json")
    if not config.evidence_output_dir:
        config.evidence_output_dir = os.path.join(dataset_dir, "codebert_semantic_evidence")
    if not config.source_root:
        config.source_root = _default_source_root()
    if not config.source_cache_file:
        config.source_cache_file = _default_source_cache_file()
    if not config.cache_dir:
        config.cache_dir = _default_model_cache_dir()

    config.experiments_dir = os.path.abspath(config.experiments_dir)
    config.results_file = os.path.abspath(config.results_file)
    config.metadata_dir = os.path.abspath(config.metadata_dir)
    config.output_file = os.path.abspath(config.output_file)
    config.evidence_output_dir = os.path.abspath(config.evidence_output_dir)
    config.source_root = os.path.abspath(config.source_root)
    config.source_cache_file = os.path.abspath(config.source_cache_file)
    config.cache_dir = os.path.abspath(config.cache_dir)
    config.backend = str(config.backend or "codebert").lower()
    if config.backend not in {"codebert", "tfidf"}:
        raise ValueError("CodeBERT semantic backend must be 'codebert' or 'tfidf'")
    config.alpha = max(0.0, min(1.0, float(config.alpha)))
    config.candidate_limit = max(1, int(config.candidate_limit))
    config.max_test_cases = max(1, int(config.max_test_cases))
    config.max_chunks = max(1, int(config.max_chunks))
    config.batch_size = max(1, int(config.batch_size))
    return config


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _write_json(path: str, data: object) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4)


def _sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def _bug_filter(value: str) -> set:
    return {item.strip() for item in str(value or "").split(",") if item.strip()}


def _metadata_path(metadata_dir: str, bug_id: str) -> str:
    if not metadata_dir or not os.path.isdir(metadata_dir):
        return ""
    exact = os.path.join(metadata_dir, f"{bug_id}_meta.json")
    if os.path.exists(exact):
        return exact
    candidates = sorted(glob.glob(os.path.join(metadata_dir, f"{glob.escape(bug_id)}*_meta.json")))
    return candidates[0] if candidates else ""


def _scores_for_entry(entry: dict, score_field: str) -> Dict[str, float]:
    raw = entry.get(score_field) or entry.get("scores") or entry.get("tarantula_scores") or {}
    if not isinstance(raw, dict):
        return {}
    scores: Dict[str, float] = {}
    for key, value in raw.items():
        try:
            scores[str(key)] = float(value)
        except (TypeError, ValueError):
            continue
    return scores


def _candidate_functions(scores: Dict[str, float], limit: int) -> List[str]:
    return [
        key
        for key, _ in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
    ][: max(1, limit)]


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _failing_tests(metadata: dict) -> List[dict]:
    tests = metadata.get("tests") if isinstance(metadata, dict) else []
    if not isinstance(tests, list):
        return []
    primary = [
        test
        for test in tests
        if isinstance(test, dict)
        and _outcome(test.get("outcome")) == "FAIL"
        and _outcome(test.get("outcome_fixed")) == "PASS"
    ]
    if primary:
        return primary
    return [
        test
        for test in tests
        if isinstance(test, dict) and _outcome(test.get("outcome")) == "FAIL"
    ]


def _test_output(test: dict) -> str:
    runtime = test.get("runtime") if isinstance(test, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}
    parts: List[str] = []
    for value in (
        test.get("actual_output"),
        test.get("fail_reason"),
        runtime.get("stdout"),
        runtime.get("stderr"),
        test.get("expected_output"),
    ):
        text = str(value or "").replace("\x00", "").strip()
        if text and text not in parts:
            parts.append(text)
    return "\n".join(parts)


def _truncate_middle(text: object, max_chars: int) -> str:
    value = str(text or "").replace("\x00", "")
    if max_chars <= 0 or len(value) <= max_chars:
        return value
    half = max_chars // 2
    return value[:half].rstrip() + "\n/* ... truncated ... */\n" + value[-half:].lstrip()


def _commit_from_text(text: object) -> str:
    match = re.search(r"git_repo_dir_([0-9a-fA-F]{7,40})", str(text or ""))
    return match.group(1) if match else ""


def _project_from_source_file(path: str) -> str:
    match = re.search(r"(?:^|/|\\)out(?:/|\\)(?P<project>[^/\\]+)(?:/|\\)git_repo_dir_", path or "")
    return match.group("project") if match else ""


def _path_parts(path: str) -> List[str]:
    return [part for part in str(path or "").replace("\\", "/").split("/") if part]


def _suffix_score(candidate: str, wanted: str) -> int:
    left = list(reversed(_path_parts(candidate)))
    right = list(reversed(_path_parts(wanted)))
    score = 0
    for lpart, rpart in zip(left, right):
        if lpart != rpart:
            break
        score += 1
    return score


def _repo_root_from_path(path: str) -> str:
    current = os.path.abspath(path)
    if os.path.isfile(current):
        current = os.path.dirname(current)
    while current and current != os.path.dirname(current):
        if os.path.basename(current).startswith("git_repo_dir"):
            return current
        current = os.path.dirname(current)
    return ""


def _read_text_file(path: str) -> str:
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


class JsonlSourceCache:
    def __init__(self, path: str):
        self.path = path
        self.loaded = False
        self.by_basename: Dict[str, List[dict]] = {}

    def _load(self) -> None:
        if self.loaded:
            return
        self.loaded = True
        if not self.path or not os.path.exists(self.path):
            return
        with open(self.path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    item = json.loads(line)
                except json.JSONDecodeError:
                    continue
                content = item.get("content")
                if not isinstance(content, str) or not content:
                    continue
                raw_path = str(item.get("path") or item.get("id") or item.get("file") or "")
                basename = os.path.basename(raw_path.replace("\\", "/"))
                if not basename:
                    continue
                commit = _commit_from_text(raw_path) or _commit_from_text(item.get("commit"))
                if not commit:
                    match = re.search(r"([0-9a-fA-F]{7,40})___", raw_path)
                    commit = match.group(1) if match else ""
                self.by_basename.setdefault(basename, []).append(
                    {
                        "path": raw_path,
                        "commit": commit,
                        "content": content,
                    }
                )

    def get(self, wanted_path: str, commit: str = "") -> Tuple[str, str]:
        self._load()
        basename = os.path.basename(str(wanted_path or "").replace("\\", "/"))
        records = self.by_basename.get(basename, [])
        if not records:
            return "", ""
        if commit:
            exact = [item for item in records if str(item.get("commit") or "").startswith(commit)]
            if exact:
                records = exact
        best = max(records, key=lambda item: _suffix_score(str(item.get("path") or ""), wanted_path))
        return str(best.get("content") or ""), f"source_cache:{best.get('path') or basename}"


class SourceResolver:
    def __init__(self, config: CodeBertSemanticConfig, metadata: dict, cache: JsonlSourceCache):
        self.config = config
        self.metadata = metadata if isinstance(metadata, dict) else {}
        self.cache = cache
        self.project = str(self.metadata.get("project") or "")
        self.source_file = str(self.metadata.get("source_file") or "")
        self.commit = _commit_from_text(self.source_file) or self._commit_from_tests()
        if not self.project:
            self.project = _project_from_source_file(self.source_file)
        self.repo_root = self._infer_repo_root()
        self.by_basename: Dict[str, List[str]] = {}
        self.indexed = False
        self.text_cache: Dict[str, str] = {}

    def _commit_from_tests(self) -> str:
        for test in self.metadata.get("tests") or []:
            if not isinstance(test, dict):
                continue
            for value in (test.get("actual_output"), test.get("fail_reason")):
                commit = _commit_from_text(value)
                if commit:
                    return commit
            runtime = test.get("runtime")
            if isinstance(runtime, dict):
                for value in (runtime.get("cwd"), runtime.get("replay_command"), runtime.get("stdout")):
                    commit = _commit_from_text(value)
                    if commit:
                        return commit
        return ""

    def _map_docker_path(self, path: str) -> str:
        if path and os.path.exists(path):
            return path
        parts = _path_parts(path)
        roots = [self.config.source_root]
        for root in roots:
            if not root:
                continue
            if parts and parts[0] == "out":
                candidate = os.path.join(root, *parts[1:])
                if os.path.exists(candidate):
                    return candidate
            candidate = os.path.join(root, *parts)
            if os.path.exists(candidate):
                return candidate
        return ""

    def _infer_repo_root(self) -> str:
        mapped = self._map_docker_path(self.source_file)
        if mapped:
            root = _repo_root_from_path(mapped)
            if root:
                return root
        if self.project and self.commit and self.config.source_root:
            candidate = os.path.join(
                self.config.source_root,
                self.project,
                f"git_repo_dir_{self.commit}",
            )
            if os.path.isdir(candidate):
                return os.path.abspath(candidate)
        if self.config.source_root and os.path.basename(self.config.source_root).startswith("git_repo_dir"):
            return self.config.source_root
        return ""

    def _index_repo(self) -> None:
        if self.indexed or not self.repo_root or not os.path.isdir(self.repo_root):
            self.indexed = True
            return
        self.indexed = True
        for root, dirs, files in os.walk(self.repo_root):
            dirs[:] = [
                name
                for name in dirs
                if name not in {".git", "__pycache__"}
                and not name.startswith("build")
                and not name.startswith("cmake-build")
            ]
            for name in files:
                if name.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")):
                    self.by_basename.setdefault(name, []).append(os.path.join(root, name))

    def source_text(self, wanted_path: str) -> Tuple[str, str, str]:
        mapped = self._map_docker_path(wanted_path)
        if mapped and os.path.isfile(mapped):
            if mapped not in self.text_cache:
                self.text_cache[mapped] = _read_text_file(mapped)
            return self.text_cache[mapped], mapped, "file"

        basename = os.path.basename(str(wanted_path or "").replace("\\", "/"))
        if basename and self.repo_root:
            self._index_repo()
            candidates = self.by_basename.get(basename, [])
            if candidates:
                best = max(candidates, key=lambda path: _suffix_score(path, wanted_path))
                if best not in self.text_cache:
                    self.text_cache[best] = _read_text_file(best)
                return self.text_cache[best], best, "file"

        cached_text, cached_path = self.cache.get(wanted_path, self.commit)
        if cached_text:
            return cached_text, cached_path, "source_cache"
        return "", "", "missing_source"


def _line_start_for_offset(text: str, offset: int, back_lines: int = 0) -> int:
    start = text.rfind("\n", 0, max(0, offset)) + 1
    for _ in range(back_lines):
        prev = text.rfind("\n", 0, max(0, start - 1))
        if prev < 0:
            return 0
        candidate = prev + 1
        line = text[candidate:start].strip()
        if not line:
            break
        start = candidate
    return start


def _line_end_for_offset(text: str, offset: int) -> int:
    end = text.find("\n", max(0, offset))
    return len(text) if end < 0 else end


def _offset_for_line(lines: Sequence[str], line_no: int) -> int:
    line_no = max(1, min(line_no, len(lines)))
    return sum(len(line) for line in lines[: line_no - 1])


def _extract_enclosing_test_code(source_text: str, line_no: int, max_chars: int) -> Tuple[str, str]:
    lines = source_text.splitlines(keepends=True)
    if not lines:
        return "", "empty_source"
    offset = _offset_for_line(lines, line_no)
    best: Tuple[int, int] = (-1, -1)
    for match in re.finditer(r"\{", source_text):
        open_index = match.start()
        if open_index > offset:
            break
        close_index = _brace_match(source_text, open_index)
        if close_index >= offset and close_index > open_index:
            best = (open_index, close_index + 1)
    if best[0] >= 0:
        start = _line_start_for_offset(source_text, best[0], back_lines=6)
        end = _line_end_for_offset(source_text, best[1])
        return _truncate_middle(source_text[start:end].strip(), max_chars), "enclosing_block"

    start_line = max(1, line_no - 30)
    end_line = min(len(lines), line_no + 30)
    snippet = "".join(lines[start_line - 1 : end_line])
    return _truncate_middle(snippet.strip(), max_chars), "line_window"


def _failure_for_test(test: dict) -> dict:
    runtime = test.get("runtime") if isinstance(test, dict) else {}
    if not isinstance(runtime, dict):
        runtime = {}
    exit_code = runtime.get("exit_code")
    output = _test_output(test)
    failure = parse_structured_failure(
        output,
        bool(runtime.get("timed_out")),
        exit_code if isinstance(exit_code, int) else None,
    )
    failure["test_id"] = test.get("test_id", "") if isinstance(test, dict) else ""
    return failure


def _test_code_record(
    resolver: SourceResolver,
    test: dict,
    failure: dict,
    max_chars: int,
) -> dict:
    location = str(failure.get("assertion_location") or "")
    match = re.match(r"(?P<path>.*):(?P<line>\d+)$", location)
    if not match:
        return {
            "test_id": test.get("test_id", ""),
            "assertion_location": location,
            "source_path": "",
            "code": "",
            "code_kind": "missing",
            "code_status": "assertion_location_missing",
        }
    source_text, source_path, source_status = resolver.source_text(match.group("path"))
    if not source_text:
        return {
            "test_id": test.get("test_id", ""),
            "assertion_location": location,
            "source_path": "",
            "code": "",
            "code_kind": "missing",
            "code_status": source_status,
        }
    code, kind = _extract_enclosing_test_code(source_text, int(match.group("line")), max_chars)
    return {
        "test_id": test.get("test_id", ""),
        "assertion_location": location,
        "source_path": source_path,
        "code": code,
        "code_kind": kind if code else "missing",
        "code_status": source_status if code else "test_code_not_found",
    }


def _candidate_code_record(
    resolver: SourceResolver,
    function_key: str,
    max_chars: int,
) -> dict:
    file_part, function_name = _split_function_key(function_key)
    source_text, source_path, source_status = resolver.source_text(file_part)
    if not source_text:
        return {
            "function": function_key,
            "file": file_part,
            "function_name": function_name,
            "source_path": "",
            "code": "",
            "code_kind": "missing",
            "code_status": source_status,
        }
    code, kind = _extract_function_code(source_text, function_name, max_chars)
    return {
        "function": function_key,
        "file": file_part,
        "function_name": function_name,
        "source_path": source_path,
        "code": code,
        "code_kind": kind if code else "missing",
        "code_status": source_status if code else kind,
    }


def _build_query_text(
    failing_tests: Sequence[dict],
    failures: Sequence[dict],
    test_code_records: Sequence[dict],
    config: CodeBertSemanticConfig,
) -> str:
    sections: List[str] = []
    for index, test in enumerate(failing_tests[: config.max_test_cases]):
        failure = failures[index] if index < len(failures) else {}
        test_code = test_code_records[index] if index < len(test_code_records) else {}
        sections.append(f"Failing test: {test.get('test_id', '')}")
        for key in ("failure_type", "oracle", "assertion_location", "observed_expression", "actual_value", "expected_value"):
            value = failure.get(key)
            if value:
                sections.append(f"{key}: {value}")
        signal_lines = failure.get("signal_lines") or []
        if signal_lines:
            sections.append("signal_lines:\n" + "\n".join(str(line) for line in signal_lines[:20]))
        if test_code.get("code"):
            sections.append("test_case_code:\n" + str(test_code.get("code")))
        if config.include_test_output:
            output = _truncate_middle(_test_output(test), 3500)
            if output:
                sections.append("failure_output:\n" + output)
    return _truncate_middle("\n\n".join(sections), config.max_query_chars)


def _candidate_text(record: dict) -> str:
    header = (
        f"Function: {record.get('function', '')}\n"
        f"File: {record.get('file', '')}\n"
        f"Function name: {record.get('function_name', '')}\n"
    )
    code = str(record.get("code") or "")
    if code:
        return header + "function_code:\n" + code
    return header + f"source_status: {record.get('code_status', 'missing')}"


def _line_chunks(text: str, chunk_chars: int, max_chunks: int) -> List[str]:
    text = str(text or "").strip()
    if not text:
        return [""]
    if chunk_chars <= 0 or len(text) <= chunk_chars:
        return [text]
    chunks: List[str] = []
    current: List[str] = []
    current_len = 0
    for line in text.splitlines():
        add_len = len(line) + 1
        if current and current_len + add_len > chunk_chars:
            chunks.append("\n".join(current))
            current = []
            current_len = 0
            if len(chunks) >= max_chunks:
                break
        current.append(line)
        current_len += add_len
    if current and len(chunks) < max_chunks:
        chunks.append("\n".join(current))
    return chunks[:max_chunks] or [text[:chunk_chars]]


def _l2_normalize(vector: List[float]) -> List[float]:
    norm = math.sqrt(sum(value * value for value in vector))
    if norm <= 0:
        return vector
    return [value / norm for value in vector]


def _cosine(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    return sum(a * b for a, b in zip(left, right))


class CodeBertScorer:
    def __init__(self, config: CodeBertSemanticConfig):
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except Exception as exc:
            raise RuntimeError(
                "CodeBERT backend requires torch and transformers. "
                "Use --codebert-semantic-backend tfidf for an offline smoke test."
            ) from exc

        os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
        os.environ.setdefault("HF_HUB_DISABLE_SYMLINKS_WARNING", "1")
        os.environ.setdefault("HF_HUB_DISABLE_PROGRESS_BARS", "1")
        self.torch = torch
        self.config = config
        try:
            from transformers import logging as transformers_logging

            transformers_logging.set_verbosity_error()
        except Exception:
            pass
        device = config.device or ("cuda" if torch.cuda.is_available() else "cpu")
        self.device = torch.device(device)
        self.tokenizer = AutoTokenizer.from_pretrained(
            config.model_name,
            cache_dir=config.cache_dir,
            local_files_only=config.local_files_only,
        )
        self.model = AutoModel.from_pretrained(
            config.model_name,
            cache_dir=config.cache_dir,
            local_files_only=config.local_files_only,
        )
        self.model.to(self.device)
        self.model.eval()

    def _embed_chunks(self, chunks: Sequence[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        torch = self.torch
        for start in range(0, len(chunks), self.config.batch_size):
            batch = list(chunks[start : start + self.config.batch_size])
            encoded = self.tokenizer(
                batch,
                padding=True,
                truncation=True,
                max_length=self.config.max_length,
                return_tensors="pt",
            )
            encoded = {key: value.to(self.device) for key, value in encoded.items()}
            with torch.no_grad():
                output = self.model(**encoded)
                hidden = output.last_hidden_state
                mask = encoded["attention_mask"].unsqueeze(-1).to(hidden.dtype)
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1.0)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
            vectors.extend(pooled.cpu().tolist())
        return vectors

    def embed(self, text: str) -> List[float]:
        chunks = _line_chunks(text, self.config.chunk_chars, self.config.max_chunks)
        vectors = self._embed_chunks(chunks)
        if not vectors:
            return []
        width = len(vectors[0])
        mean = [0.0] * width
        for vector in vectors:
            for index, value in enumerate(vector):
                mean[index] += float(value)
        return _l2_normalize([value / len(vectors) for value in mean])

    def similarities(self, query: str, documents: Sequence[str]) -> List[Tuple[float, float]]:
        query_vector = self.embed(query)
        out: List[Tuple[float, float]] = []
        for document in documents:
            raw = _cosine(query_vector, self.embed(document))
            out.append((raw, max(0.0, min(1.0, raw))))
        return out


class TfidfScorer:
    def __init__(self, config: CodeBertSemanticConfig):
        try:
            from sklearn.feature_extraction.text import TfidfVectorizer
            from sklearn.metrics.pairwise import cosine_similarity
        except Exception as exc:
            raise RuntimeError("TF-IDF backend requires scikit-learn.") from exc
        self.vectorizer_cls = TfidfVectorizer
        self.cosine_similarity = cosine_similarity

    def similarities(self, query: str, documents: Sequence[str]) -> List[Tuple[float, float]]:
        if not documents:
            return []
        matrix = self.vectorizer_cls(token_pattern=r"(?u)\b\w+\b").fit_transform([query] + list(documents))
        values = self.cosine_similarity(matrix[0:1], matrix[1:]).ravel()
        return [(float(value), max(0.0, min(1.0, float(value)))) for value in values]


def _make_scorer(config: CodeBertSemanticConfig):
    if config.backend == "tfidf":
        return TfidfScorer(config)
    return CodeBertScorer(config)


def _normalize_scores(scores: Dict[str, float]) -> Dict[str, float]:
    if not scores:
        return {}
    values = list(scores.values())
    low = min(values)
    high = max(values)
    if high <= low:
        return {key: 1.0 for key in scores}
    return {key: (value - low) / (high - low) for key, value in scores.items()}


def _fuse_scores(
    baseline_scores: Dict[str, float],
    candidate_similarities: Dict[str, float],
    alpha: float,
) -> Dict[str, float]:
    normalized = _normalize_scores(baseline_scores)
    fused = {
        key: (1.0 - alpha) * normalized.get(key, 0.0)
        for key in baseline_scores
    }
    for key, similarity in candidate_similarities.items():
        fused[key] = (1.0 - alpha) * normalized.get(key, 0.0) + alpha * similarity
    return _sort_scores(fused)


def _rank_ground_truth(scores: Dict[str, float], ground_truth: Sequence[str]) -> Optional[int]:
    for rank, (key, _) in enumerate(
        sorted((scores or {}).items(), key=lambda item: (-item[1], item[0])),
        start=1,
    ):
        for gt in ground_truth:
            if key == gt or key.endswith(f":{gt}") or key.endswith(f"::{gt}"):
                return rank
    return None


def _prepare_bug(
    bug_id: str,
    entry: dict,
    metadata: dict,
    config: CodeBertSemanticConfig,
    source_cache: JsonlSourceCache,
) -> Tuple[str, List[dict], dict]:
    resolver = SourceResolver(config, metadata, source_cache)
    failing_tests = _failing_tests(metadata)[: config.max_test_cases]
    failures = [_failure_for_test(test) for test in failing_tests]
    test_code_records = [
        _test_code_record(resolver, test, failure, config.max_test_chars)
        for test, failure in zip(failing_tests, failures)
    ]
    query_text = _build_query_text(failing_tests, failures, test_code_records, config)

    scores = _scores_for_entry(entry, config.score_field)
    candidates = _candidate_functions(scores, config.candidate_limit)
    candidate_records = []
    for rank, function in enumerate(candidates, start=1):
        code_record = _candidate_code_record(resolver, function, config.max_candidate_chars)
        candidate_records.append(
            {
                "rank": rank,
                "function": function,
                "baseline_score": scores.get(function, 0.0),
                **code_record,
            }
        )

    context = {
        "bug_id": bug_id,
        "dataset": entry.get("dataset", config.dataset),
        "metadata_project": metadata.get("project", ""),
        "metadata_source_file": metadata.get("source_file", ""),
        "repo_root": resolver.repo_root,
        "source_cache_file": config.source_cache_file,
        "query_text": query_text,
        "failures": failures,
        "test_code_records": test_code_records,
        "candidate_records": candidate_records,
        "context_stats": {
            "failing_tests_used": len(failing_tests),
            "test_cases_with_code": sum(1 for item in test_code_records if item.get("code")),
            "candidate_count": len(candidate_records),
            "candidates_with_code": sum(1 for item in candidate_records if item.get("code")),
        },
    }
    return query_text, candidate_records, context


def rerank_bug_with_codebert(
    bug_id: str,
    entry: dict,
    metadata: dict,
    scorer,
    config: CodeBertSemanticConfig,
    source_cache: JsonlSourceCache,
) -> Tuple[dict, dict]:
    baseline_scores = _scores_for_entry(entry, config.score_field)
    query_text, candidate_records, evidence = _prepare_bug(
        bug_id,
        entry,
        metadata,
        config,
        source_cache,
    )
    documents = [_candidate_text(record) for record in candidate_records]
    scored = scorer.similarities(query_text, documents)

    candidate_similarities: Dict[str, float] = {}
    ranked = []
    for record, (raw_cosine, similarity) in zip(candidate_records, scored):
        function = str(record.get("function") or "")
        candidate_similarities[function] = similarity
        ranked.append(
            {
                "function": function,
                "baseline_rank": record.get("rank"),
                "baseline_score": record.get("baseline_score", 0.0),
                "raw_cosine": raw_cosine,
                "similarity": similarity,
                "code_status": record.get("code_status", ""),
                "code_kind": record.get("code_kind", ""),
                "source_path": record.get("source_path", ""),
            }
        )
    final_scores = _fuse_scores(baseline_scores, candidate_similarities, config.alpha)
    ranked = sorted(
        ranked,
        key=lambda item: (
            -final_scores.get(str(item.get("function") or ""), 0.0),
            str(item.get("function") or ""),
        ),
    )

    evidence["embedding_ranked"] = ranked
    evidence["embedding_candidate_scores"] = candidate_similarities
    result = {
        "dataset": entry.get("dataset", config.dataset),
        "formula": entry.get("formula", ""),
        "reranker": "codebert_semantic_embedding",
        "score_field": config.score_field,
        "scores": final_scores,
        "baseline_scores": _sort_scores(baseline_scores),
        "codebert_semantic_scores": final_scores,
        "codebert_candidate_scores": _sort_scores(candidate_similarities),
        "codebert_ranked": ranked,
        "ground_truth": entry.get("ground_truth", []),
        "metadata_path": _metadata_path(config.metadata_dir, bug_id),
        "codebert_semantic_config": {
            "backend": config.backend,
            "model_name": config.model_name,
            "candidate_limit": config.candidate_limit,
            "alpha": config.alpha,
            "max_query_chars": config.max_query_chars,
            "max_candidate_chars": config.max_candidate_chars,
            "max_test_chars": config.max_test_chars,
            "max_test_cases": config.max_test_cases,
            "max_chunks": config.max_chunks,
            "chunk_chars": config.chunk_chars,
            "cache_dir": config.cache_dir,
        },
        "codebert_context_stats": evidence.get("context_stats", {}),
    }
    return result, evidence


def run_codebert_semantic_rerank(config: CodeBertSemanticConfig) -> Dict[str, dict]:
    config = _resolve_config(config)
    results = _load_json(config.results_file)
    filters = _bug_filter(config.bug_id_filter)
    bug_ids = [bug_id for bug_id in sorted(results) if not filters or bug_id in filters]

    scorer = _make_scorer(config)
    source_cache = JsonlSourceCache(config.source_cache_file)
    output: Dict[str, dict] = {}
    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    if config.keep_evidence:
        os.makedirs(config.evidence_output_dir, exist_ok=True)

    for bug_id in bug_ids:
        metadata_path = _metadata_path(config.metadata_dir, bug_id)
        metadata = _load_json(metadata_path) if metadata_path else {}
        result, evidence = rerank_bug_with_codebert(
            bug_id,
            results.get(bug_id, {}),
            metadata,
            scorer,
            config,
            source_cache,
        )
        output[bug_id] = result
        if config.keep_evidence:
            evidence_path = os.path.join(config.evidence_output_dir, f"{bug_id}.json")
            _write_json(evidence_path, evidence)
            output[bug_id]["codebert_semantic_evidence_path"] = evidence_path
        before = _rank_ground_truth(result.get("baseline_scores", {}), result.get("ground_truth", []))
        after = _rank_ground_truth(result.get("codebert_semantic_scores", {}), result.get("ground_truth", []))
        stats = result.get("codebert_context_stats") or {}
        print(
            f"  {bug_id}: rank {before if before is not None else '-'} -> "
            f"{after if after is not None else '-'}; "
            f"test_code={stats.get('test_cases_with_code', 0)}/{stats.get('failing_tests_used', 0)} "
            f"candidate_code={stats.get('candidates_with_code', 0)}/{stats.get('candidate_count', 0)}"
        )

    _write_json(config.output_file, output)
    return output


def summarize_codebert_semantic_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    for bug_id, entry in sorted(results.items()):
        ground_truth = entry.get("ground_truth", [])
        before = _rank_ground_truth(entry.get("baseline_scores", {}), ground_truth)
        after = _rank_ground_truth(entry.get("codebert_semantic_scores", {}), ground_truth)
        delta = None if before is None or after is None else before - after
        rows.append(
            {
                "bug_id": bug_id,
                "before_rank": before,
                "after_rank": after,
                "delta": delta,
                "context_stats": entry.get("codebert_context_stats", {}),
            }
        )
    total = len(rows)
    topk = {}
    for k in TOPK_VALUES:
        before_count = sum(1 for row in rows if row["before_rank"] is not None and row["before_rank"] <= k)
        after_count = sum(1 for row in rows if row["after_rank"] is not None and row["after_rank"] <= k)
        topk[f"top{k}"] = {
            "k": k,
            "before_count": before_count,
            "before_percent": (before_count / total * 100.0) if total else 0.0,
            "after_count": after_count,
            "after_percent": (after_count / total * 100.0) if total else 0.0,
            "delta": after_count - before_count,
        }
    return {
        "total": total,
        "topk": topk,
        "improved": sum(1 for row in rows if row["delta"] is not None and row["delta"] > 0),
        "same": sum(1 for row in rows if row["delta"] == 0),
        "worse": sum(1 for row in rows if row["delta"] is not None and row["delta"] < 0),
        "rows": rows,
    }


def codebert_semantic_summary_file(output_file: str) -> str:
    base, ext = os.path.splitext(output_file)
    return f"{base}_summary{ext or '.json'}"


def print_codebert_semantic_summary(results: Dict[str, dict], output_file: str = "") -> None:
    summary = summarize_codebert_semantic_results(results)
    total = summary["total"]
    print("\nCodeBERT semantic rerank summary:")
    print(f"  bugs: {total}")
    print("  K    baseline             CodeBERT             Delta")
    for label in ("top1", "top3", "top5", "top10", "top20", "top30"):
        item = summary["topk"][label]
        print(
            f"  {item['k']:<4} "
            f"{item['before_count']}/{total} ({item['before_percent']:>5.1f}%)      "
            f"{item['after_count']}/{total} ({item['after_percent']:>5.1f}%)      "
            f"{item['delta']:+d}"
        )
    print(
        f"  rank delta: improved={summary['improved']} "
        f"same={summary['same']} worse={summary['worse']}"
    )
    if output_file:
        summary_file = codebert_semantic_summary_file(output_file)
        _write_json(summary_file, summary)
        print(f"  output: {output_file}")
        print(f"  summary: {summary_file}")


def add_codebert_semantic_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--codebert-semantic-rerank", action="store_true", help="Run CodeBERT embedding semantic function reranking.")
    parser.add_argument("--codebert-semantic-dataset", default="fmt", help="Experiment dataset folder, e.g. fmt or libyang.")
    parser.add_argument("--codebert-semantic-results-file", default="", help="Path to baseline function FL results JSON.")
    parser.add_argument("--codebert-semantic-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--codebert-semantic-output-file", default="", help="Output JSON path for CodeBERT rerank results.")
    parser.add_argument("--codebert-semantic-evidence-output-dir", default="", help="Directory for per-bug embedding evidence JSON.")
    parser.add_argument("--codebert-semantic-source-root", default="", help="Host root used to resolve /out/... source paths.")
    parser.add_argument("--codebert-semantic-source-cache-file", default="", help="Optional github_src_path.jsonl source cache.")
    parser.add_argument("--codebert-semantic-cache-dir", default="", help="Workspace cache directory for HuggingFace model files.")
    parser.add_argument("--codebert-semantic-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--codebert-semantic-score-field", default="scores", help="Entry score field used as the FL prior.")
    parser.add_argument("--codebert-semantic-candidate-limit", type=int, default=30, help="Top-k baseline functions embedded and reranked.")
    parser.add_argument("--codebert-semantic-alpha", type=float, default=0.35, help="Fusion weight for semantic similarity in [0, 1].")
    parser.add_argument("--codebert-semantic-backend", choices=("codebert", "tfidf"), default="codebert", help="Embedding backend.")
    parser.add_argument("--codebert-semantic-model", default=DEFAULT_MODEL, help="HuggingFace model id for CodeBERT.")
    parser.add_argument("--codebert-semantic-local-files-only", action="store_true", help="Do not download the HuggingFace model.")
    parser.add_argument("--codebert-semantic-device", default="", help="Torch device, e.g. cpu or cuda.")
    parser.add_argument("--codebert-semantic-max-length", type=int, default=512, help="Max tokenizer sequence length.")
    parser.add_argument("--codebert-semantic-max-query-chars", type=int, default=20000, help="Max characters in failure/test query text.")
    parser.add_argument("--codebert-semantic-max-candidate-chars", type=int, default=12000, help="Max characters of candidate function code.")
    parser.add_argument("--codebert-semantic-max-test-chars", type=int, default=12000, help="Max characters of each failing test case code.")
    parser.add_argument("--codebert-semantic-max-test-cases", type=int, default=3, help="Max failing test cases embedded per bug.")
    parser.add_argument("--codebert-semantic-max-chunks", type=int, default=8, help="Max text chunks averaged per embedding.")
    parser.add_argument("--codebert-semantic-chunk-chars", type=int, default=2600, help="Approximate characters per CodeBERT chunk.")
    parser.add_argument("--codebert-semantic-batch-size", type=int, default=4, help="CodeBERT chunk batch size.")
    parser.add_argument("--codebert-semantic-no-test-output", action="store_true", help="Embed test code and parsed fields without raw test output.")
    parser.add_argument("--codebert-semantic-no-keep-evidence", action="store_true", help="Do not write per-bug evidence JSON.")


def codebert_semantic_config_from_args(args: argparse.Namespace) -> CodeBertSemanticConfig:
    return CodeBertSemanticConfig(
        dataset=args.codebert_semantic_dataset,
        results_file=args.codebert_semantic_results_file,
        metadata_dir=args.codebert_semantic_metadata_dir,
        output_file=args.codebert_semantic_output_file,
        evidence_output_dir=args.codebert_semantic_evidence_output_dir,
        source_root=args.codebert_semantic_source_root,
        source_cache_file=args.codebert_semantic_source_cache_file,
        cache_dir=args.codebert_semantic_cache_dir,
        bug_id_filter=args.codebert_semantic_bug_id,
        score_field=args.codebert_semantic_score_field,
        candidate_limit=args.codebert_semantic_candidate_limit,
        alpha=args.codebert_semantic_alpha,
        backend=args.codebert_semantic_backend,
        model_name=args.codebert_semantic_model,
        local_files_only=args.codebert_semantic_local_files_only,
        device=args.codebert_semantic_device,
        max_length=args.codebert_semantic_max_length,
        max_query_chars=args.codebert_semantic_max_query_chars,
        max_candidate_chars=args.codebert_semantic_max_candidate_chars,
        max_test_chars=args.codebert_semantic_max_test_chars,
        max_test_cases=args.codebert_semantic_max_test_cases,
        max_chunks=args.codebert_semantic_max_chunks,
        chunk_chars=args.codebert_semantic_chunk_chars,
        include_test_output=not args.codebert_semantic_no_test_output,
        keep_evidence=not args.codebert_semantic_no_keep_evidence,
        batch_size=args.codebert_semantic_batch_size,
    )
