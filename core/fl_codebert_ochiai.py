from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import pickle
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Tuple

from data_loaders.defects4c_loader import (
    FAIL_OUTCOMES,
    PASS_OUTCOMES,
    Defects4CLoadConfig,
    default_defects4c_root,
    load_defects4c_bugs,
)
from core.fl_jaccard_ochiai import TOPK_VALUES, calculate_ochiai


DEFAULT_CODEBERT_MODEL = "microsoft/codebert-base"


@dataclass
class CodeBertOchiaiConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    selection: str = "topk"
    threshold: float = 0.75
    top_k: int = 50
    similarity_mode: str = "codebert"
    codebert_weight: float = 1.0
    coverage_weight: float = 0.0
    model_name: str = DEFAULT_CODEBERT_MODEL
    backend: str = "codebert"
    device: str = "auto"
    batch_size: int = 8
    max_length: int = 512
    max_test_code_chars: int = 6000
    cache_dir: str = ""
    use_cache: bool = True
    local_files_only: bool = False
    exclude_fixed_fail_tests: bool = True


@dataclass
class TestCodeContext:
    bug: dict
    defects4c_root: str
    max_chars: int
    repo_root: str = ""
    source_cache: Dict[str, str] = field(default_factory=dict)
    extraction_cache: Dict[str, dict] = field(default_factory=dict)
    source_index: Dict[str, List[str]] = field(default_factory=dict)
    indexed_test_sources: bool = False


def _clean_text(value: object) -> str:
    return str(value or "").replace("\x00", "")


def _truncate_middle(text: str, max_chars: int) -> str:
    if max_chars <= 0 or len(text) <= max_chars:
        return text
    half = max_chars // 2
    return text[:half].rstrip() + "\n/* ... truncated ... */\n" + text[-half:].lstrip()


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _split_tests(test_data: Sequence[dict]) -> Tuple[List[dict], List[dict]]:
    failing = []
    passing = []
    for test in test_data:
        outcome = _outcome(test.get("outcome"))
        if outcome in FAIL_OUTCOMES:
            failing.append(test)
        elif outcome in PASS_OUTCOMES:
            passing.append(test)
    return failing, passing


def cosine_similarity(left: Sequence[float], right: Sequence[float]) -> float:
    if not left or not right or len(left) != len(right):
        return 0.0
    dot = sum(float(a) * float(b) for a, b in zip(left, right))
    left_norm = math.sqrt(sum(float(a) * float(a) for a in left))
    right_norm = math.sqrt(sum(float(b) * float(b) for b in right))
    if not left_norm or not right_norm:
        return 0.0
    return dot / (left_norm * right_norm)


def coverage_jaccard_similarity(left: Sequence[str], right: Sequence[str]) -> float:
    left_set = {str(item) for item in left if item}
    right_set = {str(item) for item in right if item}
    if not left_set and not right_set:
        return 0.0
    union = left_set | right_set
    return float(len(left_set & right_set)) / float(len(union)) if union else 0.0


def _minmax_normalize(values: Sequence[float]) -> List[float]:
    if not values:
        return []
    low = min(values)
    high = max(values)
    if high <= low:
        return [1.0 for _ in values]
    return [(float(value) - low) / (high - low) for value in values]


def _descending_borda_scores(values: Sequence[float]) -> List[float]:
    if not values:
        return []
    if len(values) == 1:
        return [1.0]

    indexed = sorted(
        enumerate(float(value) for value in values),
        key=lambda item: (-item[1], item[0]),
    )
    scores = [0.0] * len(values)
    start = 0
    while start < len(indexed):
        end = start + 1
        while end < len(indexed) and indexed[end][1] == indexed[start][1]:
            end += 1

        # Borda score maps rank 1 -> 1.0 and the last rank -> 0.0.
        # Tied items receive the average score over their occupied rank span.
        tied_scores = [
            (len(values) - rank) / (len(values) - 1)
            for rank in range(start + 1, end + 1)
        ]
        score = sum(tied_scores) / len(tied_scores)
        for position in range(start, end):
            original_index = indexed[position][0]
            scores[original_index] = score
        start = end
    return scores


class HashEmbeddingBackend:
    """Deterministic offline backend for tests and smoke runs."""

    def __init__(self, dim: int = 256):
        self.dim = dim
        self.name = "hash"
        self.device = "cpu"

    def encode(self, texts: Sequence[str]) -> List[List[float]]:
        vectors = []
        for text in texts:
            vec = [0.0] * self.dim
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_:]*|\d+(?:\.\d+)?|[^\s]", text)
            if not tokens:
                tokens = [text]
            for token in tokens:
                digest = hashlib.sha256(token.encode("utf-8", errors="ignore")).digest()
                index = int.from_bytes(digest[:4], "big") % self.dim
                sign = 1.0 if digest[4] % 2 == 0 else -1.0
                weight = 1.0 + (len(token) > 8) * 0.25
                vec[index] += sign * weight
            norm = math.sqrt(sum(value * value for value in vec))
            vectors.append([value / norm for value in vec] if norm else vec)
        return vectors


class CodeBertEmbeddingBackend:
    def __init__(
        self,
        model_name: str = DEFAULT_CODEBERT_MODEL,
        device: str = "auto",
        max_length: int = 512,
        batch_size: int = 8,
        local_files_only: bool = False,
    ):
        try:
            import torch
            from transformers import AutoModel, AutoTokenizer
        except ImportError as exc:
            raise RuntimeError(
                "CodeBERT backend requires torch and transformers. "
                "Install them or run with --codebert-backend hash for an offline smoke test."
            ) from exc

        self.torch = torch
        self.name = model_name
        self.max_length = max(8, int(max_length))
        self.batch_size = max(1, int(batch_size))
        if device == "auto":
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device
        self.tokenizer = AutoTokenizer.from_pretrained(
            model_name,
            local_files_only=local_files_only,
        )
        self.model = AutoModel.from_pretrained(
            model_name,
            local_files_only=local_files_only,
        )
        self.model.to(self.device)
        self.model.eval()

    def encode(self, texts: Sequence[str]) -> List[List[float]]:
        vectors: List[List[float]] = []
        torch = self.torch
        with torch.no_grad():
            for start in range(0, len(texts), self.batch_size):
                batch = list(texts[start:start + self.batch_size])
                encoded = self.tokenizer(
                    batch,
                    padding=True,
                    truncation=True,
                    max_length=self.max_length,
                    return_tensors="pt",
                )
                encoded = {key: value.to(self.device) for key, value in encoded.items()}
                output = self.model(**encoded)
                hidden = output.last_hidden_state
                mask = encoded["attention_mask"].unsqueeze(-1).float()
                pooled = (hidden * mask).sum(dim=1) / mask.sum(dim=1).clamp(min=1e-9)
                pooled = torch.nn.functional.normalize(pooled, p=2, dim=1)
                vectors.extend(pooled.cpu().tolist())
        return vectors


def _make_embedding_backend(config: CodeBertOchiaiConfig):
    backend = str(config.backend or "codebert").lower()
    if backend == "hash":
        return HashEmbeddingBackend()
    if backend != "codebert":
        raise ValueError("CodeBERT backend must be 'codebert' or 'hash'")
    return CodeBertEmbeddingBackend(
        model_name=config.model_name,
        device=config.device,
        max_length=config.max_length,
        batch_size=config.batch_size,
        local_files_only=config.local_files_only,
    )


def _docker_repo_match(text: str) -> Optional[re.Match]:
    return re.search(r"(/out/([^/\s'\";&]+)/((?:git_repo_dir|repo_dir)_[A-Za-z0-9._-]+))", text)


def _host_path_from_docker_path(path: str, defects4c_root: str) -> str:
    normalized = _clean_text(path).replace("\\", "/")
    match = re.search(r"/out/([^/]+)/((?:git_repo_dir|repo_dir)_[^/\s'\";&]+)(/.*)?$", normalized)
    if not match:
        return path if os.path.exists(path) else ""
    rest = (match.group(3) or "").strip("/")
    root = defects4c_root or default_defects4c_root()
    parts = [root, "out_tmp_dirs", match.group(1), match.group(2)]
    if rest:
        parts.extend(part for part in rest.split("/") if part)
    candidate = os.path.join(*parts)
    if os.path.exists(candidate):
        return candidate
    docker_repo = match.group(0)
    return docker_repo if os.path.exists(docker_repo) else candidate


def _repo_root_from_bug(bug: dict, defects4c_root: str) -> str:
    texts = [
        _clean_text(bug.get("source_file")),
        _clean_text(bug.get("metadata_path")),
    ]
    for test in bug.get("tests", [])[:20]:
        runtime = test.get("runtime") if isinstance(test, dict) else {}
        if isinstance(runtime, dict):
            texts.extend([
                _clean_text(runtime.get("replay_command")),
                _clean_text(runtime.get("cwd")),
            ])
    for text in texts:
        match = _docker_repo_match(text)
        if not match:
            continue
        host = _host_path_from_docker_path(match.group(1), defects4c_root)
        if os.path.isdir(host):
            return host
    return ""


def _runtime(test: dict) -> dict:
    runtime = test.get("runtime") if isinstance(test, dict) else {}
    return runtime if isinstance(runtime, dict) else {}


def _failure(test: dict) -> dict:
    failure = test.get("failure") if isinstance(test, dict) else {}
    return failure if isinstance(failure, dict) else {}


def _gtest_filter_from_command(command: str) -> str:
    match = re.search(r"--gtest_filter=([^\s]+)", command)
    if not match:
        return ""
    value = match.group(1).strip("\"'")
    value = value.split(":", 1)[0].split("-", 1)[0]
    return value.strip()


def _gtest_identifier(test: dict) -> Tuple[str, str]:
    runtime = _runtime(test)
    raw = _gtest_filter_from_command(_clean_text(runtime.get("replay_command")))
    if not raw:
        test_id = _clean_text(test.get("test_id"))
        raw = test_id.split("::", 1)[1] if "::" in test_id else test_id
    if "." not in raw:
        return "", ""
    suite, test_name = raw.split(".", 1)
    suite = suite.split("/", 1)[0]
    test_name = test_name.split("/", 1)[0]
    return suite.strip(), test_name.strip()


def _binary_name(test: dict) -> str:
    command = _clean_text(_runtime(test).get("replay_command")).replace("\\", "/")
    if not command:
        test_id = _clean_text(test.get("test_id"))
        return test_id.split("::", 1)[0] if "::" in test_id else ""
    match = re.search(r"/bin/([^/\s'\";&]+)", command)
    if match:
        return os.path.basename(match.group(1))
    first = command.strip().split()[0] if command.strip() else ""
    return os.path.basename(first)


def _assertion_source_path(test: dict, defects4c_root: str) -> Tuple[str, int]:
    location = _clean_text(_failure(test).get("assertion_location"))
    match = re.match(r"(?P<path>.*):(?P<line>\d+)$", location)
    if not match:
        return "", 0
    path = _host_path_from_docker_path(match.group("path"), defects4c_root)
    try:
        line_no = int(match.group("line"))
    except ValueError:
        line_no = 0
    return path, line_no


def _read_source(path: str, context: TestCodeContext) -> str:
    if not path or not os.path.isfile(path):
        return ""
    if path not in context.source_cache:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            context.source_cache[path] = f.read()
    return context.source_cache[path]


def _index_test_sources(context: TestCodeContext) -> None:
    if context.indexed_test_sources or not context.repo_root or not os.path.isdir(context.repo_root):
        return
    context.indexed_test_sources = True
    roots = []
    for name in ("test", "tests", "unittest", "unittests"):
        candidate = os.path.join(context.repo_root, name)
        if os.path.isdir(candidate):
            roots.append(candidate)
    if not roots:
        roots = [context.repo_root]
    for root in roots:
        for current, dirs, files in os.walk(root):
            dirs[:] = [
                name
                for name in dirs
                if name not in {".git", "build", "__pycache__"}
                and not name.startswith("build_")
                and not name.startswith("cmake-build")
            ]
            for filename in files:
                if filename.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")):
                    context.source_index.setdefault(filename, []).append(os.path.join(current, filename))


def _candidate_test_source_files(test: dict, context: TestCodeContext) -> List[str]:
    candidates: List[str] = []
    assertion_path, _ = _assertion_source_path(test, context.defects4c_root)
    if assertion_path:
        candidates.append(assertion_path)

    binary = _binary_name(test)
    stems = [binary] if binary else []
    test_id_prefix = _clean_text(test.get("test_id")).split("::", 1)[0]
    if test_id_prefix and test_id_prefix not in stems:
        stems.append(test_id_prefix)

    for stem in stems:
        for directory in ("test", "tests"):
            for ext in (".cc", ".cpp", ".cxx", ".c", ".h", ".hpp"):
                path = os.path.join(context.repo_root, directory, f"{stem}{ext}")
                if os.path.exists(path):
                    candidates.append(path)

    _index_test_sources(context)
    for stem in stems:
        for ext in (".cc", ".cpp", ".cxx", ".c", ".h", ".hpp"):
            candidates.extend(context.source_index.get(f"{stem}{ext}", []))

    seen = set()
    unique = []
    for path in candidates:
        absolute = os.path.abspath(path)
        if absolute not in seen and os.path.isfile(absolute):
            seen.add(absolute)
            unique.append(absolute)
    return unique


def _brace_match(text: str, open_index: int) -> int:
    depth = 0
    quote = ""
    escape = False
    line_comment = False
    block_comment = False
    index = open_index
    while index < len(text):
        char = text[index]
        nxt = text[index + 1] if index + 1 < len(text) else ""
        if line_comment:
            if char == "\n":
                line_comment = False
            index += 1
            continue
        if block_comment:
            if char == "*" and nxt == "/":
                block_comment = False
                index += 2
            else:
                index += 1
            continue
        if quote:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == quote:
                quote = ""
            index += 1
            continue
        if char == "/" and nxt == "/":
            line_comment = True
            index += 2
            continue
        if char == "/" and nxt == "*":
            block_comment = True
            index += 2
            continue
        if char in {"'", '"'}:
            quote = char
            index += 1
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return -1


def _line_offsets(text: str) -> List[int]:
    offsets = [0]
    for match in re.finditer("\n", text):
        offsets.append(match.end())
    return offsets


def _offset_for_line(text: str, line_no: int) -> int:
    if line_no <= 1:
        return 0
    offsets = _line_offsets(text)
    if line_no - 1 < len(offsets):
        return offsets[line_no - 1]
    return len(text)


def _gtest_macro_pattern(suite: str = "", test_name: str = "") -> re.Pattern:
    macro = r"(?:TEST|TEST_F|TEST_P|TYPED_TEST|TYPED_TEST_P)"
    if suite and test_name:
        body = (
            macro
            + r"\s*\(\s*"
            + re.escape(suite)
            + r"\s*,\s*"
            + re.escape(test_name)
            + r"\s*\)\s*\{"
        )
    else:
        body = macro + r"\s*\([^)]*\)\s*\{"
    return re.compile(body, re.MULTILINE)


def _extract_gtest_block(text: str, suite: str, test_name: str, max_chars: int) -> Tuple[str, str]:
    if not suite or not test_name:
        return "", "test identifier not found"
    pattern = _gtest_macro_pattern(suite, test_name)
    for match in pattern.finditer(text):
        open_index = text.find("{", match.start(), match.end())
        end = _brace_match(text, open_index)
        if end >= 0:
            return _truncate_middle(text[match.start():end + 1].strip(), max_chars), "gtest_body"
    fallback = re.search(r"\b" + re.escape(test_name) + r"\b", text)
    if fallback:
        start = max(0, text.rfind("\n", 0, fallback.start()))
        for _ in range(20):
            prev = text.rfind("\n", 0, start)
            if prev < 0:
                start = 0
                break
            start = prev
        end = fallback.end()
        for _ in range(45):
            nxt = text.find("\n", end)
            if nxt < 0:
                end = len(text)
                break
            end = nxt + 1
        return _truncate_middle(text[start:end].strip(), max_chars), "name_snippet"
    return "", "test body not found"


def _extract_gtest_block_around_line(text: str, line_no: int, max_chars: int) -> Tuple[str, str]:
    if line_no <= 0:
        return "", "assertion location not available"
    target = _offset_for_line(text, line_no)
    pattern = _gtest_macro_pattern()
    best = None
    for match in pattern.finditer(text):
        if match.start() > target:
            break
        open_index = text.find("{", match.start(), match.end())
        end = _brace_match(text, open_index)
        if end >= target:
            best = (match.start(), end + 1)
    if best:
        return _truncate_middle(text[best[0]:best[1]].strip(), max_chars), "gtest_body_at_assertion"
    return "", "test body around assertion not found"


def _explicit_test_code(test: dict) -> Tuple[str, str]:
    for key in ("test_code", "test_source", "source_code", "code", "body"):
        value = test.get(key) if isinstance(test, dict) else ""
        if isinstance(value, str) and value.strip():
            return value.strip(), key
    return "", ""


def _metadata_test_text(test: dict, max_chars: int) -> str:
    runtime = _runtime(test)
    failure = _failure(test)
    covered = test.get("covered_functions") or []
    if not isinstance(covered, list):
        covered = []
    parts = [
        f"test_id: {_clean_text(test.get('test_id'))}",
        f"outcome: {_clean_text(test.get('outcome'))}",
        f"replay_command: {_clean_text(runtime.get('replay_command'))}",
        f"failure_type: {_clean_text(failure.get('type'))}",
        f"observed_expression: {_clean_text(failure.get('observed_expression'))}",
        f"actual: {_clean_text(failure.get('actual_value'))}",
        f"expected: {_clean_text(failure.get('expected_value'))}",
    ]
    for key in ("fail_reason", "actual_output", "expected_output"):
        value = _clean_text(test.get(key)).strip()
        if value:
            parts.append(f"{key}: {value}")
    signal_lines = failure.get("signal_lines") if isinstance(failure, dict) else []
    if isinstance(signal_lines, list) and signal_lines:
        parts.append("signal_lines:\n" + "\n".join(_clean_text(line) for line in signal_lines[:12]))
    if covered:
        parts.append("covered_functions:\n" + "\n".join(_clean_text(item) for item in covered[:80]))
    return _truncate_middle("\n".join(part for part in parts if part.strip()), max_chars)


def build_test_code_record(test: dict, context: TestCodeContext) -> dict:
    test_id = _clean_text(test.get("test_id"))
    cache_key = test_id or str(id(test))
    if cache_key in context.extraction_cache:
        return context.extraction_cache[cache_key]

    code, kind = _explicit_test_code(test)
    source_path = ""
    error = ""
    if not code:
        suite, test_name = _gtest_identifier(test)
        assertion_path, assertion_line = _assertion_source_path(test, context.defects4c_root)
        candidate_files = _candidate_test_source_files(test, context)
        for path in candidate_files:
            source = _read_source(path, context)
            if not source:
                continue
            if assertion_path and os.path.abspath(path) == os.path.abspath(assertion_path):
                code, kind = _extract_gtest_block_around_line(source, assertion_line, context.max_chars)
                if code:
                    source_path = path
                    break
            code, kind = _extract_gtest_block(source, suite, test_name, context.max_chars)
            if code:
                source_path = path
                break
            error = kind
    if not code:
        code = _metadata_test_text(test, context.max_chars)
        kind = "metadata_fallback"
        error = error or "test source unavailable"

    record = {
        "test_id": test_id,
        "outcome": _clean_text(test.get("outcome")),
        "text": _truncate_middle(code, context.max_chars),
        "code_kind": kind,
        "source_path": source_path,
        "code_error": "" if kind != "metadata_fallback" else error,
        "code_chars": len(code),
        "covered_function_count": len(test.get("covered_functions") or []),
    }
    context.extraction_cache[cache_key] = record
    return record


def _text_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()


def _model_slug(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", name).strip("_") or "model"


def _default_experiments_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "experiments"))


def _default_cache_dir(config: CodeBertOchiaiConfig) -> str:
    return os.path.join(_default_experiments_dir(), config.dataset, "codebert_test_embeddings")


def _embedding_cache_path(records: Sequence[dict], config: CodeBertOchiaiConfig, bug_id: str) -> str:
    cache_dir = config.cache_dir or _default_cache_dir(config)
    fingerprints = [(record.get("test_id", ""), _text_hash(record.get("text", ""))) for record in records]
    digest = hashlib.sha256(json.dumps(fingerprints, separators=(",", ":")).encode("utf-8")).hexdigest()[:16]
    name = f"{bug_id}__{config.backend}__{_model_slug(config.model_name)}__{digest}.pkl"
    return os.path.join(cache_dir, name)


def _encode_records(records: Sequence[dict], embedder, config: CodeBertOchiaiConfig, bug_id: str) -> List[List[float]]:
    texts = [record.get("text", "") for record in records]
    if not config.use_cache:
        return embedder.encode(texts)

    cache_path = _embedding_cache_path(records, config, bug_id)
    if os.path.exists(cache_path):
        try:
            with open(cache_path, "rb") as f:
                payload = pickle.load(f)
            if payload.get("text_hashes") == [_text_hash(text) for text in texts]:
                vectors = payload.get("vectors")
                if isinstance(vectors, list) and len(vectors) == len(records):
                    return vectors
        except Exception:
            pass

    vectors = embedder.encode(texts)
    os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    with open(cache_path, "wb") as f:
        pickle.dump(
            {
                "backend": config.backend,
                "model": config.model_name,
                "text_hashes": [_text_hash(text) for text in texts],
                "vectors": vectors,
            },
            f,
        )
    return vectors


def score_passing_tests_by_embedding(
    failing_tests: Sequence[dict],
    passing_tests: Sequence[dict],
    context: TestCodeContext,
    embedder,
    config: CodeBertOchiaiConfig,
    bug_id: str = "",
) -> Tuple[List[dict], dict]:
    fail_records = [build_test_code_record(test, context) for test in failing_tests]
    pass_records = [build_test_code_record(test, context) for test in passing_tests]
    all_records = fail_records + pass_records
    vectors = _encode_records(all_records, embedder, config, bug_id or _clean_text(context.bug.get("bug_id")))
    fail_vectors = vectors[:len(fail_records)]
    pass_vectors = vectors[len(fail_records):]

    raw_scored = []
    failing_coverages = [
        (str(test.get("test_id") or f"fail_{index}"), test.get("covered_functions") or [])
        for index, test in enumerate(failing_tests)
    ]
    for index, (record, vector) in enumerate(zip(pass_records, pass_vectors)):
        best_embedding_score = 0.0
        best_embedding_fail_id = ""
        for fail_record, fail_vector in zip(fail_records, fail_vectors):
            score = cosine_similarity(vector, fail_vector)
            if score > best_embedding_score:
                best_embedding_score = score
                best_embedding_fail_id = fail_record.get("test_id", "")

        pass_coverage = passing_tests[index].get("covered_functions") or []
        best_coverage_score = 0.0
        best_coverage_fail_id = ""
        for fail_id, fail_coverage in failing_coverages:
            score = coverage_jaccard_similarity(pass_coverage, fail_coverage)
            if score > best_coverage_score:
                best_coverage_score = score
                best_coverage_fail_id = fail_id

        raw_scored.append(
            {
                "index": index,
                "test_id": record.get("test_id", f"pass_{index}"),
                "codebert_similarity": best_embedding_score,
                "coverage_jaccard_similarity": best_coverage_score,
                "nearest_codebert_fail_test": best_embedding_fail_id,
                "nearest_coverage_fail_test": best_coverage_fail_id,
                "code_kind": record.get("code_kind", ""),
                "code_chars": record.get("code_chars", 0),
                "source_path": record.get("source_path", ""),
                "covered_function_count": record.get("covered_function_count", 0),
            }
        )
    normalized_codebert = _minmax_normalize([item["codebert_similarity"] for item in raw_scored])
    codebert_rank_scores = _descending_borda_scores([item["codebert_similarity"] for item in raw_scored])
    coverage_rank_scores = _descending_borda_scores([item["coverage_jaccard_similarity"] for item in raw_scored])
    scored = []
    total_weight = max(config.codebert_weight + config.coverage_weight, 1e-9)
    codebert_weight = config.codebert_weight / total_weight
    coverage_weight = config.coverage_weight / total_weight
    for item, normalized, codebert_rank, coverage_rank in zip(
        raw_scored,
        normalized_codebert,
        codebert_rank_scores,
        coverage_rank_scores,
    ):
        item["normalized_codebert_similarity"] = normalized
        item["codebert_rank_score"] = codebert_rank
        item["coverage_rank_score"] = coverage_rank
        if config.similarity_mode == "hybrid":
            item["score"] = (
                codebert_weight * normalized
                + coverage_weight * item["coverage_jaccard_similarity"]
            )
        elif config.similarity_mode == "rank_fusion":
            item["score"] = (
                codebert_weight * codebert_rank
                + coverage_weight * coverage_rank
            )
        else:
            item["score"] = item["codebert_similarity"]
        item["nearest_fail_test"] = (
            item["nearest_coverage_fail_test"]
            if config.similarity_mode in {"hybrid", "rank_fusion"}
            and coverage_weight > codebert_weight
            else item["nearest_codebert_fail_test"]
        )
        scored.append(item)
    stats = _code_extraction_stats(fail_records + pass_records)
    stats["failing_code_records"] = _compact_code_records(fail_records)
    embedding_scores = [item["codebert_similarity"] for item in scored]
    coverage_scores = [item["coverage_jaccard_similarity"] for item in scored]
    final_scores = [item["score"] for item in scored]
    stats["similarity_mode"] = config.similarity_mode
    stats["codebert_weight"] = codebert_weight
    stats["coverage_weight"] = coverage_weight
    stats["max_codebert_similarity"] = max(embedding_scores) if embedding_scores else 0.0
    stats["avg_codebert_similarity"] = (sum(embedding_scores) / len(embedding_scores)) if embedding_scores else 0.0
    stats["max_coverage_jaccard_similarity"] = max(coverage_scores) if coverage_scores else 0.0
    stats["avg_coverage_jaccard_similarity"] = (sum(coverage_scores) / len(coverage_scores)) if coverage_scores else 0.0
    stats["max_final_similarity"] = max(final_scores) if final_scores else 0.0
    stats["avg_final_similarity"] = (sum(final_scores) / len(final_scores)) if final_scores else 0.0
    return sorted(scored, key=lambda item: (-item["score"], item["test_id"])), stats


def _compact_code_records(records: Sequence[dict]) -> List[dict]:
    return [
        {
            "test_id": record.get("test_id", ""),
            "code_kind": record.get("code_kind", ""),
            "code_chars": record.get("code_chars", 0),
            "source_path": record.get("source_path", ""),
            "code_error": record.get("code_error", ""),
        }
        for record in records
    ]


def _code_extraction_stats(records: Sequence[dict]) -> dict:
    by_kind: Dict[str, int] = {}
    with_source = 0
    chars = []
    for record in records:
        kind = _clean_text(record.get("code_kind")) or "unknown"
        by_kind[kind] = by_kind.get(kind, 0) + 1
        if record.get("source_path"):
            with_source += 1
        chars.append(int(record.get("code_chars") or 0))
    return {
        "test_code_records": len(records),
        "test_code_by_kind": by_kind,
        "test_code_with_source": with_source,
        "avg_test_code_chars": (sum(chars) / len(chars)) if chars else 0.0,
    }


def select_passing_tests_by_embedding(
    failing_tests: Sequence[dict],
    passing_tests: Sequence[dict],
    context: TestCodeContext,
    embedder,
    config: CodeBertOchiaiConfig,
    bug_id: str = "",
) -> Tuple[List[dict], dict]:
    scored, code_stats = score_passing_tests_by_embedding(
        failing_tests,
        passing_tests,
        context,
        embedder,
        config,
        bug_id=bug_id,
    )
    if config.selection == "topk":
        selected_scores = scored[: max(0, config.top_k)]
    else:
        selected_scores = [item for item in scored if item["score"] >= config.threshold]

    selected_indices = {item["index"] for item in selected_scores}
    selected_passes = [
        test
        for index, test in enumerate(passing_tests)
        if index in selected_indices
    ]
    all_scores = [item["score"] for item in scored]
    kept_scores = [item["score"] for item in selected_scores]
    embedding_scores = [item["codebert_similarity"] for item in scored]
    kept_embedding_scores = [item["codebert_similarity"] for item in selected_scores]
    coverage_scores = [item["coverage_jaccard_similarity"] for item in scored]
    kept_coverage_scores = [item["coverage_jaccard_similarity"] for item in selected_scores]
    stats = {
        "selection": config.selection,
        "threshold": config.threshold,
        "top_k": config.top_k,
        "original_failing_tests": len(failing_tests),
        "original_passing_tests": len(passing_tests),
        "selected_passing_tests": len(selected_passes),
        "reduction_ratio": (
            1.0 - (len(selected_passes) / len(passing_tests))
            if passing_tests
            else 0.0
        ),
        "max_embedding_similarity": max(embedding_scores) if embedding_scores else 0.0,
        "avg_embedding_similarity": (sum(embedding_scores) / len(embedding_scores)) if embedding_scores else 0.0,
        "min_selected_embedding_similarity": min(kept_embedding_scores) if kept_embedding_scores else 0.0,
        "max_selected_embedding_similarity": max(kept_embedding_scores) if kept_embedding_scores else 0.0,
        "max_coverage_jaccard_similarity": max(coverage_scores) if coverage_scores else 0.0,
        "avg_coverage_jaccard_similarity": (sum(coverage_scores) / len(coverage_scores)) if coverage_scores else 0.0,
        "min_selected_coverage_jaccard_similarity": min(kept_coverage_scores) if kept_coverage_scores else 0.0,
        "max_selected_coverage_jaccard_similarity": max(kept_coverage_scores) if kept_coverage_scores else 0.0,
        "max_final_similarity": max(all_scores) if all_scores else 0.0,
        "avg_final_similarity": (sum(all_scores) / len(all_scores)) if all_scores else 0.0,
        "min_selected_similarity": min(kept_scores) if kept_scores else 0.0,
        "max_selected_similarity": max(kept_scores) if kept_scores else 0.0,
        "selected_tests": selected_scores,
        **code_stats,
    }
    return selected_passes, stats


def reduce_tests_and_rank_by_codebert(
    bug: dict,
    embedder,
    config: CodeBertOchiaiConfig,
) -> Tuple[Dict[str, float], dict]:
    failing_tests, passing_tests = _split_tests(bug.get("tests", []))
    context = TestCodeContext(
        bug=bug,
        defects4c_root=config.defects4c_root or default_defects4c_root(),
        max_chars=config.max_test_code_chars,
    )
    context.repo_root = _repo_root_from_bug(bug, context.defects4c_root)
    selected_passes, stats = select_passing_tests_by_embedding(
        failing_tests,
        passing_tests,
        context,
        embedder,
        config,
        bug_id=_clean_text(bug.get("bug_id")),
    )
    reduced_tests = list(failing_tests) + selected_passes
    scores = calculate_ochiai(reduced_tests)
    stats["reduced_test_count"] = len(reduced_tests)
    stats["scored_function_count"] = len(scores)
    stats["repo_root"] = context.repo_root
    return scores, stats


def _default_output_file(config: CodeBertOchiaiConfig) -> str:
    experiments_dir = _default_experiments_dir()
    if str(config.dataset).lower() == "all" and not config.metadata_dir:
        return os.path.join(experiments_dir, "defects4c_codebert_ochiai_function_results.json")
    return os.path.join(experiments_dir, config.dataset, "codebert_ochiai_function_results.json")


def _resolve_config(config: CodeBertOchiaiConfig) -> CodeBertOchiaiConfig:
    config.selection = str(config.selection or "topk").lower()
    config.backend = str(config.backend or "codebert").lower()
    if config.selection not in {"threshold", "topk"}:
        raise ValueError("CodeBERT selection must be 'threshold' or 'topk'")
    if config.backend not in {"codebert", "hash"}:
        raise ValueError("CodeBERT backend must be 'codebert' or 'hash'")
    config.similarity_mode = str(config.similarity_mode or "codebert").lower()
    if config.similarity_mode not in {"codebert", "hybrid", "rank_fusion"}:
        raise ValueError("CodeBERT similarity mode must be 'codebert', 'hybrid', or 'rank_fusion'")
    if config.similarity_mode == "codebert":
        config.codebert_weight = 1.0
        config.coverage_weight = 0.0
    elif config.codebert_weight < 0 or config.coverage_weight < 0:
        raise ValueError("Similarity weights must be non-negative")
    elif config.codebert_weight + config.coverage_weight <= 0:
        raise ValueError("At least one similarity weight must be positive")
    if not config.output_file:
        config.output_file = _default_output_file(config)
    if not config.defects4c_root:
        config.defects4c_root = default_defects4c_root()
    return config


def _rank_ground_truth(scores: Dict[str, float], ground_truth: Sequence[str]) -> Optional[int]:
    for rank, (key, _) in enumerate(
        sorted((scores or {}).items(), key=lambda item: (-item[1], item[0])),
        start=1,
    ):
        for gt in ground_truth:
            if key == gt or key.endswith(f":{gt}") or key.endswith(f"::{gt}"):
                return rank
    return None


def run_codebert_ochiai_fault_localization(config: CodeBertOchiaiConfig) -> Dict[str, dict]:
    config = _resolve_config(config)
    loader_config = Defects4CLoadConfig(
        dataset=config.dataset,
        metadata_dir=config.metadata_dir,
        defects4c_root=config.defects4c_root,
        bug_id_filter=config.bug_id_filter,
        exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
    )
    bugs = load_defects4c_bugs(loader_config)
    embedder = _make_embedding_backend(config)
    output: Dict[str, dict] = {}

    for bug in bugs:
        print(f"Embedding test cases and ranking {bug['bug_id']}...")
        scores, reduction = reduce_tests_and_rank_by_codebert(bug, embedder, config)
        output[bug["bug_id"]] = {
            "dataset": bug.get("dataset", config.dataset),
            "formula": "ochiai",
            "preprocessing": "codebert_test_code_similarity_reduction",
            "scores": scores,
            "codebert_ochiai_scores": scores,
            "ground_truth": bug.get("ground_truth", []),
            "metadata_path": bug.get("metadata_path", ""),
            "metadata_bug_id": bug.get("metadata_bug_id", ""),
            "project": bug.get("project", ""),
            "source_file": bug.get("source_file", ""),
            "embedding": {
                "backend": config.backend,
                "model": config.model_name if config.backend == "codebert" else "hash",
                "device": getattr(embedder, "device", ""),
                "max_length": config.max_length,
                "max_test_code_chars": config.max_test_code_chars,
                "local_files_only": config.local_files_only,
                "similarity_mode": config.similarity_mode,
                "codebert_weight": config.codebert_weight,
                "coverage_weight": config.coverage_weight,
            },
            "reduction": reduction,
            "test_filter": bug.get("test_filter", {}),
        }

    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    with open(config.output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def codebert_ochiai_summary_file(output_file: str) -> str:
    base, ext = os.path.splitext(output_file)
    return f"{base}_summary{ext or '.json'}"


def summarize_codebert_ochiai_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    selected_pass_counts = []
    original_pass_counts = []
    code_kind_totals: Dict[str, int] = {}
    with_source_total = 0
    code_records_total = 0
    for bug_id, entry in sorted(results.items()):
        reduction = entry.get("reduction") or {}
        rank = _rank_ground_truth(entry.get("codebert_ochiai_scores", {}), entry.get("ground_truth", []))
        selected_pass_counts.append(int(reduction.get("selected_passing_tests") or 0))
        original_pass_counts.append(int(reduction.get("original_passing_tests") or 0))
        by_kind = reduction.get("test_code_by_kind") or {}
        if isinstance(by_kind, dict):
            for key, value in by_kind.items():
                code_kind_totals[str(key)] = code_kind_totals.get(str(key), 0) + int(value or 0)
        with_source_total += int(reduction.get("test_code_with_source") or 0)
        code_records_total += int(reduction.get("test_code_records") or 0)
        rows.append(
            {
                "bug_id": bug_id,
                "rank": rank,
                "ground_truth": entry.get("ground_truth", []),
                "original_passing_tests": reduction.get("original_passing_tests", 0),
                "selected_passing_tests": reduction.get("selected_passing_tests", 0),
                "max_embedding_similarity": reduction.get("max_embedding_similarity", 0.0),
                "avg_embedding_similarity": reduction.get("avg_embedding_similarity", 0.0),
                "max_coverage_jaccard_similarity": reduction.get("max_coverage_jaccard_similarity", 0.0),
                "avg_coverage_jaccard_similarity": reduction.get("avg_coverage_jaccard_similarity", 0.0),
                "max_final_similarity": reduction.get("max_final_similarity", 0.0),
                "avg_final_similarity": reduction.get("avg_final_similarity", 0.0),
                "scored_function_count": reduction.get("scored_function_count", 0),
                "repo_root": reduction.get("repo_root", ""),
            }
        )

    total = len(rows)
    topk = {}
    for k in TOPK_VALUES:
        count = sum(1 for row in rows if row["rank"] is not None and row["rank"] <= k)
        topk[f"top{k}"] = {
            "k": k,
            "count": count,
            "percent": (count / total * 100.0) if total else 0.0,
        }

    return {
        "total": total,
        "evaluated": sum(1 for row in rows if row["rank"] is not None),
        "topk": topk,
        "pass_tests": {
            "original_total": sum(original_pass_counts),
            "selected_total": sum(selected_pass_counts),
            "selected_avg": (sum(selected_pass_counts) / total) if total else 0.0,
        },
        "test_code": {
            "records": code_records_total,
            "with_source": with_source_total,
            "by_kind": code_kind_totals,
        },
        "rows": rows,
    }


def print_codebert_ochiai_summary(results: Dict[str, dict], output_file: str = "") -> None:
    summary = summarize_codebert_ochiai_results(results)
    print("\nCodeBERT-test-code-reduced Ochiai function-level FL summary:")
    print(f"  bugs: {summary['total']} evaluated={summary['evaluated']}")
    for label in ("top1", "top3", "top5", "top10", "top20", "top30"):
        item = summary["topk"][label]
        print(f"  {label}: {item['count']}/{summary['total']} ({item['percent']:.2f}%)")
    pass_tests = summary["pass_tests"]
    print(
        "  pass tests: "
        f"selected {pass_tests['selected_total']}/{pass_tests['original_total']} "
        f"(avg {pass_tests['selected_avg']:.2f}/bug)"
    )
    test_code = summary["test_code"]
    print(
        "  test code: "
        f"source {test_code['with_source']}/{test_code['records']} "
        f"kinds={test_code['by_kind']}"
    )
    if output_file:
        summary_file = codebert_ochiai_summary_file(output_file)
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print(f"  output: {output_file}")
        print(f"  summary: {summary_file}")


def add_codebert_ochiai_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fl-codebert-ochiai", action="store_true", help="Run CodeBERT-test-code-similarity-reduced Ochiai FL for Defects4C.")
    parser.add_argument("--codebert-dataset", default="fmt", help="Defects4C unified_debugging dataset, e.g. fmt, cjson, tcpdump, or all.")
    parser.add_argument("--codebert-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--codebert-defects4c-root", default="", help="Path to the defects4c repository.")
    parser.add_argument("--codebert-output-file", default="", help="Output JSON path for CodeBERT-Ochiai FL results.")
    parser.add_argument("--codebert-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--codebert-selection", choices=("threshold", "topk"), default="topk", help="Pass-test reduction strategy.")
    parser.add_argument("--codebert-threshold", type=float, default=0.75, help="Keep pass tests with embedding cosine >= threshold.")
    parser.add_argument("--codebert-top-k", type=int, default=50, help="Keep top K most similar pass tests when selection=topk.")
    parser.add_argument("--codebert-similarity-mode", choices=("codebert", "hybrid", "rank_fusion"), default="codebert", help="Similarity score for pass-test selection.")
    parser.add_argument("--codebert-code-weight", type=float, default=0.5, help="Hybrid/rank-fusion weight for CodeBERT similarity.")
    parser.add_argument("--codebert-coverage-weight", type=float, default=0.5, help="Hybrid/rank-fusion weight for coverage Jaccard similarity.")
    parser.add_argument("--codebert-model", default=DEFAULT_CODEBERT_MODEL, help="Hugging Face model name/path for CodeBERT embeddings.")
    parser.add_argument("--codebert-backend", choices=("codebert", "hash"), default="codebert", help="Embedding backend; hash is only an offline smoke-test fallback.")
    parser.add_argument("--codebert-device", default="auto", help="Embedding device: auto, cpu, cuda, cuda:0, etc.")
    parser.add_argument("--codebert-batch-size", type=int, default=8, help="CodeBERT embedding batch size.")
    parser.add_argument("--codebert-max-length", type=int, default=512, help="Tokenizer max sequence length.")
    parser.add_argument("--codebert-max-test-code-chars", type=int, default=6000, help="Max characters of test-case code/text to embed.")
    parser.add_argument("--codebert-cache-dir", default="", help="Directory for cached test embeddings.")
    parser.add_argument("--codebert-no-cache", action="store_true", help="Disable embedding cache.")
    parser.add_argument("--codebert-local-files-only", action="store_true", help="Use only locally cached Hugging Face model files.")
    parser.add_argument("--codebert-include-fixed-fail", action="store_true", help="Keep tests that also fail on the fixed version.")


def codebert_ochiai_config_from_args(args: argparse.Namespace) -> CodeBertOchiaiConfig:
    return CodeBertOchiaiConfig(
        dataset=args.codebert_dataset,
        metadata_dir=args.codebert_metadata_dir,
        defects4c_root=args.codebert_defects4c_root,
        output_file=args.codebert_output_file,
        bug_id_filter=args.codebert_bug_id,
        selection=args.codebert_selection,
        threshold=args.codebert_threshold,
        top_k=args.codebert_top_k,
        similarity_mode=args.codebert_similarity_mode,
        codebert_weight=args.codebert_code_weight,
        coverage_weight=args.codebert_coverage_weight,
        model_name=args.codebert_model,
        backend=args.codebert_backend,
        device=args.codebert_device,
        batch_size=args.codebert_batch_size,
        max_length=args.codebert_max_length,
        max_test_code_chars=args.codebert_max_test_code_chars,
        cache_dir=args.codebert_cache_dir,
        use_cache=not args.codebert_no_cache,
        local_files_only=args.codebert_local_files_only,
        exclude_fixed_fail_tests=not args.codebert_include_fixed_fail,
    )
