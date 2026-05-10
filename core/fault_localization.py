import math
import re
from collections import Counter


def _calculate_tarantula_score(covered_failed, covered_passed, total_failed, total_passed):
    """
    Tarantula suspiciousness:
        (failed(e) / total_failed) /
        ((failed(e) / total_failed) + (passed(e) / total_passed))
    """
    if total_failed <= 0:
        return 0.0

    if total_passed <= 0:
        return 1.0 if covered_failed > 0 else 0.0

    fail_ratio = covered_failed / total_failed
    pass_ratio = covered_passed / total_passed
    if fail_ratio + pass_ratio == 0:
        return 0.0
    return fail_ratio / (fail_ratio + pass_ratio)


def _sort_scores(scores):
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def _normalize_scores(scores):
    if not scores:
        return {}
    values = list(scores.values())
    min_score = min(values)
    max_score = max(values)
    if max_score == min_score:
        return {key: (1.0 if max_score > 0 else 0.0) for key in scores}
    return {key: (value - min_score) / (max_score - min_score) for key, value in scores.items()}


def _outcome_is_pass(outcome):
    return str(outcome or "").upper() in ("PASSED", "PASS")


def _outcome_is_fail(outcome):
    return str(outcome or "").upper() in ("FAILED", "FAIL")


def _tokenize(text):
    if not text:
        return []

    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text))
    text = text.replace("::", " ").replace("_", " ").replace("-", " ").replace("/", " ")
    raw_tokens = re.findall(r"[A-Za-z][A-Za-z0-9]+|[0-9]+", text.lower())
    stopwords = {
        "test", "tests", "failed", "failure", "error", "running", "passed",
        "expected", "actual", "line", "out", "git", "repo", "dir", "tmp",
        "metadata", "php", "sapi", "linux", "total", "from", "case", "cases",
    }
    return [token for token in raw_tokens if len(token) > 1 and token not in stopwords]


def _signal_lines(text):
    if not text:
        return []

    signal = re.compile(
        r"FAIL|FAILED|ERROR|Failure|Actual|Expected|AddressSanitizer|"
        r"SUMMARY|Segmentation|Assertion|assert|overflow|underflow|invalid|"
        r"not a directory|permission|crash|fatal|warning",
        re.IGNORECASE,
    )
    lines = []
    for line in str(text).splitlines():
        line = line.strip()
        if line and signal.search(line):
            lines.append(line)
    return lines[:40]


def _build_ir_query(test_data):
    parts = []
    for test in test_data:
        if not _outcome_is_fail(test.get("outcome")):
            continue
        parts.append(test.get("test_id", ""))
        parts.append(test.get("fail_reason", ""))
        parts.extend(_signal_lines(test.get("actual_output", "")))
    return _tokenize(" ".join(str(part) for part in parts if part))


def _coverage_counts(test_data, key_func):
    total_passed = 0
    total_failed = 0
    passed = {}
    failed = {}

    for test in test_data:
        outcome = test.get("outcome", "")
        covered = test.get("covered_methods", [])
        keys = set()
        for method_key in covered:
            key = key_func(method_key)
            if key:
                keys.add(key)

        if _outcome_is_pass(outcome):
            total_passed += 1
            for key in keys:
                passed[key] = passed.get(key, 0) + 1
        elif _outcome_is_fail(outcome):
            total_failed += 1
            for key in keys:
                failed[key] = failed.get(key, 0) + 1

    return passed, failed, total_passed, total_failed


def _bm25_like_scores(query_tokens, candidate_docs):
    if not query_tokens or not candidate_docs:
        return {key: 0.0 for key in candidate_docs}

    query = Counter(query_tokens)
    doc_tokens = {key: _tokenize(doc) for key, doc in candidate_docs.items()}
    doc_freq = Counter()
    for tokens in doc_tokens.values():
        doc_freq.update(set(tokens))

    total_docs = len(candidate_docs)
    avg_len = sum(len(tokens) for tokens in doc_tokens.values()) / total_docs if total_docs else 0.0
    k1 = 1.2
    b = 0.75
    raw_scores = {}

    for key, tokens in doc_tokens.items():
        if not tokens:
            raw_scores[key] = 0.0
            continue

        tf = Counter(tokens)
        doc_len = len(tokens)
        score = 0.0
        for token, qf in query.items():
            if token not in tf:
                continue
            idf = math.log(1.0 + (total_docs - doc_freq[token] + 0.5) / (doc_freq[token] + 0.5))
            denom = tf[token] + k1 * (1.0 - b + b * (doc_len / avg_len if avg_len else 1.0))
            score += qf * idf * (tf[token] * (k1 + 1.0)) / denom
        raw_scores[key] = score

    return _normalize_scores(raw_scores)


def _file_doc(file_key, functions_by_file):
    funcs = functions_by_file.get(file_key, [])
    return " ".join([file_key, *funcs])


def _class_doc(class_key, functions_by_class):
    funcs = functions_by_class.get(class_key, [])
    return " ".join([class_key, *funcs])


def _function_doc(function_key):
    return function_key


def _rerank_scores(base_scores, ir_scores, rarity_scores, parent_scores=None, weights=None):
    weights = weights or {}
    base_norm = _normalize_scores(base_scores)
    parent_norm = _normalize_scores(parent_scores or {})
    out = {}

    for key, base_score in base_scores.items():
        out[key] = (
            weights.get("base", 1.0) * base_norm.get(key, 0.0)
            + weights.get("ir", 0.0) * ir_scores.get(key, 0.0)
            + weights.get("rarity", 0.0) * rarity_scores.get(key, 0.0)
            + weights.get("parent", 0.0) * parent_norm.get(key, 0.0)
        )

    return _sort_scores(out)


def _rarity_scores(base_scores, passed_counts, total_passed):
    if total_passed <= 0:
        return {key: 0.0 for key in base_scores}
    return {
        key: max(0.0, 1.0 - (passed_counts.get(key, 0) / total_passed))
        for key in base_scores
    }


def _reranker_weights(level):
    table = {
        "file": {"base": 1.0, "ir": 0.7, "rarity": 0.3},
        "class": {"base": 1.0, "ir": 0.5, "rarity": 0.3, "parent": 0.7},
        "function": {"base": 1.0, "ir": 0.7, "rarity": 0.3, "parent": 0.7},
    }
    return table[level]


def calculate_ir_reranked_file_scores(test_data, file_scores, functions_by_file=None):
    query_tokens = _build_ir_query(test_data)
    functions_by_file = functions_by_file or {}
    candidate_docs = {
        file_key: _file_doc(file_key, functions_by_file)
        for file_key in file_scores
    }
    ir_scores = _bm25_like_scores(query_tokens, candidate_docs)
    passed, _, total_passed, _ = _coverage_counts(test_data, _extract_file_from_key)
    rarity = _rarity_scores(file_scores, passed, total_passed)
    return _rerank_scores(
        file_scores,
        ir_scores,
        rarity,
        weights=_reranker_weights("file"),
    )


def calculate_ir_reranked_class_scores(test_data, class_scores, file_scores, functions_by_class=None):
    if not class_scores:
        return {}

    query_tokens = _build_ir_query(test_data)
    functions_by_class = functions_by_class or {}
    candidate_docs = {
        class_key: _class_doc(class_key, functions_by_class)
        for class_key in class_scores
    }
    ir_scores = _bm25_like_scores(query_tokens, candidate_docs)
    passed, _, total_passed, _ = _coverage_counts(test_data, _extract_class_from_key)
    rarity = _rarity_scores(class_scores, passed, total_passed)
    parent_scores = {
        class_key: file_scores.get(_extract_file_from_key(class_key), 0.0)
        for class_key in class_scores
    }
    return _rerank_scores(
        class_scores,
        ir_scores,
        rarity,
        parent_scores=parent_scores,
        weights=_reranker_weights("class"),
    )


def calculate_ir_reranked_function_scores(test_data, function_scores, class_scores, file_scores):
    query_tokens = _build_ir_query(test_data)
    candidate_docs = {function_key: _function_doc(function_key) for function_key in function_scores}
    ir_scores = _bm25_like_scores(query_tokens, candidate_docs)
    passed, _, total_passed, _ = _coverage_counts(test_data, lambda key: key)
    rarity = _rarity_scores(function_scores, passed, total_passed)

    parent_scores = {}
    for function_key in function_scores:
        class_key = _extract_class_from_key(function_key)
        if class_key:
            parent_scores[function_key] = class_scores.get(class_key, file_scores.get(_extract_file_from_key(function_key), 0.0))
        else:
            parent_scores[function_key] = file_scores.get(_extract_file_from_key(function_key), 0.0)

    return _rerank_scores(
        function_scores,
        ir_scores,
        rarity,
        parent_scores=parent_scores,
        weights=_reranker_weights("function"),
    )


def calculate_fault_localization(test_data):
    """
    Computes Tarantula score for each covered function using the test results.

    test_data: list of dicts with 'outcome' ('PASSED', 'FAILED') and 'covered_methods' (list)
    Returns: dict { 'method_name': score }
    """
    total_passed = 0
    total_failed = 0
    method_passed = {} # Số lần mỗi hàm được kiểm tra và pass
    method_failed = {} # Số lần mỗi hàm được kiểm tra và fail

    for test in test_data:
        outcome = test.get('outcome', '').upper()
        covered = test.get('covered_methods', [])
        
        covered_methods = set(covered)

        if outcome in ['PASSED', 'PASS']:
            total_passed += 1
            for m in covered_methods:
                method_passed[m] = method_passed.get(m, 0) + 1
        elif outcome in ['FAILED', 'FAIL']:
            total_failed += 1
            for m in covered_methods:
                method_failed[m] = method_failed.get(m, 0) + 1

    scores = {}
    all_methods = set(method_passed.keys()).union(method_failed.keys())
    
    for m in all_methods:
        p_m = method_passed.get(m, 0)
        f_m = method_failed.get(m, 0)
        
        scores[m] = _calculate_tarantula_score(f_m, p_m, total_failed, total_passed)

    # Sort descending by score
    return _sort_scores(scores)


def _extract_file_from_key(method_key):
    """
    Trích xuất tên file từ coverage key.

    Sau khi normalize, coverage keys có 2 dạng chính:
      - Defects4C / C:   file.c:function_name
      - Defects4C / C++: file.h:class::method  hoặc  file.h:ns::class::method
      - Codeflaws:       path/to/file.c::function  (chỉ xuất hiện khi CHƯA normalize)

    Quy tắc: tên file luôn nằm trước dấu ':' đơn đầu tiên (không phải '::').
    Ví dụ:
      format.h:basic_writer::int_writer  →  format.h
      schema_compile_node.c:lys_compile  →  schema_compile_node.c
      path/to/file.c::function           →  file.c  (fallback cho Codeflaws raw)
    """
    import os
    import re

    # Tìm dấu ':' đơn đầu tiên (không phải một phần của '::')
    # Dùng regex: ':' không đi kèm ':' trước hoặc sau nó
    match = re.search(r'(?<!:):(?!:)', method_key)
    if match:
        file_part = method_key[:match.start()]
        return os.path.basename(file_part) if file_part else method_key

    # Fallback: nếu chỉ có '::' (Codeflaws raw style)
    if "::" in method_key:
        src_path = method_key.rsplit("::", 1)[0]
        return os.path.basename(src_path)

    return method_key


def _extract_class_from_key(method_key):
    """
    Trích xuất class/scope key từ coverage key C++ dạng:
      file.h:class::method
      file.h:namespace::class::method

    Returns:
      "file.h:class" hoặc "file.h:namespace::class" nếu có scope,
      None nếu function không có phần class/scope.
    """
    import re

    match = re.search(r'(?<!:):(?!:)', method_key)
    if not match:
        return None

    file_key = _extract_file_from_key(method_key)
    func_part = method_key[match.end():]
    if "::" not in func_part:
        return None

    class_part = func_part.rsplit("::", 1)[0]
    if not class_part:
        return None
    return f"{file_key}:{class_part}"


def calculate_fault_localization_file_level(test_data):
    """
    Computes Tarantula score at the FILE level.
    Aggregates coverage from covered_methods to file granularity.

    test_data: list of dicts with 'outcome' ('PASSED', 'FAILED') and 'covered_methods' (list)
    Returns: dict { 'file_name': score }
    """
    total_passed = 0
    total_failed = 0
    file_passed = {}  # Số lần mỗi file được cover bởi test pass
    file_failed = {}  # Số lần mỗi file được cover bởi test fail

    for test in test_data:
        outcome = test.get('outcome', '').upper()
        covered = test.get('covered_methods', [])

        # Trích xuất danh sách file duy nhất từ covered_methods
        covered_files = set()
        for m in covered:
            f = _extract_file_from_key(m)
            covered_files.add(f)

        if outcome in ['PASSED', 'PASS']:
            total_passed += 1
            for f in covered_files:
                file_passed[f] = file_passed.get(f, 0) + 1
        elif outcome in ['FAILED', 'FAIL']:
            total_failed += 1
            for f in covered_files:
                file_failed[f] = file_failed.get(f, 0) + 1

    scores = {}
    all_files = set(file_passed.keys()).union(file_failed.keys())

    for f in all_files:
        p_f = file_passed.get(f, 0)
        f_f = file_failed.get(f, 0)

        scores[f] = _calculate_tarantula_score(f_f, p_f, total_failed, total_passed)

    # Sort descending by score
    return _sort_scores(scores)


def calculate_fault_localization_class_level(test_data):
    """
    Computes Tarantula score at the CLASS/SCOPE level for C++ coverage keys.
    Only keys containing a C++ scope separator after the file separator are used.

    test_data: list of dicts with 'outcome' ('PASSED', 'FAILED') and 'covered_methods' (list)
    Returns: dict { 'file_name:class_or_scope': score }
    """
    total_passed = 0
    total_failed = 0
    class_passed = {}
    class_failed = {}

    for test in test_data:
        outcome = test.get('outcome', '').upper()
        covered = test.get('covered_methods', [])

        covered_classes = set()
        for m in covered:
            class_key = _extract_class_from_key(m)
            if class_key:
                covered_classes.add(class_key)

        if outcome in ['PASSED', 'PASS']:
            total_passed += 1
            for c in covered_classes:
                class_passed[c] = class_passed.get(c, 0) + 1
        elif outcome in ['FAILED', 'FAIL']:
            total_failed += 1
            for c in covered_classes:
                class_failed[c] = class_failed.get(c, 0) + 1

    scores = {}
    all_classes = set(class_passed.keys()).union(class_failed.keys())

    for c in all_classes:
        p_c = class_passed.get(c, 0)
        f_c = class_failed.get(c, 0)
        scores[c] = _calculate_tarantula_score(f_c, p_c, total_failed, total_passed)

    return _sort_scores(scores)
