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
