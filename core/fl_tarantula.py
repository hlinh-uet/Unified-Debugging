def calculate_tarantula(test_data):
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
        
        if outcome in ['PASSED', 'PASS']:
            total_passed += 1
            for m in covered:
                method_passed[m] = method_passed.get(m, 0) + 1
        elif outcome in ['FAILED', 'FAIL']:
            total_failed += 1
            for m in covered:
                method_failed[m] = method_failed.get(m, 0) + 1

    scores = {}
    all_methods = set(method_passed.keys()).union(method_failed.keys())
    
    for m in all_methods:
        p_m = method_passed.get(m, 0)
        f_m = method_failed.get(m, 0)
        
        if total_failed == 0:
            score = 0.0
        elif total_passed == 0:
            score = 1.0 if f_m > 0 else 0.0
        else:
            fail_ratio = f_m / total_failed
            pass_ratio = p_m / total_passed
            if fail_ratio + pass_ratio == 0:
                score = 0.0
            else:
                score = fail_ratio / (fail_ratio + pass_ratio)
                
        scores[m] = score

    # Sort descending by score
    return dict(sorted(scores.items(), key=lambda item: item[1], reverse=True))
