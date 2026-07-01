from core.fl_jaccard_ochiai import (
    calculate_ochiai,
    jaccard_similarity,
    reduce_tests_and_rank,
    select_passing_tests,
    summarize_jaccard_ochiai_results,
)


def test_jaccard_similarity_ignores_shared_zeroes():
    assert jaccard_similarity({"a", "b", "c"}, {"b", "c", "d"}) == 0.5
    assert jaccard_similarity(set(), {"a"}) == 0.0


def test_select_passing_tests_by_threshold():
    failing = [{"test_id": "f1", "outcome": "FAIL", "covered_functions": ["a", "b", "c"]}]
    passing = [
        {"test_id": "p1", "outcome": "PASS", "covered_functions": ["a", "b"]},
        {"test_id": "p2", "outcome": "PASS", "covered_functions": ["x", "y"]},
    ]

    selected, stats = select_passing_tests(failing, passing, selection="threshold", threshold=0.5)

    assert [test["test_id"] for test in selected] == ["p1"]
    assert stats["selected_passing_tests"] == 1
    assert stats["original_passing_tests"] == 2


def test_select_passing_tests_by_topk():
    failing = [{"test_id": "f1", "outcome": "FAIL", "covered_functions": ["a", "b", "c"]}]
    passing = [
        {"test_id": "p1", "outcome": "PASS", "covered_functions": ["a"]},
        {"test_id": "p2", "outcome": "PASS", "covered_functions": ["a", "b"]},
        {"test_id": "p3", "outcome": "PASS", "covered_functions": ["x"]},
    ]

    selected, stats = select_passing_tests(failing, passing, selection="topk", top_k=2)

    assert [test["test_id"] for test in selected] == ["p1", "p2"]
    assert [item["test_id"] for item in stats["selected_tests"]] == ["p2", "p1"]


def test_reduced_ochiai_can_boost_functions_after_pruning_dissimilar_passes():
    tests = [
        {"test_id": "fail", "outcome": "FAIL", "covered_functions": ["fault", "general"]},
        {"test_id": "near", "outcome": "PASS", "covered_functions": ["fault"]},
        {"test_id": "noise1", "outcome": "PASS", "covered_functions": ["general", "noise1", "noise2", "noise3"]},
        {"test_id": "noise2", "outcome": "PASS", "covered_functions": ["general", "noise4", "noise5", "noise6"]},
    ]

    baseline = calculate_ochiai(tests)
    reduced, stats = reduce_tests_and_rank(tests, selection="threshold", threshold=0.3)

    assert list(baseline)[0] == "fault"
    assert list(reduced)[0] == "general"
    assert reduced["general"] > baseline["general"]
    assert stats["selected_passing_tests"] == 1


def test_summarize_jaccard_ochiai_results_reports_top30():
    scores = {f"file.c:f{i}": 1.0 / i for i in range(1, 35)}
    summary = summarize_jaccard_ochiai_results(
        {
            "Bug.1": {
                "jaccard_ochiai_scores": scores,
                "ground_truth": ["file.c:f30"],
                "reduction": {"selected_passing_tests": 2, "original_passing_tests": 10},
            }
        }
    )

    assert list(summary["topk"]) == ["top1", "top3", "top5", "top10", "top20", "top30"]
    assert summary["topk"]["top30"]["count"] == 1
