import json

from core.fl_dstar import calculate_dstar, summarize_dstar_results
from data_loaders.defects4c_loader import (
    Defects4CLoadConfig,
    load_defects4c_bugs,
    normalize_function_key,
)


def test_calculate_dstar_uses_failed_and_passed_coverage():
    tests = [
        {"outcome": "FAIL", "covered_functions": ["file.c:fault", "file.c:helper"]},
        {"outcome": "FAIL", "covered_functions": ["file.c:fault"]},
        {"outcome": "PASS", "covered_functions": ["file.c:helper"]},
        {"outcome": "PASS", "covered_functions": ["file.c:unrelated"]},
    ]

    scores = calculate_dstar(tests, star=2)

    assert list(scores)[0] == "file.c:fault"
    assert scores["file.c:fault"] == 9.0
    assert scores["file.c:helper"] == 0.5
    assert scores["file.c:unrelated"] == 0.0


def test_normalize_function_key_preserves_cpp_scope():
    assert (
        normalize_function_key(
            "/out/fmt/include/fmt/format.h::basic_writer::write_double",
            "format.h",
        )
        == "format.h:basic_writer::write_double"
    )
    assert (
        normalize_function_key("format.h:basic_writer::write_double", "format.h")
        == "format.h:basic_writer::write_double"
    )


def test_load_defects4c_bugs_reads_metadata_and_filters_fixed_fail(tmp_path):
    metadata = {
        "bug_id": "Bug.1",
        "project": "owner___repo",
        "source_file": "/out/owner___repo/src/foo.cpp",
        "source_basename": "foo.cpp",
        "ground_truth": ["/out/owner___repo/src/foo.cpp::Ns::fault"],
        "tests": [
            {"test_id": "t1", "outcome": "FAIL", "outcome_fixed": "PASS", "covered_functions": ["foo.cpp:Ns::fault"]},
            {"test_id": "t2", "outcome": "PASS", "outcome_fixed": "PASS", "covered_functions": ["foo.cpp:helper"]},
            {"test_id": "t3", "outcome": "FAIL", "outcome_fixed": "FAIL", "covered_functions": ["foo.cpp:flaky"]},
        ],
    }
    (tmp_path / "Bug.1_meta.json").write_text(json.dumps(metadata), encoding="utf-8")

    bugs = load_defects4c_bugs(
        Defects4CLoadConfig(metadata_dir=str(tmp_path), dataset="unit")
    )

    assert len(bugs) == 1
    assert bugs[0]["ground_truth"] == ["foo.cpp:Ns::fault"]
    assert [test["test_id"] for test in bugs[0]["tests"]] == ["t1", "t2"]
    assert bugs[0]["test_filter"]["excluded_fixed_fail_tests"] == ["t3"]


def test_load_defects4c_bugs_uses_metadata_filename_as_unique_bug_id(tmp_path):
    metadata = {
        "bug_id": "A.3",
        "source_basename": "foo.cpp",
        "ground_truth_functions": ["fault"],
        "tests": [{"test_id": "t1", "outcome": "FAIL", "outcome_fixed": "PASS", "covered_functions": ["foo.cpp:fault"]}],
    }
    (tmp_path / "A.3__one_meta.json").write_text(json.dumps(metadata), encoding="utf-8")
    (tmp_path / "A.3__two_meta.json").write_text(json.dumps(metadata), encoding="utf-8")

    bugs = load_defects4c_bugs(
        Defects4CLoadConfig(metadata_dir=str(tmp_path), dataset="unit")
    )

    assert [bug["bug_id"] for bug in bugs] == ["A.3__one", "A.3__two"]
    assert [bug["metadata_bug_id"] for bug in bugs] == ["A.3", "A.3"]


def test_summarize_dstar_results_reports_required_topk_values():
    scores = {f"file.c:f{i}": 1.0 / i for i in range(1, 35)}
    results = {
        "Bug.1": {
            "dstar_scores": scores,
            "ground_truth": ["file.c:f30"],
            "spectrum": {"covered_function_count": 34},
        }
    }

    summary = summarize_dstar_results(results)

    assert list(summary["topk"]) == ["top1", "top3", "top5", "top10", "top20", "top30"]
    assert summary["topk"]["top20"]["count"] == 0
    assert summary["topk"]["top30"]["count"] == 1
