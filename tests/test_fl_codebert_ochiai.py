from core.fl_codebert_ochiai import (
    CodeBertOchiaiConfig,
    TestCodeContext as CodeContext,
    build_test_code_record,
    cosine_similarity,
    select_passing_tests_by_embedding,
    _descending_borda_scores,
)


class FakeEmbedder:
    def encode(self, texts):
        vectors = {
            "FAIL_CODE": [1.0, 0.0],
            "NEAR_CODE": [0.9, 0.1],
            "COVER_CODE": [0.8, 0.6],
            "FAR_CODE": [0.0, 1.0],
        }
        return [vectors.get(text, [0.0, 0.0]) for text in texts]


def test_cosine_similarity_handles_normal_vectors():
    assert cosine_similarity([1.0, 0.0], [1.0, 0.0]) == 1.0
    assert cosine_similarity([1.0, 0.0], [0.0, 1.0]) == 0.0


def test_build_test_code_record_extracts_gtest_body(tmp_path):
    test_dir = tmp_path / "test"
    test_dir.mkdir()
    (test_dir / "format-test.cc").write_text(
        """
TEST(FormatToTest, Format) {
  EXPECT_EQ("part1", fmt::format("part{}", 1));
}

TEST(FormatToTest, FormatToNonbackInsertIteratorWithSignAndNumericAlignment) {
  char buffer[16] = {};
  fmt::format_to(buffer, "{: =+}", 42.0);
  EXPECT_STREQ("+42", buffer);
}
""",
        encoding="utf-8",
    )
    test = {
        "test_id": "format-test::FormatToTest.FormatToNonbackInsertIteratorWithSignAndNumericAlignment",
        "outcome": "FAIL",
        "runtime": {
            "replay_command": "/repo/build/bin/format-test --gtest_filter=FormatToTest.FormatToNonbackInsertIteratorWithSignAndNumericAlignment"
        },
    }
    context = CodeContext(
        bug={"bug_id": "Bug.1"},
        defects4c_root="",
        max_chars=1000,
        repo_root=str(tmp_path),
    )

    record = build_test_code_record(test, context)

    assert record["code_kind"] == "gtest_body"
    assert "fmt::format_to" in record["text"]
    assert "EXPECT_STREQ" in record["text"]


def test_select_passing_tests_by_embedding_uses_nearest_failing_code():
    failing = [{"test_id": "f1", "outcome": "FAIL", "test_code": "FAIL_CODE"}]
    passing = [
        {"test_id": "near", "outcome": "PASS", "test_code": "NEAR_CODE"},
        {"test_id": "far", "outcome": "PASS", "test_code": "FAR_CODE"},
    ]
    context = CodeContext(
        bug={"bug_id": "Bug.1"},
        defects4c_root="",
        max_chars=1000,
    )
    config = CodeBertOchiaiConfig(
        backend="hash",
        selection="topk",
        top_k=1,
        use_cache=False,
    )

    selected, stats = select_passing_tests_by_embedding(
        failing,
        passing,
        context,
        FakeEmbedder(),
        config,
        bug_id="Bug.1",
    )

    assert [test["test_id"] for test in selected] == ["near"]
    assert stats["selected_passing_tests"] == 1
    assert stats["selected_tests"][0]["nearest_fail_test"] == "f1"


def test_hybrid_similarity_can_select_coverage_nearest_test():
    failing = [
        {
            "test_id": "f1",
            "outcome": "FAIL",
            "test_code": "FAIL_CODE",
            "covered_functions": ["fault", "helper"],
        }
    ]
    passing = [
        {
            "test_id": "code-near",
            "outcome": "PASS",
            "test_code": "NEAR_CODE",
            "covered_functions": ["unrelated"],
        },
        {
            "test_id": "coverage-near",
            "outcome": "PASS",
            "test_code": "COVER_CODE",
            "covered_functions": ["fault", "helper"],
        },
        {
            "test_id": "far",
            "outcome": "PASS",
            "test_code": "FAR_CODE",
            "covered_functions": ["noise"],
        },
    ]
    context = CodeContext(
        bug={"bug_id": "Bug.1"},
        defects4c_root="",
        max_chars=1000,
    )
    config = CodeBertOchiaiConfig(
        backend="hash",
        selection="topk",
        top_k=1,
        similarity_mode="hybrid",
        codebert_weight=0.5,
        coverage_weight=0.5,
        use_cache=False,
    )

    selected, stats = select_passing_tests_by_embedding(
        failing,
        passing,
        context,
        FakeEmbedder(),
        config,
        bug_id="Bug.1",
    )

    assert [test["test_id"] for test in selected] == ["coverage-near"]
    assert stats["selected_tests"][0]["coverage_jaccard_similarity"] == 1.0
    assert stats["selected_tests"][0]["score"] > stats["selected_tests"][0]["normalized_codebert_similarity"]


def test_descending_borda_scores_handles_ties():
    assert _descending_borda_scores([0.9, 0.4, 0.4, 0.1]) == [1.0, 0.5, 0.5, 0.0]


def test_rank_fusion_similarity_uses_rank_scores():
    failing = [
        {
            "test_id": "f1",
            "outcome": "FAIL",
            "test_code": "FAIL_CODE",
            "covered_functions": ["fault", "helper"],
        }
    ]
    passing = [
        {
            "test_id": "code-near",
            "outcome": "PASS",
            "test_code": "NEAR_CODE",
            "covered_functions": ["unrelated"],
        },
        {
            "test_id": "coverage-near",
            "outcome": "PASS",
            "test_code": "COVER_CODE",
            "covered_functions": ["fault", "helper"],
        },
        {
            "test_id": "far",
            "outcome": "PASS",
            "test_code": "FAR_CODE",
            "covered_functions": ["noise"],
        },
    ]
    context = CodeContext(
        bug={"bug_id": "Bug.1"},
        defects4c_root="",
        max_chars=1000,
    )
    config = CodeBertOchiaiConfig(
        backend="hash",
        selection="topk",
        top_k=1,
        similarity_mode="rank_fusion",
        codebert_weight=0.5,
        coverage_weight=0.5,
        use_cache=False,
    )

    selected, stats = select_passing_tests_by_embedding(
        failing,
        passing,
        context,
        FakeEmbedder(),
        config,
        bug_id="Bug.1",
    )

    assert [test["test_id"] for test in selected] == ["coverage-near"]
    assert stats["selected_tests"][0]["codebert_rank_score"] == 0.5
    assert stats["selected_tests"][0]["coverage_rank_score"] == 1.0
    assert stats["selected_tests"][0]["score"] == 0.75
