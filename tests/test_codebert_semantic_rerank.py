from core.codebert_semantic_rerank import _extract_enclosing_test_code, _fuse_scores


def test_extract_enclosing_test_code_uses_full_test_block():
    source = """
TEST(FormatToTest, KeepsSign) {
  char buffer[16] = {};
  fmt::format_to(buffer, "{: =+}", 42.0);
  EXPECT_STREQ("+42", buffer);
}

TEST(Other, Case) {
  EXPECT_EQ(1, 1);
}
""".strip()

    code, kind = _extract_enclosing_test_code(source, 4, 2000)

    assert kind == "enclosing_block"
    assert "TEST(FormatToTest, KeepsSign)" in code
    assert 'EXPECT_STREQ("+42", buffer);' in code
    assert "TEST(Other, Case)" not in code


def test_fuse_scores_adds_semantic_signal_for_candidates():
    baseline = {"a": 10.0, "b": 9.0, "c": 1.0}
    fused = _fuse_scores(baseline, {"b": 1.0}, alpha=0.5)

    assert list(fused)[0] == "b"
    assert fused["b"] > fused["a"]
