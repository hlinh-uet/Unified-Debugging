import json
import os
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from core.apr.common import classify_patch_outcome, filter_zero_test_artifact_failures
from core.apr.artifacts import write_llm_patch_artifact
from core.apr.artifacts import (
    build_initial_test_snapshot,
    build_validation_snapshot,
)
from core.apr.revalidate import _validate_bug_artifacts
from data_loaders.sandbox_adapter import Defects4CAdapter
from evaluation.eval_apr import _classify_fix


class PatchOutcomeTests(unittest.TestCase):
    def test_classifies_all_evaluation_outcomes(self):
        init_failed = ["original-a", "original-b"]

        self.assertEqual("plausible", classify_patch_outcome(init_failed, []))
        self.assertEqual("cleanfix", classify_patch_outcome(init_failed, ["original-b"]))
        self.assertEqual(
            "noisefix",
            classify_patch_outcome(init_failed, ["original-b", "regression"]),
        )
        self.assertEqual("nonefix", classify_patch_outcome(init_failed, init_failed))
        self.assertEqual(
            "negfix",
            classify_patch_outcome(init_failed, [*init_failed, "regression"]),
        )
        self.assertEqual(
            "invalid",
            classify_patch_outcome(init_failed, [], "compile_failed"),
        )

    def test_evaluation_uses_the_same_classification(self):
        self.assertEqual("CleanFix", _classify_fix(["a", "b"], ["b"]))
        self.assertEqual("NoiseFix", _classify_fix(["a", "b"], ["b", "c"]))
        self.assertEqual("NoneFix", _classify_fix(["a"], ["a"]))
        self.assertEqual("NegFix", _classify_fix(["a"], ["a", "c"]))


class ZeroTestArtifactTests(unittest.TestCase):
    ZERO_TEST_LOG = """__UD_FAIL__ ranges-test
Internal ctest changing into directory: /tmp/build_meta_fmt
14: [==========] Running 0 tests from 0 test cases.
14: [==========] 0 tests from 0 test cases ran. (0 ms total)
14: [  PASSED  ] 0 tests.
1/1 Test #14: ranges-test ......................   Passed    0.01 sec
100% tests passed, 0 tests failed out of 1
__UD_PASS__ scan-test::ScanTest.ReadText
"""

    def test_zero_test_ctest_artifact_does_not_create_regression(self):
        initial = build_initial_test_snapshot(
            [
                {"test_id": "format-test::FormatterTest.HashFlag", "outcome": "FAIL"},
                {"test_id": "ranges-test", "outcome": "PASS"},
            ],
            exclude_fixed_fail_tests=True,
        )
        self.assertNotIn("ranges-test", initial["comparison_passed"])
        self.assertNotIn("ranges-test", initial["full_passed"])
        snapshot = build_validation_snapshot(
            initial,
            validation_details={
                "validation_error": "",
                "full_post_passed_tests": ["format-test::FormatterTest.HashFlag"],
                "full_post_failed_tests": ["ranges-test"],
                "validation_log_tail": self.ZERO_TEST_LOG,
            },
            post_passed=["format-test::FormatterTest.HashFlag"],
            post_failed=["ranges-test"],
            exclude_fixed_fail_tests=True,
        )

        self.assertEqual("plausible", snapshot["status"])
        self.assertEqual([], snapshot["post_failed_tests"])
        self.assertEqual([], snapshot["full_post_failed_tests"])
        self.assertIn("ranges-test", snapshot["post_passed_tests"])
        self.assertIn("ranges-test", snapshot["full_post_passed_tests"])
        self.assertEqual(
            [],
            filter_zero_test_artifact_failures(
                ["ranges-test"],
                {"validation_log_tail": self.ZERO_TEST_LOG},
            ),
        )

    def test_metadata_validation_ids_skip_zero_coverage_pass_tests(self):
        adapter = Defects4CAdapter("example", data_folder="fmt")
        ids = adapter._metadata_test_ids_from_bug_meta(
            {
                "tests": [
                    {
                        "test_id": "ranges-test",
                        "outcome": "PASS",
                        "outcome_fixed": "PASS",
                        "covered_functions": [],
                    },
                    {
                        "test_id": "format-test::FormatterTest.HashFlag",
                        "outcome": "FAIL",
                        "outcome_fixed": "PASS",
                        "covered_functions": [],
                    },
                    {
                        "test_id": "format-test::FormatterTest.NamedArg",
                        "outcome": "PASS",
                        "outcome_fixed": "PASS",
                        "covered_functions": ["format.h:format"],
                    },
                    {
                        "test_id": "compile-fp-test",
                        "outcome": "PASS",
                        "outcome_fixed": "PASS",
                        "covered_functions": [],
                    },
                ],
            }
        )

        self.assertEqual(
            [
                "format-test::FormatterTest.HashFlag",
                "format-test::FormatterTest.NamedArg",
                "compile-fp-test",
            ],
            ids,
        )

    def test_fmt_runner_allows_empty_ctest_target_but_not_empty_gtest_filter(self):
        adapter = Defects4CAdapter("example", data_folder="fmt")
        script = adapter._fmt_run_one_test_script()

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "run_one_test.sh")
            with open(script_path, "w") as f:
                f.write(script)
            os.chmod(script_path, 0o755)

            ctest_path = os.path.join(tmpdir, "ctest")
            with open(ctest_path, "w") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "echo '[==========] Running 0 tests from 0 test cases.'\n"
                    "echo '[  PASSED  ] 0 tests.'\n"
                    "echo '100% tests passed, 0 tests failed out of 1'\n"
                    "exit 0\n"
                )
            os.chmod(ctest_path, 0o755)
            env = {**os.environ, "PATH": tmpdir + os.pathsep + os.environ.get("PATH", "")}

            result = subprocess.run(
                [script_path, "ranges-test"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

            os.makedirs(os.path.join(tmpdir, "build_meta_fmt", "test"))
            bin_dir = os.path.join(tmpdir, "build_meta_fmt", "bin")
            os.makedirs(bin_dir)
            binary_path = os.path.join(bin_dir, "format-test")
            with open(binary_path, "w") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "echo '[==========] Running 0 tests from 0 test cases.'\n"
                    "echo '[  PASSED  ] 0 tests.'\n"
                    "exit 0\n"
                )
            os.chmod(binary_path, 0o755)

            result = subprocess.run(
                [script_path, "format-test::NoSuch.Test"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)

    def test_libyang_runner_does_not_treat_ten_tests_as_zero_tests(self):
        adapter = Defects4CAdapter("example", data_folder="libyang")
        script = adapter._metadata_run_one_test_script({"project": "CESNET___libyang"})

        with tempfile.TemporaryDirectory() as tmpdir:
            script_path = os.path.join(tmpdir, "run_one_test.sh")
            with open(script_path, "w") as f:
                f.write(script)
            os.chmod(script_path, 0o755)

            test_dir = os.path.join(tmpdir, "build_meta_libyang", "tests")
            os.makedirs(test_dir)
            binary_path = os.path.join(test_dir, "utest_parser_json")
            with open(binary_path, "w") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "echo '[==========] Running 10 test(s).'\n"
                    "echo '[ RUN      ] test_rpc'\n"
                    "echo '[       OK ] test_rpc'\n"
                    "echo '[==========] 10 test(s) run.'\n"
                    "echo '[  PASSED  ] 10 test(s).'\n"
                    "exit 0\n"
                )
            os.chmod(binary_path, 0o755)

            result = subprocess.run(
                [script_path, "utest_parser_json::test_rpc"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)

            with open(binary_path, "w") as f:
                f.write(
                    "#!/usr/bin/env bash\n"
                    "echo '[==========] 0 test(s) run.'\n"
                    "exit 0\n"
                )
            os.chmod(binary_path, 0o755)

            result = subprocess.run(
                [script_path, "utest_parser_json::test_rpc"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)


class ArtifactSnapshotTests(unittest.TestCase):
    def test_pre_filtered_pipeline_tests_reconstruct_full_init_scope(self):
        initial = build_initial_test_snapshot(
            [
                {"test_id": "actionable", "outcome": "FAIL", "outcome_fixed": "PASS"},
                {"test_id": "passing", "outcome": "PASS", "outcome_fixed": "PASS"},
            ],
            exclude_fixed_fail_tests=True,
            excluded_fixed_fail_tests=["fixed-fail"],
        )

        self.assertEqual(["actionable"], initial["comparison_failed"])
        self.assertEqual(
            ["actionable", "fixed-fail"],
            initial["full_failed"],
        )
        self.assertEqual(["actionable"], initial["fields"]["init_failed_tests"])
        self.assertEqual(
            ["actionable", "fixed-fail"],
            initial["fields"]["full_init_failed_tests"],
        )

    def test_initial_apr_artifact_persists_complete_snapshot(self):
        initial = build_initial_test_snapshot(
            [
                {"test_id": "fixed-fail", "outcome": "FAIL", "outcome_fixed": "FAIL"},
                {"test_id": "actionable", "outcome": "FAIL", "outcome_fixed": "PASS"},
                {"test_id": "passing", "outcome": "PASS", "outcome_fixed": "PASS"},
            ],
            exclude_fixed_fail_tests=True,
        )
        snapshot = build_validation_snapshot(
            initial,
            validation_details={
                "validation_error": "",
                "full_post_passed_tests": ["passing", "actionable"],
                "full_post_failed_tests": ["fixed-fail"],
                "fixed_fail_excluded_tests": ["fixed-fail"],
            },
            post_passed=["passing", "actionable"],
            post_failed=[],
            exclude_fixed_fail_tests=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            with (
                patch("core.apr.artifacts.EXPERIMENTS_DIR", tmpdir),
                patch("core.apr.artifacts.LLM_PATCHES_DIR", os.path.join(tmpdir, "llm_patches")),
            ):
                artifact = write_llm_patch_artifact(
                    bug_id="example",
                    attempt_index=1,
                    qualified_name="example.c:main",
                    candidate_relpath="example.c",
                    llm_provider="openrouter",
                    raw_patch="int main(void) { return 0; }",
                    patched_function="int main(void) { return 0; }",
                    patched_file="int main(void) { return 0; }",
                    status=snapshot["status"],
                    validation_error=snapshot["validation_error"],
                    evaluation_snapshot=snapshot,
                )

                metadata_path = os.path.join(tmpdir, artifact["metadata_path"])
                with open(metadata_path, "r") as f:
                    saved = json.load(f)

        self.assertEqual("plausible", saved["status"])
        self.assertEqual(["actionable"], saved["init_failed_tests"])
        self.assertEqual([], saved["post_failed_tests"])
        self.assertEqual(
            ["fixed-fail", "actionable"],
            saved["full_init_failed_tests"],
        )
        self.assertEqual(["fixed-fail"], saved["full_post_failed_tests"])
        for legacy_key in (
            "status_scope",
            "patch_comparison_status",
            "init_failed_count",
            "post_failed_count",
            "patch_comparison_post_failed_tests",
            "fixed_fail_excluded_count",
            "test_filter",
        ):
            self.assertNotIn(legacy_key, saved)
        self.assertNotIn("full_post_failed_tests", saved["validation_details"])


class RevalidateScopeTests(unittest.TestCase):
    def test_init_and_post_use_the_same_filtered_scope(self):
        tests = [
            {
                "test_id": "fixed-fail",
                "outcome": "FAIL",
                "outcome_fixed": "FAIL",
            },
            {
                "test_id": "actionable-fail",
                "outcome": "FAIL",
                "outcome_fixed": "PASS",
            },
            {
                "test_id": "passing",
                "outcome": "PASS",
                "outcome_fixed": "PASS",
            },
        ]
        bug = SimpleNamespace(bug_id="example", tests=tests, raw={})

        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = os.path.join(tmpdir, "candidate.json")
            patched_path = os.path.join(tmpdir, "candidate.patched.c")
            with open(metadata_path, "w") as f:
                json.dump({"status": "failed"}, f)
            with open(patched_path, "w") as f:
                f.write("int main(void) { return 0; }\n")

            artifact = {
                "attempt_index": 1,
                "function": "example.c:main",
                "repair_target_relpath": "example.c",
                "patched_file_path": patched_path,
                "effective_post_failed_tests": ["legacy-top-level"],
                "status_scope": "legacy-scope",
                "post_failed_count": 99,
                "patch_comparison_post_failed_tests": ["legacy-comparison"],
                "test_filter": {"legacy": True},
                "validation_details": {
                    "effective_post_failed_tests": ["legacy-nested"],
                    "full_post_failed_tests": ["legacy-duplicate"],
                    "patch_comparison_post_failed_tests": ["legacy-comparison"],
                },
                "_metadata_abs_path": metadata_path,
                "_patched_file_abs_path": patched_path,
            }
            details = {
                "validation_error": "",
                "full_post_passed_tests": ["passing"],
                "full_post_failed_tests": ["fixed-fail", "actionable-fail"],
                "patch_comparison_post_passed_tests": ["passing"],
                "patch_comparison_post_failed_tests": ["actionable-fail"],
                "fixed_fail_excluded_tests": ["fixed-fail"],
            }

            with patch("core.apr.revalidate.validate_patch") as validate:
                validate.return_value = False, ["passing"], ["actionable-fail"]
                validate.last_details = details
                result = _validate_bug_artifacts("fmt", bug, [artifact])

            self.assertEqual("nonefix", result["status"])
            self.assertEqual(["actionable-fail"], result["init_failed_tests"])
            self.assertEqual(["actionable-fail"], result["post_failed_tests"])
            self.assertEqual(
                ["fixed-fail", "actionable-fail"],
                result["full_init_failed_tests"],
            )
            self.assertEqual(
                ["fixed-fail", "actionable-fail"],
                result["full_post_failed_tests"],
            )
            self.assertEqual(["fixed-fail"], result["fixed_fail_excluded_tests"])

            with open(metadata_path, "r") as f:
                saved_artifact = json.load(f)
            self.assertEqual("nonefix", saved_artifact["status"])
            self.assertEqual(["actionable-fail"], saved_artifact["init_failed_tests"])
            self.assertEqual(["actionable-fail"], saved_artifact["post_failed_tests"])
            self.assertNotIn("effective_post_failed_tests", saved_artifact)
            self.assertNotIn(
                "effective_post_failed_tests",
                saved_artifact["validation_details"],
            )
            self.assertNotIn(
                "full_post_failed_tests",
                saved_artifact["validation_details"],
            )
            self.assertNotIn(
                "patch_comparison_post_failed_tests",
                saved_artifact["validation_details"],
            )
            for legacy_key in (
                "status_scope",
                "post_failed_count",
                "patch_comparison_post_failed_tests",
                "test_filter",
            ):
                self.assertNotIn(legacy_key, saved_artifact)

    def test_include_fixed_fail_uses_full_scope_for_both_sides(self):
        tests = [
            {
                "test_id": "fixed-fail",
                "outcome": "FAIL",
                "outcome_fixed": "FAIL",
            },
            {
                "test_id": "passing",
                "outcome": "PASS",
                "outcome_fixed": "PASS",
            },
        ]
        bug = SimpleNamespace(bug_id="example", tests=tests, raw={})

        with tempfile.TemporaryDirectory() as tmpdir:
            metadata_path = os.path.join(tmpdir, "candidate.json")
            patched_path = os.path.join(tmpdir, "candidate.patched.c")
            with open(metadata_path, "w") as f:
                json.dump({"status": "failed"}, f)
            with open(patched_path, "w") as f:
                f.write("int main(void) { return 0; }\n")

            artifact = {
                "attempt_index": 1,
                "function": "example.c:main",
                "repair_target_relpath": "example.c",
                "patched_file_path": patched_path,
                "_metadata_abs_path": metadata_path,
                "_patched_file_abs_path": patched_path,
            }
            details = {
                "validation_error": "",
                "full_post_passed_tests": ["passing"],
                "full_post_failed_tests": ["fixed-fail"],
                "patch_comparison_post_passed_tests": ["passing"],
                "patch_comparison_post_failed_tests": [],
                "fixed_fail_excluded_tests": ["fixed-fail"],
            }

            with patch("core.apr.revalidate.validate_patch") as validate:
                validate.return_value = True, ["passing"], []
                validate.last_details = details
                result = _validate_bug_artifacts(
                    "fmt",
                    bug,
                    [artifact],
                    exclude_fixed_fail_tests=False,
                )

            self.assertEqual("nonefix", result["status"])
            self.assertEqual(["fixed-fail"], result["init_failed_tests"])
            self.assertEqual(["fixed-fail"], result["post_failed_tests"])
            self.assertEqual([], result["fixed_fail_excluded_tests"])


if __name__ == "__main__":
    unittest.main()
