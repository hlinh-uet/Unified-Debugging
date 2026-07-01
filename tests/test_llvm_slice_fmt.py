import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UDBG = ROOT / "Unified-Debugging"
FMT_PROJECT = ROOT / "defects4c" / "defectsc_tpl" / "projects_v1" / "fmtlib___fmt"
sys.path.insert(0, str(UDBG))
sys.path.insert(0, str(FMT_PROJECT))

import collect_llvm_slice_fmt as llvm_slice  # noqa: E402
from core.fl_dg_slice_dstar import calculate_dg_slice_dstar, spectrum_counts  # noqa: E402


def test_normalize_source_path_maps_container_and_host_paths():
    assert llvm_slice.normalize_source_path(
        "/out/fmtlib___fmt/git_repo_dir_abc/include/fmt/printf.h"
    ) == "include/fmt/printf.h"
    assert llvm_slice.normalize_source_path(
        "D:/project/Forstudy/defects4c/out_tmp_dirs/fmtlib___fmt/git_repo_dir_abc/src/format.cc"
    ) == "src/format.cc"


def test_load_node_map_normalizes_function_and_production_scope(tmp_path):
    path = tmp_path / "node_map_1_1.jsonl"
    row = {
        "node_id": 10,
        "module": "printf-test.cc",
        "function": "fmt::printf_arg_formatter::operator()",
        "file": "/out/fmtlib___fmt/git_repo_dir_abc/include/fmt/printf.h",
        "line": 260,
        "column": 7,
        "opcode": "store",
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")

    nodes = llvm_slice.load_node_map(tmp_path)

    assert nodes[10][0]["relative_file"] == "include/fmt/printf.h"
    assert nodes[10][0]["line_key"] == "include/fmt/printf.h:260"
    assert nodes[10][0]["production"] is True
    assert nodes[10][0]["qualified_function"] == "printf.h:printf_arg_formatter::operator()"


def test_parse_dg_debug_ll_extracts_sliced_source_lines(tmp_path):
    ll = tmp_path / "slice-debug.ll"
    ll.write_text(
        """
define void @sample() !dbg !10 {
entry:
  %0 = load i32, ptr null, align 4, !dbg !12
  ret void, !dbg !13
}
!1 = !DIFile(filename: "include/fmt/printf.h", directory: "/repo")
!10 = distinct !DISubprogram(name: "operator()", linkageName: "printf_arg_formatter::operator()", file: !1, scope: !1)
!12 = !DILocation(line: 260, column: 7, scope: !10)
!13 = !DILocation(line: 261, column: 3, scope: !10)
""",
        encoding="utf-8",
    )

    parsed = llvm_slice.parse_dg_debug_ll(ll, Path("/repo"))

    assert "include/fmt/printf.h:260" in parsed["line_keys"]
    assert "include/fmt/printf.h:261" in parsed["line_keys"]
    assert "printf.h:printf_arg_formatter::operator()" in parsed["functions"]


def test_dynamic_slice_intersects_executed_nodes_with_static_lines():
    node_map = {
        1: [
            {
                "production": True,
                "line_key": "include/fmt/printf.h:260",
                "qualified_function": "printf.h:printf_arg_formatter::operator()",
            }
        ],
        2: [
            {
                "production": True,
                "line_key": "include/fmt/printf.h:999",
                "qualified_function": "printf.h:unrelated",
            }
        ],
    }

    agg = llvm_slice.aggregate_node_ids(
        {1, 2},
        node_map,
        production_only=True,
        static_line_filter={"include/fmt/printf.h:260"},
    )

    assert agg["node_ids"] == {1}
    assert agg["functions"] == ["printf.h:printf_arg_formatter::operator()"]
    assert agg["lines"] == ["include/fmt/printf.h:260"]


def test_failure_criterion_uses_assertion_location_and_expression_variables(tmp_path):
    test = {
        "failure": {
            "type": "assertion_output",
            "oracle": "gtest",
            "assertion_location": "/out/fmtlib___fmt/git_repo_dir_abc/test/printf-test.cc:162",
            "observed_expression": "fmt::sprintf(make_positional(\"%-5c\"), 'a')",
        }
    }

    criterion = llvm_slice.failure_criterion(test, tmp_path)

    assert criterion["source"] == "test/printf-test.cc"
    assert criterion["line"] == 162
    assert "sprintf" in criterion["variables"]
    assert "sprintf" in criterion["dg_criteria"]
    assert "162:sprintf" in criterion["dg_criteria"]


def test_dg_slice_dstar_uses_dynamic_slice_for_fail_and_execution_for_pass():
    tests = [
        {
            "outcome": "FAIL",
            "llvm_slice": {
                "dynamic_slice_functions": ["printf.h:fault"],
                "executed_functions": ["printf.h:fault", "printf.h:helper"],
            },
        },
        {
            "outcome": "PASS",
            "llvm_slice": {
                "executed_functions": ["printf.h:helper"],
                "dynamic_slice_functions": [],
            },
        },
    ]

    total_passed, total_failed, passed, failed = spectrum_counts(tests)
    scores = calculate_dg_slice_dstar(tests)

    assert total_passed == 1
    assert total_failed == 1
    assert passed == {"printf.h:helper": 1}
    assert failed == {"printf.h:fault": 1}
    assert list(scores)[0] == "printf.h:fault"
