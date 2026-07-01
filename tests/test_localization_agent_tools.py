import json

from core.localization_agent_tools import (
    LocalizationAgentLlmConfig,
    LocalizationAgentConfig,
    _complete_llm_locations,
    build_case_card,
    build_localization_llm_prompt_input,
    find_function_range,
    get_function_code,
    print_localization_agent_summary,
    rank_functions,
    run_localization_agent_llm,
    run_localization_agent_tools,
)
from data_loaders.defects4c_loader import Defects4CLoadConfig, load_defects4c_bugs


def _write_sample_case(tmp_path):
    source = tmp_path / "repo" / "src" / "foo.cpp"
    source.parent.mkdir(parents=True)
    source.write_text(
        "\n".join(
            [
                "int fault(int x) {",
                "  if (x < 0) {",
                "    return 0;",
                "  }",
                "  return x + 1;",
                "}",
                "",
                "int helper(int x) {",
                "  return x;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    metadata = {
        "bug_id": "Bug.1",
        "dataset_name": "defects4c",
        "language": "C++",
        "project": "owner___repo",
        "source_file": str(source),
        "source_basename": "foo.cpp",
        "type_name": "Incorrect return value",
        "ground_truth": [f"{source}::fault"],
        "tests": [
            {
                "test_id": "FooTest.Negative",
                "outcome": "FAIL",
                "outcome_fixed": "PASS",
                "failure": {
                    "type": "assertion_output",
                    "oracle": "gtest",
                    "assertion_location": str(source) + ":3",
                    "expected_value": "1",
                    "actual_value": "0",
                    "signal_lines": ["Expected: 1", "Actual: 0"],
                },
                "covered_functions": ["foo.cpp:fault", "foo.cpp:helper"],
                "covered_lines": [{"file": str(source), "line": 3}],
                "runtime": {"replay_command": "run FooTest.Negative"},
            },
            {
                "test_id": "FooTest.Positive",
                "outcome": "PASS",
                "outcome_fixed": "PASS",
                "covered_functions": ["foo.cpp:helper"],
            },
        ],
    }

    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    metadata_path = metadata_dir / "Bug.1_meta.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    bug = load_defects4c_bugs(Defects4CLoadConfig(metadata_dir=str(metadata_dir), dataset="unit"))[0]
    return metadata_dir, bug, metadata


def test_case_card_does_not_expose_ground_truth(tmp_path):
    _, bug, metadata = _write_sample_case(tmp_path)

    card = build_case_card(bug, metadata)

    assert "ground_truth" not in card
    assert card["test_counts"]["failing"] == 1
    assert card["failing_tests"][0]["test_id"] == "FooTest.Negative"


def test_rank_functions_prioritizes_fail_only_function(tmp_path):
    _, bug, metadata = _write_sample_case(tmp_path)

    ranked = rank_functions(bug, metadata, top_k=2)

    assert ranked[0]["function_id"] == "foo.cpp:fault"
    assert ranked[0]["covered_by"]["passing_count"] == 0
    assert ranked[1]["function_id"] == "foo.cpp:helper"


def test_get_function_code_extracts_executed_line_window(tmp_path):
    _, bug, metadata = _write_sample_case(tmp_path)

    code = get_function_code(
        bug,
        "foo.cpp:fault",
        mode="executed_lines",
        test_id="FooTest.Negative",
        metadata=metadata,
        context_lines=1,
    )

    assert code["available"] is True
    assert code["range"]["start_line"] == 1
    assert [row["line"] for row in code["lines"]] == [2, 3, 4]
    assert "return 0" in code["lines"][1]["text"]


def test_find_function_range_skips_member_call_site_before_definition(tmp_path):
    source = tmp_path / "foo.cpp"
    source.write_text(
        "\n".join(
            [
                "int wrapper(Obj& obj) { return obj.fault(1); }",
                "",
                "int fault(int x) {",
                "  return x;",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    function_range = find_function_range(str(source), "foo.cpp:fault")

    assert function_range["found"] is True
    assert function_range["start_line"] == 3
    assert function_range["end_line"] == 5


def test_run_localization_agent_tools_writes_payload_without_agent_ground_truth(tmp_path):
    metadata_dir, _, _ = _write_sample_case(tmp_path)
    output_file = tmp_path / "agent_payload.json"

    output = run_localization_agent_tools(
        LocalizationAgentConfig(
            dataset="unit",
            metadata_dir=str(metadata_dir),
            output_file=str(output_file),
            top_k=1,
            inspect_top_k=1,
            code_mode="signature",
        )
    )

    entry = output["Bug.1"]
    assert output_file.exists()
    assert entry["ranked_functions"][0]["function_id"] == "foo.cpp:fault"
    assert "ground_truth" not in entry["case_card"]
    assert entry["evaluation_only"]["ground_truth"] == ["foo.cpp:fault"]
    assert entry["evaluation_only"]["initial_hit_rank"] == 1
    assert entry["evaluation_only"]["initial_topk"]["top_1"] is True


def test_localization_agent_summary_reports_topk_metrics(tmp_path, capsys):
    metadata_dir, _, _ = _write_sample_case(tmp_path)
    output = run_localization_agent_tools(
        LocalizationAgentConfig(
            dataset="unit",
            metadata_dir=str(metadata_dir),
            output_file=str(tmp_path / "agent_payload.json"),
            top_k=2,
            inspect_top_k=0,
        )
    )

    print_localization_agent_summary(output)

    captured = capsys.readouterr()
    assert "initial-ranking eval" in captured.out
    assert "Top@1: 1/1 = 100.0%" in captured.out
    assert "Top@30: 1/1 = 100.0%" in captured.out


def test_llm_locations_backfill_missing_candidates(tmp_path):
    metadata_dir, _, _ = _write_sample_case(tmp_path)
    payload = run_localization_agent_tools(
        LocalizationAgentConfig(
            dataset="unit",
            metadata_dir=str(metadata_dir),
            output_file=str(tmp_path / "agent_payload.json"),
            top_k=2,
            inspect_top_k=0,
        )
    )

    completed = _complete_llm_locations(
        payload["Bug.1"],
        {"top_locations": [{"function_id": "foo.cpp:helper", "reason": "model choice"}]},
        candidate_limit=2,
    )

    assert [row["function_id"] for row in completed["top_locations"]] == ["foo.cpp:helper", "foo.cpp:fault"]
    assert completed["top_locations"][1]["rank"] == 2
    assert completed["postprocess"]["backfilled_locations"] == 1


def test_localization_agent_llm_dry_run_builds_prompt_without_ground_truth(tmp_path):
    metadata_dir, _, _ = _write_sample_case(tmp_path)
    payload_file = tmp_path / "agent_payload.json"
    llm_output = tmp_path / "agent_llm.json"
    payload = run_localization_agent_tools(
        LocalizationAgentConfig(
            dataset="unit",
            metadata_dir=str(metadata_dir),
            output_file=str(payload_file),
            top_k=2,
            inspect_top_k=2,
            code_mode="executed_lines",
        )
    )

    prompt_input = build_localization_llm_prompt_input(
        payload["Bug.1"],
        LocalizationAgentLlmConfig(dataset="unit"),
    )

    assert "ground_truth" not in json.dumps(prompt_input)
    assert prompt_input["candidates"][0]["function_id"] == "foo.cpp:fault"

    result = run_localization_agent_llm(
        LocalizationAgentLlmConfig(
            dataset="unit",
            payload_file=str(payload_file),
            output_file=str(llm_output),
            dry_run=True,
        )
    )

    assert llm_output.exists()
    assert result["Bug.1"]["dry_run"] is True
    assert result["Bug.1"]["llm_result"] == {}
