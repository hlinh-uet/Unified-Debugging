import json

from core.localization_kg_agent import (
    EvidenceKgToolbox,
    LocalizationKgBuildConfig,
    LocalizationKgExploreConfig,
    _empty_belief_state,
    _scripted_action,
    _stop_reason,
    _update_belief_from_response,
    build_localization_evidence_kg,
    run_localization_kg_explorer,
)


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
                "covered_function_lines": {
                    "foo.cpp:fault": [f"{source}:2", f"{source}:3", f"{source}:4"],
                    "foo.cpp:helper": [f"{source}:9"],
                },
                "covered_lines": [{"file": str(source), "line": 3}],
                "runtime": {"replay_command": "run FooTest.Negative"},
            },
            {
                "test_id": "FooTest.Positive",
                "outcome": "PASS",
                "outcome_fixed": "PASS",
                "covered_functions": ["foo.cpp:helper"],
                "covered_function_lines": {"foo.cpp:helper": [f"{source}:9"]},
            },
        ],
    }

    metadata_dir = tmp_path / "metadata"
    metadata_dir.mkdir()
    metadata_path = metadata_dir / "Bug.1_meta.json"
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")
    return metadata_dir


def _build_sample_kg(tmp_path):
    metadata_dir = _write_sample_case(tmp_path)
    kg_file = tmp_path / "kg.json"
    return build_localization_evidence_kg(
        LocalizationKgBuildConfig(
            dataset="unit",
            metadata_dir=str(metadata_dir),
            kg_file=str(kg_file),
            max_code_terms_per_function=20,
        )
    )


def test_build_evidence_kg_creates_core_nodes_and_edges(tmp_path):
    kg = _build_sample_kg(tmp_path)

    assert "Bug.1" in kg["bugs"]
    assert kg["bugs"]["Bug.1"]["ground_truth"] == ["foo.cpp:fault"]
    assert kg["tests"]
    assert kg["failures"]
    assert any(node["function_id"] == "foo.cpp:fault" for node in kg["functions"].values())
    assert any(edge["relation"] == "COVERS_FUNCTION" for edge in kg["edges"])
    assert "fault" in kg["term_index"]["Bug.1"]


def test_bootstrap_packet_does_not_preload_candidates_or_ground_truth(tmp_path):
    kg = _build_sample_kg(tmp_path)
    toolbox = EvidenceKgToolbox(kg, LocalizationKgExploreConfig(dataset="unit", dry_run=True))

    bootstrap = toolbox.get_case_bootstrap("Bug.1")["bootstrap"]
    serialized = json.dumps(bootstrap)

    assert "ground_truth" not in serialized
    assert "ranked_functions" not in serialized
    assert "foo.cpp:fault" not in serialized
    assert bootstrap["failing_tests"][0]["test_id"] == "FooTest.Negative"


def test_kg_tools_return_semantic_and_execution_evidence(tmp_path):
    kg = _build_sample_kg(tmp_path)
    toolbox = EvidenceKgToolbox(kg, LocalizationKgExploreConfig(dataset="unit", dry_run=True))

    semantic = toolbox.search_functions_by_terms("Bug.1", ["fault"], limit=5)
    execution = toolbox.get_failing_execution_path("Bug.1", "FooTest.Negative", limit=5)

    assert semantic["functions"][0]["function_id"] == "foo.cpp:fault"
    assert any(item["function_id"] == "foo.cpp:fault" for item in execution["functions"])
    assert semantic["evidence_items"][0]["type"] == "semantic_match"
    assert execution["evidence_items"][0]["type"] == "failing_execution"


def test_belief_update_increases_candidate_score_from_evidence():
    state = _empty_belief_state()
    response = {
        "intent": "fail_pass_contrast",
        "evidence_items": [
            {"type": "semantic_match", "function_id": "foo.cpp:fault", "terms": ["fault"]},
            {"type": "failing_execution", "function_id": "foo.cpp:fault", "executed_line_count": 3},
            {"type": "fail_pass_contrast", "function_id": "foo.cpp:fault", "contrast": 1.0},
        ],
    }

    new_candidates, new_evidence = _update_belief_from_response(state, response)

    assert new_candidates == 1
    assert new_evidence == 3
    assert state["candidates"]["foo.cpp:fault"]["belief"] > 0.5


def test_stopping_controller_confidence_and_budget():
    state = _empty_belief_state()
    state["tool_history"] = [
        {"tool": "search_functions_by_terms"},
        {"tool": "get_failing_execution_path"},
        {"tool": "find_fail_pass_contrast"},
        {"tool": "compare_fail_pass_coverage"},
        {"tool": "compare_fail_pass_coverage"},
        {"tool": "expand_function_dependencies"},
        {"tool": "get_function_slice"},
    ]
    state["candidates"] = {
        "foo.cpp:fault": {
            "function_id": "foo.cpp:fault",
            "belief": 0.9,
            "uncertainty": 0.1,
            "checked_intents": {
                "execution_path": True,
                "fail_pass_contrast": True,
                "code_slice": True,
            },
        },
        "foo.cpp:helper": {"function_id": "foo.cpp:helper", "belief": 0.2, "uncertainty": 0.8},
    }
    config = LocalizationKgExploreConfig(dataset="unit", dry_run=True, stop_confidence=0.75)

    assert _stop_reason(state, config, step=1, last_eig=0.5, explicit_submit=False) == "confidence"
    assert _stop_reason(_empty_belief_state(), LocalizationKgExploreConfig(dataset="unit", max_steps=1), step=1, last_eig=0.5, explicit_submit=False) == "budget"


def test_confidence_stop_requires_causal_evidence():
    state = _empty_belief_state()
    state["candidates"] = {
        "foo.cpp:fault": {
            "function_id": "foo.cpp:fault",
            "belief": 0.9,
            "uncertainty": 0.1,
            "checked_intents": {
                "semantic_relevance": True,
                "execution_path": True,
                "fail_pass_contrast": True,
            },
        },
        "foo.cpp:helper": {"function_id": "foo.cpp:helper", "belief": 0.2, "uncertainty": 0.8},
    }

    reason = _stop_reason(
        state,
        LocalizationKgExploreConfig(dataset="unit", dry_run=True, stop_confidence=0.75),
        step=1,
        last_eig=0.5,
        explicit_submit=False,
    )

    assert reason == ""


def test_phase_planner_forces_balanced_tool_order(tmp_path):
    kg = _build_sample_kg(tmp_path)
    state = _empty_belief_state()

    action = _scripted_action(kg, "Bug.1", state, 1)
    assert action["tool"] == "search_functions_by_terms"

    _update_belief_from_response(
        state,
        {
            "intent": "semantic_relevance",
            "evidence_items": [{"type": "semantic_match", "function_id": "foo.cpp:fault", "terms": ["fault"]}],
        },
    )
    state["tool_history"].append({"tool": "search_functions_by_terms", "intent": "semantic_relevance", "args": action["args"]})
    action = _scripted_action(kg, "Bug.1", state, 2)
    assert action["tool"] == "get_failing_execution_path"

    state["tool_history"].append({"tool": "get_failing_execution_path", "intent": "execution_path", "args": {}})
    action = _scripted_action(kg, "Bug.1", state, 3)
    assert action["tool"] == "find_fail_pass_contrast"

    state["tool_history"].append({"tool": "find_fail_pass_contrast", "intent": "fail_pass_contrast", "args": {}})
    action = _scripted_action(kg, "Bug.1", state, 4)
    assert action["tool"] == "compare_fail_pass_coverage"


def test_dry_run_explorer_discovers_ground_truth_without_preloaded_topk(tmp_path):
    kg = _build_sample_kg(tmp_path)
    kg_file = tmp_path / "kg.json"
    output_file = tmp_path / "explore.json"
    kg_file.write_text(json.dumps(kg), encoding="utf-8")

    results = run_localization_kg_explorer(
        LocalizationKgExploreConfig(
            dataset="unit",
            kg_file=str(kg_file),
            output_file=str(output_file),
            dry_run=True,
            max_steps=6,
            stop_confidence=0.95,
        )
    )

    entry = results["Bug.1"]
    assert output_file.exists()
    assert "ground_truth" not in json.dumps(entry["case_bootstrap"])
    assert entry["final_candidates"][0]["function_id"] == "foo.cpp:fault"
    assert entry["evaluation_only"]["hit_rank"] == 1
    assert entry["evaluation_only"]["topk"]["top_1"] is True
