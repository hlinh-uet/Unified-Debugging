import hashlib
import json
import os
import re
import shutil
from typing import Optional, Tuple

from configs.path import (
    EXPERIMENTS_DIR,
    get_apr_runtime_dir,
    get_llm_patches_dir,
    get_patches_dir,
)
from core.apr.agent.correctness_repair.fail_context_agent import (
    run_correctness_fail_context_agent,
)
from core.apr.agent.correctness_repair.fix_agent import (
    run_correctness_fix_agent,
)
from core.apr.agent.correctness_repair.repair_planning_pipeline import (
    run_correctness_repair_planning,
)
from core.apr.agent.security_repair.fail_context_agent import (
    run_security_fail_context_agent,
)
from core.apr.agent.security_repair.fix_agent import (
    run_security_fix_agent,
)
from core.apr.agent.security_repair.related_code_context_agent import (
    run_related_code_context_agent as run_security_related_code_context_agent,
)
from core.apr.agent.security_repair.repair_constraints_agent import (
    run_security_repair_constraints_agent,
)
from core.apr.common import (
    APR_SKIP_EXISTING,
    APR_TOP_K,
    build_repair_scope,
    candidate_relpath_from_buggy_tree,
    candidate_is_strictly_better,
    candidate_quality_key,
    extract_function_code_by_line_range,
    enumerate_function_targets,
    disambiguate_function_targets,
    is_plausible_status,
    is_defects4c_dataset,
    parser_diagnostics,
    source_slice_by_byte_range,
    source_root,
    source_language_from_path,
)
from core.apr.artifacts import (
    build_initial_test_snapshot,
    build_invalid_snapshot,
    build_validation_snapshot,
    extract_evaluation_snapshot,
    write_llm_patch_artifact,
    write_replacement_target_artifact,
    write_repair_objective_artifact,
)
from core.apr.validation import validate_patch
from core.apr.agent.refix import run_refix_for_failed_artifacts
from core.apr.oracle_target_identity import exact_target_matches
from core.test_filtering import (
    filter_bug_map_for_pipeline,
    has_failed_tests,
)
from core.utils import (
    extract_function_code,
    parse_sbfl_qualified_name,
    replace_source_range_bytes,
    resolve_fl_candidate_source_path,
    source_function_name_for_extraction,
)
from data_loaders.base_loader import get_loader
from data_loaders.sandbox_adapter import defects4c_docker_ready, get_sandbox_adapter


def _build_candidate_validation_context(
    *,
    agent: str,
    bug_id: str,
    qualified_name: str,
    candidate_relpath: str,
    repair_target_file: str,
    raw_patch: str,
    patched_function: str,
    snapshot: dict,
    validation_details: dict,
    fail_context_agent_artifact: dict,
    repair_objective: dict,
    repair_objective_artifact: dict,
    replacement_target_artifact: dict,
    related_code_context_agent_artifact: dict,
    repair_context_agent_artifact: dict,
    fix_agent_artifact: dict,
    repair_plan: Optional[dict] = None,
) -> dict:
    """Build rich validation feedback for ReFix/debug artifacts."""
    return {
        "agent": agent,
        "bug_id": bug_id,
        "function": qualified_name,
        "repair_target_file": repair_target_file,
        "repair_target_relpath": candidate_relpath,
        "evaluation_snapshot": extract_evaluation_snapshot(snapshot),
        "raw_validation_details": validation_details or {},
        "raw_patch_excerpt": (raw_patch or "")[:8000],
        "patched_function_excerpt": (patched_function or "")[:8000],
        "fail_context_agent_artifact": fail_context_agent_artifact or {},
        "repair_objective": repair_objective or {},
        "repair_objective_artifact": repair_objective_artifact or {},
        "replacement_target_artifact": replacement_target_artifact or {},
        "related_code_context_agent_artifact": related_code_context_agent_artifact or {},
        "repair_context_agent_artifact": repair_context_agent_artifact or {},
        "fix_agent_artifact": fix_agent_artifact or {},
        "repair_plan": repair_plan or {},
    }


def _target_replacement_unit(replacement_target: dict) -> str:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    return str(envelope.get("replacement_unit") or "")


def _target_replacement_range(replacement_target: dict) -> tuple:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    try:
        start = int(replacement_range["start_byte"])
        end = int(replacement_range["end_byte"])
    except Exception:
        return -1, -1
    if start < 0 or end < start:
        return -1, -1
    return start, end


def _fix_agent_output_contract(
    *,
    replacement_target: dict,
    func_name: str,
    cand_label: str,
) -> dict:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    prefix = str(envelope.get("replacement_prefix") or "")
    notes = []
    if prefix:
        notes.append("The replacement unit includes a declaration/storage prefix before the parsed function node.")
    for note in envelope.get("notes") or []:
        if note:
            notes.append(str(note))
    must_preserve = [
        "Preserve the resolved function name, signature, return type, storage qualifiers, template context, and enclosing scope.",
        "Preserve existing coding style and unrelated behavior.",
    ]
    if prefix:
        must_preserve.append(f"Preserve this exact declaration prefix at the start of the returned unit: {prefix!r}.")
    return {
        "target_function": envelope.get("resolved_function_name") or envelope.get("function_name") or func_name,
        "source_file": envelope.get("source_file") or cand_label,
        "editable_scope": "Edit only the provided target replacement unit. The pipeline decides the source range to replace.",
        "return_format": "Return exactly one raw complete C/C++ replacement unit; no markdown, prose, code fences, includes, wrappers, or test code.",
        "replacement_unit_kind": "tree_sitter_resolved_replacement_unit",
        "declaration_prefix": prefix,
        "must_preserve": must_preserve,
        "must_not": [
            "Do not mention or reason about byte ranges or line ranges.",
            "Do not add global helpers, includes, namespaces, classes, main functions, or changes outside the target replacement unit.",
            "Do not invent APIs, macros, enum constants, types, fields, helpers, error codes, or constructor initializers outside the provided related evidence.",
        ],
        "notes": notes[:6],
        "repair_scope": (replacement_target or {}).get("repair_scope") or {},
    }


def _target_replacement_requires_raw_unit(
    replacement_target: dict,
    function_start: int,
) -> bool:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    try:
        replacement_start = int(replacement_range["start_byte"])
    except Exception:
        return False
    notes = set(str(note) for note in (envelope.get("notes") or []))
    range_normalization = envelope.get("range_normalization") or {}
    expansion_reasons = set(str(note) for note in (range_normalization.get("expansion_reasons") or []))
    replacement_unit = str(envelope.get("replacement_unit") or "").lstrip()
    return (
        bool(envelope.get("replacement_includes_prefix"))
        or replacement_start != function_start
        or replacement_unit.startswith("template")
        or any("template" in note or "declaration_prefix" in note for note in notes | expansion_reasons)
    )


def _run_default_repair_objective(
    *,
    bug,
    bug_id: str,
    dataset: str,
) -> Tuple[dict, dict]:
    project_defaults = {
        "tcpdump": "vulnerability",
        "php": "vulnerability",
        "fmt": "general_bug",
        "libyang": "general_bug",
    }
    project_aliases = {
        "tcpdump": ("tcpdump",),
        "php": ("php", "php-src", "phpsrc"),
        "fmt": ("fmt", "fmtlib"),
        "libyang": ("libyang",),
    }
    raw = getattr(bug, "raw", None) if bug is not None else None
    values = [dataset, bug_id, getattr(bug, "dataset", "") if bug is not None else ""]
    if isinstance(raw, dict):
        for key in (
            "project",
            "data_folder",
            "metadata_slug",
            "metadata_stem",
            "bug_id",
            "original_bug_id",
            "source_file",
            "source_relpath",
            "source_repo_dir",
            "buggy_tree_dir",
        ):
            value = raw.get(key)
            if value:
                values.append(str(value))

    text = " ".join(str(value or "") for value in values).lower()
    tokens = set(re.findall(r"[a-z0-9]+", text))
    project = (dataset or "").strip().lower() or "unknown"
    project_evidence = [f"no project default matched; fallback to general_bug for {project!r}"]
    for candidate, aliases in project_aliases.items():
        matched_alias = ""
        for alias in aliases:
            alias_lc = alias.lower()
            alias_tokens = set(re.findall(r"[a-z0-9]+", alias_lc))
            if alias_lc in text or alias_tokens.issubset(tokens):
                matched_alias = alias
                break
        if matched_alias:
            project = candidate
            project_evidence = [f"project default matched {candidate!r} via {matched_alias!r}"]
            break

    bug_kind = project_defaults.get(project, "general_bug")
    route = "security_repair" if bug_kind == "vulnerability" else "correctness_repair"
    if route == "security_repair":
        objective_payload = {
            "validation_oracle": "security_runtime_failure",
            "repair_goal": (
                "Repair the vulnerability by eliminating unsafe runtime behavior at the failing "
                "operation while preserving valid input behavior."
            ),
            "failure_categories": ["project_default_vulnerability", "runtime_safety"],
            "preferred_patch_operators": [
                "bounds_or_length_validation",
                "null_or_lifetime_guard",
                "integer_overflow_guard",
                "safe_error_return",
            ],
            "forbidden_patch_operators": [
                "output_only_change_that_ignores_unsafe_state",
                "silence_crash_without_fixing_root_cause",
                "large_unrelated_rewrite",
            ],
            "route_policy": [
                "Keep this as a vulnerability repair route.",
                "Prioritize removing unsafe memory/runtime behavior over output-only matching.",
                "Preserve behavior for valid inputs unless the safety fix requires a documented error path.",
            ],
            "target_context_policy": [
                "Rank operations that can trigger unsafe access, lifetime, null, or overflow behavior.",
                "Prefer local context that explains the failing runtime safety condition.",
            ],
            "fix_policy": [
                "Add the narrowest guard or validation needed at the unsafe operation.",
                "Use existing project error handling conventions from related context.",
                "Do not rewrite unrelated parsing, formatting, or state machinery.",
            ],
            "scores": {"security": 100, "correctness": 0, "build": 0},
        }
    else:
        objective_payload = {
            "validation_oracle": "correctness_failure",
            "repair_goal": (
                "Repair the general correctness bug by satisfying the observable expected behavior "
                "with the smallest behavior-preserving source change."
            ),
            "failure_categories": ["project_default_general_bug", "correctness"],
            "preferred_patch_operators": [
                "condition_fix",
                "format_or_numeric_semantics_fix",
                "state_update_fix",
                "edge_case_handling",
            ],
            "forbidden_patch_operators": [
                "security_only_guard_unrelated_to_failure",
                "test_specific_hardcoded_output",
                "large_unrelated_rewrite",
            ],
            "route_policy": [
                "Keep this as a general correctness repair route.",
                "Prioritize the failing semantic/output contract over vulnerability-style hardening.",
                "Preserve existing behavior outside the demonstrated correctness failure.",
            ],
            "target_context_policy": [
                "Rank operations that produce the wrong observable value, state, formatting, or branch.",
                "Prefer local context that explains the failing correctness assertion.",
            ],
            "fix_policy": [
                "Patch the smallest expression, branch, state update, or formatting rule that explains the failure.",
                "Do not add broad safety checks unless required by the correctness contract.",
                "Do not hard-code expected output or rewrite unrelated behavior.",
            ],
            "scores": {"security": 0, "correctness": 100, "build": 0},
        }

    repair_objective = {
        "objective_source": {
            "name": "pipeline_project_default",
            "version": 1,
            "strategy": "project_default_static_mapping",
        },
        "bug_id": bug_id,
        "dataset": dataset,
        "project": project,
        "bug_kind": bug_kind,
        "metadata_label": bug_kind,
        "oracle_subkind": f"project_default_{bug_kind}",
        "route": route,
        "confidence": "high",
        "evidence": {
            "project_default": project_evidence,
            "oracle": [],
        },
        "notes": (
            [f"Project {project!r} is configured as {bug_kind}."]
            if project in project_defaults
            else ["Project was not in the configured defaults; treated as general_bug."]
        ),
        **objective_payload,
    }
    artifact = write_repair_objective_artifact(
        bug_id=bug_id,
        attempt_index=0,
        qualified_name="project_default",
        candidate_relpath="",
        repair_objective=repair_objective,
    )
    return repair_objective, artifact


def _repair_route(repair_objective: dict) -> str:
    route = str((repair_objective or {}).get("route") or "").strip()
    if route == "security_repair":
        return "security_repair"
    return "correctness_repair"


def _repair_branch_agents(repair_objective: dict) -> tuple:
    if _repair_route(repair_objective) == "security_repair":
        return (
            run_security_fail_context_agent,
            run_security_related_code_context_agent,
            run_security_repair_constraints_agent,
            run_security_fix_agent,
        )
    return (
        run_correctness_fail_context_agent,
        None,
        None,
        run_correctness_fix_agent,
    )


def _resolve_target_for_repair(
    *,
    source_code: str,
    source_func_name: str,
    source_language: str,
    candidate_path: str,
    cand_label: str,
    resolution_hints: Optional[dict] = None,
) -> tuple:
    """Resolve a repair target only from source-backed tree-sitter candidates."""
    enumerated_targets = enumerate_function_targets(
        source_code,
        source_func_name,
        source_language,
        source_path=candidate_path,
        source_file=cand_label,
    )
    ast_targets = list(enumerated_targets)
    exact_target = (
        (resolution_hints or {}).get("exact_target")
        if isinstance((resolution_hints or {}).get("exact_target"), dict)
        else {}
    )
    if exact_target:
        exact_matches = [
            item for item in ast_targets
            if exact_target_matches(item, exact_target)
        ]
        if len(exact_matches) != 1:
            error = "tree_sitter_exact_target_identity_mismatch"
            resolution = _tree_sitter_target_resolution_failure(
                error=error,
                source_code=source_code,
                source_func_name=source_func_name,
                source_language=source_language,
                candidate_path=candidate_path,
                cand_label=cand_label,
                candidates=enumerated_targets,
                forced_target_id=str(exact_target.get("target_id") or ""),
            )
            resolution["expected_exact_target"] = {
                key: exact_target.get(key)
                for key in (
                    "target_id", "source_file", "start_byte", "end_byte", "start_line",
                    "end_line", "ast_hash", "repository_revision",
                )
                if exact_target.get(key) not in (None, "")
            }
            return "", -1, -1, source_func_name, resolution
        ast_targets = exact_matches
    forced_target_id = str((resolution_hints or {}).get("target_candidate_id") or "")
    if forced_target_id and not exact_target:
        forced = [item for item in ast_targets if str(item.get("id") or "") == forced_target_id]
        if forced:
            ast_targets = forced
        else:
            error = "tree_sitter_forced_target_candidate_not_found"
            resolution = _tree_sitter_target_resolution_failure(
                error=error,
                source_code=source_code,
                source_func_name=source_func_name,
                source_language=source_language,
                candidate_path=candidate_path,
                cand_label=cand_label,
                candidates=enumerated_targets,
                forced_target_id=forced_target_id,
            )
            return "", -1, -1, source_func_name, resolution
    discrimination = disambiguate_function_targets(ast_targets, resolution_hints)
    if discrimination.get("status") == "resolved" and len(discrimination.get("candidates") or []) == 1:
        ast_targets = discrimination["candidates"]
    if len(ast_targets) == 1:
        ast_target = ast_targets[0]
        start_idx = int(ast_target["start_byte"])
        end_idx = int(ast_target["end_byte"])
        func_code = source_slice_by_byte_range(source_code, start_idx, end_idx)
        if not func_code or func_code != str(ast_target.get("code") or ""):
            error = "tree_sitter_candidate_source_byte_range_mismatch"
            resolution = _tree_sitter_target_resolution_failure(
                error=error,
                source_code=source_code,
                source_func_name=source_func_name,
                source_language=source_language,
                candidate_path=candidate_path,
                cand_label=cand_label,
                candidates=ast_targets,
                forced_target_id=forced_target_id,
            )
            return "", -1, -1, source_func_name, resolution
        replacement_identity = {
            key: value
            for key, value in ast_target.items()
            if key != "code"
        }
        replacement_envelope = {
            "function_name": source_func_name,
            "resolved_function_name": ast_target["resolved_name"],
            "source_file": cand_label,
            "source_path": candidate_path,
            "language": source_language,
            "original_function_range": {
                "start_byte": start_idx,
                "end_byte": end_idx,
                "start_line": ast_target.get("start_line"),
                "end_line": ast_target.get("end_line"),
            },
            "replacement_range": {
                "start_byte": start_idx,
                "end_byte": end_idx,
                "start_line": ast_target.get("start_line"),
                "end_line": ast_target.get("end_line"),
            },
            "replacement_includes_prefix": False,
            "replacement_prefix": "",
            "replacement_unit": func_code,
            "range_normalization": {
                "raw_ast_range": {
                    "start_byte": start_idx,
                    "end_byte": end_idx,
                    "start_line": ast_target.get("start_line"),
                    "end_line": ast_target.get("end_line"),
                },
                "normalized_range": {
                    "start_byte": start_idx,
                    "end_byte": end_idx,
                    "start_line": ast_target.get("start_line"),
                    "end_line": ast_target.get("end_line"),
                },
                "expanded_prefix": "",
                "expansion_reasons": [],
            },
            "notes": ["exact_tree_sitter_function_definition_byte_range"],
        }
        replacement_target = {
            "analysis_engine": {
                "name": "replacement_target",
                "version": 2,
                "strategy": "tree_sitter_ast_enumeration_source_byte_range",
                "parser": {
                    **parser_diagnostics(source_language),
                    "fallback_policy": (
                        "Tree-sitter AST enumeration is required; no alternative "
                        "target resolver is present."
                    ),
                },
                "fallback_policy": "none",
                "capabilities": [
                    "ast_function_enumeration",
                    "exact_source_byte_range",
                ],
            },
            "status": "resolved",
            "replacement_identity": replacement_identity,
            "replacement_envelope": replacement_envelope,
            "replacement_start": start_idx,
            "replacement_end": end_idx,
            "replacement_unit": func_code,
            "repair_scope": build_repair_scope(ast_targets),
        }
        replacement_target["target_resolution"] = {
            "status": "resolved",
            "provider": "tree_sitter",
            "strategy": "tree_sitter_ast_enumeration_source_byte_range",
            "candidates": ast_targets,
            "uncertainties": [],
            "discriminator": discrimination.get("discriminator") or [],
            "candidate_scores": discrimination.get("scores") or [],
            "source_backing": {
                "target_id": ast_target.get("target_id"),
                "start_byte": start_idx,
                "end_byte": end_idx,
                "sha256": hashlib.sha256(func_code.encode("utf-8", errors="replace")).hexdigest(),
            },
            "exact_target_verification": (
                {
                    "status": "verified",
                    "target_id": exact_target.get("target_id"),
                    "repository_revision": exact_target.get("repository_revision"),
                }
                if exact_target else {}
            ),
            "fallback_policy": "none",
        }
        return func_code, start_idx, end_idx, ast_target["resolved_name"], replacement_target

    if len(ast_targets) > 1:
        # Do not let a CPG score silently choose a different overload.  Preserve
        # the complete candidate set so a future signature/runtime discriminator
        # or coordinated repair can select/group it explicitly.
        alternative_scope = build_repair_scope(ast_targets, atomic=False)
        alternative_scope.update({
            "kind": "target_alternatives",
            "execution": "ranked_alternatives",
        })
        resolution = {
            "status": "ambiguous",
            "provider": "tree_sitter",
            "candidates": ast_targets,
            "uncertainties": ["multiple_source_backed_target_candidates"],
            "repair_scope": alternative_scope,
        }
        return "", -1, -1, source_func_name, {
            "status": "ambiguous",
            "error": "ambiguous_source_target_requires_signature_or_runtime_discriminator",
            "replacement_unit": "",
            "repair_scope": resolution["repair_scope"],
            "target_resolution": resolution,
        }

    error = "tree_sitter_function_target_not_found"
    diagnostics = parser_diagnostics(source_language)
    if not diagnostics.get("parser_package_available"):
        error = "tree_sitter_parser_package_unavailable"
    elif not diagnostics.get("grammar_available") or not diagnostics.get("language_object_available"):
        error = "tree_sitter_language_grammar_unavailable"
    resolution = _tree_sitter_target_resolution_failure(
        error=error,
        source_code=source_code,
        source_func_name=source_func_name,
        source_language=source_language,
        candidate_path=candidate_path,
        cand_label=cand_label,
        candidates=enumerated_targets,
        forced_target_id=forced_target_id,
    )
    return "", -1, -1, source_func_name, resolution


def _tree_sitter_target_resolution_failure(
    *,
    error: str,
    source_code: str,
    source_func_name: str,
    source_language: str,
    candidate_path: str,
    cand_label: str,
    candidates: list,
    forced_target_id: str = "",
) -> dict:
    """Build the persisted failure payload for tree-sitter-only resolution."""
    diagnostics = parser_diagnostics(source_language)
    diagnostics["fallback_policy"] = (
        "Tree-sitter AST enumeration is required; no alternative target resolver is present."
    )
    source_bytes = (source_code or "").encode("utf-8", errors="replace")
    target_resolution = {
        "status": "not_found",
        "provider": "tree_sitter",
        "strategy": "tree_sitter_ast_enumeration_source_byte_range",
        "requested_name": source_func_name,
        "forced_target_id": forced_target_id,
        "source_path": candidate_path,
        "source_file": cand_label,
        "language": source_language,
        "source_byte_length": len(source_bytes),
        "source_sha256": hashlib.sha256(source_bytes).hexdigest(),
        "candidates": list(candidates or []),
        "candidate_count": len(candidates or []),
        "parser": diagnostics,
        "uncertainties": [error],
        "fallback_policy": "none",
    }
    return {
        "analysis_engine": {
            "name": "replacement_target",
            "version": 1,
            "strategy": "tree_sitter_ast_enumeration_source_byte_range",
            "parser": diagnostics,
            "fallback_policy": "none",
            "capabilities": ["ast_function_enumeration", "source_backed_byte_range"],
        },
        "status": "not_found",
        "error": error,
        "replacement_identity": {},
        "replacement_envelope": {},
        "replacement_start": -1,
        "replacement_end": -1,
        "replacement_unit": "",
        "target_resolution": target_resolution,
    }


def _target_resolution_hints(failed_tests_context: dict) -> dict:
    behavior = failed_tests_context if isinstance(failed_tests_context, dict) else {}
    for key in ("behavior_context", "final_behavior_context", "behavior_evidence"):
        if isinstance(behavior.get(key), dict):
            behavior = behavior[key]
            break
    frames = []
    covered_lines = []
    for test in (behavior.get("tests") or [])[:12]:
        if not isinstance(test, dict):
            continue
        frames.extend(str(item) for item in test.get("stack_frames") or [] if str(item).strip())
        covered_lines.extend(item for item in test.get("covered_lines") or [] if str(item).isdigit())
    return {"stack_frames": frames[:40], "covered_lines": covered_lines[:200]}


def _normalize_llm_replacement(
    *,
    raw_patch: str,
    replacement_target: dict,
    function_start: int,
    source_func_name: str,
    source_language: str,
    source_code: str = "",
    replacement_start_idx: int = -1,
    replacement_end_idx: int = -1,
    direct_source_replacement: bool = False,
) -> tuple:
    """Return (replacement_text, validation_error) for the target replacement range."""
    if direct_source_replacement:
        return (raw_patch or "").strip(), ""
    replacement = (raw_patch or "").strip()
    if "```" in replacement or "<fixed_code" in replacement.lower():
        return "", "wrapped_response"
    if not replacement:
        return "", "empty_response"

    if _target_replacement_requires_raw_unit(replacement_target, function_start):
        envelope = (replacement_target or {}).get("replacement_envelope") or {}
        prefix = str(envelope.get("replacement_prefix") or "")
        first_prefix_line = prefix.strip().splitlines()[0] if prefix.strip() else ""
        if first_prefix_line and first_prefix_line not in replacement[: max(300, len(first_prefix_line) + 20)]:
            replacement = prefix + replacement

    reparsed_func, _, _ = extract_function_code(
        replacement,
        source_func_name,
        language=source_language,
    )
    if not reparsed_func:
        if source_code and replacement_start_idx >= 0 and replacement_end_idx >= replacement_start_idx:
            candidate_source = replace_source_range_bytes(
                source_code,
                replacement_start_idx,
                replacement_end_idx,
                replacement,
            )
            envelope = (replacement_target or {}).get("replacement_envelope") or {}
            line_range = envelope.get("replacement_range") or {}
            patched_func, _, _, _, _, _ = extract_function_code_by_line_range(
                candidate_source,
                start_line=int(line_range.get("start_line") or 1),
                end_line=int(line_range.get("end_line") or line_range.get("start_line") or 1),
                language=source_language,
                requested_name=source_func_name,
            )
            if patched_func:
                return replacement, ""
        return "", "malformed_function"

    if _target_replacement_requires_raw_unit(replacement_target, function_start):
        whole_file_error = _validate_replacement_in_whole_file(
            source_code=source_code,
            replacement_start_idx=replacement_start_idx,
            replacement_end_idx=replacement_end_idx,
            replacement=replacement,
            replacement_target=replacement_target,
            source_func_name=source_func_name,
            source_language=source_language,
        )
        if whole_file_error:
            return "", whole_file_error
        return replacement, ""
    return reparsed_func, ""


def _validate_replacement_in_whole_file(
    *,
    source_code: str,
    replacement_start_idx: int,
    replacement_end_idx: int,
    replacement: str,
    replacement_target: dict,
    source_func_name: str,
    source_language: str,
) -> str:
    if not source_code or replacement_start_idx < 0 or replacement_end_idx < replacement_start_idx:
        return ""
    try:
        candidate_source = replace_source_range_bytes(
            source_code,
            replacement_start_idx,
            replacement_end_idx,
            replacement,
        )
    except Exception:
        return "replacement_range_invalid"
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    line_range = envelope.get("replacement_range") or {}
    try:
        start_line = int(line_range.get("start_line") or 1)
        end_line = int(line_range.get("end_line") or start_line)
    except Exception:
        start_line = 1
        end_line = 1
    patched_func, _, _, _, _, _ = extract_function_code_by_line_range(
        candidate_source,
        start_line=start_line,
        end_line=end_line,
        language=source_language,
        requested_name=source_func_name,
    )
    if not patched_func:
        return "patched_source_target_not_parseable"
    return ""


def _repair_plan_id(repair_plan: Optional[dict]) -> str:
    plan_id = str((repair_plan or {}).get("id") or "").strip()
    if not plan_id:
        return ""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", plan_id).strip("._-")
    return cleaned[:50]


def _patch_artifact_suffix(repair_plan: Optional[dict]) -> str:
    plan_id = _repair_plan_id(repair_plan)
    return f"patch_{plan_id}" if plan_id else "patch"



def _evaluate_fix_patch_candidate(
    *,
    bug_id: str,
    dataset: str,
    initial: dict,
    exclude_fixed_fail_tests: bool,
    llm_patch_attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    candidate_path: str,
    cand_label: str,
    cand_base: str,
    primary_base: str,
    llm_provider: Optional[str],
    raw_patch: str,
    source_code: str,
    replacement_target: dict,
    replacement_start_idx: int,
    replacement_end_idx: int,
    start_idx: int,
    source_func_name: str,
    source_language: str,
    target_replacement_unit: str,
    score: float,
    fail_context_agent_artifact: dict,
    repair_objective: dict,
    repair_objective_artifact: dict,
    replacement_target_artifact: dict,
    related_code_context_agent_artifact: dict,
    repair_context_agent_artifact: dict,
    fix_agent_artifact: dict,
    repair_plan: Optional[dict] = None,
) -> tuple:
    artifact_suffix = _patch_artifact_suffix(repair_plan)
    candidate_patched_func, normalize_error = _normalize_llm_replacement(
        raw_patch=raw_patch,
        replacement_target=replacement_target,
        function_start=start_idx,
        source_func_name=source_func_name,
        source_language=source_language,
        source_code=source_code,
        replacement_start_idx=replacement_start_idx,
        replacement_end_idx=replacement_end_idx,
        direct_source_replacement=_repair_route(repair_objective) == "correctness_repair",
    )
    if normalize_error:
        print("    [ERROR] LLM trả về function không hoàn chỉnh/không parse được. Bỏ qua validate.")
        snapshot = build_invalid_snapshot(
            initial,
            validation_error=normalize_error,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        llm_patch_artifact = write_llm_patch_artifact(
            bug_id=bug_id,
            attempt_index=llm_patch_attempt_index,
            qualified_name=qualified_name,
            candidate_relpath=candidate_relpath,
            llm_provider=llm_provider,
            raw_patch=raw_patch,
            patched_function=candidate_patched_func,
            status=snapshot["status"],
            validation_error=snapshot["validation_error"],
            evaluation_snapshot=snapshot,
            validation_context=_build_candidate_validation_context(
                agent="fix_agent",
                bug_id=bug_id,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                repair_target_file=candidate_path,
                raw_patch=raw_patch,
                patched_function=candidate_patched_func,
                snapshot=snapshot,
                validation_details=snapshot.get("validation_details") or {},
                fail_context_agent_artifact=fail_context_agent_artifact,
                repair_objective=repair_objective,
                repair_objective_artifact=repair_objective_artifact,
                replacement_target_artifact=replacement_target_artifact,
                related_code_context_agent_artifact=related_code_context_agent_artifact,
                repair_context_agent_artifact=repair_context_agent_artifact,
                fix_agent_artifact=fix_agent_artifact,
                repair_plan=repair_plan,
            ),
            fail_context_agent_artifact=fail_context_agent_artifact,
            repair_objective_artifact=repair_objective_artifact,
            replacement_target_artifact=replacement_target_artifact,
            related_code_context_agent_artifact=related_code_context_agent_artifact,
            repair_context_agent_artifact=repair_context_agent_artifact,
            fix_agent_artifact=fix_agent_artifact,
            artifact_suffix=artifact_suffix,
        )
        return {
            "function": qualified_name,
            "score": score,
            "repair_target_file": candidate_path,
            "repair_target_relpath": candidate_relpath,
            "patched_function": candidate_patched_func,
            "patched_file": "",
            "llm_patch_artifact": llm_patch_artifact,
            "fix_agent_evaluation": extract_evaluation_snapshot(snapshot),
            **snapshot,
        }, False

    candidate_patched_source = replace_source_range_bytes(
        source_code,
        replacement_start_idx,
        replacement_end_idx,
        candidate_patched_func,
    )
    safe_cand = cand_label.replace("/", "__").replace(" ", "_")
    tmp_path = os.path.join(
        get_apr_runtime_dir(),
        f"tmp_{bug_id.replace('@', '__')}__{safe_cand}",
    )
    with open(tmp_path, "w") as f:
        f.write(candidate_patched_source)

    _, post_passed, post_failed = validate_patch(
        tmp_path,
        bug_id,
        dataset,
        src_basename=cand_base,
        src_relpath=candidate_relpath,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    validation_details = getattr(validate_patch, "last_details", {}) or {}
    validation_error = validation_details.get("validation_error", "")
    snapshot = build_validation_snapshot(
        initial,
        validation_details=validation_details,
        post_passed=post_passed,
        post_failed=post_failed,
        validation_error=validation_error,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    candidate_result = {
        "function": qualified_name,
        "score": score,
        "repair_target_file": candidate_path,
        "repair_target_relpath": candidate_relpath,
        "patched_function": candidate_patched_func,
        "patched_file": candidate_patched_source,
        "repair_plan": repair_plan or {},
        "_coordination": {
            "unit_id": str(((replacement_target.get("replacement_identity") or {}).get("id") or "")),
            "source_code": source_code,
            "original_unit": target_replacement_unit,
            "patched_unit": candidate_patched_func,
            "replacement_start_idx": replacement_start_idx,
            "replacement_end_idx": replacement_end_idx,
            "language": source_language,
            "repair_plan": repair_plan or {},
        },
        **snapshot,
    }
    candidate_result["llm_patch_artifact"] = write_llm_patch_artifact(
        bug_id=bug_id,
        attempt_index=llm_patch_attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        raw_patch=raw_patch,
        patched_function=candidate_patched_func,
        patched_file=candidate_patched_source,
        status=snapshot["status"],
        validation_error=snapshot["validation_error"],
        evaluation_snapshot=snapshot,
        validation_context=_build_candidate_validation_context(
            agent="fix_agent",
            bug_id=bug_id,
            qualified_name=qualified_name,
            candidate_relpath=candidate_relpath,
            repair_target_file=candidate_path,
            raw_patch=raw_patch,
            patched_function=candidate_patched_func,
            snapshot=snapshot,
            validation_details=validation_details,
            fail_context_agent_artifact=fail_context_agent_artifact,
            repair_objective=repair_objective,
            repair_objective_artifact=repair_objective_artifact,
            replacement_target_artifact=replacement_target_artifact,
            related_code_context_agent_artifact=related_code_context_agent_artifact,
            repair_context_agent_artifact=repair_context_agent_artifact,
            fix_agent_artifact=fix_agent_artifact,
            repair_plan=repair_plan,
        ),
        fail_context_agent_artifact=fail_context_agent_artifact,
        repair_objective_artifact=repair_objective_artifact,
        replacement_target_artifact=replacement_target_artifact,
        related_code_context_agent_artifact=related_code_context_agent_artifact,
        repair_context_agent_artifact=repair_context_agent_artifact,
        fix_agent_artifact=fix_agent_artifact,
        artifact_suffix=artifact_suffix,
    )
    candidate_result["fix_agent_evaluation"] = extract_evaluation_snapshot(snapshot)
    if snapshot["status"] == "plausible":
        print(f"    [SUCCESS] Bản vá hợp lệ cho {bug_id} trong hàm '{qualified_name}'!")
        if _repair_route(repair_objective) == "correctness_repair":
            # The controller persists the selected candidate after leaving the
            # plan loop.  Remove only this temporary validation input here.
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        else:
            patch_name = (
                f"{bug_id}_patch.c"
                if cand_base == primary_base
                else f"{bug_id}_patch__{safe_cand}"
            )
            patches_dir = get_patches_dir()
            patch_path = os.path.join(patches_dir, patch_name)
            os.makedirs(patches_dir, exist_ok=True)
            try:
                shutil.move(tmp_path, patch_path)
            except Exception as e_mv:
                print(f"    [WARN] Không lưu được patch file: {e_mv}")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        return candidate_result, True

    print("    [FAIL] Bản vá không vượt qua kiểm tra.")
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    return candidate_result, False


def _candidate_trace_record(candidate: Optional[dict], *, agent: str) -> dict:
    """Return a compact manifest entry; full patch content stays in artifact files."""
    if not candidate:
        return {}
    artifact = candidate.get("llm_patch_artifact") or {}
    return {
        "agent": agent,
        "function": candidate.get("function"),
        "score": candidate.get("score"),
        "repair_target_file": candidate.get("repair_target_file"),
        "repair_target_relpath": candidate.get("repair_target_relpath"),
        "llm_patch_artifact": artifact,
        "validation_context_path": artifact.get("validation_context_path", ""),
        "quality_key": list(candidate_quality_key(candidate)),
        **extract_evaluation_snapshot(candidate),
    }


def _persist_selected_correctness_patch(
    *, bug_id: str, candidate: dict, primary_base: str
) -> str:
    """Persist the first plausible correctness candidate selected by the controller."""
    if not is_plausible_status((candidate or {}).get("status")):
        return ""
    patched_source = str((candidate or {}).get("patched_file") or "")
    if not patched_source:
        return ""
    target = str(
        (candidate or {}).get("repair_target_relpath")
        or (candidate or {}).get("repair_target_file")
        or ""
    )
    target_base = os.path.basename(target)
    safe_target = target.replace("/", "__").replace(" ", "_")
    patch_name = (
        f"{bug_id}_patch.c"
        if target_base == primary_base
        else f"{bug_id}_patch__{safe_target or target_base or 'target'}"
    )
    patches_dir = get_patches_dir()
    os.makedirs(patches_dir, exist_ok=True)
    patch_path = os.path.join(patches_dir, patch_name)
    try:
        with open(patch_path, "w") as handle:
            handle.write(patched_source)
    except OSError as exc:
        print(f"    [WARN] Không lưu được selected correctness patch: {exc}")
        return ""
    return patch_path


def _evaluate_coordinated_alternative_candidates(
    *,
    bug_id: str,
    dataset: str,
    initial: dict,
    exclude_fixed_fail_tests: bool,
    attempt_index: int,
    llm_provider: Optional[str],
    candidate_results: list,
) -> Optional[dict]:
    """Combine distinct source-backed alternatives and run the real validator."""
    usable = [
        item for item in candidate_results or []
        if isinstance(item.get("_coordination"), dict)
        and item["_coordination"].get("unit_id")
    ]
    groups = {}
    for item in usable:
        key = (str(item.get("function") or ""), str(item.get("repair_target_file") or ""))
        unit_id = str(item["_coordination"].get("unit_id") or "")
        current = groups.setdefault(key, {}).get(unit_id)
        if current is None or candidate_quality_key(item) < candidate_quality_key(current):
            groups[key][unit_id] = item
    viable = [units for units in groups.values() if len(units) >= 2]
    if not viable:
        return None
    units = max(viable, key=len)
    selected = list(units.values())[:6]
    first = selected[0]
    source_code = str(first["_coordination"].get("source_code") or "")
    if not source_code or any(str(item["_coordination"].get("source_code") or "") != source_code for item in selected):
        return None

    patched_units = {}
    structured_edits = []
    region_contracts = []
    scope_units = []
    patched_source = source_code
    replacements = []
    for item in selected:
        meta = item["_coordination"]
        unit_id = str(meta["unit_id"])
        patched_units[unit_id] = str(meta.get("patched_unit") or "")
        scope_units.append({"id": unit_id})
        plan = meta.get("repair_plan") or {}
        structured_edits.extend({**edit, "unit_id": unit_id} for edit in plan.get("structured_edits") or [] if isinstance(edit, dict))
        region_contracts.extend({**contract, "unit_id": unit_id} for contract in plan.get("region_contracts") or [] if isinstance(contract, dict))
        replacements.append((int(meta.get("replacement_start_idx") or 0), int(meta.get("replacement_end_idx") or 0), patched_units[unit_id]))
    ordered_ranges = sorted((start, end) for start, end, _ in replacements)
    if any(left_end > right_start for (_, left_end), (right_start, _) in zip(ordered_ranges, ordered_ranges[1:])):
        return None
    coordinated_plan = {
        "id": "coordinated_source_backed_alternatives",
        "normalization_status": "accepted",
        "repair_scope": {"kind": "coordinated_units", "atomic": True, "units": scope_units},
        "structured_edits": structured_edits,
        "region_contracts": region_contracts,
        "required_evidence_ids": list(dict.fromkeys(
            evidence_id
            for item in selected
            for evidence_id in ((item["_coordination"].get("repair_plan") or {}).get("required_evidence_ids") or [])
        )),
        "allowed_new_symbols": list(dict.fromkeys(
            symbol
            for item in selected
            for symbol in ((item["_coordination"].get("repair_plan") or {}).get("allowed_new_symbols") or [])
        )),
    }
    for start, end, replacement in sorted(replacements, reverse=True):
        patched_source = replace_source_range_bytes(patched_source, start, end, replacement)

    target_path = str(first.get("repair_target_file") or "")
    target_relpath = str(first.get("repair_target_relpath") or "")
    safe_target = (target_relpath or os.path.basename(target_path)).replace("/", "__").replace(" ", "_")
    tmp_path = os.path.join(
        get_apr_runtime_dir(),
        f"tmp_{bug_id.replace('@', '__')}__coordinated__{safe_target}",
    )
    with open(tmp_path, "w") as handle:
        handle.write(patched_source)
    _, post_passed, post_failed = validate_patch(
        tmp_path,
        bug_id,
        dataset,
        src_basename=os.path.basename(target_relpath or target_path),
        src_relpath=target_relpath,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    details = getattr(validate_patch, "last_details", {}) or {}
    snapshot = build_validation_snapshot(
        initial,
        validation_details=details,
        post_passed=post_passed,
        post_failed=post_failed,
        validation_error=details.get("validation_error", ""),
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    raw_patch = json.dumps({unit_id: patched_units[unit_id] for unit_id in patched_units}, ensure_ascii=False)
    parent_artifact = first.get("llm_patch_artifact") or {}
    artifact = write_llm_patch_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=str(first.get("function") or "coordinated"),
        candidate_relpath=target_relpath,
        llm_provider=llm_provider,
        raw_patch=raw_patch,
        patched_function="\n\n".join(patched_units.values()),
        patched_file=patched_source,
        status=snapshot["status"],
        validation_error=snapshot["validation_error"],
        evaluation_snapshot=snapshot,
        validation_context={
            "agent": "fix_agent_coordinated",
            "evaluation_snapshot": extract_evaluation_snapshot(snapshot),
            "raw_validation_details": details,
            "repair_plan": coordinated_plan,
            "parent_patch_artifacts": [item.get("llm_patch_artifact") or {} for item in selected],
        },
        fail_context_agent_artifact=parent_artifact.get("fail_context_agent_artifact") or {},
        repair_objective_artifact=parent_artifact.get("repair_objective_artifact") or {},
        replacement_target_artifact=parent_artifact.get("replacement_target_artifact") or {},
        repair_context_agent_artifact=parent_artifact.get("repair_context_agent_artifact") or {},
        fix_agent_artifact=parent_artifact.get("fix_agent_artifact") or {},
        artifact_suffix="patch_coordinated",
    )
    if is_plausible_status(snapshot.get("status")):
        patches_dir = get_patches_dir()
        os.makedirs(patches_dir, exist_ok=True)
        patch_path = os.path.join(
            patches_dir,
            f"{bug_id}_patch__coordinated__{safe_target}",
        )
        shutil.copyfile(tmp_path, patch_path)
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    return {
        "function": first.get("function"),
        "score": min(float(item.get("score") or 0.0) for item in selected),
        "repair_target_file": target_path,
        "repair_target_relpath": target_relpath,
        "patched_function": "\n\n".join(patched_units.values()),
        "patched_file": patched_source,
        "repair_plan": coordinated_plan,
        "llm_patch_artifact": artifact,
        "fix_agent_evaluation": extract_evaluation_snapshot(snapshot),
        "coordinated_unit_ids": list(patched_units),
        **snapshot,
    }


def run_apr_pipeline(
    dataset: str = "codeflaws",
    llm_provider: Optional[str] = None,
    exclude_fixed_fail_tests: bool = True,
    fl_results_filename: str = "fault_localization_results.json",
    apr_results_filename: str = "apr_results.json",
    apr_top_k: Optional[int] = None,
    valid_mode: bool = False,
    only_missing: bool = False,
    skip_bug_ids: Optional[set] = None,
):
    """
    Pipeline APR (LLM-based).
    Load dữ liệu qua get_loader() – không đọc lại file JSON thủ công.

    Args:
        dataset:      Tên dataset (mặc định 'codeflaws').
        llm_provider: 'openai' | 'openrouter'.
                      Nếu None, đọc từ LLM_PROVIDER trong .env.
    """
    os.makedirs(get_apr_runtime_dir(), exist_ok=True)

    fl_results_file = (
        fl_results_filename
        if os.path.isabs(fl_results_filename)
        else os.path.join(EXPERIMENTS_DIR, fl_results_filename)
    )
    if not os.path.exists(fl_results_file):
        print(f"[APR] Lỗi: {fl_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(fl_results_file, "r") as f:
        fl_results = json.load(f)
    top_k = APR_TOP_K if apr_top_k is None else apr_top_k

    ds_lc = (dataset or "").lower()
    if is_defects4c_dataset(ds_lc):
        ok_d, info_d = defects4c_docker_ready(dataset)
        if not ok_d:
            print(f"[APR] {info_d}")
            print("[APR] Dừng sớm — không gọi LLM khi chưa validate được trên Docker.")
            return
        os.environ["DEFECTS4C_CONTAINER"] = info_d
        print(f"[APR] Defects4C: dùng container '{info_d}' để validate patch.")

    print(f"[APR] Đang load bug records từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}
    bug_map, excluded_fixed_fail_by_bug = filter_bug_map_for_pipeline(
        bug_map,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    total_excluded_zero_test_noop = sum(
        len((bug.raw or {}).get("pipeline_excluded_zero_test_noop_tests", []))
        for bug in bug_map.values()
        if isinstance(bug.raw, dict)
    )
    if exclude_fixed_fail_tests:
        total_excluded = sum(len(v) for v in excluded_fixed_fail_by_bug.values())
        print(
            f"[APR] Fixed-fail filtering bật: loại {total_excluded} "
            "test buggy+fixed đều FAIL khỏi context APR."
        )
    if total_excluded_zero_test_noop:
        print(
            f"[APR] Loại {total_excluded_zero_test_noop} test PASS/no-op có coverage rỗng "
            "khỏi context APR/validation."
        )
    dataset_key = (dataset or "").strip().lower()
    filtered_fl_results = {}
    skipped_other_dataset = 0
    skipped_missing_bug = 0
    for bug_id, result_data in fl_results.items():
        result_dataset = ""
        if isinstance(result_data, dict):
            result_dataset = str(result_data.get("dataset") or "").strip().lower()
        if result_dataset and result_dataset != dataset_key:
            skipped_other_dataset += 1
            continue
        if bug_id not in bug_map:
            skipped_missing_bug += 1
            continue
        filtered_fl_results[bug_id] = result_data
    fl_results = filtered_fl_results
    if skipped_other_dataset or skipped_missing_bug:
        print(
            f"[APR] Bỏ qua {skipped_other_dataset} FL records khác dataset và "
            f"{skipped_missing_bug} records không có trong loader '{dataset}'."
        )

    converged_bug_ids = {
        str(bug_id).strip()
        for bug_id in (skip_bug_ids or set())
        if str(bug_id).strip()
    }
    if converged_bug_ids:
        before_converged_filter = len(fl_results)
        fl_results = {
            bug_id: result_data
            for bug_id, result_data in fl_results.items()
            if bug_id not in converged_bug_ids
        }
        print(
            f"[APR] Bỏ qua {before_converged_filter - len(fl_results)} bug đã "
            "plausible ở vòng trước."
        )

    if only_missing:
        before_missing_filter = len(fl_results)
        fl_results = {
            bug_id: result_data
            for bug_id, result_data in fl_results.items()
            if not os.path.isdir(
                os.path.join(
                    get_llm_patches_dir(),
                    re.sub(r"[^A-Za-z0-9._-]+", "_", str(bug_id)).strip("._-")
                    or "unknown",
                )
            )
        }
        print(
            f"[APR] --only-missing: giữ {len(fl_results)}/{before_missing_filter} "
            "bug chưa có thư mục llm_patches; không retry artifact cũ."
        )

    apr_results = {}
    apr_results_file = (
        apr_results_filename
        if os.path.isabs(apr_results_filename)
        else os.path.join(EXPERIMENTS_DIR, apr_results_filename)
    )
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass
    apr_results = {
        bug_id: result
        for bug_id, result in apr_results.items()
        if bug_id in bug_map and (
            not isinstance(result, dict)
            or not result.get("dataset")
            or str(result.get("dataset")).strip().lower() == dataset_key
        )
    }

    print("[APR] Đang chạy Automated Program Repair (LLM)...")

    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results:
            if is_plausible_status(apr_results[bug_id].get("status")):
                print(f"[APR] Bỏ qua bug {bug_id} vì đã có patch plausible.")
                continue
            if APR_SKIP_EXISTING:
                print(
                    f"[APR] Retry bug {bug_id}: record cũ trong "
                    f"{os.path.basename(apr_results_file)} chưa plausible "
                    f"(status={apr_results[bug_id].get('status')})."
                )

        bug_record = bug_map.get(bug_id)
        excluded_fixed_fail_tests = excluded_fixed_fail_by_bug.get(bug_id, [])
        if exclude_fixed_fail_tests and bug_record and not has_failed_tests(bug_record.tests):
            print(
                f"    [APR] Bỏ qua {bug_id}: không còn failed test actionable "
                "sau khi loại buggy+fixed đều FAIL."
            )
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "status": "skipped",
                "real_status": "skipped",
                "validation_error": "no_actionable_failed_tests_after_fixed_fail_filter",
                "fixed_fail_excluded_tests": list(excluded_fixed_fail_tests),
            }
            with open(apr_results_file, "w") as f:
                json.dump(apr_results, f, indent=4)
            continue

        scores = result_data.get("scores", result_data) if isinstance(result_data, dict) else result_data
        if not scores:
            continue

        sorted_funcs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_funcs = sorted_funcs[:top_k] if top_k > 0 else sorted_funcs
        print(f"[APR] Xử lý bug {bug_id}... (top-{top_k if top_k > 0 else 'all'})")

        try:
            adapter = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"    [Error] Không thể lấy adapter cho {bug_id}: {e}")
            continue

        if not os.path.exists(bug_source_path):
            print(f"    [Skip] File nguồn không tồn tại: {bug_source_path}")
            continue

        primary_base = os.path.basename(bug_source_path)
        raw_meta = bug_record.raw if bug_record else None
        source_cache: dict = {}

        repair_objective, repair_objective_artifact = _run_default_repair_objective(
            bug=bug_record,
            bug_id=bug_id,
            dataset=dataset,
        )
        (
            run_branch_fail_context_agent,
            run_branch_related_code_context_agent,
            run_constraints_agent,
            run_branch_fix_agent,
        ) = _repair_branch_agents(repair_objective)
        print(
            "    [ROUTE] "
            f"{repair_objective.get('project')} defaults to {repair_objective.get('bug_kind')} "
            f"-> {repair_objective.get('route')} "
            f"(oracle={repair_objective.get('validation_oracle')}, "
            f"confidence={repair_objective.get('confidence')})"
        )
        failed_tests_context, fail_context_agent_artifact = run_branch_fail_context_agent(
            bug=bug_record,
            bug_id=bug_id,
            llm_provider=llm_provider,
        )
        if not failed_tests_context:
            print(f"    [ERROR] FailContextAgent trả về None. Bỏ qua bug {bug_id}.")
            continue
        initial = build_initial_test_snapshot(
            bug_record.tests if bug_record else [],
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            excluded_fixed_fail_tests=excluded_fixed_fail_tests,
        )

        target_func = None
        attempted = False
        llm_attempted = False
        llm_patch_attempt_index = 0
        candidate_results = []
        best_candidate = None

        exact_targets = (
            list(result_data.get("exact_targets") or [])
            if valid_mode and isinstance(result_data, dict)
            else []
        )
        if valid_mode and not exact_targets:
            exact_resolution = (
                result_data.get("exact_target_resolution")
                if isinstance(result_data, dict) and isinstance(result_data.get("exact_target_resolution"), dict)
                else {}
            )
            diagnostics = exact_resolution.get("diagnostics") or ["exact_oracle_target_missing"]
            print(
                f"    [APR-valid] Bỏ qua {bug_id}: valid mode yêu cầu exact AST target; "
                f"{', '.join(str(item) for item in diagnostics)}"
            )
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": True,
                "fl_results_file": os.path.basename(fl_results_file),
                "status": "skipped",
                "real_status": "skipped",
                "validation_error": "exact_oracle_target_missing",
                "exact_target_resolution": exact_resolution,
            }
            with open(apr_results_file, "w") as f:
                json.dump(apr_results, f, indent=4)
            continue
        pending_funcs = (
            [
                (
                    str(target.get("fl_key") or result_data.get("oracle_top1") or ""),
                    float(target.get("score") or 1.0),
                    target,
                )
                for target in exact_targets
                if isinstance(target, dict) and target.get("target_id")
            ]
            if valid_mode else
            [(qualified_name, score, None) for qualified_name, score in top_funcs]
        )
        queued_target_ids = set()
        while pending_funcs:
            qualified_name, score, forced_target = pending_funcs.pop(0)
            if score == 0.0:
                continue

            file_hint, func_name = parse_sbfl_qualified_name(qualified_name)
            if not func_name:
                continue
            if is_defects4c_dataset(ds_lc) and not file_hint:
                print(f"  - [Skip] FL key thiếu file hint cho dataset nhiều file: {qualified_name}")
                continue

            candidate_path = resolve_fl_candidate_source_path(
                dataset, bug_source_path, file_hint or "", raw_meta, func_name=func_name
            )
            if not os.path.isfile(candidate_path):
                print(
                    f"  - [Skip] Không tìm thấy file nguồn cho '{qualified_name}': {candidate_path}"
                )
                continue
            if candidate_path not in source_cache:
                with open(candidate_path, "r") as f:
                    source_cache[candidate_path] = f.read()
            source_code = source_cache[candidate_path]
            candidate_relpath = candidate_relpath_from_buggy_tree(candidate_path, raw_meta)
            cand_base = os.path.basename(candidate_relpath or candidate_path)
            cand_label = candidate_relpath or cand_base

            print(f"  - Kiểm tra hàm '{func_name}' trong {cand_label} (Score: {score:.4f})")
            source_language = source_language_from_path(candidate_path)
            source_func_name = source_function_name_for_extraction(
                func_name,
                candidate_path,
                raw_meta,
            )
            if source_func_name != func_name:
                print(f"    [MAP] Symbol build '{func_name}' -> source '{source_func_name}'")
            header_context_root = ""
            if isinstance(raw_meta, dict):
                header_context_root = raw_meta.get("buggy_tree_dir") or raw_meta.get("source_repo_dir") or ""
            cpg_source_root = source_root(candidate_path, header_context_root)
            resolution_hints = _target_resolution_hints(failed_tests_context)
            if isinstance(forced_target, dict) and forced_target.get("target_id"):
                resolution_hints["exact_target"] = forced_target
                print(
                    "    [FL-EXACT-TARGET] "
                    f"{forced_target.get('source_file')}:{forced_target.get('start_line')}-"
                    f"{forced_target.get('end_line')}"
                )
            elif isinstance(forced_target, dict) and forced_target.get("id"):
                resolution_hints["target_candidate_id"] = str(forced_target.get("id"))
            (
                func_code,
                start_idx,
                end_idx,
                resolved_source_func_name,
                replacement_target,
            ) = _resolve_target_for_repair(
                source_code=source_code,
                source_func_name=source_func_name,
                source_language=source_language,
                candidate_path=candidate_path,
                cand_label=cand_label,
                resolution_hints=resolution_hints,
            )
            if resolved_source_func_name and resolved_source_func_name != source_func_name:
                print(f"    [RESOLVE] Target '{source_func_name}' -> '{resolved_source_func_name}'")
                source_func_name = resolved_source_func_name
            if not func_code:
                llm_patch_attempt_index += 1
                if replacement_target.get("status") == "ambiguous":
                    write_replacement_target_artifact(
                        bug_id=bug_id,
                        attempt_index=llm_patch_attempt_index,
                        qualified_name=qualified_name,
                        candidate_relpath=candidate_relpath,
                        replacement_target=replacement_target,
                        status="ambiguous",
                        error=replacement_target.get("error") or "ambiguous_target",
                    )
                    candidate_count = (
                        (replacement_target.get("repair_scope") or {}).get("unit_count") or 0
                    )
                    if _repair_route(repair_objective) == "correctness_repair":
                        print(
                            "    [TARGET-AMBIGUOUS] Có "
                            f"{candidate_count} source candidates; correctness repair dừng target này "
                            "và giữ artifact lỗi, không queue alternative/fallback."
                        )
                    else:
                        print(
                            "    [TARGET-AMBIGUOUS] Có "
                            f"{candidate_count} source candidates; xếp từng source-backed alternative "
                            "vào hàng đợi security APR."
                        )
                        alternatives = list(
                            (replacement_target.get("target_resolution") or {}).get("candidates") or []
                        )
                        new_items = []
                        for alternative in alternatives:
                            target_id = str(alternative.get("id") or "")
                            queue_key = (qualified_name, target_id)
                            if not target_id or queue_key in queued_target_ids:
                                continue
                            queued_target_ids.add(queue_key)
                            new_items.append((qualified_name, score, alternative))
                        pending_funcs[0:0] = new_items
                else:
                    resolution_error = (
                        replacement_target.get("error")
                        or "tree_sitter_target_resolution_failed"
                    )
                    write_replacement_target_artifact(
                        bug_id=bug_id,
                        attempt_index=llm_patch_attempt_index,
                        qualified_name=qualified_name,
                        candidate_relpath=candidate_relpath,
                        replacement_target=replacement_target,
                        status="failed",
                        error=resolution_error,
                    )
                    print(
                        "    [TARGET-ERROR] Tree-sitter không resolve được "
                        f"'{func_name}': {resolution_error}. Đã ghi artifact lỗi; "
                        "không có target fallback."
                    )
                continue

            target_func = qualified_name
            attempted = True

            llm_patch_attempt_index += 1
            if replacement_target.get("status") == "not_found" or not replacement_target.get("replacement_unit"):
                resolution_error = (
                    replacement_target.get("error")
                    or "tree_sitter_replacement_range_resolution_failed"
                )
                write_replacement_target_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    replacement_target=replacement_target,
                    status="failed",
                    error=resolution_error,
                )
                print(
                    "    [SKIP] Tree-sitter không resolve được replacement target "
                    f"cho {source_func_name}: {resolution_error}. Đã ghi artifact lỗi."
                )
                continue
            target_replacement_unit = _target_replacement_unit(replacement_target)
            replacement_start_idx, replacement_end_idx = _target_replacement_range(replacement_target)
            if not target_replacement_unit or replacement_start_idx < 0 or replacement_end_idx < replacement_start_idx:
                write_replacement_target_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    replacement_target=replacement_target,
                    status="failed",
                    error="tree_sitter_replacement_target_contract_incomplete",
                )
                print("    [TARGET-ERROR] Tree-sitter target thiếu source unit/range; đã ghi artifact lỗi.")
                continue
            replacement_target_artifact = write_replacement_target_artifact(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                replacement_target=replacement_target,
            )
            output_contract = _fix_agent_output_contract(
                replacement_target=replacement_target,
                func_name=source_func_name,
                cand_label=cand_label,
            )
            related_code_context = {}
            related_code_context_agent_artifact = {}
            repair_route = _repair_route(repair_objective)
            if (
                repair_route != "correctness_repair"
                and run_branch_related_code_context_agent is not None
            ):
                related_code_context, related_code_context_agent_artifact = run_branch_related_code_context_agent(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    func_name=source_func_name,
                    cand_label=cand_label,
                    func_code=func_code,
                    source_code=source_code,
                    source_path=candidate_path,
                    start_idx=start_idx,
                    end_idx=end_idx,
                    context_root=header_context_root,
                    replacement_target=replacement_target,
                    repair_objective=repair_objective,
                )
            if repair_route == "correctness_repair":
                try:
                    compilation_context = adapter.prepare_compilation_database(
                        source_root=cpg_source_root,
                        source_path=candidate_path,
                        src_relpath=candidate_relpath,
                    )
                except Exception as exc:
                    compilation_context = {
                        "version": 1,
                        "available": False,
                        "database_path": "",
                        "diagnostics": [
                            f"sandbox_compilation_database_exception:{type(exc).__name__}"
                        ],
                    }
                repair_context, repair_context_agent_artifact = run_correctness_repair_planning(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    llm_provider=llm_provider,
                    func_name=source_func_name,
                    cand_label=cand_label,
                    func_code=target_replacement_unit,
                    source_root=cpg_source_root,
                    source_path=candidate_path,
                    failed_tests_context=failed_tests_context,
                    replacement_target=replacement_target,
                    repair_objective=repair_objective,
                    output_contract=output_contract,
                    max_plans=3,
                    compilation_context=compilation_context,
                )
                repair_plans = repair_context.get("plans") or []
                if not repair_plans:
                    errors = ";".join(str(item) for item in (repair_context.get("errors") or [])[-4:])
                    print(
                        "    [SKIP] BehaviorCausalSearchController không sinh được patch portfolio. "
                        f"{errors}"
                    )
                    continue
            else:
                repair_context, repair_context_agent_artifact = run_constraints_agent(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    func_name=source_func_name,
                    func_code=target_replacement_unit,
                    replacement_target=replacement_target,
                    related_code_context=related_code_context,
                    failed_tests_context=failed_tests_context,
                    repair_objective=repair_objective,
                )
                first_hazard = (((repair_context.get("repair_constraints") or {}).get("risk_operations") or [{}])[0])
                if first_hazard:
                    print(
                        "    [RISK-BRIEF] "
                        f"{first_hazard.get('id')} {first_hazard.get('kind')} "
                        f"line={first_hazard.get('line')}"
                    )
                repair_plans = [None]

            for repair_plan in repair_plans:
                if repair_plan:
                    print(
                        f"    [PLAN] {repair_plan.get('id')}: "
                        f"{str(repair_plan.get('edit_intent') or '')[:120]}"
                    )
                fix_kwargs = {
                    "bug_id": bug_id,
                    "attempt_index": llm_patch_attempt_index,
                    "qualified_name": qualified_name,
                    "candidate_relpath": candidate_relpath,
                    "llm_provider": llm_provider,
                    "func_name": source_func_name,
                    "cand_label": cand_label,
                    "func_code": target_replacement_unit,
                    "failed_tests_context": failed_tests_context,
                    "repair_objective": repair_objective,
                }
                if repair_route == "correctness_repair":
                    fix_kwargs["repair_context"] = repair_context
                    fix_kwargs["output_contract"] = output_contract
                    fix_kwargs["repair_plan"] = repair_plan
                else:
                    fix_kwargs["repair_constraints"] = repair_context
                raw_patch, fix_agent_artifact = run_branch_fix_agent(**fix_kwargs)
                if not raw_patch:
                    print("    [ERROR] LLM trả về None. Bỏ qua plan này.")
                    continue

                llm_attempted = True
                candidate_result, plan_success = _evaluate_fix_patch_candidate(
                    bug_id=bug_id,
                    dataset=dataset,
                    initial=initial,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    llm_patch_attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    candidate_path=candidate_path,
                    cand_label=cand_label,
                    cand_base=cand_base,
                    primary_base=primary_base,
                    llm_provider=llm_provider,
                    raw_patch=raw_patch,
                    source_code=source_code,
                    replacement_target=replacement_target,
                    replacement_start_idx=replacement_start_idx,
                    replacement_end_idx=replacement_end_idx,
                    start_idx=start_idx,
                    source_func_name=source_func_name,
                    source_language=source_language,
                    target_replacement_unit=target_replacement_unit,
                    score=score,
                    fail_context_agent_artifact=fail_context_agent_artifact,
                    repair_objective=repair_objective,
                    repair_objective_artifact=repair_objective_artifact,
                    replacement_target_artifact=replacement_target_artifact,
                    related_code_context_agent_artifact=related_code_context_agent_artifact,
                    repair_context_agent_artifact=repair_context_agent_artifact,
                    fix_agent_artifact=fix_agent_artifact,
                    repair_plan=repair_plan,
                )
                if repair_plan:
                    candidate_result["repair_plan"] = {
                        key: repair_plan.get(key)
                        for key in (
                            "id",
                            "source_hypothesis_id",
                            "hypothesis",
                            "target_unit_id",
                            "edit_intent",
                            "behavior_claim",
                            "mechanism_claim",
                            "edit_strategy",
                            "repair_scope",
                            "structured_edits",
                            "must_preserve",
                            "region_contracts",
                            "required_evidence_ids",
                            "required_symbol_actions",
                            "allowed_new_symbols",
                            "forbidden_symbol_actions",
                            "forbidden_symbols",
                            "risk",
                            "confidence",
                        )
                    }
                candidate_results.append(candidate_result)
                if plan_success:
                    if (
                        best_candidate is None
                        or candidate_quality_key(candidate_result) < candidate_quality_key(best_candidate)
                    ):
                        best_candidate = candidate_result
                    # A full validator pass is the terminal condition for this
                    # target. Avoid additional LLM calls and full-suite runs for
                    # the remaining plans.
                    break
            if best_candidate is not None:
                break

        if (
            best_candidate is None
            and candidate_results
            and _repair_route(repair_objective) != "correctness_repair"
        ):
            coordinated_candidate = _evaluate_coordinated_alternative_candidates(
                bug_id=bug_id,
                dataset=dataset,
                initial=initial,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                attempt_index=llm_patch_attempt_index + 1,
                llm_provider=llm_provider,
                candidate_results=candidate_results,
            )
            if coordinated_candidate:
                if is_plausible_status(coordinated_candidate.get("status")):
                    candidate_results.append(coordinated_candidate)
                    best_candidate = coordinated_candidate
                    print(
                        "    [COORDINATED] Atomic multi-target patch passed validation for units: "
                        + ", ".join(coordinated_candidate.get("coordinated_unit_ids") or [])
                    )
                else:
                    print("    [COORDINATED] Atomic multi-target patch was executed but did not improve the oracle.")

        if best_candidate is None and candidate_results:
            best_candidate = min(
                candidate_results,
                key=candidate_quality_key,
            )
            target_func = best_candidate["function"]
            print(
                f"    [BEST] Chọn candidate tốt nhất: {target_func} "
                f"(patch_failed={len(best_candidate['post_failed_tests'])}, "
                f"full_failed={len(best_candidate['full_post_failed_tests'])})"
            )

        fix_agent_best_candidate = best_candidate
        refix_result = None
        refix_selected = False
        if best_candidate and not is_plausible_status(best_candidate.get("status")):
            refix_artifacts = []
            artifact = dict(best_candidate.get("llm_patch_artifact") or {})
            if artifact.get("patched_file_path") or artifact.get("patched_function_path"):
                artifact["_repair_target_file_abs_path"] = best_candidate.get("repair_target_file") or ""
                refix_artifacts.append(artifact)
            if refix_artifacts and bug_record:
                print("    [REFIX] FixAgent chưa success; chạy ReFix trên best failed candidate.")
                refix_result = run_refix_for_failed_artifacts(
                    dataset=dataset,
                    bug=bug_record,
                    artifacts=refix_artifacts,
                    llm_provider=llm_provider,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    excluded_fixed_fail_tests=excluded_fixed_fail_tests,
                    refix_round=1,
                )
                if refix_result:
                    if candidate_is_strictly_better(refix_result, best_candidate):
                        best_candidate = refix_result
                        refix_selected = True
                        print(
                            f"    [REFIX] ReFix tốt hơn FixAgent best: status={refix_result.get('status')} "
                            f"full_status={refix_result.get('real_status')}"
                        )
                    else:
                        print(
                            f"    [REFIX] Giữ FixAgent best vì ReFix không cải thiện: "
                            f"refix_status={refix_result.get('status')} "
                            f"refix_full_status={refix_result.get('real_status')}"
                        )

        if best_candidate:
            if _repair_route(repair_objective) == "correctness_repair":
                _persist_selected_correctness_patch(
                    bug_id=bug_id,
                    candidate=best_candidate,
                    primary_base=primary_base,
                )
            fix_agent_evaluation = (
                extract_evaluation_snapshot(fix_agent_best_candidate)
                if fix_agent_best_candidate
                else {}
            )
            refix_agent_evaluation = (
                extract_evaluation_snapshot(refix_result)
                if refix_result
                else {}
            )
            evaluation_history = []
            if fix_agent_evaluation:
                evaluation_history.append(
                    {
                        "agent": "fix_agent",
                        "artifact": (fix_agent_best_candidate or {}).get("llm_patch_artifact") or {},
                        **fix_agent_evaluation,
                    }
                )
            if refix_agent_evaluation:
                evaluation_history.append(
                    {
                        "agent": "refix_agent",
                        "artifact": (refix_result or {}).get("llm_patch_artifact") or {},
                        **refix_agent_evaluation,
                    }
                )
            fix_agent_candidates = [
                _candidate_trace_record(candidate, agent="fix_agent")
                for candidate in candidate_results
            ]
            fix_agent_best_trace = _candidate_trace_record(
                fix_agent_best_candidate,
                agent="fix_agent",
            )
            refix_agent_result_trace = _candidate_trace_record(
                refix_result,
                agent="refix_agent",
            )
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "repair_objective": repair_objective,
                "repair_objective_artifact": repair_objective_artifact,
                "patched_function": best_candidate.get("patched_function"),
                "patched_file": best_candidate.get("patched_file"),
                "llm_patch_artifact": best_candidate.get("llm_patch_artifact") or {},
                "selected_agent": "refix_agent" if refix_selected else "fix_agent",
                "selected_candidate": _candidate_trace_record(
                    best_candidate,
                    agent="refix_agent" if refix_selected else "fix_agent",
                ),
                "fix_agent_candidates": fix_agent_candidates,
                "fix_agent_best_candidate": fix_agent_best_trace,
                "refix_agent_result": refix_agent_result_trace,
                "fix_agent_evaluation": fix_agent_evaluation,
                "refix_agent_evaluation": refix_agent_evaluation,
                "evaluation_history": evaluation_history,
                "refix_attempted": bool(refix_result),
                "refix_selected": refix_selected,
                "refix_applied": refix_selected,
                "refix_source_artifact": (refix_result or {}).get("refix_source_artifact") or {},
                "repair_target_file": best_candidate.get("repair_target_file"),
                "repair_target_relpath": candidate_relpath_from_buggy_tree(
                    best_candidate.get("repair_target_file") or "",
                    raw_meta,
                ) or best_candidate.get("repair_target_relpath", ""),
                "selected_function": best_candidate.get("function"),
                **extract_evaluation_snapshot(best_candidate),
            }
        else:
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "repair_objective": repair_objective,
                "repair_objective_artifact": repair_objective_artifact,
                "status": "llm_failed" if attempted and not llm_attempted else "skipped",
                "real_status": "llm_failed" if attempted and not llm_attempted else "skipped",
                "validation_error": "",
                **initial["fields"],
                "fixed_fail_excluded_tests": list(initial["excluded"]),
            }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)
