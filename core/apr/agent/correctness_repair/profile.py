from typing import Any, Dict, List


def repair_planning_profile(repair_objective: Dict[str, Any], failure_contract: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "route": "correctness_repair",
        "planning_focus": "observable_behavior",
        "repair_goal": (repair_objective or {}).get("repair_goal") or (failure_contract or {}).get("repair_goal"),
        "patch_shape": [
            "Repair the value-flow, predicate, dispatch, numeric/rounding, formatting, iterator-progress, or state transition that controls the expected-vs-actual mismatch.",
            "Prefer a small semantic edit over a defensive bypass.",
            "Use existing project APIs/macros/types visible in related context.",
        ],
        "step_priorities": [
            "Identify the exact expected behavior and observed behavior.",
            "Select the ranked edit location that controls that observable behavior.",
            "Apply a minimal semantic change to the controlling predicate/value/dispatch/numeric/formatting/state logic.",
            "Preserve valid-input success paths; add error/exception behavior only when the oracle expects it.",
        ],
        "must_preserve": [
            "Expected valid-input behavior must still execute rather than being bypassed by a broad guard.",
            "Existing formatting, iterator-progress, buffer write, and return-value contracts must stay compatible with nearby code.",
        ],
        "forbidden_changes": [
            "Do not add broad defensive guards or error returns for valid-input correctness tests unless failure evidence expects an error.",
            "Do not rewrite unrelated memory/buffer/ownership mechanics unless they directly control the observable mismatch.",
            "Do not invent unseen APIs, macros, flags, enum constants, types, helpers, or error codes.",
        ],
    }


def target_guardrails(repair_objective: Dict[str, Any]) -> List[str]:
    rules = [
        "Correctness route: satisfy the expected-vs-actual behavior directly.",
        "Do not add broad defensive guards or error returns for valid-input tests unless failure evidence expects an error.",
        "Prefer semantic output/return/state, predicate, dispatch, numeric, formatting, or iterator-progress fixes over unrelated safety rewrites.",
    ]
    rules.extend(str(item) for item in (repair_objective or {}).get("target_context_policy") or [])
    return rules


def related_behavioral_contracts(repair_objective: Dict[str, Any]) -> List[dict]:
    return [
        {
            "symbol": "repair_route",
            "kind": "correctness_repair_route",
            "contract": "Prioritize expected/actual observable behavior: output, return, exception, formatting, numeric, iterator-progress, and dispatch semantics.",
            "evidence": (repair_objective or {}).get("route_policy") or [],
        },
        {
            "symbol": "repair_route",
            "kind": "no_unseen_api_or_macro",
            "contract": "For correctness fixes, reuse visible project APIs/macros/types; do not invent new flags, helpers, error codes, or wrappers.",
            "evidence": (repair_objective or {}).get("forbidden_patch_operators") or [],
        },
    ]


def patch_validation_rules() -> List[str]:
    return [
        "Correctness validation: judge the patch by whether expected output/return/exception/state now matches the oracle.",
        "Flag patches that replace a value-flow/predicate/numeric/formatting bug with broad defensive guards or new error returns.",
        "For output iterator, reserve/write, numeric, and formatting changes, check whether the patch preserves existing low-level contracts and idioms.",
    ]


def refix_policy_rules() -> List[str]:
    return [
        "Correctness ReFix: refine the value-flow, predicate, dispatch, numeric, formatting, iterator-progress, or state edit that explains the mismatch.",
        "Do not turn valid-input expected-success tests into error/exception returns unless validation explicitly expects an error.",
        "If the failed patch rewrote unrelated buffer or output mechanics, revert/refine that exact rewrite and preserve useful semantic changes.",
    ]
