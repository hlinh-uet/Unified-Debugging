from typing import Any, Dict, List


def repair_planning_profile(repair_objective: Dict[str, Any], failure_contract: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "route": "security_repair",
        "planning_focus": "unsafe_runtime_path",
        "repair_goal": (repair_objective or {}).get("repair_goal") or (failure_contract or {}).get("repair_goal"),
        "patch_shape": [
            "Repair the nearest unsafe pointer/index/allocation/lifetime/cleanup behavior or the guard/size flow that feeds it.",
            "Fail closed only for invalid or malformed input paths supported by evidence.",
            "Preserve valid-path behavior and existing cleanup/resource conventions.",
        ],
        "step_priorities": [
            "Identify the unsafe sink or unsafe transition on the failing path.",
            "Select the ranked edit location that guards, feeds, or performs that unsafe behavior.",
            "Patch the nearest guard, bounds/length calculation, allocation size, lifetime transition, or cleanup/error path.",
            "Verify the unsafe path is no longer reachable while valid paths keep their original semantics.",
        ],
        "must_preserve": [
            "Valid-path observable behavior and resource cleanup conventions must remain intact.",
            "Existing ownership, lifetime, and error-path conventions must not be weakened.",
        ],
        "forbidden_changes": [
            "Do not produce output-only, logging-only, formatting-only, or cosmetic patches while the unsafe path remains reachable.",
            "Do not delete cleanup/error handling unconditionally.",
            "Do not invent unseen validation helpers, macros, enum constants, types, fields, or error codes.",
        ],
    }


def target_guardrails(repair_objective: Dict[str, Any]) -> List[str]:
    rules = [
        "Security route: the patch must guard or remove the unsafe memory/pointer/index/allocation/lifetime behavior.",
        "Do not accept output-only, logging-only, or formatting-only changes that leave the unsafe sink reachable.",
        "Prefer the nearest guard, size/index calculation, allocation-size fix, lifetime fix, or cleanup/error-path refinement.",
    ]
    rules.extend(str(item) for item in (repair_objective or {}).get("target_context_policy") or [])
    return rules


def related_behavioral_contracts(repair_objective: Dict[str, Any]) -> List[dict]:
    return [
        {
            "symbol": "repair_route",
            "kind": "security_repair_route",
            "contract": "Prioritize unsafe pointer/index/allocation/lifetime sinks and existing validation/cleanup conventions.",
            "evidence": (repair_objective or {}).get("route_policy") or [],
        },
        {
            "symbol": "repair_route",
            "kind": "security_forbidden_patch_shape",
            "contract": "Do not satisfy validation by changing only output text while leaving a memory-safety sink reachable.",
            "evidence": (repair_objective or {}).get("forbidden_patch_operators") or [],
        },
    ]


def patch_validation_rules() -> List[str]:
    return [
        "Security validation: judge the patch by whether the unsafe sink is no longer reachable on the failing path.",
        "Flag output-only, logging-only, or cosmetic patches that leave the unsafe memory/pointer/index/allocation/lifetime behavior reachable.",
        "Check that valid-path behavior and cleanup/error conventions are preserved while invalid paths fail closed.",
    ]


def refix_policy_rules() -> List[str]:
    return [
        "Security ReFix: refine the nearest guard, size/index/allocation calculation, lifetime transition, or cleanup/error path for the unsafe sink.",
        "Do not replace a real safety fix with an output-only or formatting-only change.",
        "Preserve cleanup/resource-release conventions; do not delete error handling unconditionally.",
    ]
