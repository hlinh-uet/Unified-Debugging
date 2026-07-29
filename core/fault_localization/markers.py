"""Generic source instrumentation for exact failing-scenario trace windows."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Tuple

from core.program_analysis.source_utils import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)

from .scenario import _is_assertion_name, extract_assertion_scenarios


SCENARIO_MARKER_GENERATION = "targeted_test_ranges_same_line_v2"
SLICE_PROBE_GENERATION = "executed_path_boundaries_v1"


MARKER_DECLARATION_CPP = r"""
#if defined(__GNUC__) || defined(__clang__)
extern "C" void udbg_trace_marker(const char*, const char*)
    __attribute__((weak));
#define UDBG_FL_SCENARIO_MARK(ID) \
  do { if (udbg_trace_marker) udbg_trace_marker("scenario_begin", ID); } while (0)
#else
#define UDBG_FL_SCENARIO_MARK(ID) do { } while (0)
#endif
""".strip()

MARKER_DECLARATION_C = r"""
#if defined(__GNUC__) || defined(__clang__)
extern void udbg_trace_marker(const char*, const char*)
    __attribute__((weak));
#define UDBG_FL_SCENARIO_MARK(ID) \
  do { if (udbg_trace_marker) udbg_trace_marker("scenario_begin", ID); } while (0)
#else
#define UDBG_FL_SCENARIO_MARK(ID) do { } while (0)
#endif
""".strip()
SLICE_DECLARATION_CPP = r"""
#if defined(__GNUC__) || defined(__clang__)
extern "C" void udbg_trace_marker(const char*, const char*)
    __attribute__((weak));
extern "C" void udbg_trace_scalar(const char*, long long)
    __attribute__((weak));
static int udbg_fl_trace_condition(const char*, int)
    __attribute__((no_instrument_function));
static int udbg_fl_trace_condition(const char* id, int value) {
  if (udbg_trace_scalar)
    udbg_trace_scalar(id, value ? 1LL : 0LL);
  return value;
}
#define UDBG_FL_SLICE_MARK(KIND, ID) \
  do { if (udbg_trace_marker) udbg_trace_marker(KIND, ID); } while (0)
#else
#define UDBG_FL_SLICE_MARK(KIND, ID) do { } while (0)
#endif
""".strip()
SLICE_DECLARATION_C = r"""
#if defined(__GNUC__) || defined(__clang__)
extern void udbg_trace_marker(const char*, const char*)
    __attribute__((weak));
extern void udbg_trace_scalar(const char*, long long)
    __attribute__((weak));
static int udbg_fl_trace_condition(const char*, int)
    __attribute__((no_instrument_function));
static int udbg_fl_trace_condition(const char* id, int value) {
  if (udbg_trace_scalar)
    udbg_trace_scalar(id, value ? 1LL : 0LL);
  return value;
}
#define UDBG_FL_SLICE_MARK(KIND, ID) \
  do { if (udbg_trace_marker) udbg_trace_marker(KIND, ID); } while (0)
#else
#define UDBG_FL_SLICE_MARK(KIND, ID) do { } while (0)
#endif
""".strip()


def instrument_assertion_scenarios(
    *,
    source: str,
    source_path: str,
    allowed_byte_ranges: List[Tuple[int, int]] | None = None,
) -> Tuple[str, Dict[str, Any]]:
    """Insert one marker before each assertion's concrete producer region."""
    language = source_language_from_path(source_path)
    scenarios = extract_assertion_scenarios(
        source=source,
        source_path=source_path,
        source_start_line=1,
        test_id="",
    )
    if allowed_byte_ranges is not None:
        ranges = [
            (int(start), int(end))
            for start, end in allowed_byte_ranges
            if int(start) < int(end)
        ]
        scenarios = [
            scenario
            for scenario in scenarios
            if any(
                start <= int(scenario.get("start_byte") or 0) < end
                for start, end in ranges
            )
        ]
    if not scenarios:
        return source, {
            "changed": False,
            "scenario_count": 0,
            "diagnostics": [
                (
                    "no_assertion_scenarios_in_target_ranges"
                    if allowed_byte_ranges is not None
                    else "no_assertion_scenarios"
                )
            ],
        }
    tree, source_bytes = parse_tree(source, language)
    statement_nodes = []
    if tree is not None and source_bytes is not None:
        statement_nodes = [
            node
            for node in walk_nodes(tree.root_node)
            if node.type in {
                "expression_statement",
                "declaration",
                "return_statement",
            }
        ]
    insertions = {}
    records = []
    prepared = []
    for scenario in scenarios:
        assertion_start = int(scenario.get("start_byte") or 0)
        marker_region = _producer_region(
            scenario=scenario,
            assertion_start=assertion_start,
            statement_nodes=statement_nodes,
            source_bytes=source_bytes,
        )
        prepared.append((scenario, assertion_start, marker_region))
    region_counts = Counter(
        int(region.get("start_byte") or 0)
        for _, _, region in prepared
    )
    raw_source = source.encode("utf-8")
    for scenario, assertion_start, marker_region in prepared:
        insertion_start = int(marker_region["start_byte"])
        # A producer shared by several later assertions cannot identify which
        # assertion failed. Keep those markers at their own statement instead
        # of emitting multiple ambiguous markers (and nested wrapper blocks)
        # at the same producer boundary.
        if (
            insertion_start < assertion_start
            and region_counts[insertion_start] > 1
        ):
            marker_region = _statement_region(
                statement_start=assertion_start,
                statement_nodes=statement_nodes,
            )
            insertion_start = int(marker_region["start_byte"])
        marker_id = str(scenario.get("source_marker_id") or "")
        if not marker_id:
            continue
        wraps_statement = bool(marker_region.get("wrap_statement"))
        marker = (
            ("{ " if wraps_statement else "")
            + f'UDBG_FL_SCENARIO_MARK("{marker_id}"); '
        )
        insertions.setdefault(insertion_start, []).append(marker)
        if wraps_statement:
            insertions.setdefault(
                int(marker_region["end_byte"]), []
            ).append(" }")
        records.append({
            "source_marker_id": marker_id,
            "scenario_id": scenario.get("scenario_id"),
            "assertion_line": scenario.get("line"),
            "marker_byte": insertion_start,
            "statement_block_wrapped": wraps_statement,
            "producer_marker_moved_before_assertion": (
                insertion_start < assertion_start
            ),
        })
    if not insertions:
        return source, {
            "changed": False,
            "scenario_count": len(scenarios),
            "diagnostics": ["scenario_marker_insertion_unavailable"],
        }
    instrumented_bytes = raw_source
    for offset in sorted(insertions, reverse=True):
        text = "".join(dict.fromkeys(insertions[offset])).encode("utf-8")
        instrumented_bytes = (
            instrumented_bytes[:offset]
            + text
            + instrumented_bytes[offset:]
        )
    instrumented = instrumented_bytes.decode("utf-8", errors="replace")
    declaration = (
        MARKER_DECLARATION_C
        if language == "c"
        else MARKER_DECLARATION_CPP
    )
    instrumented = (
        declaration
        + "\n"
        + _line_directive(source_path)
        + "\n"
        + instrumented
    )
    return instrumented, {
        "changed": True,
        "scenario_count": len(scenarios),
        "marker_count": len(records),
        "markers": records,
        "diagnostics": [],
    }


def instrument_slice_probes(
    *,
    source: str,
    source_path: str,
    probes: List[Dict[str, Any]],
) -> Tuple[str, Dict[str, Any]]:
    """Instrument bounded branch and control/data boundary sites.

    Branches record their concrete boolean outcome. Argument, return and write
    probes are occurrence boundaries: they deliberately avoid casting unknown
    project types, so instrumentation cannot change ownership or value
    semantics for structs, pointers, or C++ move-only values.
    """
    language = source_language_from_path(source_path)
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return source, {
            "changed": False,
            "installed_probe_ids": [],
            "diagnostics": ["slice_probe_source_ast_unavailable"],
        }
    source_line_offset = _instrumented_source_line_offset(source)
    conditions = []
    functions = []
    boundary_nodes = []
    for node in walk_nodes(tree.root_node):
        if node.type == "function_definition":
            body = node.child_by_field_name("body")
            if body is not None:
                functions.append({
                    "node": node,
                    "body": body,
                    "start_line": int(node.start_point[0]) + 1,
                    "end_line": int(node.end_point[0]) + 1,
                })
        if node.type in {
            "if_statement",
            "conditional_expression",
            "while_statement",
            "for_statement",
        }:
            condition = node.child_by_field_name("condition")
            if condition is not None:
                conditions.append({
                    "node": condition,
                    "line": int(condition.start_point[0]) + 1,
                    "expression": _normalize_expression(
                        node_text(condition, source_bytes)
                    ),
                })
        if node.type in {
            "return_statement",
            "assignment_expression",
            "update_expression",
            "declaration",
        }:
            boundary_nodes.append({
                "node": node,
                "line": int(node.start_point[0]) + 1,
                "expression": _normalize_expression(
                    node_text(node, source_bytes)
                ),
            })

    edits = []
    installed = []
    installed_records = []
    used_conditions = set()
    statement_markers: Dict[Tuple[int, int], Dict[str, Any]] = {}
    entry_markers: Dict[int, List[str]] = {}
    for probe in probes:
        probe_id = str(probe.get("probe_id") or "")
        kind = str(probe.get("kind") or "")
        line = int(probe.get("line") or 0)
        requested = _normalize_expression(
            str(probe.get("expression") or "")
        )
        if not probe_id:
            continue
        installed_here = False
        if kind == "branch_outcome":
            candidates = [
                item for item in conditions
                if (
                    not line
                    or int(item["line"]) in {
                        line,
                        line + source_line_offset,
                    }
                )
            ]
            candidates = _matching_probe_nodes(
                candidates, requested=requested
            )
            if not candidates:
                continue
            item = min(
                candidates,
                key=lambda value: len(value["expression"]),
            )
            node = item["node"]
            identity = (int(node.start_byte), int(node.end_byte))
            if identity in used_conditions:
                continue
            original = node_text(node, source_bytes)
            if ";" in original or re.match(
                r"^\s*(?:auto|const|volatile|struct|class|enum|"
                r"[A-Za-z_][A-Za-z0-9_:<>]*\s+[*&]?\s*[A-Za-z_])"
                r"\s*=",
                original,
            ):
                continue
            edits.append((
                identity[0],
                identity[1],
                (
                    f'(udbg_fl_trace_condition("{probe_id}", !!('
                    + original
                    + ")))"
                ),
            ))
            used_conditions.add(identity)
            installed_here = True
        elif kind == "argument":
            candidates = [
                item for item in functions
                if (
                    not line
                    or int(item["start_line"]) <= line <= int(item["end_line"])
                    or (
                        source_line_offset
                        and int(item["start_line"])
                        <= line + source_line_offset
                        <= int(item["end_line"])
                    )
                )
            ]
            if not candidates:
                continue
            item = min(
                candidates,
                key=lambda value: (
                    int(value["end_line"]) - int(value["start_line"]),
                    int(value["start_line"]),
                ),
            )
            offset = int(item["body"].start_byte) + 1
            entry_markers.setdefault(offset, []).append(
                f'UDBG_FL_SLICE_MARK("slice_argument", "{probe_id}");'
            )
            installed_here = True
        elif kind in {"return_value", "output_write"}:
            allowed_types = (
                {"return_statement"}
                if kind == "return_value"
                else {
                    "assignment_expression",
                    "update_expression",
                    "declaration",
                }
            )
            candidates = [
                item for item in boundary_nodes
                if item["node"].type in allowed_types
                and (
                    not line
                    or int(item["line"]) in {
                        line,
                        line + source_line_offset,
                    }
                )
            ]
            candidates = _matching_probe_nodes(
                candidates, requested=requested
            )
            if not candidates:
                continue
            item = min(
                candidates,
                key=lambda value: len(value["expression"]),
            )
            statement = _containing_executable_statement(item["node"])
            if statement is None:
                continue
            identity = (
                int(statement.start_byte),
                int(statement.end_byte),
            )
            record = statement_markers.setdefault(identity, {
                "node": statement,
                "markers": [],
            })
            marker_kind = (
                "slice_return"
                if kind == "return_value"
                else "slice_write"
            )
            record["markers"].append(
                f'UDBG_FL_SLICE_MARK("{marker_kind}", "{probe_id}");'
            )
            installed_here = True
        if not installed_here:
            continue
        installed.append(probe_id)
        installed_records.append({
            "probe_id": probe_id,
            "kind": kind,
            "line": line,
        })

    for offset, markers in entry_markers.items():
        edits.append((
            offset,
            offset,
            " " + " ".join(dict.fromkeys(markers)) + " ",
        ))
    for (start, end), record in statement_markers.items():
        statement = record["node"]
        marker_text = " ".join(dict.fromkeys(record["markers"]))
        original = node_text(statement, source_bytes)
        parent_type = (
            str(statement.parent.type)
            if statement.parent is not None else ""
        )
        if parent_type in {
            "compound_statement",
            "translation_unit",
            "case_statement",
        }:
            edits.append((start, start, marker_text + " "))
        else:
            edits.append((
                start,
                end,
                "{ " + marker_text + " " + original + " }",
            ))
    if not edits:
        return source, {
            "changed": False,
            "installed_probe_ids": [],
            "diagnostics": ["slice_probe_sites_unresolved"],
        }
    instrumented_bytes = source.encode("utf-8")
    for start, end, replacement in sorted(
        edits,
        key=lambda item: (item[0], item[1]),
        reverse=True,
    ):
        instrumented_bytes = (
            instrumented_bytes[:start]
            + replacement.encode("utf-8")
            + instrumented_bytes[end:]
        )
    declaration = (
        SLICE_DECLARATION_C
        if language == "c"
        else SLICE_DECLARATION_CPP
    )
    instrumented = instrumented_bytes.decode(
        "utf-8", errors="replace"
    )
    return (
        declaration
        + "\n"
        + _line_directive(source_path)
        + "\n"
        + instrumented
    ), {
        "changed": True,
        "generation": SLICE_PROBE_GENERATION,
        "installed_probe_ids": list(dict.fromkeys(installed)),
        "installed_probes": installed_records,
        "diagnostics": [],
    }


def _matching_probe_nodes(
    candidates: List[Dict[str, Any]], *, requested: str
) -> List[Dict[str, Any]]:
    if not requested:
        return candidates
    exact = [
        item
        for item in candidates
        if item["expression"] == requested
        or item["expression"] in requested
        or requested in item["expression"]
    ]
    return exact or candidates


def _instrumented_source_line_offset(source: str) -> int:
    """Return the physical line prefix added by an earlier marker pass."""
    match = re.search(
        r"(?m)^[ \t]*#line[ \t]+1[ \t]+[\"<][^\"\n>]+[\">][ \t]*$",
        str(source or ""),
    )
    if not match:
        return 0
    return str(source[:match.start()]).count("\n") + 1


def _containing_executable_statement(node: Any) -> Any:
    current = node
    while current is not None:
        if current.type in {
            "expression_statement",
            "declaration",
            "return_statement",
        }:
            return current
        current = current.parent
    return None


def _producer_region(
    *,
    scenario: Dict[str, Any],
    assertion_start: int,
    statement_nodes: List[Any],
    source_bytes: bytes | None,
) -> Dict[str, Any]:
    """Return the statement boundary that starts the concrete producer.

    A separate marker statement is safe inside a compound body.  For a direct
    ``if``/``else``/loop body without braces, the selected statement is wrapped
    in a block so instrumentation cannot make the assertion unconditional or
    detach an ``else``.
    """
    assertion_region = _statement_region(
        statement_start=assertion_start,
        statement_nodes=statement_nodes,
    )
    selected = assertion_region.get("node")
    if source_bytes is None:
        return {
            "start_byte": assertion_start,
            "end_byte": assertion_start,
            "wrap_statement": False,
        }
    actual = str(scenario.get("actual_expression") or "")
    identifiers = {
        value
        for value in re.findall(
            r"\b[A-Za-z_][A-Za-z0-9_]*\b", actual
        )
        if value not in {"true", "false", "nullptr", "NULL"}
    }
    if identifiers:
        assertion_line = int(scenario.get("line") or 0)
        candidates = []
        for node in statement_nodes:
            end = int(node.end_byte)
            if end > assertion_start:
                continue
            line = int(node.start_point[0]) + 1
            if assertion_line and assertion_line - line > 32:
                continue
            text = node_text(node, source_bytes)
            if not any(
                re.search(rf"\b{re.escape(identifier)}\b", text)
                for identifier in identifiers
            ):
                continue
            if not _contains_non_control_call(node, source_bytes):
                continue
            if _contains_assertion_call(node, source_bytes):
                continue
            candidates.append((
                assertion_start - end,
                -int(node.start_byte),
                node,
            ))
        if candidates:
            selected = min(
                candidates, key=lambda item: (item[0], item[1])
            )[2]
    if selected is None:
        return {
            "start_byte": assertion_start,
            "end_byte": assertion_start,
            "wrap_statement": False,
        }
    parent_type = (
        str(selected.parent.type)
        if selected.parent is not None else ""
    )
    return {
        "start_byte": int(selected.start_byte),
        "end_byte": int(selected.end_byte),
        "wrap_statement": parent_type not in {
            "compound_statement",
            "translation_unit",
            "case_statement",
        },
    }


def _statement_region(
    *,
    statement_start: int,
    statement_nodes: List[Any],
) -> Dict[str, Any]:
    selected = next(
        (
            node for node in statement_nodes
            if int(node.start_byte) == int(statement_start)
        ),
        None,
    )
    if selected is None:
        return {
            "start_byte": int(statement_start),
            "end_byte": int(statement_start),
            "wrap_statement": False,
            "node": None,
        }
    parent_type = (
        str(selected.parent.type)
        if selected.parent is not None else ""
    )
    return {
        "start_byte": int(selected.start_byte),
        "end_byte": int(selected.end_byte),
        "wrap_statement": parent_type not in {
            "compound_statement",
            "translation_unit",
            "case_statement",
        },
        "node": selected,
    }


def _contains_non_control_call(node: Any, source_bytes: bytes) -> bool:
    for child in walk_nodes(node):
        if child.type != "call_expression":
            continue
        function = child.child_by_field_name("function")
        name = (
            node_text(function, source_bytes).strip()
            if function is not None else ""
        )
        leaf = name.rsplit("::", 1)[-1].lower()
        if leaf and leaf not in {
            "if", "for", "while", "switch", "sizeof",
        } and not leaf.startswith(("expect", "assert", "check", "require")):
            return True
    return False


def _contains_assertion_call(node: Any, source_bytes: bytes) -> bool:
    for child in walk_nodes(node):
        if child.type != "call_expression":
            continue
        function = child.child_by_field_name("function")
        name = (
            node_text(function, source_bytes).strip()
            if function is not None else ""
        )
        if _is_assertion_name(name):
            return True
    return False


def _normalize_expression(value: str) -> str:
    text = re.sub(r"\s+", "", str(value or ""))
    while text.startswith("(") and text.endswith(")"):
        text = text[1:-1]
    return text.rstrip(";")


def _line_directive(source_path: str) -> str:
    escaped = str(source_path or "").replace("\\", "\\\\").replace(
        '"', '\\"'
    )
    return f'#line 1 "{escaped}"'
