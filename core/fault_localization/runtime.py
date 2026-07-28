"""Build and run regression failures with ordered function instrumentation."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import re
import shlex
import subprocess
import tempfile
import textwrap
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from data_loaders.sandbox_adapter import Defects4CAdapter
from .artifacts import atomic_write_gzip_json
from .markers import (
    SCENARIO_MARKER_GENERATION,
    instrument_assertion_scenarios,
    instrument_branch_probes,
)


TRACE_SCHEMA = "unified_debugging.runtime_trace.v3"
SUPPORTED_TRACE_SCHEMAS = {
    TRACE_SCHEMA,
    "unified_debugging.runtime_trace.v2",
}
TRACE_MAX_EVENTS = 300_000
PERSISTED_EVENT_LIMIT = 8_000
FULL_RUNTIME_CACHE_FILENAME = "runtime_evidence.full.json.gz"
RUNTIME_CACHE_FILENAME = "runtime_evidence.json"
TRACE_RUNTIME_SOURCE = textwrap.dedent(
    r"""
    #define _GNU_SOURCE
    #include <dlfcn.h>
    #include <fcntl.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <sys/syscall.h>
    #include <sys/types.h>
    #include <unistd.h>

    #define NOINST __attribute__((no_instrument_function))

    static int trace_fd = -1;
    static unsigned long trace_events = 0;
    static unsigned long trace_limit = 300000;
    static __thread unsigned trace_depth = 0;
    static __thread int resolving_throw = 0;

    static void trace_init(void) NOINST;
    static void trace_fini(void) NOINST;
    static void trace_write(char event, void *fn, void *site, unsigned depth) NOINST;
    static void trace_write_marker(
        const char *kind, const char *id, unsigned depth) NOINST;
    static void trace_write_scalar(
        const char *id, long long value, unsigned depth) NOINST;

    static void trace_init(void) {
      const char *path = getenv("UDBG_TRACE_FILE");
      const char *limit = getenv("UDBG_TRACE_MAX_EVENTS");
      if (limit && *limit) {
        unsigned long value = strtoul(limit, NULL, 10);
        if (value > 0) trace_limit = value;
      }
      if (path && *path) {
        trace_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
      }
    }

    static void trace_fini(void) {
      if (trace_fd >= 0) close(trace_fd);
      trace_fd = -1;
    }

    __attribute__((constructor, no_instrument_function))
    static void trace_ctor(void) { trace_init(); }

    __attribute__((destructor, no_instrument_function))
    static void trace_dtor(void) { trace_fini(); }

    static void trace_write(char event, void *fn, void *site, unsigned depth) {
      if (trace_fd < 0) return;
      unsigned long index = __atomic_fetch_add(&trace_events, 1, __ATOMIC_RELAXED);
      if (index >= trace_limit) return;

      Dl_info info;
      Dl_info site_info;
      memset(&info, 0, sizeof(info));
      memset(&site_info, 0, sizeof(site_info));
      const char *module = "";
      const char *symbol = "";
      const char *site_module = "";
      const char *site_symbol = "";
      uintptr_t base = 0;
      uintptr_t site_base = 0;
      if (dladdr(fn, &info)) {
        module = info.dli_fname ? info.dli_fname : "";
        symbol = info.dli_sname ? info.dli_sname : "";
        base = (uintptr_t)info.dli_fbase;
      }
      if (site && dladdr(site, &site_info)) {
        site_module = site_info.dli_fname ? site_info.dli_fname : "";
        site_symbol = site_info.dli_sname ? site_info.dli_sname : "";
        site_base = (uintptr_t)site_info.dli_fbase;
      }
      uintptr_t address = (uintptr_t)fn;
      uintptr_t offset = base && address >= base ? address - base : address;
      uintptr_t site_address = (uintptr_t)site;
      uintptr_t site_offset =
          site_base && site_address >= site_base
              ? site_address - site_base
              : site_address;
      char line[4096];
      int length = snprintf(
          line, sizeof(line),
          "%c\t%ld\t%ld\t%u\t%lx\t%lx\t%lx\t%s\t%s\t%lx\t%s\t%s\n",
          event,
          (long)getpid(),
          (long)syscall(SYS_gettid),
          depth,
          (unsigned long)address,
          (unsigned long)offset,
          (unsigned long)site_address,
          module,
          symbol,
          (unsigned long)site_offset,
          site_module,
          site_symbol);
      if (length > 0) {
        size_t count = (size_t)length < sizeof(line) ? (size_t)length : sizeof(line) - 1;
        (void)write(trace_fd, line, count);
      }
    }

    static void trace_write_marker(
        const char *kind, const char *id, unsigned depth) {
      if (trace_fd < 0) return;
      unsigned long index = __atomic_fetch_add(&trace_events, 1, __ATOMIC_RELAXED);
      if (index >= trace_limit) return;
      char line[1024];
      int length = snprintf(
          line, sizeof(line), "M\t%ld\t%ld\t%u\t%s\t%s\n",
          (long)getpid(),
          (long)syscall(SYS_gettid),
          depth,
          kind ? kind : "",
          id ? id : "");
      if (length > 0) {
        size_t count =
            (size_t)length < sizeof(line) ? (size_t)length : sizeof(line) - 1;
        (void)write(trace_fd, line, count);
      }
    }

    static void trace_write_scalar(
        const char *id, long long value, unsigned depth) {
      if (trace_fd < 0) return;
      unsigned long index = __atomic_fetch_add(&trace_events, 1, __ATOMIC_RELAXED);
      if (index >= trace_limit) return;
      char line[1024];
      int length = snprintf(
          line, sizeof(line), "V\t%ld\t%ld\t%u\t%s\t%lld\n",
          (long)getpid(),
          (long)syscall(SYS_gettid),
          depth,
          id ? id : "",
          value);
      if (length > 0) {
        size_t count =
            (size_t)length < sizeof(line) ? (size_t)length : sizeof(line) - 1;
        (void)write(trace_fd, line, count);
      }
    }

    void udbg_trace_marker(const char *kind, const char *id)
        __attribute__((no_instrument_function, visibility("default")));

    void udbg_trace_marker(const char *kind, const char *id) {
      trace_write_marker(kind, id, trace_depth);
    }

    void udbg_trace_scalar(const char *id, long long value)
        __attribute__((no_instrument_function, visibility("default")));

    void udbg_trace_scalar(const char *id, long long value) {
      trace_write_scalar(id, value, trace_depth);
    }

    void __cyg_profile_func_enter(void *fn, void *site)
        __attribute__((no_instrument_function));
    void __cyg_profile_func_exit(void *fn, void *site)
        __attribute__((no_instrument_function));

    void __cyg_profile_func_enter(void *fn, void *site) {
      trace_write('E', fn, site, trace_depth);
      trace_depth++;
    }

    void __cyg_profile_func_exit(void *fn, void *site) {
      if (trace_depth > 0) trace_depth--;
      trace_write('X', fn, site, trace_depth);
    }

    /*
     * Record C++ exception provenance without depending on project types.
     * The event points at the concrete throw callsite.  It is observational:
     * ownership and the original ABI call are passed through unchanged.
     */
    typedef void (*udbg_cxa_throw_fn)(
        void *, void *, void (*)(void *));

    void __cxa_throw(void *object, void *type_info, void (*destructor)(void *))
        __attribute__((no_instrument_function, noreturn));

    void __cxa_throw(void *object, void *type_info, void (*destructor)(void *)) {
      void *site = __builtin_return_address(0);
      if (!resolving_throw) {
        resolving_throw = 1;
        trace_write('T', site, site, trace_depth);
      }
      udbg_cxa_throw_fn original =
          (udbg_cxa_throw_fn)dlsym(RTLD_NEXT, "__cxa_throw");
      resolving_throw = 0;
      if (original) {
        original(object, type_info, destructor);
      }
      _exit(127);
    }
    """
).lstrip()


def collect_regression_runtime_evidence(
    bug: Any,
    *,
    artifact_dir: str = "",
    compile_timeout: int = 1800,
    test_timeout: int = 180,
) -> Dict[str, Any]:
    """Trace only tests that fail on buggy and pass on fixed."""
    regression_ids = [
        str(test.get("test_id") or "").strip()
        for test in getattr(bug, "tests", None) or []
        if _is_regression_failure(test) and str(test.get("test_id") or "").strip()
    ]
    result = {
        "schema": TRACE_SCHEMA,
        "engine": "gcc_clang_finstrument_functions",
        "fresh_execution": False,
        "regression_test_ids": regression_ids,
        "tests": [],
        "functions": {},
        "dynamic_edges": [],
        "diagnostics": [],
        "cache_identity": _runtime_cache_identity(
            bug, regression_ids=regression_ids
        ),
    }
    if not regression_ids:
        result["diagnostics"].append("no_regression_failed_tests")
        return result

    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    required = (
        "container_repo_dir", "commit_after", "commit_before",
        "compile_cmd", "test_cmd_template",
    )
    missing = [key for key in required if not str(raw.get(key) or "").strip()]
    if missing:
        result["diagnostics"].append(
            "runtime_metadata_missing:" + ",".join(missing)
        )
        return result

    data_folder = str(raw.get("data_folder") or raw.get("metadata_slug") or "")
    adapter = Defects4CAdapter(str(bug.bug_id), data_folder=data_folder or None)
    container = adapter._select_defects4c_container(raw)
    if not container:
        result["diagnostics"].append("runtime_container_not_running")
        return result

    container_repo = str(raw["container_repo_dir"]).rstrip("/")
    src_files = adapter._phase_a_src_files(raw)
    prepared = adapter._prepare_generic_workspace(
        container=container,
        container_repo=container_repo,
        commit_after=str(raw["commit_after"]),
        commit_before=str(raw["commit_before"]),
        src_files=src_files,
        clean=True,
    )
    if not prepared:
        result["diagnostics"].append("runtime_workspace_prepare_failed")
        adapter._reset_generic_workspace(container, container_repo)
        return result

    trace_id = hashlib.sha256(
        f"{bug.bug_id}:{os.getpid()}".encode("utf-8")
    ).hexdigest()[:16]
    container_trace_root = f"/tmp/udbg_trace_{trace_id}"
    host_artifact_dir = os.path.abspath(
        artifact_dir or os.path.join(tempfile.gettempdir(), "udbg_runtime_traces")
    )
    os.makedirs(host_artifact_dir, exist_ok=True)
    try:
        compatibility = adapter._apply_known_build_compatibility_patches(
            container=container,
            container_repo=container_repo,
            bug_meta=raw,
        )
        if compatibility is None:
            result["diagnostics"].append("runtime_build_compat_patch_failed")
            return result
        result["build_compatibility_patches"] = list(compatibility)

        setup = _install_trace_toolchain(
            container=container,
            container_trace_root=container_trace_root,
        )
        if not setup.get("available"):
            result["diagnostics"].extend(setup.get("diagnostics") or [])
            return result
        marker_instrumentation = _install_scenario_markers(
            container=container,
            container_repo=container_repo,
            raw=raw,
            allowed_ranges_by_source=_failing_test_source_ranges(
                bug=bug,
                raw=raw,
            ),
        )
        result["scenario_marker_instrumentation"] = marker_instrumentation
        result["diagnostics"].extend(
            marker_instrumentation.get("diagnostics") or []
        )

        template = str(raw.get("test_cmd_template") or "").strip()
        helper = adapter._extract_metadata_helper_path(template)
        if helper:
            adapter._ensure_metadata_test_helper(
                container=container,
                container_repo=container_repo,
                bug_meta=raw,
                helper_path=helper,
            )

        compile_log = os.path.join(host_artifact_dir, "compile.log")
        compile_result = _run_trace_build(
            container=container,
            container_repo=container_repo,
            compile_cmd=str(raw["compile_cmd"]),
            wrapper_bin=str(setup["wrapper_bin"]),
            timeout=compile_timeout,
        )
        _write_text(compile_log, compile_result.get("output") or "")
        result["compile"] = {
            "returncode": compile_result.get("returncode"),
            "artifact": compile_log,
            "instrumentation": [
                "-g",
                "-O0",
                "-finstrument-functions",
                "-fno-omit-frame-pointer",
                "-Wl,--export-dynamic",
            ],
            "legacy_coverage_flags_removed": True,
        }
        if compile_result.get("returncode") != 0:
            result["diagnostics"].append("runtime_trace_build_failed")
            return result
        compilation_database = _copy_compilation_database(
            container=container,
            container_repo=container_repo,
            host_artifact_dir=host_artifact_dir,
            host_source_root=str(raw.get("buggy_tree_dir") or ""),
        )
        result["compile"]["compilation_database"] = compilation_database
        if not compilation_database:
            result["diagnostics"].append(
                "runtime_compilation_database_unavailable"
            )

        all_functions: Dict[str, Dict[str, Any]] = {}
        all_edges = Counter()
        all_callsites = Counter()
        all_exception_events = []
        all_value_observations = []
        for test_id in regression_ids:
            test_result = _run_one_traced_test(
                container=container,
                container_repo=container_repo,
                container_trace_root=container_trace_root,
                trace_library=str(setup["trace_library"]),
                test_template=template,
                test_id=test_id,
                host_artifact_dir=host_artifact_dir,
                timeout=test_timeout,
            )
            result["tests"].append(test_result)
            if not test_result.get("failed_as_expected"):
                result["diagnostics"].append(
                    f"regression_test_did_not_reproduce:{test_id}"
                )
                continue
            for key, record in (test_result.get("functions") or {}).items():
                aggregate = all_functions.setdefault(key, {
                    "key": key,
                    "function": record.get("function"),
                    "source_path": record.get("source_path"),
                    "source_line": record.get("source_line"),
                    "test_ids": [],
                    "enter_count": 0,
                    "active_at_failure_count": 0,
                    "max_depth": 0,
                    "max_event_span": 0,
                    "best_reverse_distance": None,
                    "invocation_ids": [],
                    "callsite_ids": [],
                })
                aggregate["test_ids"].append(test_id)
                aggregate["enter_count"] += int(record.get("enter_count") or 0)
                aggregate["active_at_failure_count"] += int(
                    bool(record.get("active_at_failure"))
                )
                aggregate["max_depth"] = max(
                    int(aggregate["max_depth"]),
                    int(record.get("max_depth") or 0),
                )
                aggregate["max_event_span"] = max(
                    int(aggregate["max_event_span"]),
                    int(record.get("max_event_span") or 0),
                )
                distance = record.get("reverse_distance")
                if distance is not None and (
                    aggregate["best_reverse_distance"] is None
                    or int(distance) < int(aggregate["best_reverse_distance"])
                ):
                    aggregate["best_reverse_distance"] = int(distance)
                for invocation_id in record.get("invocation_ids") or []:
                    if invocation_id not in aggregate["invocation_ids"]:
                        aggregate["invocation_ids"].append(invocation_id)
                for callsite_id in record.get("callsite_ids") or []:
                    if callsite_id not in aggregate["callsite_ids"]:
                        aggregate["callsite_ids"].append(callsite_id)
            for edge in test_result.get("dynamic_edges") or []:
                pair = (str(edge.get("caller") or ""), str(edge.get("callee") or ""))
                if pair[0] and pair[1]:
                    all_edges[pair] += int(edge.get("count") or 1)
            for callsite in test_result.get("dynamic_callsites") or []:
                identity = (
                    str(callsite.get("caller") or ""),
                    str(callsite.get("callee") or ""),
                    str(callsite.get("callsite_id") or ""),
                    str(callsite.get("source_path") or ""),
                    int(callsite.get("source_line") or 0),
                )
                if identity[0] and identity[1]:
                    all_callsites[identity] += int(
                        callsite.get("count") or 1
                    )
            for event in test_result.get("exception_events") or []:
                all_exception_events.append({
                    **event,
                    "test_id": test_id,
                })
            for observation in test_result.get("value_observations") or []:
                all_value_observations.append({
                    **observation,
                    "test_id": test_id,
                })

        for record in all_functions.values():
            record["test_ids"] = sorted(set(record["test_ids"]))
        result["functions"] = all_functions
        result["dynamic_edges"] = [
            {"caller": caller, "callee": callee, "count": count}
            for (caller, callee), count in all_edges.most_common()
        ]
        result["dynamic_callsites"] = [
            {
                "caller": caller,
                "callee": callee,
                "callsite_id": callsite_id,
                "source_path": source_path,
                "source_line": source_line,
                "count": count,
            }
            for (
                caller,
                callee,
                callsite_id,
                source_path,
                source_line,
            ), count in all_callsites.most_common()
        ]
        result["exception_events"] = all_exception_events
        result["value_observations"] = all_value_observations
        result["fresh_execution"] = bool(regression_ids) and (
            len(result["tests"]) == len(regression_ids)
            and all(
                test.get("failed_as_expected")
                and test.get("trace_event_count", 0) > 0
                for test in result["tests"]
            )
        )
        if not result["fresh_execution"]:
            result["diagnostics"].append(
                "runtime_trace_regression_set_incomplete"
            )
        return result
    except Exception as exc:
        result["diagnostics"].append(
            f"runtime_trace_exception:{type(exc).__name__}:{exc}"
        )
        return result
    finally:
        _docker_exec(
            container,
            f"rm -rf -- {shlex.quote(container_trace_root)}",
            timeout=60,
        )
        adapter._reset_generic_workspace(container, container_repo)


def collect_targeted_probe_runtime_evidence(
    bug: Any,
    *,
    probe_plan: Dict[str, Any],
    artifact_dir: str = "",
    compile_timeout: int = 1800,
    test_timeout: int = 180,
) -> Dict[str, Any]:
    """Second pass: observe selected branch outcomes on the failing execution."""
    probes = [
        item
        for item in probe_plan.get("targeted_probes") or []
        if isinstance(item, dict)
        and item.get("kind") == "branch_outcome"
        and str(item.get("probe_id") or "")
    ]
    identity = _targeted_probe_identity(
        bug=bug,
        probes=probes,
        scenario_marker_id=str(
            probe_plan.get("source_marker_id") or ""
        ),
    )
    cache_path = os.path.join(
        os.path.abspath(artifact_dir),
        "targeted_probe_runtime.full.json.gz",
    ) if artifact_dir else ""
    if cache_path and os.path.isfile(cache_path):
        try:
            with gzip.open(
                cache_path, "rt", encoding="utf-8"
            ) as stream:
                cached = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError):
            cached = None
        if (
            isinstance(cached, dict)
            and cached.get("identity") == identity
            and cached.get("fresh_execution")
        ):
            cached["cache"] = {"hit": True, "source": cache_path}
            return cached
    result = {
        "schema": "unified_debugging.targeted_probe_runtime.v1",
        "identity": identity,
        "scenario_id": probe_plan.get("scenario_id"),
        "source_marker_id": probe_plan.get("source_marker_id"),
        "fresh_execution": False,
        "probes": probes,
        "tests": [],
        "value_observations": [],
        "diagnostics": [],
        "ground_truth_used": False,
        "cache": {"hit": False, "source": cache_path},
    }
    if not probes:
        result["diagnostics"].append("no_targeted_branch_probes")
        return result
    regression_ids = [
        str(test.get("test_id") or "").strip()
        for test in getattr(bug, "tests", None) or []
        if _is_regression_failure(test)
        and str(test.get("test_id") or "").strip()
    ]
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    required = (
        "container_repo_dir", "commit_after", "commit_before",
        "compile_cmd", "test_cmd_template",
    )
    missing = [key for key in required if not str(raw.get(key) or "").strip()]
    if missing:
        result["diagnostics"].append(
            "targeted_probe_metadata_missing:" + ",".join(missing)
        )
        return result
    data_folder = str(raw.get("data_folder") or raw.get("metadata_slug") or "")
    adapter = Defects4CAdapter(
        str(bug.bug_id), data_folder=data_folder or None
    )
    container = adapter._select_defects4c_container(raw)
    if not container:
        result["diagnostics"].append(
            "targeted_probe_container_not_running"
        )
        return result
    container_repo = str(raw["container_repo_dir"]).rstrip("/")
    prepared = adapter._prepare_generic_workspace(
        container=container,
        container_repo=container_repo,
        commit_after=str(raw["commit_after"]),
        commit_before=str(raw["commit_before"]),
        src_files=adapter._phase_a_src_files(raw),
        clean=True,
    )
    if not prepared:
        result["diagnostics"].append(
            "targeted_probe_workspace_prepare_failed"
        )
        adapter._reset_generic_workspace(container, container_repo)
        return result
    trace_id = hashlib.sha256(
        f"probe:{bug.bug_id}:{os.getpid()}".encode("utf-8")
    ).hexdigest()[:16]
    container_trace_root = f"/tmp/udbg_probe_{trace_id}"
    host_artifact_dir = os.path.abspath(
        artifact_dir or os.path.join(
            tempfile.gettempdir(), "udbg_targeted_probes"
        )
    )
    os.makedirs(host_artifact_dir, exist_ok=True)
    try:
        compatibility = adapter._apply_known_build_compatibility_patches(
            container=container,
            container_repo=container_repo,
            bug_meta=raw,
        )
        if compatibility is None:
            result["diagnostics"].append(
                "targeted_probe_build_compat_patch_failed"
            )
            return result
        setup = _install_trace_toolchain(
            container=container,
            container_trace_root=container_trace_root,
        )
        if not setup.get("available"):
            result["diagnostics"].extend(
                setup.get("diagnostics") or []
            )
            return result
        marker_audit = _install_scenario_markers(
            container=container,
            container_repo=container_repo,
            raw=raw,
            allowed_ranges_by_source=_failing_test_source_ranges(
                bug=bug,
                raw=raw,
            ),
        )
        result["scenario_marker_instrumentation"] = marker_audit
        branch_audit = _install_targeted_branch_probes(
            container=container,
            container_repo=container_repo,
            raw=raw,
            probes=probes,
        )
        result["branch_probe_instrumentation"] = branch_audit
        result["diagnostics"].extend(
            branch_audit.get("diagnostics") or []
        )
        installed = set(
            branch_audit.get("installed_probe_ids") or []
        )
        if not installed:
            result["diagnostics"].append(
                "targeted_probe_no_branches_instrumented"
            )
            return result
        compile_result = _run_trace_build(
            container=container,
            container_repo=container_repo,
            compile_cmd=str(raw["compile_cmd"]),
            wrapper_bin=str(setup["wrapper_bin"]),
            timeout=compile_timeout,
        )
        result["compile"] = {
            "returncode": compile_result.get("returncode"),
            "output_tail": str(
                compile_result.get("output") or ""
            )[-4000:],
        }
        if compile_result.get("returncode") != 0:
            result["diagnostics"].append(
                "targeted_probe_build_failed"
            )
            return result
        template = str(raw.get("test_cmd_template") or "").strip()
        for test_id in regression_ids:
            test_result = _run_one_traced_test(
                container=container,
                container_repo=container_repo,
                container_trace_root=container_trace_root,
                trace_library=str(setup["trace_library"]),
                test_template=template,
                test_id=test_id,
                host_artifact_dir=host_artifact_dir,
                timeout=test_timeout,
            )
            compact_test = {
                key: value
                for key, value in test_result.items()
                if key not in {"events", "functions", "dynamic_edges"}
            }
            marker_id = str(probe_plan.get("source_marker_id") or "")
            selected_events, marker_found = _events_for_marker(
                test_result.get("events") or [],
                marker_id=marker_id,
            )
            compact_test["scenario_marker_id"] = marker_id
            compact_test["scenario_marker_found"] = marker_found
            if marker_id and not marker_found:
                result["diagnostics"].append(
                    f"targeted_probe_scenario_marker_missing:{test_id}"
                )
            result["tests"].append(compact_test)
            result["value_observations"].extend(
                {
                    **observation,
                    "test_id": test_id,
                }
                for observation in (
                    selected_events
                )
                if observation.get("event") == "value"
                if str(observation.get("probe_id") or "") in installed
            )
        result["fresh_execution"] = bool(regression_ids) and (
            len(result["tests"]) == len(regression_ids)
            and all(
                test.get("failed_as_expected")
                for test in result["tests"]
            )
        )
        if not result["fresh_execution"]:
            result["diagnostics"].append(
                "targeted_probe_regression_set_incomplete"
            )
        observed_ids = {
            str(item.get("probe_id") or "")
            for item in result["value_observations"]
        }
        result["unobserved_probe_ids"] = sorted(installed - observed_ids)
        return result
    except Exception as exc:
        result["diagnostics"].append(
            f"targeted_probe_exception:{type(exc).__name__}:{exc}"
        )
        return result
    finally:
        if cache_path and result.get("fresh_execution"):
            atomic_write_gzip_json(cache_path, result)
        _docker_exec(
            container,
            f"rm -rf -- {shlex.quote(container_trace_root)}",
            timeout=60,
        )
        adapter._reset_generic_workspace(container, container_repo)


def load_cached_runtime_evidence(
    bug: Any,
    *,
    artifact_dir: str,
    require_current_instrumentation: bool = False,
) -> Tuple[Dict[str, Any] | None, Dict[str, Any]]:
    """Load a complete per-bug runtime cache without rerunning its tests.

    ``require_current_instrumentation`` is used by normal FL runs after an
    instrumentation upgrade.  Legacy caches remain readable for cache-only
    evaluation, but they cannot silently prevent a normal run from collecting
    the scenario markers needed by the current localization engine.
    """
    regression_ids = [
        str(test.get("test_id") or "").strip()
        for test in getattr(bug, "tests", None) or []
        if _is_regression_failure(test) and str(test.get("test_id") or "").strip()
    ]
    paths = [
        os.path.join(artifact_dir, FULL_RUNTIME_CACHE_FILENAME),
        os.path.join(artifact_dir, RUNTIME_CACHE_FILENAME),
    ]
    diagnostics = []
    for path in paths:
        if not os.path.isfile(path):
            continue
        try:
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", encoding="utf-8") as stream:
                cached = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            diagnostics.append(
                f"runtime_cache_read_failed:{os.path.basename(path)}:"
                f"{type(exc).__name__}"
            )
            continue
        _upgrade_runtime_evidence(cached)
        _relocate_cached_artifacts(cached, artifact_dir=artifact_dir)
        valid, reasons = _validate_runtime_cache(
            cached,
            expected_identity=_runtime_cache_identity(
                bug, regression_ids=regression_ids
            ),
            require_current_instrumentation=require_current_instrumentation,
        )
        if not valid:
            diagnostics.extend(reasons)
            continue
        cached["cache"] = {
            "hit": True,
            "source": path,
            "full_ordered_events": path.endswith(".gz"),
            "legacy_identity_accepted": not bool(
                cached.get("cache_identity")
            ),
        }
        return cached, {
            "hit": True,
            "source": path,
            "full_ordered_events": path.endswith(".gz"),
            "diagnostics": diagnostics,
        }
    return None, {
        "hit": False,
        "source": "",
        "full_ordered_events": False,
        "diagnostics": diagnostics or ["runtime_cache_not_found"],
    }


def write_full_runtime_evidence_cache(
    runtime_evidence: Dict[str, Any],
    *,
    artifact_dir: str,
) -> str:
    """Persist the complete ordered stream compactly for future FL runs."""
    if not runtime_evidence or not artifact_dir:
        return ""
    os.makedirs(artifact_dir, exist_ok=True)
    runtime_evidence["schema"] = TRACE_SCHEMA
    return atomic_write_gzip_json(
        os.path.join(artifact_dir, FULL_RUNTIME_CACHE_FILENAME),
        runtime_evidence,
    )


def _upgrade_runtime_evidence(runtime_evidence: Dict[str, Any]) -> None:
    """Add v3 invocation/callsite identity to an otherwise valid v2 cache."""
    if not isinstance(runtime_evidence, dict):
        return
    aggregate_callsites = Counter()
    aggregate_exceptions = []
    aggregate_functions = runtime_evidence.get("functions") or {}
    for function in aggregate_functions.values():
        if isinstance(function, dict):
            function.setdefault("invocation_ids", [])
            function.setdefault("callsite_ids", [])
    for test in runtime_evidence.get("tests") or []:
        if not isinstance(test, dict):
            continue
        events = test.get("events") or []
        stacks: Dict[Tuple[Any, Any], Dict[int, Dict[str, Any]]] = (
            defaultdict(dict)
        )
        test_callsites = Counter()
        exception_events = []
        for index, event in enumerate(events):
            if not isinstance(event, dict):
                continue
            event.setdefault("event_id", index)
            kind = str(event.get("event") or "")
            pid = event.get("pid")
            tid = event.get("tid")
            depth = int(event.get("depth") or 0)
            stack = stacks[(pid, tid)]
            if kind == "enter":
                parent = stack.get(depth - 1) or {}
                callsite_id = str(event.get("callsite_id") or "")
                if not callsite_id:
                    callsite_id = _callsite_identity(
                        caller=str(parent.get("key") or ""),
                        callee=str(event.get("key") or ""),
                        source_path=str(
                            event.get("call_source_path") or ""
                        ),
                        source_line=int(
                            event.get("call_source_line") or 0
                        ),
                    )
                invocation_id = str(event.get("invocation_id") or "")
                if not invocation_id:
                    invocation_id = _invocation_identity(
                        raw_event_index=index,
                        callsite_id=callsite_id,
                    )
                event.update({
                    "callsite_id": callsite_id,
                    "invocation_id": invocation_id,
                    "parent_invocation_id": str(
                        parent.get("invocation_id") or ""
                    ),
                })
                stack[depth] = event
                for stale_depth in [
                    value for value in stack if value > depth
                ]:
                    stack.pop(stale_depth, None)
                key = str(event.get("key") or "")
                function = aggregate_functions.get(key) or {}
                if isinstance(function, dict):
                    if invocation_id not in function["invocation_ids"]:
                        function["invocation_ids"].append(invocation_id)
                    if (
                        callsite_id
                        and callsite_id not in function["callsite_ids"]
                    ):
                        function["callsite_ids"].append(callsite_id)
                caller = str(parent.get("key") or "")
                if caller and key:
                    identity = (
                        caller,
                        key,
                        callsite_id,
                        str(event.get("call_source_path") or ""),
                        int(event.get("call_source_line") or 0),
                    )
                    test_callsites[identity] += 1
                    aggregate_callsites[identity] += 1
                continue
            if kind == "exit":
                opened = stack.get(depth) or {}
                event.setdefault(
                    "invocation_id",
                    str(opened.get("invocation_id") or ""),
                )
                event.setdefault(
                    "parent_invocation_id",
                    str(opened.get("parent_invocation_id") or ""),
                )
                event.setdefault(
                    "callsite_id",
                    str(opened.get("callsite_id") or ""),
                )
                stack.pop(depth, None)
                continue
            if kind == "throw":
                opened = stack.get(max(stack), {}) if stack else {}
                event.setdefault(
                    "invocation_id",
                    str(opened.get("invocation_id") or ""),
                )
                event.setdefault(
                    "parent_invocation_id",
                    str(opened.get("parent_invocation_id") or ""),
                )
                exception_events.append(event)
        test["dynamic_callsites"] = [
            {
                "caller": caller,
                "callee": callee,
                "callsite_id": callsite_id,
                "source_path": source_path,
                "source_line": source_line,
                "count": count,
            }
            for (
                caller,
                callee,
                callsite_id,
                source_path,
                source_line,
            ), count in test_callsites.most_common()
        ]
        test.setdefault("exception_events", exception_events)
        aggregate_exceptions.extend(
            {
                **event,
                "test_id": str(test.get("test_id") or ""),
            }
            for event in test.get("exception_events") or []
        )
    runtime_evidence["dynamic_callsites"] = [
        {
            "caller": caller,
            "callee": callee,
            "callsite_id": callsite_id,
            "source_path": source_path,
            "source_line": source_line,
            "count": count,
        }
        for (
            caller,
            callee,
            callsite_id,
            source_path,
            source_line,
        ), count in aggregate_callsites.most_common()
    ]
    runtime_evidence.setdefault("exception_events", aggregate_exceptions)
    runtime_evidence["schema"] = TRACE_SCHEMA
    migrations = runtime_evidence.setdefault("cache_migrations", [])
    migration = "runtime_trace_v2_to_v3_invocation_identity"
    if migration not in migrations:
        migrations.append(migration)


def _runtime_cache_identity(
    bug: Any, *, regression_ids: List[str]
) -> Dict[str, Any]:
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    return {
        "version": 3,
        "bug_id": str(getattr(bug, "bug_id", "") or ""),
        "dataset": str(getattr(bug, "dataset", "") or ""),
        "commit_before": str(raw.get("commit_before") or ""),
        "commit_after": str(raw.get("commit_after") or ""),
        "regression_test_ids": sorted(set(regression_ids)),
        "engine": "gcc_clang_finstrument_functions",
        "instrumentation": "-O0 -finstrument-functions",
        "event_identity": "invocation_parent_callsite_v1",
        "exception_events": "cxa_throw_v1",
        "scenario_marker_generation": SCENARIO_MARKER_GENERATION,
    }


def _validate_runtime_cache(
    cached: Any,
    *,
    expected_identity: Dict[str, Any],
    require_current_instrumentation: bool = False,
) -> Tuple[bool, List[str]]:
    if not isinstance(cached, dict):
        return False, ["runtime_cache_not_object"]
    reasons = []
    if cached.get("schema") not in SUPPORTED_TRACE_SCHEMAS:
        reasons.append("runtime_cache_schema_mismatch")
    if cached.get("engine") != "gcc_clang_finstrument_functions":
        reasons.append("runtime_cache_engine_mismatch")
    if not cached.get("fresh_execution"):
        reasons.append("runtime_cache_not_fresh")
    if (
        require_current_instrumentation
        and (
            "scenario_marker_instrumentation" not in cached
            or str(
                (
                    cached.get("scenario_marker_instrumentation")
                    or {}
                ).get("generation")
                or ""
            )
            != SCENARIO_MARKER_GENERATION
        )
    ):
        reasons.append(
            "runtime_cache_instrumentation_generation_mismatch"
        )
    expected_ids = expected_identity.get("regression_test_ids") or []
    cached_ids = sorted(set(
        str(value)
        for value in cached.get("regression_test_ids") or []
        if str(value)
    ))
    if cached_ids != expected_ids:
        reasons.append("runtime_cache_regression_tests_mismatch")
    identity = cached.get("cache_identity") or {}
    for field in ("bug_id", "dataset", "commit_before", "commit_after"):
        expected = str(expected_identity.get(field) or "")
        actual = str(identity.get(field) or "")
        if identity and expected and actual != expected:
            reasons.append(f"runtime_cache_identity_mismatch:{field}")
    tests = {
        str(item.get("test_id") or ""): item
        for item in cached.get("tests") or []
        if isinstance(item, dict)
    }
    for test_id in expected_ids:
        test = tests.get(test_id) or {}
        if not test.get("failed_as_expected"):
            reasons.append(f"runtime_cache_test_not_reproduced:{test_id}")
        if int(test.get("trace_event_count") or 0) <= 0:
            reasons.append(f"runtime_cache_test_has_no_events:{test_id}")
        if not test.get("events"):
            reasons.append(f"runtime_cache_ordered_events_missing:{test_id}")
        for field in ("output_artifact", "trace_artifact"):
            value = str(test.get(field) or "")
            if not value or not os.path.isfile(value):
                reasons.append(
                    f"runtime_cache_artifact_missing:{test_id}:{field}"
                )
    if not isinstance(cached.get("functions"), dict) or not cached["functions"]:
        reasons.append("runtime_cache_functions_missing")
    return not reasons, list(dict.fromkeys(reasons))


def _relocate_cached_artifacts(
    cached: Dict[str, Any], *, artifact_dir: str
) -> None:
    """Repair absolute artifact paths when a results directory was moved."""
    compile_record = cached.get("compile") or {}
    for field in ("artifact", "compilation_database"):
        value = str(compile_record.get(field) or "")
        candidate = os.path.join(artifact_dir, os.path.basename(value))
        if value and not os.path.isfile(value) and os.path.isfile(candidate):
            compile_record[field] = candidate
    for test in cached.get("tests") or []:
        if not isinstance(test, dict):
            continue
        for field in ("output_artifact", "trace_artifact"):
            value = str(test.get(field) or "")
            candidate = os.path.join(artifact_dir, os.path.basename(value))
            if value and not os.path.isfile(value) and os.path.isfile(candidate):
                test[field] = candidate


def _install_trace_toolchain(
    *, container: str, container_trace_root: str
) -> Dict[str, Any]:
    compiler_query = (
        "for name in cc c++ gcc g++ clang clang++; do "
        "path=$(command -v \"$name\" 2>/dev/null || true); "
        "if [ -n \"$path\" ]; then printf '%s\\t%s\\n' \"$name\" \"$path\"; fi; "
        "done"
    )
    found = _docker_exec(container, compiler_query, timeout=30)
    compilers = {}
    for line in str(found.get("stdout") or "").splitlines():
        name, separator, path = line.partition("\t")
        if separator and path:
            compilers[name] = path
    real_cc = compilers.get("gcc") or compilers.get("cc") or compilers.get("clang")
    if not real_cc:
        return {"available": False, "diagnostics": ["trace_compiler_not_found"]}

    with tempfile.TemporaryDirectory(prefix="udbg_trace_toolchain_") as local:
        bin_dir = os.path.join(local, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        _write_text(os.path.join(local, "trace_runtime.c"), TRACE_RUNTIME_SOURCE)
        for name, real_path in compilers.items():
            wrapper = (
                "#!/bin/sh\n"
                f"exec {shlex.quote(real_path)} \"$@\" "
                "-g -O0 -finstrument-functions -fno-omit-frame-pointer "
                "-Wl,--export-dynamic\n"
            )
            path = os.path.join(bin_dir, name)
            _write_text(path, wrapper)
            os.chmod(path, 0o755)
        _docker_exec(
            container,
            f"rm -rf -- {shlex.quote(container_trace_root)} && "
            f"mkdir -p {shlex.quote(container_trace_root)}",
            timeout=30,
        )
        copied = subprocess.run(
            ["docker", "cp", local + "/.", f"{container}:{container_trace_root}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if copied.returncode != 0:
            return {
                "available": False,
                "diagnostics": ["trace_toolchain_copy_failed"],
            }

    trace_library = f"{container_trace_root}/libudbg_trace.so"
    build_cmd = (
        f"{shlex.quote(real_cc)} -shared -fPIC -g -O0 "
        f"-o {shlex.quote(trace_library)} "
        f"{shlex.quote(container_trace_root + '/trace_runtime.c')} -ldl"
    )
    built = _docker_exec(container, build_cmd, timeout=60)
    if built.get("returncode") != 0:
        return {
            "available": False,
            "diagnostics": [
                "trace_runtime_build_failed",
                str(built.get("stderr") or "")[-1000:],
            ],
        }
    return {
        "available": True,
        "diagnostics": [],
        "wrapper_bin": f"{container_trace_root}/bin",
        "trace_library": trace_library,
    }


def _install_scenario_markers(
    *,
    container: str,
    container_repo: str,
    raw: Dict[str, Any],
    allowed_ranges_by_source: Dict[
        str, List[Tuple[int, int]]
    ] | None = None,
) -> Dict[str, Any]:
    """Instrument test assertions in the disposable buggy workspace."""
    host_root = os.path.realpath(
        str(raw.get("buggy_tree_dir") or "")
    )
    records = []
    diagnostics = []
    if not host_root or not os.path.isdir(host_root):
        return {
            "available": False,
            "files": [],
            "diagnostics": ["scenario_marker_host_source_unavailable"],
        }
    test_files = [
        str(value)
        for value in raw.get("test_files") or []
        if str(value)
    ]
    for configured_path in test_files:
        host_path = os.path.realpath(
            configured_path
            if os.path.isabs(configured_path)
            else os.path.join(host_root, configured_path)
        )
        if not _path_within(host_path, host_root) or not os.path.isfile(
            host_path
        ):
            diagnostics.append(
                f"scenario_marker_test_file_unavailable:{configured_path}"
            )
            continue
        # Metadata may use either checkout-relative or host-absolute paths.
        # Container installation must always be rooted at container_repo.
        relative = os.path.relpath(host_path, host_root)
        allowed_ranges = (
            (allowed_ranges_by_source or {}).get(relative)
            if allowed_ranges_by_source is not None
            else None
        )
        if allowed_ranges_by_source is not None and not allowed_ranges:
            records.append({
                "source_file": relative,
                "changed": False,
                "scenario_count": 0,
                "marker_count": 0,
                "installed": False,
                "diagnostics": [
                    "failing_test_source_range_unavailable"
                ],
            })
            diagnostics.append(
                f"scenario_marker_target_range_unavailable:{relative}"
            )
            continue
        try:
            source = open(
                host_path, "r", encoding="utf-8", errors="replace"
            ).read()
        except OSError:
            diagnostics.append(
                f"scenario_marker_test_file_read_failed:{relative}"
            )
            continue
        instrumented, audit = instrument_assertion_scenarios(
            source=source,
            source_path=relative,
            allowed_byte_ranges=allowed_ranges,
        )
        record = {
            "source_file": relative,
            **audit,
        }
        if not audit.get("changed"):
            records.append(record)
            continue
        container_path = (
            f"{container_repo.rstrip('/')}/{relative.lstrip('./')}"
        )
        with tempfile.TemporaryDirectory(
            prefix="udbg_scenario_marker_"
        ) as local_dir:
            local_path = os.path.join(
                local_dir, os.path.basename(relative) or "test_source"
            )
            _write_text(local_path, instrumented)
            copied = subprocess.run(
                ["docker", "cp", local_path, f"{container}:{container_path}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        record["installed"] = copied.returncode == 0
        if copied.returncode != 0:
            diagnostics.append(
                f"scenario_marker_copy_failed:{relative}"
            )
        records.append(record)
    return {
        "available": any(
            record.get("installed") for record in records
        ),
        "generation": SCENARIO_MARKER_GENERATION,
        "targeted_to_failing_test_definitions": (
            allowed_ranges_by_source is not None
        ),
        "files": records,
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }


def _failing_test_source_ranges(
    *, bug: Any, raw: Dict[str, Any]
) -> Dict[str, List[Tuple[int, int]]]:
    """Resolve exact source ranges for regression-failing test definitions."""
    try:
        # Imported lazily to avoid a module import cycle: causal imports this
        # runtime module, while collection happens only after both are loaded.
        from .causal import _build_test_source_contexts

        contexts = _build_test_source_contexts(bug, raw)
    except Exception:
        return {}
    host_root = os.path.realpath(
        str(raw.get("buggy_tree_dir") or "")
    )
    output: Dict[str, List[Tuple[int, int]]] = defaultdict(list)
    for context in contexts.get("tests") or []:
        path = os.path.realpath(
            str(context.get("test_source_path") or "")
        )
        source_range = context.get("test_source_range") or {}
        start = int(source_range.get("start_byte") or -1)
        end = int(source_range.get("end_byte") or -1)
        if (
            host_root
            and _path_within(path, host_root)
            and 0 <= start < end
        ):
            relative = os.path.relpath(path, host_root)
            output[relative].append((start, end))
    return {
        path: sorted(set(ranges))
        for path, ranges in output.items()
    }


def _install_targeted_branch_probes(
    *,
    container: str,
    container_repo: str,
    raw: Dict[str, Any],
    probes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    host_root = os.path.realpath(
        str(raw.get("buggy_tree_dir") or "")
    )
    by_path: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    diagnostics = []
    for probe in probes:
        path = os.path.realpath(str(probe.get("source_path") or ""))
        if (
            host_root
            and _path_within(path, host_root)
            and os.path.isfile(path)
        ):
            by_path[path].append(probe)
        else:
            diagnostics.append(
                f"targeted_probe_source_unavailable:"
                f"{probe.get('probe_id')}"
            )
    installed_ids = []
    files = []
    for host_path, file_probes in by_path.items():
        try:
            source = open(
                host_path, "r", encoding="utf-8", errors="replace"
            ).read()
        except OSError:
            diagnostics.append(
                f"targeted_probe_source_read_failed:{host_path}"
            )
            continue
        instrumented, audit = instrument_branch_probes(
            source=source,
            source_path=os.path.relpath(host_path, host_root),
            probes=file_probes,
        )
        relative = os.path.relpath(host_path, host_root)
        record = {"source_file": relative, **audit}
        if not audit.get("changed"):
            files.append(record)
            diagnostics.extend(audit.get("diagnostics") or [])
            continue
        container_path = (
            f"{container_repo.rstrip('/')}/{relative.lstrip('./')}"
        )
        with tempfile.TemporaryDirectory(
            prefix="udbg_branch_probe_"
        ) as local_dir:
            local_path = os.path.join(
                local_dir, os.path.basename(relative)
            )
            _write_text(local_path, instrumented)
            copied = subprocess.run(
                ["docker", "cp", local_path, f"{container}:{container_path}"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
        record["installed"] = copied.returncode == 0
        if record["installed"]:
            installed_ids.extend(
                audit.get("installed_probe_ids") or []
            )
        else:
            diagnostics.append(
                f"targeted_probe_copy_failed:{relative}"
            )
        files.append(record)
    return {
        "available": bool(installed_ids),
        "installed_probe_ids": list(dict.fromkeys(installed_ids)),
        "files": files,
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }


def _targeted_probe_identity(
    *,
    bug: Any,
    probes: List[Dict[str, Any]],
    scenario_marker_id: str = "",
) -> str:
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    payload = {
        "schema": "unified_debugging.targeted_probe_runtime.v1",
        "bug_id": str(getattr(bug, "bug_id", "") or ""),
        "dataset": str(getattr(bug, "dataset", "") or ""),
        "commit_before": str(raw.get("commit_before") or ""),
        "scenario_marker_id": str(scenario_marker_id or ""),
        "probes": [
            {
                "probe_id": str(item.get("probe_id") or ""),
                "function": str(item.get("function") or ""),
                "kind": str(item.get("kind") or ""),
                "source_path": os.path.relpath(
                    str(item.get("source_path") or ""),
                    str(raw.get("buggy_tree_dir") or "."),
                ),
                "line": int(item.get("line") or 0),
                "expression": str(item.get("expression") or ""),
            }
            for item in sorted(
                probes, key=lambda value: str(value.get("probe_id") or "")
            )
        ],
    }
    return hashlib.sha256(json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _run_trace_build(
    *,
    container: str,
    container_repo: str,
    compile_cmd: str,
    wrapper_bin: str,
    timeout: int,
) -> Dict[str, Any]:
    command = _remove_coverage_flags(
        _prepend_wrapper_to_explicit_paths(compile_cmd, wrapper_bin)
    )
    script = (
        f"cd {shlex.quote(container_repo)} || exit 2\n"
        f"export PATH={shlex.quote(wrapper_bin)}:$PATH\n"
        "export CMAKE_EXPORT_COMPILE_COMMANDS=ON\n"
        f"timeout --kill-after=15s {shlex.quote(str(timeout) + 's')} "
        f"bash -c {shlex.quote(command)}\n"
    )
    completed = subprocess.run(
        ["docker", "exec", "-i", container, "bash", "-s"],
        input=script,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout + 30,
    )
    return {
        "returncode": completed.returncode,
        "output": completed.stdout or "",
    }


def _run_one_traced_test(
    *,
    container: str,
    container_repo: str,
    container_trace_root: str,
    trace_library: str,
    test_template: str,
    test_id: str,
    host_artifact_dir: str,
    timeout: int,
) -> Dict[str, Any]:
    slug = _safe_name(test_id)
    container_trace = f"{container_trace_root}/{slug}.trace"
    test_cmd = test_template.replace("{test_id}", shlex.quote(test_id))
    script = (
        f"cd {shlex.quote(container_repo)} || exit 2\n"
        f"rm -f -- {shlex.quote(container_trace)}\n"
        f"export UDBG_TRACE_FILE={shlex.quote(container_trace)}\n"
        f"export UDBG_TRACE_MAX_EVENTS={TRACE_MAX_EVENTS}\n"
        f"export LD_PRELOAD={shlex.quote(trace_library)}"
        '${LD_PRELOAD:+:$LD_PRELOAD}\n'
        f"timeout --kill-after=10s {shlex.quote(str(timeout) + 's')} "
        f"bash -lc {shlex.quote(test_cmd)}\n"
    )
    try:
        completed = subprocess.run(
            ["docker", "exec", "-i", container, "bash", "-s"],
            input=script,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout + 30,
        )
        returncode = completed.returncode
        output = completed.stdout or ""
    except subprocess.TimeoutExpired as exc:
        returncode = 124
        output = str(exc.stdout or "")

    output_path = os.path.join(host_artifact_dir, f"{slug}.output.log")
    trace_path = os.path.join(host_artifact_dir, f"{slug}.trace")
    _write_text(output_path, output)
    copied = subprocess.run(
        ["docker", "cp", f"{container}:{container_trace}", trace_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    diagnostics = []
    if copied.returncode != 0:
        diagnostics.append("trace_file_copy_failed")
        _write_text(trace_path, "")

    raw_events = _parse_trace_file(trace_path)
    symbolized = _symbolize_events(
        container,
        raw_events,
        container_repo=container_repo,
    )
    summarized = _summarize_events(
        symbolized,
        container_repo=container_repo,
    )
    return {
        "test_id": test_id,
        "returncode": returncode,
        "timed_out": returncode == 124,
        "failed_as_expected": returncode not in {0, 124},
        "fresh_output": output[-6000:],
        "output_artifact": output_path,
        "trace_artifact": trace_path,
        "raw_trace_event_count": len(raw_events),
        "trace_event_count": summarized["trace_event_count"],
        "trace_truncated": len(raw_events) >= TRACE_MAX_EVENTS,
        "persisted_event_count": len(summarized["events"]),
        "events_tail_truncated": (
            summarized["trace_event_count"] > len(summarized["events"])
        ),
        "functions": summarized["functions"],
        "dynamic_edges": summarized["dynamic_edges"],
        "dynamic_callsites": summarized["dynamic_callsites"],
        "exception_events": summarized["exception_events"],
        "value_observations": summarized["value_observations"],
        "active_stack": summarized["active_stack"],
        "events": summarized["events"],
        "diagnostics": diagnostics + summarized["diagnostics"],
    }


def _parse_trace_file(path: str) -> List[Dict[str, Any]]:
    events = []
    try:
        stream = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return events
    with stream:
        for index, line in enumerate(stream):
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 6 and parts[0] == "M":
                try:
                    events.append({
                        "index": index,
                        "event": "M",
                        "pid": int(parts[1]),
                        "tid": int(parts[2]),
                        "depth": int(parts[3]),
                        "marker_kind": parts[4],
                        "marker_id": parts[5],
                    })
                except ValueError:
                    pass
                continue
            if len(parts) >= 6 and parts[0] == "V":
                try:
                    events.append({
                        "index": index,
                        "event": "V",
                        "pid": int(parts[1]),
                        "tid": int(parts[2]),
                        "depth": int(parts[3]),
                        "probe_id": parts[4],
                        "value": int(parts[5]),
                    })
                except ValueError:
                    pass
                continue
            if len(parts) not in {9, 12} or parts[0] not in {"E", "X", "T"}:
                continue
            try:
                event = {
                    "index": index,
                    "event": parts[0],
                    "pid": int(parts[1]),
                    "tid": int(parts[2]),
                    "depth": int(parts[3]),
                    "address": int(parts[4], 16),
                    "offset": int(parts[5], 16),
                    "call_site": int(parts[6], 16),
                    "module": parts[7],
                    "runtime_symbol": parts[8],
                }
                if len(parts) == 12:
                    event.update({
                        "call_site_offset": int(parts[9], 16),
                        "call_site_module": parts[10],
                        "call_site_runtime_symbol": parts[11],
                    })
                events.append(event)
            except ValueError:
                continue
    return events


def _events_for_marker(
    events: List[Dict[str, Any]], *, marker_id: str
) -> Tuple[List[Dict[str, Any]], bool]:
    """Select the latest concrete execution window for one source marker."""
    if not marker_id:
        return list(events), False
    matches = [
        index
        for index, event in enumerate(events)
        if event.get("event") == "marker"
        and event.get("marker_kind") == "scenario_begin"
        and str(event.get("marker_id") or "") == marker_id
    ]
    if not matches:
        return list(events), False
    start = matches[-1] + 1
    end = next(
        (
            index
            for index in range(start, len(events))
            if events[index].get("event") == "marker"
            and events[index].get("marker_kind") == "scenario_begin"
        ),
        len(events),
    )
    return list(events[start:end]), True


def _symbolize_events(
    container: str,
    events: List[Dict[str, Any]],
    *,
    container_repo: str,
) -> List[Dict[str, Any]]:
    function_map = _resolve_event_addresses(
        container,
        events,
        container_repo=container_repo,
        module_field="module",
        offset_field="offset",
        address_field="address",
    )
    call_site_map = _resolve_event_addresses(
        container,
        events,
        container_repo=container_repo,
        module_field="call_site_module",
        offset_field="call_site_offset",
        address_field="call_site",
    )
    output = []
    for event in events:
        if event.get("event") in {"M", "V"}:
            output.append(dict(event))
            continue
        item = function_map.get(event["index"], {})
        call_item = call_site_map.get(event["index"], {})
        output.append({
            **event,
            "function": (
                item.get("function")
                or _demangle_runtime_symbol(
                    str(event.get("runtime_symbol") or "")
                )
            ),
            "source_path": item.get("source_path") or "",
            "source_line": int(item.get("source_line") or 0),
            "call_function": (
                call_item.get("function")
                or _demangle_runtime_symbol(
                    str(event.get("call_site_runtime_symbol") or "")
                )
            ),
            "call_source_path": call_item.get("source_path") or "",
            "call_source_line": int(call_item.get("source_line") or 0),
        })
    return output


def _resolve_event_addresses(
    container: str,
    events: List[Dict[str, Any]],
    *,
    container_repo: str,
    module_field: str,
    offset_field: str,
    address_field: str,
) -> Dict[int, Dict[str, Any]]:
    requests = defaultdict(list)
    event_locations = {}
    for event in events:
        module = str(event.get(module_field) or "")
        if not module or event.get(offset_field) is None:
            continue
        resolved_module = (
            module
            if module.startswith("/")
            else f"{container_repo.rstrip('/')}/{module.lstrip('./')}"
        )
        offset = int(event[offset_field])
        address = int(event.get(address_field) or 0)
        requests[resolved_module].append((offset, address))
        event_locations[event["index"]] = (resolved_module, offset)

    symbol_map = {}
    for module, values in requests.items():
        unique_offsets = list(dict.fromkeys(offset for offset, _ in values))
        resolved = _addr2line_batch(container, module, unique_offsets)
        unresolved = [
            offset for offset, item in resolved.items()
            if not item.get("source_path")
        ]
        if unresolved:
            actual_by_offset = {
                offset: address for offset, address in values if offset in unresolved
            }
            actual_result = _addr2line_batch(
                container, module, list(actual_by_offset.values())
            )
            for offset, address in actual_by_offset.items():
                if actual_result.get(address, {}).get("source_path"):
                    resolved[offset] = actual_result[address]
        for offset, item in resolved.items():
            symbol_map[(module, offset)] = item
    return {
        index: symbol_map.get(location, {})
        for index, location in event_locations.items()
    }


def _addr2line_batch(
    container: str, module: str, addresses: List[int]
) -> Dict[int, Dict[str, Any]]:
    if not module or not addresses:
        return {}
    completed = subprocess.run(
        ["docker", "exec", "-i", container, "addr2line", "-f", "-C", "-e", module],
        input="\n".join(hex(value) for value in addresses) + "\n",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=120,
    )
    if completed.returncode != 0:
        return {}
    lines = (completed.stdout or "").splitlines()
    out = {}
    for index, address in enumerate(addresses):
        function = lines[index * 2].strip() if index * 2 < len(lines) else ""
        location = lines[index * 2 + 1].strip() if index * 2 + 1 < len(lines) else ""
        source_path, source_line = _parse_addr2line_location(location)
        out[address] = {
            "function": "" if function in {"??", "?"} else function,
            "source_path": source_path,
            "source_line": source_line,
        }
    return out


def _summarize_events(
    events: List[Dict[str, Any]], *, container_repo: str
) -> Dict[str, Any]:
    functions: Dict[str, Dict[str, Any]] = {}
    edges = Counter()
    callsites = Counter()
    stacks: Dict[Tuple[int, int], List[Dict[str, Any]]] = defaultdict(list)
    production_events = []
    exception_events = []
    value_observations = []

    for event in events:
        if event.get("event") == "M":
            stack = stacks[(event["pid"], event["tid"])]
            record = {
                "event": "marker",
                "event_id": len(production_events),
                "marker_kind": str(event.get("marker_kind") or ""),
                "marker_id": str(event.get("marker_id") or ""),
                "depth": max(0, int(event.get("depth") or 0)),
                "pid": event["pid"],
                "tid": event["tid"],
                "invocation_id": (
                    str(stack[-1].get("invocation_id") or "")
                    if stack else ""
                ),
                "parent_invocation_id": (
                    str(stack[-2].get("invocation_id") or "")
                    if len(stack) > 1 else ""
                ),
            }
            production_events.append(record)
            continue
        if event.get("event") == "V":
            stack = stacks[(event["pid"], event["tid"])]
            record = {
                "event": "value",
                "event_id": len(production_events),
                "probe_id": str(event.get("probe_id") or ""),
                "value": int(event.get("value") or 0),
                "depth": max(0, int(event.get("depth") or 0)),
                "pid": event["pid"],
                "tid": event["tid"],
                "invocation_id": (
                    str(stack[-1].get("invocation_id") or "")
                    if stack else ""
                ),
                "parent_invocation_id": (
                    str(stack[-2].get("invocation_id") or "")
                    if len(stack) > 1 else ""
                ),
                "function": (
                    str(stack[-1].get("key") or "") if stack else ""
                ),
            }
            production_events.append(record)
            value_observations.append(record)
            continue
        identity = _production_identity(event, container_repo=container_repo)
        event = {**event, **identity}
        stack = stacks[(event["pid"], event["tid"])]
        depth = max(0, int(event.get("depth") or 0))
        if event["event"] == "T":
            throw_key = str(event.get("key") or "")
            parent = (
                str(stack[-1].get("key") or "")
                if stack else ""
            )
            parent_invocation_id = (
                str(stack[-1].get("invocation_id") or "")
                if stack else ""
            )
            record = {
                "event": "throw",
                "event_id": len(production_events),
                "key": throw_key,
                "throw_site_key": throw_key,
                "depth": depth,
                "pid": event["pid"],
                "tid": event["tid"],
                "invocation_id": parent_invocation_id,
                "parent_invocation_id": (
                    str(stack[-2].get("invocation_id") or "")
                    if len(stack) > 1 else ""
                ),
                "caller": parent,
                "source_path": event.get("source_path") or "",
                "source_line": int(event.get("source_line") or 0),
                "call_source_path": event.get("call_source_path") or "",
                "call_source_line": int(
                    event.get("call_source_line") or 0
                ),
            }
            production_events.append(record)
            exception_events.append(record)
            continue
        while len(stack) > depth:
            stack.pop()
        if event["event"] == "E":
            parent = next(
                (item.get("key") for item in reversed(stack) if item.get("key")),
                "",
            )
            parent_invocation_id = next(
                (
                    item.get("invocation_id")
                    for item in reversed(stack)
                    if item.get("invocation_id")
                ),
                "",
            )
            callsite_id = _callsite_identity(
                caller=str(parent or ""),
                callee=str(event.get("key") or ""),
                source_path=str(event.get("call_source_path") or ""),
                source_line=int(event.get("call_source_line") or 0),
            )
            invocation_id = _invocation_identity(
                raw_event_index=int(event.get("index") or 0),
                callsite_id=callsite_id,
            )
            event = {
                **event,
                "invocation_id": invocation_id,
                "parent_invocation_id": str(
                    parent_invocation_id or ""
                ),
                "callsite_id": callsite_id,
            }
            if len(stack) == depth:
                stack.append(event)
            elif depth < len(stack):
                stack[depth] = event
                del stack[depth + 1:]
            if event.get("key"):
                key = event["key"]
                record = functions.setdefault(key, {
                    "key": key,
                    "function": event.get("function"),
                    "source_path": event.get("source_path"),
                    "source_line": event.get("source_line"),
                    "enter_count": 0,
                    "max_depth": 0,
                    "max_event_span": 0,
                    "last_enter_event_index": -1,
                    "active_at_failure": False,
                    "reverse_distance": None,
                    "invocation_ids": [],
                    "callsite_ids": [],
                })
                record["enter_count"] += 1
                record["max_depth"] = max(record["max_depth"], depth)
                record["last_enter_event_index"] = len(production_events)
                if invocation_id not in record["invocation_ids"]:
                    record["invocation_ids"].append(invocation_id)
                if callsite_id and callsite_id not in record["callsite_ids"]:
                    record["callsite_ids"].append(callsite_id)
                production_events.append({
                    "event": "enter",
                    "event_id": len(production_events),
                    "key": key,
                    "depth": depth,
                    "pid": event["pid"],
                    "tid": event["tid"],
                    "invocation_id": invocation_id,
                    "parent_invocation_id": str(
                        parent_invocation_id or ""
                    ),
                    "callsite_id": callsite_id,
                    "call_function": event.get("call_function") or "",
                    "call_source_path": event.get("call_source_path") or "",
                    "call_source_line": int(
                        event.get("call_source_line") or 0
                    ),
                })
                if parent and parent != key:
                    edges[(parent, key)] += 1
                    callsites[(
                        str(parent),
                        str(key),
                        callsite_id,
                        str(event.get("call_source_path") or ""),
                        int(event.get("call_source_line") or 0),
                    )] += 1
        else:
            if event.get("key"):
                key = event["key"]
                opened = (
                    stack[depth]
                    if depth < len(stack)
                    and str(stack[depth].get("key") or "") == key
                    else {}
                )
                production_events.append({
                    "event": "exit",
                    "event_id": len(production_events),
                    "key": key,
                    "depth": depth,
                    "pid": event["pid"],
                    "tid": event["tid"],
                    "invocation_id": str(
                        opened.get("invocation_id") or ""
                    ),
                    "parent_invocation_id": str(
                        opened.get("parent_invocation_id") or ""
                    ),
                    "callsite_id": str(
                        opened.get("callsite_id") or ""
                    ),
                    "call_function": event.get("call_function") or "",
                    "call_source_path": event.get("call_source_path") or "",
                    "call_source_line": int(
                        event.get("call_source_line") or 0
                    ),
                })
            while len(stack) > depth:
                stack.pop()

    open_entries = {}
    for index, item in enumerate(production_events):
        if item["event"] not in {"enter", "exit"}:
            continue
        slot = (item["pid"], item["tid"], item["depth"])
        if item["event"] == "enter":
            open_entries[slot] = (item["key"], index)
            continue
        opened = open_entries.pop(slot, None)
        if not opened or opened[0] != item["key"]:
            continue
        record = functions.get(item["key"])
        if record is not None:
            record["max_event_span"] = max(
                int(record.get("max_event_span") or 0),
                index - opened[1],
            )

    reverse_seen = {}
    for item in reversed(production_events):
        if item["event"] != "enter":
            continue
        key = item["key"]
        if key not in reverse_seen:
            reverse_seen[key] = len(reverse_seen)
    for key, distance in reverse_seen.items():
        if key in functions:
            functions[key]["reverse_distance"] = distance

    active_stack = []
    for (pid, tid), stack in stacks.items():
        for item in stack:
            key = item.get("key")
            if not key or key not in functions:
                continue
            functions[key]["active_at_failure"] = True
            active_stack.append({
                "pid": pid,
                "tid": tid,
                "depth": item.get("depth"),
                "key": key,
                "invocation_id": item.get("invocation_id") or "",
            })
    return {
        "trace_event_count": len(production_events),
        "persisted_event_count": min(
            len(production_events), PERSISTED_EVENT_LIMIT
        ),
        "events_tail_truncated": (
            len(production_events) > PERSISTED_EVENT_LIMIT
        ),
        "functions": functions,
        "dynamic_edges": [
            {"caller": caller, "callee": callee, "count": count}
            for (caller, callee), count in edges.most_common()
        ],
        "dynamic_callsites": [
            {
                "caller": caller,
                "callee": callee,
                "callsite_id": callsite_id,
                "source_path": source_path,
                "source_line": source_line,
                "count": count,
            }
            for (
                caller,
                callee,
                callsite_id,
                source_path,
                source_line,
            ), count in callsites.most_common()
        ],
        "exception_events": exception_events,
        "value_observations": value_observations,
        "active_stack": active_stack,
        # Causal FL consumes the complete ordered stream in memory. The caller
        # compacts it only after producer slicing has finished.
        "events": production_events,
        "diagnostics": (
            [] if production_events else ["no_project_source_events_symbolized"]
        ),
    }


def _callsite_identity(
    *,
    caller: str,
    callee: str,
    source_path: str,
    source_line: int,
) -> str:
    payload = "\0".join((
        str(caller or ""),
        str(callee or ""),
        str(source_path or "").replace("\\", "/"),
        str(int(source_line or 0)),
    ))
    return "callsite_" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:16]


def _invocation_identity(
    *, raw_event_index: int, callsite_id: str
) -> str:
    payload = f"{int(raw_event_index)}:{str(callsite_id or '')}"
    return "invocation_" + hashlib.sha256(
        payload.encode("utf-8")
    ).hexdigest()[:16]


def compact_runtime_evidence(
    runtime_evidence: Dict[str, Any],
    *,
    event_limit: int = PERSISTED_EVENT_LIMIT,
) -> Dict[str, Any]:
    """Compact full in-memory events only after causal slicing has consumed them."""
    limit = max(1, int(event_limit or PERSISTED_EVENT_LIMIT))
    compact = {
        key: value
        for key, value in runtime_evidence.items()
        if key != "tests"
    }
    compact_tests = []
    for test in runtime_evidence.get("tests") or []:
        if not isinstance(test, dict):
            continue
        events = test.get("events") or []
        item = {
            key: value
            for key, value in test.items()
            if key != "events"
        }
        full_event_count = max(
            len(events),
            int(test.get("trace_event_count") or 0),
        )
        item["persisted_event_count"] = min(len(events), limit)
        item["events_tail_truncated"] = (
            full_event_count > min(len(events), limit)
        )
        item["full_events_used_for_slicing"] = (
            len(events) >= full_event_count
        )
        item["events"] = events[-limit:]
        compact_tests.append(item)
    compact["tests"] = compact_tests
    return compact


def _copy_compilation_database(
    *,
    container: str,
    container_repo: str,
    host_artifact_dir: str,
    host_source_root: str,
) -> str:
    """Copy and path-rewrite the build's compilation database for host Clang."""
    found = subprocess.run(
        [
            "docker", "exec", container, "find", container_repo,
            "-maxdepth", "4", "-name", "compile_commands.json",
            "-type", "f", "-print", "-quit",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    container_path = str(found.stdout or "").strip().splitlines()
    if found.returncode != 0 or not container_path:
        return ""
    host_path = os.path.join(host_artifact_dir, "compile_commands.json")
    copied = subprocess.run(
        ["docker", "cp", f"{container}:{container_path[0]}", host_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if copied.returncode != 0:
        return ""
    source_root = os.path.realpath(host_source_root) if host_source_root else ""
    if not source_root:
        return host_path
    try:
        with open(host_path, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
        rewritten = _rewrite_compilation_database_paths(
            payload,
            container_repo=container_repo,
            host_source_root=source_root,
        )
        rewritten = _normalize_compilation_database(
            rewritten,
            original=payload,
            container_repo=container_repo,
            host_source_root=source_root,
        )
        with open(host_path, "w", encoding="utf-8") as stream:
            json.dump(rewritten, stream, indent=2)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ""
    return host_path


def _rewrite_compilation_database_paths(
    payload: Any, *, container_repo: str, host_source_root: str
) -> Any:
    if isinstance(payload, str):
        return payload.replace(container_repo, host_source_root)
    if isinstance(payload, list):
        return [
            _rewrite_compilation_database_paths(
                item,
                container_repo=container_repo,
                host_source_root=host_source_root,
            )
            for item in payload
        ]
    if isinstance(payload, dict):
        return {
            key: _rewrite_compilation_database_paths(
                value,
                container_repo=container_repo,
                host_source_root=host_source_root,
            )
            for key, value in payload.items()
        }
    return payload


def _normalize_compilation_database(
    payload: Any,
    *,
    original: Any,
    container_repo: str,
    host_source_root: str,
) -> Any:
    """Make container build commands executable against the host source tree."""
    if not isinstance(payload, list) or not isinstance(original, list):
        return payload
    output = []
    for index, rewritten in enumerate(payload):
        if not isinstance(rewritten, dict):
            output.append(rewritten)
            continue
        source = original[index] if index < len(original) else {}
        source = source if isinstance(source, dict) else {}
        original_dir = str(source.get("directory") or container_repo)
        item = dict(rewritten)
        if isinstance(source.get("arguments"), list):
            item["arguments"] = _normalize_compile_arguments(
                [str(value) for value in source["arguments"]],
                original_dir=original_dir,
                container_repo=container_repo,
                host_source_root=host_source_root,
            )
        elif source.get("command"):
            try:
                arguments = shlex.split(str(source["command"]))
                item["command"] = shlex.join(_normalize_compile_arguments(
                    arguments,
                    original_dir=original_dir,
                    container_repo=container_repo,
                    host_source_root=host_source_root,
                ))
            except ValueError:
                pass
        # All relative source/include paths have been made absolute. Using an
        # existing cwd prevents Clang from silently inheriting the repository
        # process cwd when the container-only build directory does not exist.
        item["directory"] = host_source_root
        output.append(item)
    return output


def _normalize_compile_arguments(
    arguments: List[str],
    *,
    original_dir: str,
    container_repo: str,
    host_source_root: str,
) -> List[str]:
    path_flags = {"-I", "-isystem", "-iquote", "-include", "--sysroot"}

    def translate(value: str) -> str:
        if not value:
            return value
        absolute = (
            value
            if os.path.isabs(value)
            else os.path.normpath(os.path.join(original_dir, value))
        )
        if absolute == container_repo:
            return host_source_root
        if absolute.startswith(container_repo.rstrip("/") + "/"):
            return os.path.join(
                host_source_root,
                absolute[len(container_repo.rstrip("/")) + 1:],
            )
        return absolute

    output = []
    index = 0
    joined_prefixes = ("-I", "-isystem", "-iquote", "--sysroot=")
    while index < len(arguments):
        argument = arguments[index]
        if argument in path_flags and index + 1 < len(arguments):
            output.extend([argument, translate(arguments[index + 1])])
            index += 2
            continue
        matched = next(
            (
                prefix
                for prefix in joined_prefixes
                if argument.startswith(prefix) and argument != prefix
            ),
            "",
        )
        if matched:
            value = argument[len(matched):]
            output.append(matched + translate(value))
        else:
            output.append(
                translate(argument)
                if (
                    not argument.startswith("-")
                    and (
                        argument.startswith(container_repo)
                        or argument.endswith(
                            (".c", ".cc", ".cpp", ".cxx", ".h", ".hpp")
                        )
                    )
                )
                else argument.replace(container_repo, host_source_root)
            )
        index += 1
    return output


def _production_identity(
    event: Dict[str, Any], *, container_repo: str
) -> Dict[str, Any]:
    source = str(event.get("source_path") or "").replace("\\", "/")
    function = _canonical_function(str(event.get("function") or ""))
    if not source or not function:
        return {"key": ""}
    normalized_root = container_repo.rstrip("/").replace("\\", "/")
    relative = ""
    if source.startswith(normalized_root + "/"):
        relative = source[len(normalized_root) + 1:]
    elif not source.startswith("/") and not source.startswith("../"):
        relative = source.lstrip("./")
    else:
        return {"key": ""}
    lowered = "/" + relative.lower().strip("/") + "/"
    if (
        any(part in lowered for part in ("/test/", "/tests/", "/testing/", "/unittest/", "/unittests/"))
        or "/build_meta" in lowered
        or relative.startswith(".")
    ):
        return {"key": ""}
    if not relative.lower().endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")):
        return {"key": ""}
    return {
        "key": f"{os.path.basename(relative)}:{function}",
        "function": function,
        "source_path": relative,
    }


def _canonical_function(value: str) -> str:
    value = re.sub(r"\s+\[clone [^\]]+\]$", "", str(value or "").strip())
    value = re.sub(
        r"(?:\s+(?:const|volatile|override|final|&|&&))*"
        r"(?:\s+noexcept(?:\s*\([^()]*\))?)?\s*$",
        "",
        value,
    )
    value = _strip_trailing_parameter_list(value)
    value = _remove_balanced_templates(value)
    conversion = re.search(
        r"((?:[~A-Za-z_][A-Za-z0-9_]*::)*operator\s+"
        r"[^()\s]+(?:\s*[*&]+)?)\s*$",
        value,
    )
    if conversion:
        value = re.sub(r"\boperator\s+", "operator", conversion.group(1))
    # addr2line may prefix free functions with their return type. The
    # qualified function name is the final whitespace-delimited token after
    # templates and parameters have been removed.
    tokens = value.split()
    if len(tokens) > 1:
        value = tokens[-1]
    value = re.sub(r"\boperator\s+", "operator", value)
    value = re.sub(r"\s+", "", value)
    if value in {"", "??", "_GLOBAL__sub_I_main"}:
        return ""
    return value


def _strip_trailing_parameter_list(value: str) -> str:
    """Remove the final balanced argument list, not a return-type decltype."""
    value = str(value or "").rstrip()
    if not value.endswith(")"):
        return value
    depth = 0
    start = -1
    for index in range(len(value) - 1, -1, -1):
        char = value[index]
        if char == ")":
            depth += 1
        elif char == "(":
            depth -= 1
            if depth == 0:
                start = index
                break
    if start < 0:
        return value
    # For operator()(), the right-most pair is the function argument list;
    # the preceding pair remains part of the function name.
    return value[:start].rstrip()


def _remove_balanced_templates(value: str) -> str:
    out = []
    depth = 0
    for char in value:
        if char == "<":
            depth += 1
            continue
        if char == ">" and depth:
            depth -= 1
            continue
        if depth == 0:
            out.append(char)
    return "".join(out)


def _parse_addr2line_location(value: str) -> Tuple[str, int]:
    value = str(value or "").strip()
    if not value or value.startswith("??"):
        return "", 0
    value = value.split(" (discriminator ", 1)[0]
    path, separator, line = value.rpartition(":")
    if not separator:
        return value, 0
    try:
        return path, int(line)
    except ValueError:
        return value, 0


def _demangle_runtime_symbol(value: str) -> str:
    if not value:
        return ""
    completed = subprocess.run(
        ["c++filt", value],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=5,
    )
    return (completed.stdout or value).strip()


def _prepend_wrapper_to_explicit_paths(command: str, wrapper_bin: str) -> str:
    pattern = re.compile(r"(?<!\S)PATH=([^\s]+)")
    return pattern.sub(
        lambda match: f"PATH={shlex.quote(wrapper_bin)}:{match.group(1)}",
        command,
    )


def _remove_coverage_flags(command: str) -> str:
    """Drop legacy gcov flags from the reused build recipe."""
    return re.sub(
        r"(?<!\S)(?:--coverage|-fprofile-arcs|-ftest-coverage)"
        r"(?=\s|['\"]|$)",
        "",
        str(command or ""),
    )


def _docker_exec(container: str, command: str, *, timeout: int) -> Dict[str, Any]:
    try:
        completed = subprocess.run(
            ["docker", "exec", container, "bash", "-lc", command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return {
            "returncode": completed.returncode,
            "stdout": completed.stdout or "",
            "stderr": completed.stderr or "",
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "returncode": 124,
            "stdout": "",
            "stderr": f"{type(exc).__name__}:{exc}",
        }


def _is_regression_failure(test: Dict[str, Any]) -> bool:
    before = str(test.get("outcome") or "").upper()
    after = str(test.get("outcome_fixed") or "").upper()
    return before in {"FAIL", "FAILED"} and after in {"PASS", "PASSED"}


def _safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._-")
    if not cleaned:
        cleaned = "test"
    digest = hashlib.sha256(str(value).encode("utf-8")).hexdigest()[:10]
    return f"{cleaned[:80]}_{digest}"


def _path_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _write_text(path: str, value: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8", errors="replace") as stream:
        stream.write(str(value or ""))
