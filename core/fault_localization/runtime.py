"""Build regression failures with census-first, scoped ordered instrumentation."""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import textwrap
import time
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from data_loaders.sandbox_adapter import Defects4CAdapter
from core.failure_context import build_regression_fail_context
from .artifacts import atomic_write_gzip_json, atomic_write_json
from .markers import (
    SCENARIO_MARKER_GENERATION,
    SLICE_PROBE_GENERATION,
    instrument_assertion_scenarios,
    instrument_slice_probes,
)
from .trace_queries import (
    build_trace_query_plan,
    evaluate_trace_query_plan,
    observed_probe_ids,
    should_run_probe_recovery,
)
from .query_broker import (
    build_investigation_query_broker,
    merge_broker_probes_into_scopes,
)


TRACE_SCHEMA = "unified_debugging.runtime_trace.v9"
SUPPORTED_TRACE_SCHEMAS = {
    TRACE_SCHEMA,
    "unified_debugging.runtime_trace.v8",
    "unified_debugging.runtime_trace.v7",
    "unified_debugging.runtime_trace.v6",
    "unified_debugging.runtime_trace.v5",
    "unified_debugging.runtime_trace.v3",
    "unified_debugging.runtime_trace.v2",
    "unified_debugging.runtime_trace.v4",
}
TRACE_MAX_EVENTS = 300_000
TRACE_MAX_RETRY_EVENTS = 1_200_000
TRACE_MAX_ATTEMPTS = 3
TRACE_COVERAGE_SLOTS = 65_536
TRACE_HARD_MAX_EVENTS = 5_000_000
TRACE_SCOPE_MAX_RANGES = 16_384
TRACE_EDGE_SLOTS = 131_072
TRACE_DETAILED_EVENT_BUDGET = 260_000
TRACE_SLICE_SINK_LIMIT = 12
TRACE_SLICE_BOUNDARY_SINK_LIMIT = 3
TRACE_SLICE_FRONTIER_LIMIT = 24
TRACE_SLICE_PROBE_EVENT_RESERVE = 40_000
TRACE_SLICE_MAX_PROBES = 192
TRACE_SLICE_PROBE_SAMPLE_LIMIT = 64
FUNCTION_IDENTITY_SAMPLE_LIMIT = 128
PERSISTED_EVENT_LIMIT = 8_000
PERSISTED_PROBE_SAMPLES_PER_ID = 16
INSTRUMENTABLE_SOURCE_SUFFIXES = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}
FULL_RUNTIME_CACHE_FILENAME = "runtime_evidence.full.json.gz"
TRACE_SCOPE_SCHEMA = "unified_debugging.trace_scope.v4"
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
    static int scenario_window = 0;
    static int probe_only = 0;
    static int coverage_only = 0;
    static int crash_safe_coverage = 0;
    static int scope_enabled = 0;
    static unsigned long slice_probe_limit = 512;
    static __thread unsigned trace_depth = 0;
    static __thread unsigned selected_depth = 0;
    static __thread int resolving_throw = 0;
    static __thread void *function_stack[8192];

    #define UDBG_PROBE_SLOTS 4096
    struct probe_slot {
      unsigned long hash;
      unsigned long count;
    };
    static struct probe_slot probe_counts[UDBG_PROBE_SLOTS];

    #define UDBG_SCOPE_MODULE_LEN 512
    #define UDBG_SCOPE_MAX_RANGES 16384
    #define UDBG_SCOPE_STACK_DEPTH 8192
    #define UDBG_SCOPE_CACHE_SLOTS 65536
    struct scope_range {
      char module[UDBG_SCOPE_MODULE_LEN];
      uintptr_t start;
      uintptr_t end;
    };
    static struct scope_range scope_ranges[UDBG_SCOPE_MAX_RANGES];
    static unsigned long scope_range_count = 0;
    struct scope_cache_slot {
      uintptr_t function;
      unsigned char selected;
    };
    static struct scope_cache_slot scope_cache[UDBG_SCOPE_CACHE_SLOTS];
    static __thread unsigned char scope_stack[UDBG_SCOPE_STACK_DEPTH];

    struct coverage_slot {
      uintptr_t function;
      unsigned long count;
    };

    #define UDBG_COVERAGE_SLOTS 65536
    #define UDBG_COVERAGE_PROBES 32
    static struct coverage_slot coverage[UDBG_COVERAGE_SLOTS];

    struct edge_slot {
      uintptr_t caller;
      uintptr_t callee;
      unsigned long count;
    };

    #define UDBG_EDGE_SLOTS 131072
    #define UDBG_EDGE_PROBES 32
    static struct edge_slot edges[UDBG_EDGE_SLOTS];

    static void trace_init(void) NOINST;
    static void trace_fini(void) NOINST;
    static void trace_write(char event, void *fn, void *site, unsigned depth) NOINST;
    static void trace_write_marker(
        const char *kind, const char *id, unsigned depth) NOINST;
    static void trace_write_scalar(
        const char *id, long long value, unsigned depth) NOINST;
    static void trace_record_coverage(void *fn) NOINST;
    static void trace_record_edge(void *caller, void *callee) NOINST;
    static void trace_write_coverage_record(
        uintptr_t address, unsigned long count) NOINST;
    static void trace_write_edge_record(
        uintptr_t caller, uintptr_t callee, unsigned long count) NOINST;
    static void trace_flush_coverage(void) NOINST;
    static void trace_flush_edges(void) NOINST;
    static void trace_reset_scenario_window(void) NOINST;
    static void trace_load_scope(void) NOINST;
    static int trace_scope_selected(void *fn) NOINST;
    static unsigned trace_output_depth(void) NOINST;
    static int trace_slice_probe_allowed(const char *id) NOINST;

    static void trace_init(void) {
      const char *path = getenv("UDBG_TRACE_FILE");
      const char *limit = getenv("UDBG_TRACE_MAX_EVENTS");
      const char *window = getenv("UDBG_TRACE_SCENARIO_WINDOW");
      const char *probe = getenv("UDBG_TRACE_PROBE_ONLY");
      const char *census = getenv("UDBG_TRACE_COVERAGE_ONLY");
      const char *crash_safe = getenv(
          "UDBG_TRACE_CRASH_SAFE_COVERAGE");
      const char *probe_limit = getenv(
          "UDBG_TRACE_PROBE_LIMIT_PER_ID");
      if (limit && *limit) {
        unsigned long value = strtoul(limit, NULL, 10);
        if (value > 0) trace_limit = value;
      }
      if (window && *window && strcmp(window, "0") != 0) {
        scenario_window = 1;
      }
      if (probe && *probe && strcmp(probe, "0") != 0) {
        probe_only = 1;
      }
      if (census && *census && strcmp(census, "0") != 0) {
        coverage_only = 1;
      }
      if (crash_safe && *crash_safe && strcmp(crash_safe, "0") != 0) {
        crash_safe_coverage = 1;
      }
      if (probe_limit && *probe_limit) {
        unsigned long value = strtoul(probe_limit, NULL, 10);
        if (value > 0) slice_probe_limit = value;
      }
      trace_load_scope();
      if (path && *path) {
        trace_fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0666);
      }
    }

    static void trace_fini(void) {
      trace_flush_coverage();
      if (coverage_only) trace_flush_edges();
      if (trace_fd >= 0) close(trace_fd);
      trace_fd = -1;
    }

    static void trace_record_coverage(void *fn) {
      uintptr_t address = (uintptr_t)fn;
      if (!address) return;
      size_t start = (size_t)((address >> 4) % UDBG_COVERAGE_SLOTS);
      for (size_t probe = 0; probe < UDBG_COVERAGE_PROBES; ++probe) {
        size_t index = (start + probe) % UDBG_COVERAGE_SLOTS;
        uintptr_t current = __atomic_load_n(
            &coverage[index].function, __ATOMIC_RELAXED);
        if (current == address) {
          __atomic_fetch_add(
              &coverage[index].count, 1UL, __ATOMIC_RELAXED);
          return;
        }
        if (!current && __atomic_compare_exchange_n(
                &coverage[index].function, &current, address, 0,
                __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
          __atomic_store_n(
              &coverage[index].count, 1UL, __ATOMIC_RELAXED);
          if (crash_safe_coverage) {
            trace_write_coverage_record(address, 1UL);
          }
          return;
        }
      }
    }

    static void trace_record_edge(void *caller, void *callee) {
      uintptr_t left = (uintptr_t)caller;
      uintptr_t right = (uintptr_t)callee;
      if (!left || !right) return;
      uintptr_t mixed =
          (left >> 4) ^ (right >> 4) ^ (right >> 17);
      size_t start = (size_t)(mixed % UDBG_EDGE_SLOTS);
      for (size_t probe = 0; probe < UDBG_EDGE_PROBES; ++probe) {
        size_t index = (start + probe) % UDBG_EDGE_SLOTS;
        uintptr_t current_left = __atomic_load_n(
            &edges[index].caller, __ATOMIC_RELAXED);
        uintptr_t current_right = __atomic_load_n(
            &edges[index].callee, __ATOMIC_RELAXED);
        if (current_left == left && current_right == right) {
          __atomic_fetch_add(
              &edges[index].count, 1UL, __ATOMIC_RELAXED);
          return;
        }
        if (!current_left && !current_right) {
          uintptr_t expected = 0;
          if (__atomic_compare_exchange_n(
                  &edges[index].caller, &expected, left, 0,
                  __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            __atomic_store_n(
                &edges[index].callee, right, __ATOMIC_RELAXED);
            __atomic_store_n(
                &edges[index].count, 1UL, __ATOMIC_RELAXED);
            if (crash_safe_coverage) {
              trace_write_edge_record(left, right, 1UL);
            }
            return;
          }
        }
      }
    }

    static void trace_write_coverage_record(
        uintptr_t address, unsigned long count) {
      if (trace_fd < 0) return;
      if (!address || !count) return;
      Dl_info info;
      memset(&info, 0, sizeof(info));
      const char *module = "";
      const char *symbol = "";
      uintptr_t base = 0;
      if (dladdr((void *)address, &info)) {
        module = info.dli_fname ? info.dli_fname : "";
        symbol = info.dli_sname ? info.dli_sname : "";
        base = (uintptr_t)info.dli_fbase;
      }
      uintptr_t offset =
          base && address >= base ? address - base : address;
      char line[4096];
      int length = snprintf(
          line, sizeof(line), "C\t%ld\t%lx\t%lx\t%s\t%s\t%lu\n",
          (long)getpid(),
          (unsigned long)address,
          (unsigned long)offset,
          module,
          symbol,
          count);
      if (length > 0) {
        size_t size =
            (size_t)length < sizeof(line)
                ? (size_t)length
                : sizeof(line) - 1;
        (void)write(trace_fd, line, size);
      }
    }

    static void trace_flush_coverage(void) {
      if (trace_fd < 0) return;
      for (size_t index = 0; index < UDBG_COVERAGE_SLOTS; ++index) {
        uintptr_t address = __atomic_load_n(
            &coverage[index].function, __ATOMIC_RELAXED);
        unsigned long count = __atomic_load_n(
            &coverage[index].count, __ATOMIC_RELAXED);
        if (crash_safe_coverage && count > 0) count--;
        trace_write_coverage_record(address, count);
      }
    }

    static void trace_write_edge_record(
        uintptr_t caller, uintptr_t callee, unsigned long count) {
      if (trace_fd < 0 || !caller || !callee || !count) return;
      Dl_info caller_info;
      Dl_info callee_info;
      memset(&caller_info, 0, sizeof(caller_info));
      memset(&callee_info, 0, sizeof(callee_info));
      (void)dladdr((void *)caller, &caller_info);
      (void)dladdr((void *)callee, &callee_info);
      uintptr_t caller_base = (uintptr_t)caller_info.dli_fbase;
      uintptr_t callee_base = (uintptr_t)callee_info.dli_fbase;
      uintptr_t caller_offset =
          caller_base && caller >= caller_base
              ? caller - caller_base : caller;
      uintptr_t callee_offset =
          callee_base && callee >= callee_base
              ? callee - callee_base : callee;
      char line[8192];
      int length = snprintf(
          line, sizeof(line),
          "D\t%ld\t%lx\t%lx\t%s\t%s\t%lx\t%lx\t%s\t%s\t%lu\n",
          (long)getpid(),
          (unsigned long)caller,
          (unsigned long)caller_offset,
          caller_info.dli_fname ? caller_info.dli_fname : "",
          caller_info.dli_sname ? caller_info.dli_sname : "",
          (unsigned long)callee,
          (unsigned long)callee_offset,
          callee_info.dli_fname ? callee_info.dli_fname : "",
          callee_info.dli_sname ? callee_info.dli_sname : "",
          count);
      if (length > 0) {
        size_t size =
            (size_t)length < sizeof(line)
                ? (size_t)length : sizeof(line) - 1;
        (void)write(trace_fd, line, size);
      }
    }

    static void trace_flush_edges(void) {
      if (trace_fd < 0) return;
      for (size_t index = 0; index < UDBG_EDGE_SLOTS; ++index) {
        uintptr_t caller = __atomic_load_n(
            &edges[index].caller, __ATOMIC_RELAXED);
        uintptr_t callee = __atomic_load_n(
            &edges[index].callee, __ATOMIC_RELAXED);
        unsigned long count = __atomic_load_n(
            &edges[index].count, __ATOMIC_RELAXED);
        if (crash_safe_coverage && count > 0) count--;
        trace_write_edge_record(caller, callee, count);
      }
    }

    static void trace_reset_scenario_window(void) {
      if (trace_fd < 0 || !scenario_window) return;
      if (ftruncate(trace_fd, 0) == 0) {
        (void)lseek(trace_fd, 0, SEEK_SET);
        __atomic_store_n(&trace_events, 0UL, __ATOMIC_RELAXED);
        /*
         * The marker can execute below an already active test frame.  The
         * ordered stream now starts at this marker, so carry no stale depth
         * into the new parser window.
         */
        trace_depth = 0;
        selected_depth = 0;
        memset(scope_stack, 0, sizeof(scope_stack));
        memset(function_stack, 0, sizeof(function_stack));
        memset(probe_counts, 0, sizeof(probe_counts));
      }
    }

    static void trace_load_scope(void) {
      const char *path = getenv("UDBG_TRACE_SCOPE_FILE");
      if (!path || !*path) return;
      FILE *stream = fopen(path, "r");
      if (!stream) return;
      char line[2048];
      while (
          fgets(line, sizeof(line), stream)
          && scope_range_count < UDBG_SCOPE_MAX_RANGES) {
        if (line[0] != 'A' || line[1] != '\t') continue;
        char *module = line + 2;
        char *start_text = strchr(module, '\t');
        if (!start_text) continue;
        *start_text++ = '\0';
        char *end_text = strchr(start_text, '\t');
        if (!end_text) continue;
        *end_text++ = '\0';
        char *newline = strchr(end_text, '\n');
        if (newline) *newline = '\0';
        if (!*module || !*start_text || !*end_text) continue;
        char *start_end = NULL;
        char *end_end = NULL;
        uintptr_t start = (uintptr_t)strtoull(start_text, &start_end, 16);
        uintptr_t end = (uintptr_t)strtoull(end_text, &end_end, 16);
        if (
            !start_end || *start_end
            || !end_end || *end_end
            || end <= start) {
          continue;
        }
        struct scope_range *item = &scope_ranges[scope_range_count++];
        strncpy(item->module, module, UDBG_SCOPE_MODULE_LEN - 1);
        item->module[UDBG_SCOPE_MODULE_LEN - 1] = '\0';
        item->start = start;
        item->end = end;
      }
      fclose(stream);
      scope_enabled = scope_range_count > 0;
    }

    static int trace_scope_selected(void *fn) {
      if (!scope_enabled) return 1;
      uintptr_t address = (uintptr_t)fn;
      if (!address) return 0;
      size_t start = (size_t)((address >> 4) % UDBG_SCOPE_CACHE_SLOTS);
      for (size_t probe = 0; probe < 16; ++probe) {
        size_t index = (start + probe) % UDBG_SCOPE_CACHE_SLOTS;
        uintptr_t current = __atomic_load_n(
            &scope_cache[index].function, __ATOMIC_RELAXED);
        if (current == address) {
          return __atomic_load_n(
              &scope_cache[index].selected, __ATOMIC_RELAXED) != 0;
        }
        if (!current) break;
      }
      Dl_info info;
      memset(&info, 0, sizeof(info));
      if (!dladdr(fn, &info) || !info.dli_fname) return 0;
      uintptr_t base = (uintptr_t)info.dli_fbase;
      uintptr_t offset = base && address >= base ? address - base : address;
      int selected = 0;
      for (unsigned long index = 0; index < scope_range_count; ++index) {
        struct scope_range *item = &scope_ranges[index];
        if (
            strcmp(item->module, info.dli_fname) == 0
            && offset >= item->start
            && offset < item->end) {
          selected = 1;
          break;
        }
      }
      for (size_t probe = 0; probe < 16; ++probe) {
        size_t index = (start + probe) % UDBG_SCOPE_CACHE_SLOTS;
        uintptr_t current = __atomic_load_n(
            &scope_cache[index].function, __ATOMIC_RELAXED);
        if (current == address || !current) {
          __atomic_store_n(
              &scope_cache[index].selected, (unsigned char)selected,
              __ATOMIC_RELAXED);
          __atomic_store_n(
              &scope_cache[index].function, address, __ATOMIC_RELAXED);
          break;
        }
      }
      return selected;
    }

    static unsigned trace_output_depth(void) {
      return scope_enabled ? selected_depth : trace_depth;
    }

    static int trace_slice_probe_allowed(const char *id) {
      if (
          !id
          || (
              strncmp(id, "slice_", 6) != 0
              && strncmp(id, "probe_", 6) != 0)) {
        return 1;
      }
      unsigned long hash = 1469598103934665603UL;
      for (const unsigned char *cursor =
               (const unsigned char *)id; *cursor; ++cursor) {
        hash ^= (unsigned long)*cursor;
        hash *= 1099511628211UL;
      }
      if (!hash) hash = 1;
      size_t start = (size_t)(hash % UDBG_PROBE_SLOTS);
      for (size_t probe = 0; probe < 16; ++probe) {
        size_t index = (start + probe) % UDBG_PROBE_SLOTS;
        unsigned long current = __atomic_load_n(
            &probe_counts[index].hash, __ATOMIC_RELAXED);
        if (current == hash) {
          unsigned long observed = __atomic_load_n(
              &probe_counts[index].count, __ATOMIC_RELAXED);
          if (observed >= slice_probe_limit) return 0;
          unsigned long count = __atomic_fetch_add(
              &probe_counts[index].count, 1UL, __ATOMIC_RELAXED);
          return count < slice_probe_limit;
        }
        if (!current) {
          unsigned long expected = 0;
          if (__atomic_compare_exchange_n(
                  &probe_counts[index].hash, &expected, hash, 0,
                  __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
            __atomic_store_n(
                &probe_counts[index].count, 1UL, __ATOMIC_RELAXED);
            return 1;
          }
        }
      }
      return 0;
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
      if (
          scenario_window
          && kind
          && strcmp(kind, "scenario_begin") == 0) {
        trace_reset_scenario_window();
        depth = 0;
      }
      if (
          kind
          && strncmp(kind, "slice_", 6) == 0
          && !trace_slice_probe_allowed(id)) {
        return;
      }
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
      if (!trace_slice_probe_allowed(id)) return;
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
      trace_write_marker(kind, id, trace_output_depth());
    }

    void udbg_trace_scalar(const char *id, long long value)
        __attribute__((no_instrument_function, visibility("default")));

    void udbg_trace_scalar(const char *id, long long value) {
      trace_write_scalar(id, value, trace_output_depth());
    }

    void __cyg_profile_func_enter(void *fn, void *site)
        __attribute__((no_instrument_function));
    void __cyg_profile_func_exit(void *fn, void *site)
        __attribute__((no_instrument_function));

    void __cyg_profile_func_enter(void *fn, void *site) {
      int selected = trace_scope_selected(fn);
      void *parent = (
          trace_depth > 0 && trace_depth <= UDBG_SCOPE_STACK_DEPTH
          ? function_stack[trace_depth - 1] : NULL);
      if (trace_depth < UDBG_SCOPE_STACK_DEPTH) {
        scope_stack[trace_depth] = (unsigned char)(selected != 0);
        function_stack[trace_depth] = fn;
      } else {
        /* Preserve information rather than silently dropping deep frames. */
        selected = 1;
      }
      if (!probe_only) {
        trace_record_coverage(fn);
        if (coverage_only) {
          trace_record_edge(parent, fn);
        } else if (selected) {
          trace_write('E', fn, site, trace_output_depth());
        }
      }
      trace_depth++;
      if (selected) selected_depth++;
    }

    void __cyg_profile_func_exit(void *fn, void *site) {
      if (trace_depth > 0) trace_depth--;
      int selected = 1;
      if (trace_depth < UDBG_SCOPE_STACK_DEPTH) {
        selected = scope_stack[trace_depth] != 0;
        scope_stack[trace_depth] = 0;
        function_stack[trace_depth] = NULL;
      }
      if (selected && selected_depth > 0) selected_depth--;
      if (!probe_only && !coverage_only && selected) {
        trace_write('X', fn, site, trace_output_depth());
      }
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
        trace_write('T', site, site, trace_output_depth());
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


def _positive_int_env(name: str, default: int) -> int:
    try:
        value = int(str(os.getenv(name, "") or "").strip())
    except ValueError:
        return default
    return value if value > 0 else default


def _normalize_trace_scope_key(value: Any) -> str:
    """Normalize Defects4C ``file:function`` coverage keys."""
    text = str(value or "").strip().replace("\\", "/")
    if not text:
        return ""
    match = re.match(
        r"^(?P<file>.+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx))::(?P<func>.+)$",
        text,
    )
    if match:
        return (
            f"{os.path.basename(match.group('file'))}:"
            f"{match.group('func').strip()}"
        )
    separator = text.find(":")
    if separator >= 0 and not text.startswith("::", separator):
        file_hint = text[:separator].strip()
        function = text[separator + 1:].strip()
        if file_hint and function:
            return f"{os.path.basename(file_hint)}:{function}"
    return text


def _trace_scope_function(key: str) -> str:
    text = str(key or "")
    match = re.search(r"(?<!:):(?!:)", text)
    function = text[match.end():] if match else text
    function = re.sub(r"\s+\[clone [^\]]+\]$", "", function)
    function = re.sub(r"\([^()]*\)\s*$", "", function)
    function = re.sub(r"\s+", "", function)
    return function.strip()


def _trace_scope_function_match(actual: str, requested: str) -> bool:
    """Match nm's demangled function names to coverage spellings."""
    actual = str(actual or "").strip()
    requested = str(requested or "").strip()
    if not actual or not requested:
        return False
    actual = re.sub(r"\s+\[clone [^\]]+\]$", "", actual)
    actual = re.sub(r"\([^()]*\)\s*$", "", actual)
    actual = re.sub(r"\s+", "", actual)
    requested = re.sub(r"\s+\[clone [^\]]+\]$", "", requested)
    requested = re.sub(r"\([^()]*\)\s*$", "", requested)
    requested = re.sub(r"\s+", "", requested)
    if actual == requested:
        return True
    if actual.endswith("::" + requested):
        return True
    actual_leaf = actual.rsplit("::", 1)[-1]
    requested_leaf = requested.rsplit("::", 1)[-1]
    return "::" not in requested and actual_leaf == requested_leaf


def _coverage_scope_records_for_test(bug: Any, test_id: str) -> Dict[str, Any]:
    """Read the existing Defects4C/Tarantula production coverage for a test."""
    record = next(
        (
            item
            for item in getattr(bug, "tests", None) or []
            if isinstance(item, dict)
            and str(item.get("test_id") or "") == str(test_id or "")
        ),
        {},
    )
    covered = record.get("covered_functions")
    if covered is None:
        covered = record.get("covered_methods")
    normalized = sorted({
        _normalize_trace_scope_key(value)
        for value in covered or []
        if _normalize_trace_scope_key(value)
    })
    production = [
        value
        for value in normalized
        if re.search(r"\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx):", value)
    ]
    if not production:
        return {
            "schema": TRACE_SCOPE_SCHEMA,
            "enabled": False,
            "mode": "disabled",
            "source": "defects4c_metadata.covered_functions",
            "requested_keys": [],
            "diagnostics": ["coverage_metadata_missing_for_regression_test"],
        }
    return {
        "schema": TRACE_SCOPE_SCHEMA,
        "enabled": False,
        "mode": "pending_nm_address_scope",
        "source": "defects4c_metadata.covered_functions",
        "requested_keys": production,
        "requested_functions": sorted({
            _trace_scope_function(value) for value in production
            if _trace_scope_function(value)
        }),
        # Failure-semantic seeds are deliberately unavailable until the
        # regression census has produced fresh output and a Fail Context.
        "seed_functions": [],
        "diagnostics": [],
    }


def _refine_trace_scope_from_census(
    *,
    bug: Any,
    test_id: str,
    base_scope: Dict[str, Any],
    census_test: Dict[str, Any],
    artifact_dir: str,
    fail_context: Dict[str, Any] = None,
    compilation_database: str = "",
) -> Dict[str, Any]:
    """Build a bounded executed producer-to-sink slice for detailed tracing."""
    census_functions = {
        str(key): value
        for key, value in (census_test.get("functions") or {}).items()
        if str(key) and isinstance(value, dict)
    }
    metadata_keys = {
        _normalize_trace_scope_key(value)
        for value in base_scope.get("requested_keys") or []
        if _normalize_trace_scope_key(value)
    }
    metadata_executed_candidates = {
        key
        for key in census_functions
        if _normalize_trace_scope_key(key) in metadata_keys
    }
    # Fresh census execution is authoritative. Dataset coverage remains an
    # optimization/audit hint and must never hide a function that actually ran.
    executed_candidates = set(census_functions)
    if not census_functions:
        return {
            **base_scope,
            "enabled": False,
            "requested_functions": [],
            "detailed_function_keys": [],
            "detailed_function_count": 0,
            "slice_probes": [],
            "slice_probe_count": 0,
            "required_scope_over_budget": False,
            "mode": "pending_nm_address_scope",
            "selection_strategy": "query_driven_census_unavailable",
            "diagnostics": [
                *(base_scope.get("diagnostics") or []),
                "trace_census_no_executed_candidates",
            ],
        }

    candidate_edges = [
        edge
        for edge in census_test.get("dynamic_edges") or []
        if str(edge.get("caller") or "") in executed_candidates
        and str(edge.get("callee") or "") in executed_candidates
    ]
    census_runtime = {
        "tests": [census_test],
        "functions": {
            key: census_functions[key]
            for key in executed_candidates
        },
        "dynamic_edges": candidate_edges,
        "compile": {
            "compilation_database": compilation_database,
        },
    }
    producer_symbols = {
        str(value)
        for value in base_scope.get("seed_functions") or []
        if str(value)
    }
    source_evidence: Dict[str, Any] = {}
    scenario: Dict[str, Any] = {}
    try:
        from .causal import collect_failure_evidence
        from .investigation import load_or_build_source_evidence
        from .scenario import build_scenario_analysis

        failure_evidence = collect_failure_evidence(
            bug,
            runtime_evidence=census_runtime,
            fail_context=fail_context,
        )
        producer_symbols.update(
            str(value)
            for value in (
                failure_evidence.get("failure_seeds") or {}
            ).get("producer_call_symbols") or []
            if str(value)
        )
        scenario = (
            build_scenario_analysis(failure_evidence).get(
                "first_failing_scenario"
            )
            or {}
        )
        producer_symbols.update(
            str(value)
            for value in scenario.get("producer_calls") or []
            if str(value)
        )
        source_evidence = load_or_build_source_evidence(
            bug=bug,
            runtime_evidence=census_runtime,
            scenario=scenario,
            # Per-test refinement is transient. Structural file/dossier caches
            # already avoid recomputation; only the aggregate broker/final FL
            # projection is persisted.
            artifact_dir="",
        )
    except Exception:
        source_evidence = {}

    producer_roots = {
        key
        for key in executed_candidates
        if any(
            _trace_scope_function_match(
                _trace_scope_function(key),
                _trace_scope_function(symbol),
            )
            for symbol in producer_symbols
        )
    }
    dossiers = source_evidence.get("dossiers") or {}
    counts = {
        key: max(
            1,
            int(
                census_functions[key].get("coverage_enter_count")
                or census_functions[key].get("enter_count")
                or 0
            ),
        )
        for key in executed_candidates
    }
    dynamic_graph: Dict[str, set] = defaultdict(set)
    for edge in candidate_edges:
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller in executed_candidates and callee in executed_candidates:
            dynamic_graph[caller].add(callee)
    graph: Dict[str, set] = defaultdict(set)
    for caller, callees in dynamic_graph.items():
        graph[caller].update(callees)
    static_edge_count = 0
    static_edge_pairs = set()
    functions_by_leaf: Dict[str, set] = defaultdict(set)
    for key in executed_candidates:
        functions_by_leaf[
            _trace_scope_function(key).rsplit("::", 1)[-1]
        ].add(key)
    for caller in executed_candidates:
        for call in (dossiers.get(caller) or {}).get("calls") or []:
            expression = _trace_scope_function(
                str(call.get("expression") or "")
            ).rsplit("::", 1)[-1]
            for callee in functions_by_leaf.get(expression, set()):
                if caller == callee:
                    continue
                static_edge_pairs.add((caller, callee))
                if callee not in graph[caller]:
                    static_edge_count += 1
                graph[caller].add(callee)

    reachable = _graph_reachable_from(
        graph, starts=producer_roots
    ) if producer_roots else set(executed_candidates)
    try:
        from .semantic import semantic_tokens

        scenario_tokens = set(semantic_tokens([
            str(scenario.get("source") or ""),
            str(scenario.get("producer_source") or ""),
            *(scenario.get("input_literals") or []),
            *((scenario.get("observed_output") or {}).get("expected") or []),
            *((scenario.get("observed_output") or {}).get("actual") or []),
        ]))
    except Exception:
        scenario_tokens = set()
    matches_by_key = {}
    for key in executed_candidates:
        source_matches = set(
            str(value)
            for value in (
                (dossiers.get(key) or {}).get(
                    "contract_token_matches"
                )
                or []
            )
            if str(value)
        )
        name_matches = scenario_tokens & (
            _slice_expression_identifiers(key)
        )
        matches_by_key[key] = source_matches or name_matches
    token_frequency = Counter(
        token
        for key in executed_candidates
        for token in matches_by_key[key]
    )
    contract_sink_ranked = []
    boundary_sink_ranked = []
    sink_evidence: Dict[str, Dict[str, Any]] = {}
    for key in executed_candidates & reachable:
        if key in producer_roots:
            continue
        dossier = dossiers.get(key) or {}
        matches = sorted(matches_by_key[key])
        boundary_kind = _slice_boundary_kind(
            key=key,
            dossier=dossier,
        )
        behavior_count = sum(
            len(dossier.get(field) or [])
            for field in (
                "returns",
                "conditions",
                "assignments",
                "calls",
                "throws",
            )
        )
        source_available = bool(dossier.get("source_available"))
        if (
            (not matches and not boundary_kind)
            or (source_available and behavior_count <= 0 and not boundary_kind)
        ):
            continue
        specificity = sum(
            1.0 / max(1, int(token_frequency[token]))
            for token in matches
        )
        sink_evidence[key] = {
            "kind": boundary_kind or "contract_token_match",
            "contract_tokens": matches,
        }
        rank = (
            -specificity,
            -len(matches),
            counts[key],
            key,
        )
        if matches:
            contract_sink_ranked.append(rank)
        if boundary_kind:
            boundary_sink_ranked.append(rank)
    contract_sink_ranked.sort()
    boundary_sink_ranked.sort()
    contract_limit = max(
        0,
        TRACE_SLICE_SINK_LIMIT - TRACE_SLICE_BOUNDARY_SINK_LIMIT,
    )
    sink_candidates = list(dict.fromkeys([
        *(
            item[-1]
            for item in contract_sink_ranked[:contract_limit]
        ),
        *(
            item[-1]
            for item in boundary_sink_ranked[
                :TRACE_SLICE_BOUNDARY_SINK_LIMIT
            ]
        ),
        *(
            item[-1]
            for item in sorted(
                [*contract_sink_ranked, *boundary_sink_ranked]
            )
        ),
    ]))[:TRACE_SLICE_SINK_LIMIT]

    slice_paths = []
    sink_keys = []
    for sink in sink_candidates:
        path = _shortest_executed_path(
            dynamic_graph,
            starts=producer_roots,
            target=sink,
            counts=counts,
        )
        mode = "dynamic"
        if not path:
            path = _shortest_executed_path(
                graph,
                starts=producer_roots,
                target=sink,
                counts=counts,
            )
            mode = "dynamic_plus_static"
        if not path:
            continue
        sink_keys.append(sink)
        slice_paths.append({
            "sink": sink,
            "mode": mode,
            "functions": path,
        })
    path_keys = {
        key
        for path in slice_paths
        for key in path["functions"]
    }
    if not path_keys:
        path_keys.update(producer_roots)
        path_keys.update(sink_candidates[:1])

    reverse_graph: Dict[str, set] = defaultdict(set)
    for caller, callees in graph.items():
        for callee in callees:
            reverse_graph[callee].add(caller)
    frontier = set()
    for key in path_keys:
        frontier.update(graph.get(key, set()))
        frontier.update(reverse_graph.get(key, set()))
    frontier &= executed_candidates
    frontier -= path_keys
    frontier = set(sorted(
        frontier,
        key=lambda key: (counts[key], key),
    )[:TRACE_SLICE_FRONTIER_LIMIT])

    budget = min(
        TRACE_HARD_MAX_EVENTS,
        _positive_int_env(
            "UDBG_TRACE_DETAILED_EVENT_BUDGET",
            TRACE_DETAILED_EVENT_BUDGET,
        ),
    )
    probe_reserve = min(
        max(0, budget // 2),
        _positive_int_env(
            "UDBG_TRACE_SLICE_PROBE_EVENT_RESERVE",
            TRACE_SLICE_PROBE_EVENT_RESERVE,
        ),
    )
    ordered_budget = max(1, budget - probe_reserve)
    roles: Dict[str, set] = defaultdict(set)
    for key in producer_roots:
        roles[key].add("producer_root")
    for key in sink_keys:
        roles[key].add("output_error_sink")
    for key in path_keys:
        roles[key].add("executed_path")
    for key in frontier:
        roles[key].add("frontier")
    dispatch_related = set()
    for caller, callees in dynamic_graph.items():
        for callee in callees:
            if (caller, callee) not in static_edge_pairs:
                dispatch_related.update({caller, callee})
    dispatch_related &= executed_candidates
    for key in dispatch_related & (path_keys | frontier | producer_roots):
        roles[key].add("callback_or_indirect_dispatch")
    priority = []
    for key in roles:
        role_order = min(
            (
                0 if role == "producer_root"
                else 1 if role == "output_error_sink"
                else 2 if role == "executed_path"
                else 3
            )
            for role in roles[key]
        )
        priority.append((role_order, counts[key], key))
    priority.sort()
    selected = set()
    budget_dropped = []
    estimated_events = 0
    for _, _, key in priority:
        cost = 2 * counts[key]
        if estimated_events + cost > ordered_budget:
            budget_dropped.append(key)
            continue
        selected.add(key)
        estimated_events += cost
    if not selected:
        fallback = min(
            executed_candidates,
            key=lambda key: (counts[key], key),
        )
        if 2 * counts[fallback] <= ordered_budget:
            selected.add(fallback)
            roles[fallback].add("bounded_fallback")
            estimated_events = 2 * counts[fallback]

    probe_targets = path_keys | producer_roots | set(sink_keys)
    if not probe_targets:
        probe_targets = set(selected)
    slice_probes, estimated_probe_events = _build_slice_probe_plan(
        dossiers=dossiers,
        scenario=scenario,
        selected=probe_targets,
        roles=roles,
        counts=counts,
        event_budget=probe_reserve,
    )
    slice_probe_limit_per_id = max(
        1,
        min(
            TRACE_SLICE_PROBE_SAMPLE_LIMIT,
            probe_reserve // max(1, len(slice_probes)),
        ),
    )
    estimated_probe_events = (
        slice_probe_limit_per_id * len(slice_probes)
    )

    aggregate_only = sorted(
        executed_candidates - selected,
        key=lambda value: (-counts[value], value),
    )
    selected_functions = sorted({
        _trace_scope_function(key)
        for key in selected
        if _trace_scope_function(key)
    })
    observed_runtime_modules = sorted({
        str(module)
        for record in census_functions.values()
        for module in record.get("runtime_modules") or []
        if str(module)
    })
    return {
        **base_scope,
        "enabled": False,
        "mode": "pending_refined_nm_address_scope",
        "selection_strategy": (
            "query_driven_producer_sink_v1"
        ),
        "requested_functions": selected_functions,
        "observed_runtime_modules": observed_runtime_modules,
        "candidate_function_count": len(executed_candidates),
        "metadata_candidate_count": len(metadata_keys),
        "metadata_executed_candidate_count": len(
            metadata_executed_candidates
        ),
        "census_only_candidate_count": len(
            executed_candidates - metadata_executed_candidates
        ),
        "executed_candidate_count": len(executed_candidates),
        "census_function_count": len(census_functions),
        "census_edge_count": len(
            census_test.get("dynamic_edges") or []
        ),
        "static_edge_count": static_edge_count,
        "producer_root_keys": sorted(producer_roots),
        "output_error_sink_keys": sink_keys,
        "sink_evidence": {
            key: sink_evidence.get(key) or {}
            for key in sink_keys
        },
        "sink_evidence_mode": (
            "source_contract_with_name_fallback"
            if any(
                not (dossiers.get(key) or {}).get("source_available")
                for key in sink_keys
            )
            else "source_contract"
        ),
        "slice_paths": slice_paths,
        "path_function_keys": sorted(path_keys),
        "path_function_count": len(path_keys),
        "frontier_keys": sorted(frontier),
        "dispatch_related_keys": sorted(dispatch_related),
        "detailed_function_keys": sorted(selected),
        "detailed_function_count": len(selected),
        "detailed_roles": {
            key: sorted(roles[key])
            for key in sorted(selected)
        },
        "budget_dropped_function_keys": budget_dropped,
        "budget_dropped_function_count": len(budget_dropped),
        "aggregate_only_function_count": len(aggregate_only),
        "aggregate_only_hot_functions": [
            {"key": key, "enter_count": counts[key]}
            for key in aggregate_only[:40]
        ],
        "detailed_event_budget": budget,
        "ordered_event_budget": ordered_budget,
        "slice_probe_event_reserve": probe_reserve,
        "estimated_detailed_event_count": estimated_events,
        "estimated_probe_event_count": estimated_probe_events,
        "estimated_total_event_count": (
            estimated_events + estimated_probe_events
        ),
        "slice_probes": slice_probes,
        "probe_function_keys": sorted(probe_targets),
        "slice_probe_count": len(slice_probes),
        "slice_probe_limit_per_id": slice_probe_limit_per_id,
        "required_scope_over_budget": False,
        "scenario_id": str(
            scenario.get("scenario_id")
            or scenario.get("scenario_fingerprint")
            or ""
        ),
        "ground_truth_used": False,
        "diagnostics": list(base_scope.get("diagnostics") or []),
    }


def _graph_reachable_from(
    graph: Dict[str, set], *, starts: Iterable[str]
) -> set:
    pending = list(dict.fromkeys(str(value) for value in starts if str(value)))
    visited = set()
    while pending:
        key = pending.pop()
        if key in visited:
            continue
        visited.add(key)
        pending.extend(
            child for child in graph.get(key, set())
            if child not in visited
        )
    return visited


def _shortest_executed_path(
    graph: Dict[str, set],
    *,
    starts: Iterable[str],
    target: str,
    counts: Dict[str, int],
) -> List[str]:
    starts = sorted(set(str(value) for value in starts if str(value)))
    if not starts or not target:
        return []
    pending = list(starts)
    parent = {key: "" for key in starts}
    for current in pending:
        if current == target:
            return [current]
        for child in sorted(
            graph.get(current, set()),
            key=lambda key: (counts.get(key, 1), key),
        ):
            if child in parent:
                continue
            parent[child] = current
            if child == target:
                path = [target]
                while parent[path[-1]]:
                    path.append(parent[path[-1]])
                return list(reversed(path))
            pending.append(child)
    return []


def _build_slice_probe_plan(
    *,
    dossiers: Dict[str, Any],
    scenario: Dict[str, Any],
    selected: set,
    roles: Dict[str, set],
    counts: Dict[str, int],
    event_budget: int,
) -> Tuple[List[Dict[str, Any]], int]:
    """Select bounded source probes only on the executed producer/sink paths."""
    try:
        from .semantic import semantic_tokens

        relevant_tokens = set(semantic_tokens([
            str(scenario.get("source") or ""),
            str(scenario.get("producer_source") or ""),
            *(scenario.get("input_literals") or []),
            *((scenario.get("observed_output") or {}).get("expected") or []),
            *((scenario.get("observed_output") or {}).get("actual") or []),
        ]))
    except Exception:
        relevant_tokens = set()
    candidates = []
    kind_order = {
        "return_value": 0,
        "output_write": 1,
        "branch_outcome": 2,
        "argument": 3,
    }
    field_by_kind = {
        "return_value": "returns",
        "output_write": "assignments",
        "branch_outcome": "conditions",
    }
    for key in selected:
        dossier = dossiers.get(key) or {}
        endpoint = bool(
            roles.get(key, set())
            & {"output_error_sink", "producer_root"}
        )
        role_order = min(
            (
                0 if role == "output_error_sink"
                else 1 if role == "producer_root"
                else 2 if role == "executed_path"
                else 3
            )
            for role in roles.get(key) or {"executed_path"}
        )
        live_tokens = set(relevant_tokens)
        live_tokens.update(
            str(value).lower()
            for value in dossier.get("contract_token_matches") or []
            if str(value)
        )
        selected_sites: Dict[str, List[Dict[str, Any]]] = {
            "return_value": [],
            "output_write": [],
            "branch_outcome": [],
        }
        for item in dossier.get("returns") or []:
            identifiers = _slice_expression_identifiers(
                item.get("expression")
            )
            if endpoint or identifiers & live_tokens:
                selected_sites["return_value"].append(item)
                live_tokens.update(identifiers)
        for item in reversed(dossier.get("assignments") or []):
            expression = str(item.get("expression") or "")
            identifiers = _slice_expression_identifiers(expression)
            lhs = re.split(
                r"(?<![=!<>])=(?!=)|\+=|-=|\*=|/=|%=|\+\+|--",
                expression,
                maxsplit=1,
            )[0]
            lhs_identifiers = _slice_expression_identifiers(lhs)
            if (
                lhs_identifiers & live_tokens
                or identifiers & live_tokens
            ):
                selected_sites["output_write"].append(item)
                live_tokens.update(identifiers)
        for item in dossier.get("conditions") or []:
            identifiers = _slice_expression_identifiers(
                item.get("expression")
            )
            if identifiers & live_tokens:
                selected_sites["branch_outcome"].append(item)

        signature = str(dossier.get("signature") or "")
        if signature and (endpoint or live_tokens):
            candidates.append((
                role_order,
                kind_order["argument"],
                counts[key],
                key,
                {
                    "kind": "argument",
                    "line": int(dossier.get("source_line") or 0),
                    "expression": signature,
                },
            ))
        for kind, field in field_by_kind.items():
            records = list(dossier.get(field) or [])
            relevant = selected_sites[kind]
            if not relevant and endpoint:
                relevant = records[:1]
            for item in relevant[:2]:
                candidates.append((
                    role_order,
                    kind_order[kind],
                    counts[key],
                    key,
                    {
                        "kind": kind,
                        "line": int(item.get("line") or 0),
                        "expression": str(
                            item.get("expression") or ""
                        ),
                    },
                ))
    probes = []
    estimated = 0
    seen = set()
    for _, _, execution_count, key, site in sorted(
        candidates,
        key=lambda item: (
            item[0],
            item[1],
            item[2],
            item[3],
            int(item[4].get("line") or 0),
            str(item[4].get("expression") or ""),
        ),
    ):
        identity = (
            key,
            site["kind"],
            site["line"],
            site["expression"],
        )
        if identity in seen or len(probes) >= TRACE_SLICE_MAX_PROBES:
            continue
        # Hot functions must remain probeable. Runtime enforces a separate
        # per-probe quota, so estimate the bounded samples instead of charging
        # the function's full execution count against the query budget.
        cost = min(
            max(1, int(execution_count)),
            TRACE_SLICE_PROBE_SAMPLE_LIMIT,
        )
        if estimated + cost > event_budget:
            continue
        seen.add(identity)
        payload = "\0".join(str(value) for value in identity)
        source_path = str(
            (dossiers.get(key) or {}).get("source_path") or ""
        )
        probes.append({
            "probe_id": "slice_" + hashlib.sha256(
                payload.encode("utf-8")
            ).hexdigest()[:20],
            "function": key,
            "kind": site["kind"],
            "source_path": source_path,
            "line": site["line"],
            "expression": site["expression"],
            "execution_count": int(execution_count),
            "estimated_event_count": cost,
        })
        estimated += cost
    return probes, estimated


def _slice_expression_identifiers(value: Any) -> set:
    ignored = {
        "auto", "bool", "break", "case", "char", "const", "continue",
        "default", "do", "double", "else", "enum", "false", "float",
        "for", "goto", "if", "int", "long", "null", "nullptr", "return",
        "short", "signed", "sizeof", "static", "struct", "switch", "true",
        "typedef", "union", "unsigned", "void", "volatile", "while",
    }
    return {
        token
        for token in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*",
            str(value or "").lower(),
        )
        if len(token) >= 2 and token not in ignored
    }


def _slice_boundary_kind(*, key: str, dossier: Dict[str, Any]) -> str:
    """Classify explicit output/error boundaries without using ground truth."""
    text = " ".join([
        str(key or ""),
        str(dossier.get("signature") or ""),
        *(
            str(item.get("expression") or "")
            for field in ("calls", "throws", "returns", "assignments")
            for item in dossier.get(field) or []
            if isinstance(item, dict)
        ),
    ]).lower()
    if dossier.get("throws"):
        return "exception_boundary"
    if re.search(
        r"\b(?:assert|abort|panic|fatal|error|err|fail|"
        r"fprintf|printf|snprintf|puts|perror|log|write|"
        r"stderr|stdout|output)\b",
        text,
    ):
        return "error_log_output_boundary"
    return ""


def _collect_trace_nm_output(
    *, container: str, container_repo: str
) -> Tuple[str, bool]:
    query = (
        f"repo={shlex.quote(container_repo.rstrip('/'))}; "
        "find \"$repo\" -type f "
        "\\( -perm -111 -o -name '*.so' -o -name '*.so.*' \\) "
        "-print0 2>/dev/null | "
        "while IFS= read -r -d '' file; do "
        "  nm -anC --defined-only \"$file\" 2>/dev/null | "
        "  sed \"s#^#$file\\t#\"; "
        "done"
    )
    listed = _docker_exec(container, query, timeout=180)
    return (
        str(listed.get("stdout") or ""),
        listed.get("returncode") == 0,
    )


def _runtime_module_match_score(
    candidate: str,
    observed: str,
) -> int:
    """Match an nm module to the exact module spelling emitted by dladdr."""
    candidate = os.path.normpath(
        str(candidate or "").replace("\\", "/")
    )
    observed = os.path.normpath(
        str(observed or "").replace("\\", "/")
    )
    if not candidate or not observed or observed == ".":
        return 0
    if candidate == observed:
        return 4
    relative = observed
    while relative.startswith("../"):
        relative = relative[3:]
    relative = relative.lstrip("./")
    if relative and (
        candidate == relative
        or candidate.endswith("/" + relative)
    ):
        return 3
    if os.path.basename(candidate) == os.path.basename(observed):
        return 1
    return 0


def _select_trace_scope_modules(
    *,
    module_matches: Dict[str, set],
    module_ranges: Dict[str, List[Tuple[str, int, int]]],
    requested: List[str],
    test_id: str,
    observed_runtime_modules: List[str],
) -> Dict[str, Any]:
    """Select the smallest executed module set that covers requested symbols."""
    candidates = {
        module
        for module, matches in module_matches.items()
        if matches
    }
    requested_set = set(requested)
    suite = str(test_id or "").split("::", 1)[0].strip()
    suite_variants = {
        suite,
        suite.replace("_", "-"),
        suite.replace("-", "_"),
    } - {""}
    hint_modules = {
        module
        for module in candidates
        if os.path.basename(module) in suite_variants
    }
    observed_scores = {
        module: max(
            (
                _runtime_module_match_score(module, observed)
                for observed in observed_runtime_modules
            ),
            default=0,
        )
        for module in candidates
    }
    observed_candidates = {
        module
        for module, score in observed_scores.items()
        if score > 0
    }
    if observed_candidates:
        primary_pool = observed_candidates
        strategy = "runtime_census_modules"
    elif hint_modules:
        primary_pool = hint_modules
        strategy = "test_suite_hint"
    else:
        primary_pool = candidates
        strategy = "symbol_coverage_fallback"

    selected: List[str] = []
    covered = set()

    def add_greedy(pool: Iterable[str]) -> None:
        remaining = set(pool) - set(selected)
        while remaining and requested_set - covered:
            ordered = sorted(remaining)
            module = max(
                ordered,
                key=lambda value: (
                    len(
                        module_matches[value]
                        & (requested_set - covered)
                    ),
                    observed_scores.get(value, 0),
                    int(value in hint_modules),
                    int(".so" not in os.path.basename(value)),
                    -len(module_ranges.get(value) or []),
                ),
            )
            gain = (
                module_matches[module]
                & (requested_set - covered)
            )
            if not gain:
                break
            selected.append(module)
            covered.update(gain)
            remaining.remove(module)

    add_greedy(primary_pool)
    if requested_set - covered:
        add_greedy(candidates)

    aliases_by_module = {}
    observed_matches = {}
    for module in selected:
        aliases = sorted({
            str(observed)
            for observed in observed_runtime_modules
            if _runtime_module_match_score(module, observed) > 0
        })
        aliases_by_module[module] = aliases or [module]
        if aliases:
            observed_matches[module] = aliases
    return {
        "selected_modules": selected,
        "covered_functions": sorted(covered),
        "uncovered_functions": sorted(requested_set - covered),
        "selection_strategy": strategy,
        "runtime_module_aliases": aliases_by_module,
        "observed_module_matches": observed_matches,
        "suite_hint_modules": sorted(hint_modules),
    }


def _build_trace_scope_file(
    *,
    container: str,
    container_repo: str,
    container_trace_root: str,
    host_artifact_dir: str,
    test_id: str,
    scope: Dict[str, Any],
    nm_output: str = "",
    nm_available: bool = True,
    nm_loaded: bool = False,
) -> Dict[str, Any]:
    """Resolve coverage functions to post-build symbol address ranges.

    ``dladdr`` does not expose names of ``static`` functions.  Address ranges
    from ``nm -C`` therefore provide a safe function-level filter for both C
    and C++, while keeping the recording hook independent of source paths.
    """
    requested = [
        str(value)
        for value in scope.get("requested_functions") or []
        if str(value)
    ]
    if not requested:
        return {
            **scope,
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_no_requested_functions",
            ],
        }
    if not nm_loaded and nm_available:
        nm_output, nm_available = _collect_trace_nm_output(
            container=container,
            container_repo=container_repo,
        )
    if not nm_available:
        return {
            **scope,
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_nm_failed",
            ],
        }
    rows_by_module: Dict[str, List[Tuple[int, str]]] = defaultdict(list)
    for line in str(nm_output or "").splitlines():
        module, separator, payload = line.partition("\t")
        if not separator:
            continue
        parts = payload.split(None, 2)
        if len(parts) != 3:
            continue
        address_text, kind, symbol = parts
        if kind not in {"T", "t", "W", "w"}:
            continue
        try:
            address = int(address_text, 16)
        except ValueError:
            continue
        if address <= 0 or not symbol:
            continue
        rows_by_module[module].append((address, symbol))

    module_ranges: Dict[str, List[Tuple[str, int, int]]] = defaultdict(list)
    module_matches: Dict[str, set] = defaultdict(set)
    for module, rows in rows_by_module.items():
        ordered = sorted(set(rows), key=lambda item: (item[0], item[1]))
        for index, (address, symbol) in enumerate(ordered):
            symbol_matches = {
                requested_name
                for requested_name in requested
                if _trace_scope_function_match(symbol, requested_name)
            }
            if not symbol_matches:
                continue
            next_address = next(
                (
                    item[0]
                    for item in ordered[index + 1:]
                    if item[0] > address
                ),
                address + 1,
            )
            if next_address <= address:
                next_address = address + 1
            module_ranges[module].append((module, address, next_address))
            module_matches[module].update(symbol_matches)

    selection = _select_trace_scope_modules(
        module_matches=module_matches,
        module_ranges=module_ranges,
        requested=requested,
        test_id=test_id,
        observed_runtime_modules=list(
            scope.get("observed_runtime_modules") or []
        ),
    )
    selected_modules = list(selection["selected_modules"])
    if not selected_modules:
        return {
            **scope,
            "enabled": False,
            "mode": "disabled",
            "matched_function_count": 0,
            "range_count": 0,
            "selected_modules": [],
            "unmatched_functions": requested[:80],
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_runtime_module_unresolved",
            ],
        }

    symbol_ranges = sorted({
        item
        for module in selected_modules
        for item in module_ranges[module]
    })
    ranges = sorted({
        (runtime_module, start, end)
        for module, start, end in symbol_ranges
        for runtime_module in (
            selection["runtime_module_aliases"].get(module)
            or [module]
        )
    })
    matched = Counter(
        requested_name
        for module in selected_modules
        for requested_name in module_matches[module]
    )

    unmatched = sorted(
        name for name in requested if not matched.get(name)
    )
    if unmatched:
        return {
            **scope,
            "enabled": False,
            "mode": "disabled",
            "matched_function_count": len(matched),
            "range_count": len(ranges),
            "selected_modules": selected_modules,
            "module_selection_strategy": selection[
                "selection_strategy"
            ],
            "runtime_module_aliases": selection[
                "runtime_module_aliases"
            ],
            "unmatched_functions": unmatched[:80],
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_symbol_resolution_incomplete",
            ],
        }
    if len(ranges) > TRACE_SCOPE_MAX_RANGES:
        return {
            **scope,
            "enabled": False,
            "mode": "disabled",
            "matched_function_count": len(matched),
            "range_count": len(ranges),
            "selected_modules": selected_modules,
            "module_selection_strategy": selection[
                "selection_strategy"
            ],
            "runtime_module_aliases": selection[
                "runtime_module_aliases"
            ],
            "unmatched_functions": [],
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_range_capacity_exceeded",
            ],
        }
    slug = _safe_name(test_id)
    host_scope = os.path.join(host_artifact_dir, f"{slug}.scope")
    scope_lines = [
        f"A\t{module}\t{start:x}\t{end:x}"
        for module, start, end in sorted(set(ranges))
    ]
    _write_text(host_scope, "\n".join(scope_lines) + "\n")
    container_scope = f"{container_trace_root}/{slug}.scope"
    copied = subprocess.run(
        ["docker", "cp", host_scope, f"{container}:{container_scope}"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    if copied.returncode != 0:
        return {
            **scope,
            "enabled": False,
            "mode": "disabled",
            "diagnostics": [
                *(scope.get("diagnostics") or []),
                "trace_scope_copy_failed",
            ],
        }
    return {
        **scope,
        "enabled": True,
        "mode": "nm_address_ranges",
        "scope_artifact": host_scope,
        "scope_file": container_scope,
        "matched_function_count": len(matched),
        "range_count": len(set(ranges)),
        "selected_modules": selected_modules,
        "module_selection_strategy": selection[
            "selection_strategy"
        ],
        "runtime_module_aliases": selection[
            "runtime_module_aliases"
        ],
        "observed_module_matches": selection[
            "observed_module_matches"
        ],
        "unmatched_functions": [],
        "diagnostics": [],
    }


def _trace_event_limits() -> List[int]:
    """Return bounded geometric trace limits for adaptive collection."""
    initial = min(
        TRACE_HARD_MAX_EVENTS,
        _positive_int_env(
            "UDBG_TRACE_INITIAL_MAX_EVENTS",
            TRACE_MAX_EVENTS,
        ),
    )
    maximum = max(
        initial,
        min(
            TRACE_HARD_MAX_EVENTS,
            _positive_int_env(
                "UDBG_TRACE_MAX_RETRY_EVENTS",
                TRACE_MAX_RETRY_EVENTS,
            ),
        ),
    )
    attempts = min(
        8,
        _positive_int_env(
            "UDBG_TRACE_MAX_ATTEMPTS",
            TRACE_MAX_ATTEMPTS,
        ),
    )
    limits = [initial]
    while len(limits) < attempts and limits[-1] < maximum:
        limits.append(min(maximum, limits[-1] * 2))
    return list(dict.fromkeys(limits))


def _append_identity_sample(values: List[str], value: str) -> None:
    """Keep bounded audit examples; ordered events retain full identities."""
    normalized = str(value or "")
    if (
        normalized
        and len(values) < FUNCTION_IDENTITY_SAMPLE_LIMIT
        and normalized not in values
    ):
        values.append(normalized)


def _bound_function_identity_samples(function: Dict[str, Any]) -> None:
    function["invocation_ids"] = list(
        function.get("invocation_ids") or []
    )[:FUNCTION_IDENTITY_SAMPLE_LIMIT]
    function["callsite_ids"] = list(
        function.get("callsite_ids") or []
    )[:FUNCTION_IDENTITY_SAMPLE_LIMIT]
    function["runtime_modules"] = list(
        function.get("runtime_modules") or []
    )[:FUNCTION_IDENTITY_SAMPLE_LIMIT]
    function.setdefault(
        "invocation_count",
        int(function.get("enter_count") or 0),
    )


def _merge_census_into_detailed_test(
    detailed: Dict[str, Any],
    census: Dict[str, Any],
) -> None:
    """Keep aggregate census coverage/edges when ordered scope is narrow."""
    functions = detailed.setdefault("functions", {})
    for key, census_record in (census.get("functions") or {}).items():
        if not isinstance(census_record, dict):
            continue
        record = functions.setdefault(key, {
            "key": key,
            "function": census_record.get("function"),
            "source_path": census_record.get("source_path"),
            "source_line": census_record.get("source_line"),
            "enter_count": 0,
            "coverage_enter_count": 0,
            "invocation_count": 0,
            "invocation_ids": [],
            "callsite_ids": [],
            "runtime_modules": [],
        })
        census_count = int(
            census_record.get("coverage_enter_count")
            or census_record.get("enter_count")
            or 0
        )
        record["coverage_enter_count"] = max(
            int(record.get("coverage_enter_count") or 0),
            census_count,
        )
        record["enter_count"] = max(
            int(record.get("enter_count") or 0),
            census_count,
        )
        record["census_enter_count"] = census_count
        if not record.get("function"):
            record["function"] = census_record.get("function")
        if not record.get("source_path"):
            record["source_path"] = census_record.get("source_path")
        if not record.get("source_line"):
            record["source_line"] = census_record.get("source_line")
        for runtime_module in census_record.get("runtime_modules") or []:
            _append_identity_sample(
                record.setdefault("runtime_modules", []),
                runtime_module,
            )
    edge_counts = Counter()
    for edge in (
        list(detailed.get("dynamic_edges") or [])
        + list(census.get("dynamic_edges") or [])
    ):
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller and callee:
            edge_counts[(caller, callee)] += int(edge.get("count") or 1)
    detailed["dynamic_edges"] = [
        {"caller": caller, "callee": callee, "count": count}
        for (caller, callee), count in edge_counts.most_common()
    ]
    detailed["census_coverage_function_count"] = len(
        census.get("functions") or {}
    )
    detailed["census_edge_count"] = len(
        census.get("dynamic_edges") or []
    )


def _merge_trace_query_observations(
    primary: Dict[str, Any],
    recovery: Dict[str, Any],
) -> None:
    """Merge only answered probe questions, never a second ordered stream."""
    for field in ("value_observations", "slice_boundary_observations"):
        merged = []
        seen = set()
        for item in [
            *(primary.get(field) or []),
            *(recovery.get(field) or []),
        ]:
            if not isinstance(item, dict):
                continue
            identity = json.dumps(
                item,
                sort_keys=True,
                ensure_ascii=True,
                default=str,
                separators=(",", ":"),
            )
            if identity in seen:
                continue
            seen.add(identity)
            merged.append(item)
        primary[field] = merged


def _fail_context_signature_id(context: Dict[str, Any]) -> str:
    """Prefer semantic failure identity; keep legacy caches comparable."""
    contract = (
        context.get("failure_contract")
        if isinstance(context, dict)
        else {}
    )
    if not isinstance(contract, dict):
        contract = {}
    return str(
        context.get("failure_signature_id")
        or contract.get("failure_signature_id")
        or context.get("context_id")
        or ""
    )


def _compact_trace_query_recovery(
    recovery: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist query answers and audit paths, not a duplicate full trace."""
    return {
        "trace_collection_strategy": recovery.get(
            "trace_collection_strategy"
        ),
        "returncode": recovery.get("returncode"),
        "failed_as_expected": recovery.get("failed_as_expected"),
        "test_executed": recovery.get("test_executed"),
        "trace_truncated": recovery.get("trace_truncated"),
        "trace_event_limit": recovery.get("trace_event_limit"),
        "raw_trace_event_count": recovery.get(
            "raw_trace_event_count"
        ),
        "observed_probe_ids": sorted(observed_probe_ids(recovery)),
        "value_observations": recovery.get("value_observations") or [],
        "slice_boundary_observations": (
            recovery.get("slice_boundary_observations") or []
        ),
        "output_artifact": recovery.get("output_artifact"),
        "trace_artifact": recovery.get("trace_artifact"),
        "baseline_fail_context_id": recovery.get(
            "baseline_fail_context_id"
        ),
        "observed_fail_context_id": recovery.get(
            "observed_fail_context_id"
        ),
        "baseline_failure_signature_id": recovery.get(
            "baseline_failure_signature_id"
        ),
        "observed_failure_signature_id": recovery.get(
            "observed_failure_signature_id"
        ),
        "failure_signature_match": recovery.get(
            "failure_signature_match"
        ),
        "diagnostics": recovery.get("diagnostics") or [],
    }


def collect_regression_runtime_evidence(
    bug: Any,
    *,
    artifact_dir: str = "",
    compile_timeout: int = 1800,
    test_timeout: int = 180,
    query_llm_provider: str = None,
    query_llm_enabled: bool = True,
) -> Dict[str, Any]:
    """Trace regression tests using a lightweight census before E/X detail."""
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
        "trace_scope": {
            "schema": TRACE_SCOPE_SCHEMA,
            "source": "fresh_census_with_metadata_hint",
            "tests": {},
        },
        "trace_queries": {
            "schema": "unified_debugging.trace_query_bundle.v1",
            "tests": {},
        },
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
        if helper and not adapter._ensure_metadata_test_helper(
            container=container,
            container_repo=container_repo,
            bug_meta=raw,
            helper_path=helper,
        ):
            result["diagnostics"].append(
                f"runtime_test_helper_prepare_failed:{helper}"
            )
            return result

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
            captured_commands_path=str(
                setup.get("compilation_log") or ""
            ),
        )
        result["compile"]["compilation_database"] = compilation_database
        if not compilation_database:
            result["diagnostics"].append(
                "runtime_compilation_database_unavailable"
            )
        runtime_preload = _trace_runtime_preload(
            compile_cmd=str(raw["compile_cmd"]),
            trace_library=str(setup["trace_library"]),
        )
        result["compile"]["runtime_preload"] = {
            key: value
            for key, value in runtime_preload.items()
            if key != "preload"
        }
        result["diagnostics"].extend(
            runtime_preload.get("diagnostics") or []
        )
        if not runtime_preload.get("available"):
            return result
        trace_preload = str(runtime_preload["preload"])
        address_sanitizer = (
            runtime_preload.get("sanitizer") == "address"
        )
        base_scope_by_test = {}
        for test_id in regression_ids:
            scope = _coverage_scope_records_for_test(bug, test_id)
            base_scope_by_test[test_id] = scope
            result["trace_scope"]["tests"][test_id] = {
                **scope,
                "mode": "pending_census",
                "selection_strategy": (
                    "query_driven_producer_sink_v1"
                ),
            }
            result["diagnostics"].extend(scope.get("diagnostics") or [])

        census_by_test = {}
        census_fail_context_by_test = {}
        refined_scope_by_test = {}
        for test_id in regression_ids:
            census_result = _run_one_traced_test(
                container=container,
                container_repo=container_repo,
                container_trace_root=container_trace_root,
                trace_library=trace_preload,
                test_template=template,
                test_id=test_id,
                host_artifact_dir=host_artifact_dir,
                timeout=test_timeout,
                trace_max_events=10_000,
                scenario_window=False,
                artifact_namespace="census",
                attempt_index=0,
                summarize_truncated=True,
                coverage_only=True,
                address_sanitizer=address_sanitizer,
            )
            census_result["trace_scope"] = {}
            census_by_test[test_id] = census_result
            census_fail_context = build_regression_fail_context(
                bug,
                runtime_evidence={"tests": [census_result]},
                test_ids=[test_id],
            )
            census_fail_context_by_test[test_id] = census_fail_context
            refinement_started = time.monotonic()
            refined_scope = _refine_trace_scope_from_census(
                bug=bug,
                test_id=test_id,
                base_scope=base_scope_by_test.get(test_id) or {},
                census_test=census_result,
                artifact_dir=host_artifact_dir,
                fail_context=census_fail_context,
                compilation_database=compilation_database,
            )
            refined_scope["fail_context_id"] = (
                census_fail_context.get("context_id") or ""
            )
            refined_scope["refinement_seconds"] = round(
                time.monotonic() - refinement_started,
                3,
            )
            refined_scope_by_test[test_id] = refined_scope
            print(
                "    [FL] Producer→sink scope "
                f"{test_id}: "
                f"{refined_scope.get('detailed_function_count', 0)} "
                "detailed functions, "
                f"{refined_scope.get('slice_probe_count', 0)} probes, "
                f"{refined_scope.get('refinement_seconds', 0):.1f}s.",
                flush=True,
            )

        query_broker = build_investigation_query_broker(
            bug=bug,
            census_by_test=census_by_test,
            refined_scopes=refined_scope_by_test,
            artifact_dir=host_artifact_dir,
            use_llm=bool(query_llm_enabled),
            provider=query_llm_provider,
        )
        result["investigation_query_broker"] = (
            merge_broker_probes_into_scopes(
                refined_scopes=refined_scope_by_test,
                census_by_test=census_by_test,
                broker=query_broker,
                max_probes_per_test=TRACE_SLICE_MAX_PROBES,
                sample_limit=TRACE_SLICE_PROBE_SAMPLE_LIMIT,
            )
        )
        broker_artifact = str(
            result["investigation_query_broker"].get("artifact")
            or ""
        )
        if broker_artifact:
            atomic_write_json(
                broker_artifact,
                result["investigation_query_broker"],
            )
        result["diagnostics"].extend(
            result["investigation_query_broker"].get(
                "diagnostics"
            )
            or []
        )

        slice_probes = {
            str(probe.get("probe_id") or ""): probe
            for scope in refined_scope_by_test.values()
            for probe in scope.get("slice_probes") or []
            if str(probe.get("probe_id") or "")
        }
        slice_instrumentation = _install_slice_probes(
            container=container,
            container_repo=container_repo,
            raw=raw,
            probes=list(slice_probes.values()),
        )
        slice_restore_files = list(
            slice_instrumentation.pop("_restore_files", [])
        )
        result["slice_probe_instrumentation"] = slice_instrumentation
        result["diagnostics"].extend(
            slice_instrumentation.get("diagnostics") or []
        )
        if slice_instrumentation.get("available"):
            slice_compile_log = os.path.join(
                host_artifact_dir, "compile.slice_probes.log"
            )
            slice_compile = _run_trace_build(
                container=container,
                container_repo=container_repo,
                compile_cmd=str(raw["compile_cmd"]),
                wrapper_bin=str(setup["wrapper_bin"]),
                timeout=compile_timeout,
            )
            _write_text(
                slice_compile_log,
                slice_compile.get("output") or "",
            )
            result["compile"]["slice_probe_rebuild"] = {
                "returncode": slice_compile.get("returncode"),
                "artifact": slice_compile_log,
                "installed_probe_count": len(
                    slice_instrumentation.get(
                        "installed_probe_ids"
                    )
                    or []
                ),
            }
            if slice_compile.get("returncode") != 0:
                result["diagnostics"].append(
                    "runtime_slice_probe_build_failed"
                )
                restore_audit = _restore_slice_probe_sources(
                    container=container,
                    restore_files=slice_restore_files,
                )
                result["compile"]["slice_probe_rebuild"][
                    "fallback_restore"
                ] = restore_audit
                if not restore_audit.get("restored"):
                    result["diagnostics"].append(
                        "runtime_slice_probe_restore_failed"
                    )
                    return result
                slice_instrumentation["available"] = False
                slice_instrumentation["installed_probe_ids"] = []
                slice_instrumentation["fallback"] = (
                    "control_only_after_probe_build_failure"
                )
                for scope in refined_scope_by_test.values():
                    scope["slice_probes"] = []
                    scope["slice_probe_count"] = 0
                    scope["slice_probe_limit_per_id"] = 0
                    scope["estimated_probe_event_count"] = 0
                    scope["estimated_total_event_count"] = int(
                        scope.get("estimated_detailed_event_count") or 0
                    )
                    scope.setdefault("diagnostics", []).append(
                        "slice_probes_disabled_after_build_failure"
                    )
                fallback_log = os.path.join(
                    host_artifact_dir,
                    "compile.slice_probes_fallback.log",
                )
                fallback_compile = _run_trace_build(
                    container=container,
                    container_repo=container_repo,
                    compile_cmd=str(raw["compile_cmd"]),
                    wrapper_bin=str(setup["wrapper_bin"]),
                    timeout=compile_timeout,
                )
                _write_text(
                    fallback_log,
                    fallback_compile.get("output") or "",
                )
                result["compile"]["slice_probe_rebuild"][
                    "fallback_compile"
                ] = {
                    "returncode": fallback_compile.get("returncode"),
                    "artifact": fallback_log,
                }
                if fallback_compile.get("returncode") != 0:
                    result["diagnostics"].append(
                        "runtime_slice_probe_fallback_build_failed"
                    )
                    return result
            else:
                _discard_slice_probe_backups(
                    container=container,
                    restore_files=slice_restore_files,
                )

        installed_slice_probe_ids = {
            str(value)
            for value in (
                slice_instrumentation.get("installed_probe_ids") or []
            )
            if str(value)
        }
        for scope in refined_scope_by_test.values():
            planned_ids = {
                str(item.get("probe_id") or "")
                for item in scope.get("slice_probes") or []
                if str(item.get("probe_id") or "")
            }
            scope["installed_probe_ids"] = sorted(
                planned_ids & installed_slice_probe_ids
            )
            scope["not_instrumented_probe_ids"] = sorted(
                planned_ids - installed_slice_probe_ids
            )

        nm_output = ""
        nm_available = True
        nm_loaded = False
        if any(
            scope.get("requested_functions")
            for scope in refined_scope_by_test.values()
        ):
            nm_output, nm_available = _collect_trace_nm_output(
                container=container,
                container_repo=container_repo,
            )
            nm_loaded = True
        detailed_scope_by_test = {}
        for test_id in regression_ids:
            detailed_scope = _build_trace_scope_file(
                container=container,
                container_repo=container_repo,
                container_trace_root=container_trace_root,
                host_artifact_dir=host_artifact_dir,
                test_id=test_id,
                scope=refined_scope_by_test.get(test_id) or {},
                nm_output=nm_output,
                nm_available=nm_available,
                nm_loaded=nm_loaded,
            )
            detailed_scope_by_test[test_id] = detailed_scope
            result["trace_scope"]["tests"][test_id] = detailed_scope
            result["diagnostics"].extend(
                detailed_scope.get("diagnostics") or []
            )
            result["trace_queries"]["tests"][test_id] = (
                build_trace_query_plan(
                    test_id=test_id,
                    fail_context=(
                        census_fail_context_by_test.get(test_id) or {}
                    ),
                    trace_scope=detailed_scope,
                    installed_probe_ids=(
                        detailed_scope.get("installed_probe_ids") or []
                    ),
                )
            )

        all_functions: Dict[str, Dict[str, Any]] = {}
        all_edges = Counter()
        all_callsites = Counter()
        all_exception_events = []
        all_value_observations = []
        all_slice_boundary_observations = []
        for test_id in regression_ids:
            census_result = census_by_test.get(test_id) or {}
            detailed_scope = detailed_scope_by_test.get(test_id) or {}
            if detailed_scope.get("enabled"):
                test_result = _run_traced_test_adaptively(
                    container=container,
                    container_repo=container_repo,
                    container_trace_root=container_trace_root,
                    trace_library=trace_preload,
                    test_template=template,
                    test_id=test_id,
                    host_artifact_dir=host_artifact_dir,
                    timeout=test_timeout,
                    artifact_namespace="runtime",
                    scenario_window_available=bool(
                        marker_instrumentation.get("available")
                    ),
                    trace_scope_file=str(
                        detailed_scope.get("scope_file") or ""
                    ),
                    focus_immediately=True,
                    single_attempt=True,
                    slice_probe_limit=int(
                        detailed_scope.get(
                            "slice_probe_limit_per_id"
                        )
                        or 0
                    ),
                    trace_event_budget=int(
                        detailed_scope.get("detailed_event_budget")
                        or TRACE_DETAILED_EVENT_BUDGET
                    ),
                    address_sanitizer=address_sanitizer,
                )
            else:
                test_result = {
                    **census_result,
                    "coverage_only": False,
                    "trace_collection_strategy": (
                        "census_only_detailed_scope_unavailable"
                    ),
                    "adaptive_trace_attempts": [],
                    "adaptive_trace_retry_count": 0,
                    "diagnostics": [
                        *(census_result.get("diagnostics") or []),
                        "detailed_scope_unavailable_used_census_only",
                    ],
                }
            query_plan = (
                (result.get("trace_queries") or {}).get("tests") or {}
            ).get(test_id) or {}
            baseline_context_id = str(
                (
                    census_fail_context_by_test.get(test_id) or {}
                ).get("context_id")
                or ""
            )
            baseline_signature_id = _fail_context_signature_id(
                census_fail_context_by_test.get(test_id) or {}
            )
            primary_context = build_regression_fail_context(
                bug,
                runtime_evidence={"tests": [test_result]},
                test_ids=[test_id],
            )
            primary_context_id = str(
                primary_context.get("context_id") or ""
            )
            primary_signature_id = _fail_context_signature_id(
                primary_context
            )
            primary_signature_match = (
                primary_signature_id == baseline_signature_id
                if primary_signature_id and baseline_signature_id
                else None
            )
            test_result["baseline_fail_context_id"] = baseline_context_id
            test_result["observed_fail_context_id"] = primary_context_id
            test_result["baseline_failure_signature_id"] = (
                baseline_signature_id
            )
            test_result["observed_failure_signature_id"] = (
                primary_signature_id
            )
            test_result["failure_signature_match"] = (
                primary_signature_match
            )

            recovery_result = {}
            recovery_signature_match = None
            if should_run_probe_recovery(
                query_plan,
                test_result,
                primary_signature_match=primary_signature_match,
            ):
                recovery_result = _run_traced_test_adaptively(
                    container=container,
                    container_repo=container_repo,
                    container_trace_root=container_trace_root,
                    trace_library=trace_preload,
                    test_template=template,
                    test_id=test_id,
                    host_artifact_dir=host_artifact_dir,
                    timeout=test_timeout,
                    artifact_namespace="trace_query",
                    scenario_window_available=bool(
                        marker_instrumentation.get("available")
                    ),
                    probe_only=True,
                    focus_immediately=True,
                    single_attempt=True,
                    slice_probe_limit=int(
                        detailed_scope.get(
                            "slice_probe_limit_per_id"
                        )
                        or 0
                    ),
                    trace_event_budget=int(
                        detailed_scope.get(
                            "slice_probe_event_reserve"
                        )
                        or TRACE_SLICE_PROBE_EVENT_RESERVE
                    ),
                    address_sanitizer=address_sanitizer,
                )
                recovery_context = build_regression_fail_context(
                    bug,
                    runtime_evidence={"tests": [recovery_result]},
                    test_ids=[test_id],
                )
                recovery_context_id = str(
                    recovery_context.get("context_id") or ""
                )
                recovery_signature_id = _fail_context_signature_id(
                    recovery_context
                )
                recovery_signature_match = (
                    recovery_signature_id == baseline_signature_id
                    if recovery_signature_id and baseline_signature_id
                    else None
                )
                recovery_result["baseline_fail_context_id"] = (
                    baseline_context_id
                )
                recovery_result["observed_fail_context_id"] = (
                    recovery_context_id
                )
                recovery_result["baseline_failure_signature_id"] = (
                    baseline_signature_id
                )
                recovery_result["observed_failure_signature_id"] = (
                    recovery_signature_id
                )
                recovery_result["failure_signature_match"] = (
                    recovery_signature_match
                )
                if recovery_signature_match is not False:
                    _merge_trace_query_observations(
                        test_result,
                        recovery_result,
                    )
                test_result["trace_query_recovery"] = (
                    _compact_trace_query_recovery(recovery_result)
                )

            query_evidence = evaluate_trace_query_plan(
                plan=query_plan,
                primary_result=test_result,
                recovery_result=recovery_result or None,
                primary_signature_match=primary_signature_match,
                recovery_signature_match=recovery_signature_match,
            )
            test_result["trace_query_evidence"] = query_evidence
            result["trace_queries"]["tests"][test_id] = {
                **query_plan,
                "evidence": query_evidence,
            }
            if primary_signature_match is False:
                test_result.setdefault("diagnostics", []).append(
                    "detailed_failure_signature_mismatch"
                )
            test_result["trace_scope"] = detailed_scope
            test_result["census"] = {
                key: value
                for key, value in census_result.items()
                if key not in {
                    "events",
                    "functions",
                    "dynamic_edges",
                    "dynamic_callsites",
                    "exception_events",
                    "value_observations",
                    "active_stack",
                }
            }
            test_result["census"]["functions"] = census_result.get(
                "functions"
            ) or {}
            test_result["census"]["dynamic_edges"] = census_result.get(
                "dynamic_edges"
            ) or []
            test_result.setdefault("diagnostics", []).extend(
                f"census:{value}"
                for value in census_result.get("diagnostics") or []
            )
            _merge_census_into_detailed_test(
                test_result,
                census_result,
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
                    "coverage_enter_count": 0,
                    "active_at_failure_count": 0,
                    "max_depth": 0,
                    "max_event_span": 0,
                    "best_reverse_distance": None,
                    "invocation_count": 0,
                    "invocation_ids": [],
                    "callsite_ids": [],
                })
                aggregate["test_ids"].append(test_id)
                aggregate["enter_count"] += int(record.get("enter_count") or 0)
                aggregate["coverage_enter_count"] += int(
                    record.get("coverage_enter_count") or 0
                )
                aggregate["invocation_count"] += int(
                    record.get(
                        "invocation_count",
                        record.get("enter_count") or 0,
                    )
                )
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
                    _append_identity_sample(
                        aggregate["invocation_ids"],
                        invocation_id,
                    )
                for callsite_id in record.get("callsite_ids") or []:
                    _append_identity_sample(
                        aggregate["callsite_ids"],
                        callsite_id,
                    )
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
            for observation in (
                test_result.get("slice_boundary_observations") or []
            ):
                all_slice_boundary_observations.append({
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
        result["slice_boundary_observations"] = (
            all_slice_boundary_observations
        )
        result["fresh_execution"] = bool(regression_ids) and (
            len(result["tests"]) == len(regression_ids)
            and all(
                test.get("failed_as_expected")
                and (
                    int(test.get("trace_event_count") or 0) > 0
                    or (
                        test.get("trace_collection_strategy")
                        == "census_only_detailed_scope_unavailable"
                        and int(
                            test.get("coverage_record_count") or 0
                        ) > 0
                    )
                )
                and not test.get("infrastructure_error")
                and test.get("failure_signature_match") is not False
                for test in result["tests"]
            )
        )
        if not result["fresh_execution"]:
            result["diagnostics"].append(
                "runtime_trace_regression_set_incomplete"
            )
        result["fail_context"] = build_regression_fail_context(
            bug,
            runtime_evidence=result,
        )
        if host_artifact_dir:
            query_artifact = atomic_write_json(
                os.path.join(
                    host_artifact_dir,
                    "runtime_trace_queries.json",
                ),
                result.get("trace_queries") or {},
            )
            if query_artifact:
                result["trace_queries"]["artifact"] = query_artifact
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
    """Persist the complete bounded-slice stream for future FL runs."""
    if not runtime_evidence or not artifact_dir:
        return ""
    os.makedirs(artifact_dir, exist_ok=True)
    runtime_evidence["schema"] = TRACE_SCHEMA
    return atomic_write_gzip_json(
        os.path.join(artifact_dir, FULL_RUNTIME_CACHE_FILENAME),
        runtime_evidence,
    )


def _upgrade_runtime_evidence(runtime_evidence: Dict[str, Any]) -> None:
    """Add invocation/callsite identity without upgrading trace semantics."""
    if not isinstance(runtime_evidence, dict):
        return
    original_schema = str(runtime_evidence.get("schema") or "")
    aggregate_callsites = Counter()
    aggregate_exceptions = []
    aggregate_functions = runtime_evidence.get("functions") or {}
    for function in aggregate_functions.values():
        if isinstance(function, dict):
            _bound_function_identity_samples(function)
    if (
        original_schema
        in {
            "unified_debugging.runtime_trace.v3",
            "unified_debugging.runtime_trace.v4",
        }
        and "dynamic_callsites" in runtime_evidence
    ):
        for test in runtime_evidence.get("tests") or []:
            if not isinstance(test, dict):
                continue
            for function in (test.get("functions") or {}).values():
                if isinstance(function, dict):
                    _bound_function_identity_samples(function)
        return
    for test in runtime_evidence.get("tests") or []:
        if not isinstance(test, dict):
            continue
        for function in (test.get("functions") or {}).values():
            if not isinstance(function, dict):
                continue
            _bound_function_identity_samples(function)
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
                    _append_identity_sample(
                        function["invocation_ids"],
                        invocation_id,
                    )
                    _append_identity_sample(
                        function["callsite_ids"],
                        callsite_id,
                    )
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
    migrations = runtime_evidence.setdefault("cache_migrations", [])
    if original_schema == "unified_debugging.runtime_trace.v2":
        migration = "runtime_trace_v2_to_v3_invocation_identity"
        if migration not in migrations:
            migrations.append(migration)
        runtime_evidence["schema"] = "unified_debugging.runtime_trace.v3"


def _runtime_cache_identity(
    bug: Any, *, regression_ids: List[str]
) -> Dict[str, Any]:
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    coverage_payload = {}
    regression_id_set = set(regression_ids)
    for test in getattr(bug, "tests", None) or []:
        test_id = str(test.get("test_id") or "")
        if test_id not in regression_id_set:
            continue
        values = test.get("covered_functions")
        if values is None:
            values = test.get("covered_methods")
        coverage_payload[test_id] = sorted({
            _normalize_trace_scope_key(value)
            for value in values or []
            if _normalize_trace_scope_key(value)
        })
    coverage_scope_identity = hashlib.sha256(
        json.dumps(
            coverage_payload,
            sort_keys=True,
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return {
        "version": 9,
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
        "slice_probe_generation": SLICE_PROBE_GENERATION,
        "trace_collection": (
            "shared_query_broker_census_slice_probe_recovery_v2"
        ),
        "trace_scope_schema": TRACE_SCOPE_SCHEMA,
        "coverage_scope_identity": coverage_scope_identity,
        "trace_event_limits": _trace_event_limits(),
        "lightweight_coverage": (
            f"fixed_address_table_v1:{TRACE_COVERAGE_SLOTS}"
        ),
        "lightweight_edges": (
            f"fixed_address_pair_table_v1:{TRACE_EDGE_SLOTS}"
        ),
        "detailed_event_budget": min(
            TRACE_HARD_MAX_EVENTS,
            _positive_int_env(
                "UDBG_TRACE_DETAILED_EVENT_BUDGET",
                TRACE_DETAILED_EVENT_BUDGET,
            ),
        ),
        "slice_probe_event_reserve": _positive_int_env(
            "UDBG_TRACE_SLICE_PROBE_EVENT_RESERVE",
            TRACE_SLICE_PROBE_EVENT_RESERVE,
        ),
        "slice_probe_sample_limit": TRACE_SLICE_PROBE_SAMPLE_LIMIT,
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
    if require_current_instrumentation:
        for field in (
            "version",
            "trace_collection",
            "trace_scope_schema",
            "coverage_scope_identity",
            "trace_event_limits",
            "lightweight_coverage",
            "lightweight_edges",
            "detailed_event_budget",
            "slice_probe_generation",
            "slice_probe_event_reserve",
            "slice_probe_sample_limit",
        ):
            if identity.get(field) != expected_identity.get(field):
                reasons.append(
                    f"runtime_cache_identity_mismatch:{field}"
                )
    tests = {
        str(item.get("test_id") or ""): item
        for item in cached.get("tests") or []
        if isinstance(item, dict)
    }
    for test_id in expected_ids:
        test = tests.get(test_id) or {}
        census_only = (
            test.get("trace_collection_strategy")
            == "census_only_detailed_scope_unavailable"
            and int(test.get("coverage_record_count") or 0) > 0
        )
        if not test.get("failed_as_expected"):
            reasons.append(f"runtime_cache_test_not_reproduced:{test_id}")
        if (
            int(test.get("trace_event_count") or 0) <= 0
            and not census_only
        ):
            reasons.append(f"runtime_cache_test_has_no_events:{test_id}")
        if not test.get("events") and not census_only:
            reasons.append(f"runtime_cache_ordered_events_missing:{test_id}")
        scope = test.get("trace_scope") or {}
        if (
            isinstance(scope, dict)
            and scope.get("enabled")
            and str(scope.get("selection_strategy") or "").startswith(
                (
                    "query_driven_producer_sink",
                    "producer_sink_executed_paths_hard_budget",
                )
            )
        ):
            budget = int(
                scope.get("detailed_event_budget")
                or expected_identity.get("detailed_event_budget")
                or 0
            )
            observed = int(test.get("trace_event_count") or 0)
            if budget > 0 and observed > budget:
                reasons.append(
                    f"runtime_cache_trace_budget_exceeded:{test_id}:"
                    f"{observed}>{budget}"
                )
            trace_limit = int(test.get("trace_event_limit") or 0)
            if trace_limit > 0 and budget > 0 and trace_limit > budget:
                reasons.append(
                    f"runtime_cache_trace_limit_exceeds_budget:{test_id}:"
                    f"{trace_limit}>{budget}"
                )
        for field in ("output_artifact", "trace_artifact"):
            value = str(test.get(field) or "")
            if not value or not os.path.isfile(value):
                reasons.append(
                    f"runtime_cache_artifact_missing:{test_id}:{field}"
                )
            elif field == "trace_artifact" and os.path.getsize(value) <= 0:
                reasons.append(
                    f"runtime_cache_artifact_empty:{test_id}:{field}"
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

    compilation_log = (
        f"{container_trace_root.rstrip('/')}/compile_commands.tsv"
    )
    instrumentation_args = (
        "-g -O0 -finstrument-functions -fno-omit-frame-pointer "
        "-Wl,--export-dynamic"
    )
    with tempfile.TemporaryDirectory(prefix="udbg_trace_toolchain_") as local:
        bin_dir = os.path.join(local, "bin")
        os.makedirs(bin_dir, exist_ok=True)
        _write_text(os.path.join(local, "trace_runtime.c"), TRACE_RUNTIME_SOURCE)
        for name, real_path in compilers.items():
            wrapper = (
                "#!/bin/sh\n"
                "udbg_is_compile=0\n"
                "udbg_has_source=0\n"
                'for udbg_arg in "$@"; do\n'
                '  [ "$udbg_arg" = "-c" ] && udbg_is_compile=1\n'
                '  case "$udbg_arg" in\n'
                "    *.c|*.cc|*.cpp|*.cxx) udbg_has_source=1 ;;\n"
                "  esac\n"
                "done\n"
                'if [ "$udbg_is_compile" -eq 1 ] '
                '&& [ "$udbg_has_source" -eq 1 ]; then\n'
                '  udbg_tab=$(printf "\\t")\n'
                f'  udbg_record="$PWD${{udbg_tab}}{real_path}"\n'
                '  for udbg_arg in "$@"; do\n'
                '    udbg_record="${udbg_record}${udbg_tab}${udbg_arg}"\n'
                "  done\n"
                "  for udbg_arg in -g -O0 -finstrument-functions "
                "-fno-omit-frame-pointer -Wl,--export-dynamic; do\n"
                '    udbg_record="${udbg_record}${udbg_tab}${udbg_arg}"\n'
                "  done\n"
                f"  printf '%s\\n' \"$udbg_record\" >> "
                f"{shlex.quote(compilation_log)}\n"
                "fi\n"
                f"exec {shlex.quote(real_path)} \"$@\" "
                f"{instrumentation_args}\n"
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
        "compilation_log": compilation_log,
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
        if (
            str(value)
            and os.path.splitext(str(value))[1].lower()
            in INSTRUMENTABLE_SOURCE_SUFFIXES
        )
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


def _install_slice_probes(
    *,
    container: str,
    container_repo: str,
    raw: Dict[str, Any],
    probes: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Install bounded producer/sink probes before the detailed FL run."""
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
                "slice_probe_source_unavailable:"
                f"{probe.get('probe_id')}"
            )
    installed_ids = []
    files = []
    restore_files = []
    for host_path, file_probes in by_path.items():
        relative = os.path.relpath(host_path, host_root)
        container_path = (
            f"{container_repo.rstrip('/')}/{relative.lstrip('./')}"
        )
        with tempfile.TemporaryDirectory(
            prefix="udbg_slice_probe_"
        ) as local_dir:
            current_path = os.path.join(
                local_dir, "current_" + os.path.basename(relative)
            )
            fetched = subprocess.run(
                [
                    "docker", "cp",
                    f"{container}:{container_path}",
                    current_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            source_path = (
                current_path
                if fetched.returncode == 0
                else host_path
            )
            try:
                source = open(
                    source_path,
                    "r",
                    encoding="utf-8",
                    errors="replace",
                ).read()
            except OSError:
                diagnostics.append(
                    f"slice_probe_source_read_failed:{relative}"
                )
                continue
            instrumented, audit = instrument_slice_probes(
                source=source,
                source_path=relative,
                probes=file_probes,
            )
            record = {"source_file": relative, **audit}
            if not audit.get("changed"):
                files.append(record)
                diagnostics.extend(audit.get("diagnostics") or [])
                continue
            local_path = os.path.join(
                local_dir, "instrumented_" + os.path.basename(relative)
            )
            _write_text(local_path, instrumented)
            backup_path = container_path + ".udbg_slice_backup"
            backed_up = _docker_exec(
                container,
                "cp -p -- "
                f"{shlex.quote(container_path)} "
                f"{shlex.quote(backup_path)}",
                timeout=30,
            )
            if backed_up.get("returncode") != 0:
                record["installed"] = False
                diagnostics.append(
                    f"slice_probe_backup_failed:{relative}"
                )
                files.append(record)
                continue
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
            restore_files.append({
                "source": container_path,
                "backup": backup_path,
            })
        else:
            _docker_exec(
                container,
                f"rm -f -- {shlex.quote(backup_path)}",
                timeout=30,
            )
            diagnostics.append(
                f"slice_probe_copy_failed:{relative}"
            )
        files.append(record)
    return {
        "available": bool(installed_ids),
        "generation": SLICE_PROBE_GENERATION,
        "installed_probe_ids": list(dict.fromkeys(installed_ids)),
        "files": files,
        "_restore_files": restore_files,
        "diagnostics": list(dict.fromkeys(diagnostics)),
    }


def _restore_slice_probe_sources(
    *,
    container: str,
    restore_files: List[Dict[str, str]],
) -> Dict[str, Any]:
    diagnostics = []
    restored = []
    for item in restore_files:
        source = str(item.get("source") or "")
        backup = str(item.get("backup") or "")
        if not source or not backup:
            diagnostics.append("slice_probe_restore_path_missing")
            continue
        result = _docker_exec(
            container,
            "cp -p -- "
            f"{shlex.quote(backup)} {shlex.quote(source)} "
            "&& touch -- "
            f"{shlex.quote(source)} "
            "&& rm -f -- "
            f"{shlex.quote(backup)}",
            timeout=30,
        )
        if result.get("returncode") == 0:
            restored.append(source)
        else:
            diagnostics.append(
                f"slice_probe_restore_failed:{source}"
            )
    return {
        "restored": bool(restore_files)
        and len(restored) == len(restore_files),
        "restored_files": restored,
        "diagnostics": diagnostics,
    }


def _discard_slice_probe_backups(
    *,
    container: str,
    restore_files: List[Dict[str, str]],
) -> None:
    backups = [
        str(item.get("backup") or "")
        for item in restore_files
        if str(item.get("backup") or "")
    ]
    if not backups:
        return
    _docker_exec(
        container,
        "rm -f -- " + " ".join(shlex.quote(path) for path in backups),
        timeout=30,
    )


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


def _metadata_uses_address_sanitizer(compile_cmd: str) -> bool:
    """Return whether the metadata build explicitly enables AddressSanitizer."""
    for value in re.findall(
        r"(?<![A-Za-z0-9_])-fsanitize=([A-Za-z0-9_,+-]+)",
        str(compile_cmd or ""),
    ):
        if "address" in {
            item.strip().lower()
            for item in value.split(",")
            if item.strip()
        }:
            return True
    return False


def _trace_runtime_preload(
    *,
    compile_cmd: str,
    trace_library: str,
) -> Dict[str, Any]:
    """Configure tracing without replacing sanitizers selected by metadata."""
    trace_library = str(trace_library or "").strip()
    if not trace_library:
        return {
            "available": False,
            "sanitizer": "none",
            "sanitizer_runtime": "",
            "libraries": [],
            "diagnostics": ["runtime_trace_library_unavailable"],
        }
    address_sanitizer = _metadata_uses_address_sanitizer(compile_cmd)
    return {
        "available": True,
        "preload": trace_library,
        "sanitizer": "address" if address_sanitizer else "none",
        "sanitizer_runtime": (
            "linked_by_instrumented_target" if address_sanitizer else ""
        ),
        "libraries": [trace_library],
        "asan_link_order_override": bool(address_sanitizer),
        "crash_safe_coverage": bool(address_sanitizer),
        "diagnostics": [],
    }


def _run_traced_test_adaptively(
    *,
    container: str,
    container_repo: str,
    container_trace_root: str,
    trace_library: str,
    test_template: str,
    test_id: str,
    host_artifact_dir: str,
    timeout: int,
    artifact_namespace: str,
    scenario_window_available: bool,
    probe_only: bool = False,
    focus_immediately: bool = False,
    single_attempt: bool = False,
    slice_probe_limit: int = 0,
    trace_event_budget: int = 0,
    trace_scope_file: str = "",
    address_sanitizer: bool = False,
) -> Dict[str, Any]:
    """Collect one complete trace, focusing/retrying only after truncation."""
    attempts = []
    final_result: Dict[str, Any] = {}
    stopped_on_coverage_fallback = False
    limits = _trace_event_limits()
    if single_attempt:
        # A bounded-slice run must not silently use the legacy 300k/600k/
        # 1.2m escalation. The scope budget is the process-level cap, even
        # when census estimates are optimistic or a symbol range is broad.
        if trace_event_budget:
            limits = [
                min(
                    TRACE_HARD_MAX_EVENTS,
                    max(1, int(trace_event_budget)),
                )
            ]
        else:
            limits = limits[:1]
    for attempt_index, event_limit in enumerate(limits):
        scenario_window = bool(
            scenario_window_available
            and (focus_immediately or attempt_index > 0)
        )
        final_attempt = attempt_index == len(limits) - 1
        focused_coverage_terminal = bool(
            scenario_window and not probe_only and not focus_immediately
        )
        candidate = _run_one_traced_test(
            container=container,
            container_repo=container_repo,
            container_trace_root=container_trace_root,
            trace_library=trace_library,
            test_template=test_template,
            test_id=test_id,
            host_artifact_dir=host_artifact_dir,
            timeout=timeout,
            trace_max_events=event_limit,
            scenario_window=scenario_window,
            artifact_namespace=artifact_namespace,
            attempt_index=attempt_index,
            summarize_truncated=(
                final_attempt or focused_coverage_terminal
            ),
            probe_only=probe_only,
            slice_probe_limit=slice_probe_limit,
            trace_scope_file=trace_scope_file,
            address_sanitizer=address_sanitizer,
        )
        attempts.append({
            "attempt": attempt_index + 1,
            "event_limit": event_limit,
            "scenario_window": scenario_window,
            "probe_only": probe_only,
            "trace_truncated": bool(candidate.get("trace_truncated")),
            "raw_trace_event_count": int(
                candidate.get("raw_trace_event_count") or 0
            ),
            "coverage_function_count": int(
                candidate.get("coverage_function_count") or 0
            ),
            "coverage_record_count": int(
                candidate.get("coverage_record_count") or 0
            ),
            "postprocess_seconds": float(
                candidate.get("postprocess_seconds") or 0.0
            ),
            "returncode": candidate.get("returncode"),
            "infrastructure_error": str(
                candidate.get("infrastructure_error") or ""
            ),
            "output_artifact": candidate.get("output_artifact"),
            "trace_artifact": candidate.get("trace_artifact"),
        })
        final_result = candidate
        if candidate.get("infrastructure_error"):
            break
        if not candidate.get("trace_truncated"):
            break
        if (
            focused_coverage_terminal
            and int(candidate.get("coverage_record_count") or 0) > 0
        ):
            stopped_on_coverage_fallback = True
            break

    final_result["adaptive_trace_attempts"] = attempts
    final_result["adaptive_trace_retry_count"] = max(
        0, len(attempts) - 1
    )
    final_result["trace_collection_strategy"] = (
        "probe_only_single_pass"
        if probe_only
        else "bounded_slice_single_pass"
        if single_attempt and trace_scope_file
        else "coverage_scoped_adaptive"
        if trace_scope_file
        else "adaptive_scenario_window_coverage_fallback"
        if stopped_on_coverage_fallback
        else "adaptive_scenario_window"
        if any(item["scenario_window"] for item in attempts)
        else "adaptive_full_trace"
    )
    if final_result.get("trace_truncated"):
        final_result.setdefault("diagnostics", []).append(
            (
                "bounded_trace_event_budget_reached"
                if single_attempt
                else
                "trace_incomplete_using_coverage_fallback"
                if stopped_on_coverage_fallback
                else "trace_incomplete_after_adaptive_limit"
            )
        )
    return final_result


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
    trace_max_events: int = TRACE_MAX_EVENTS,
    scenario_window: bool = False,
    artifact_namespace: str = "runtime",
    attempt_index: int = 0,
    summarize_truncated: bool = True,
    probe_only: bool = False,
    coverage_only: bool = False,
    slice_probe_limit: int = 0,
    trace_scope_file: str = "",
    address_sanitizer: bool = False,
) -> Dict[str, Any]:
    slug = _safe_name(test_id)
    namespace = _safe_name(artifact_namespace or "runtime")
    if namespace == "runtime" and attempt_index == 0:
        artifact_slug = slug
    else:
        mode = (
            "probe"
            if probe_only
            else "census"
            if coverage_only
            else "focused"
            if scenario_window
            else "full"
        )
        artifact_slug = (
            f"{namespace}__{slug}__{mode}_{int(trace_max_events)}"
        )
    container_trace = f"{container_trace_root}/{artifact_slug}.trace"
    sanitizer_log_prefix = (
        f"{container_trace_root}/{artifact_slug}.asan"
    )
    test_cmd = test_template.replace("{test_id}", shlex.quote(test_id))
    sanitizer_environment = (
        "export UDBG_TRACE_CRASH_SAFE_COVERAGE=1\n"
        "export ASAN_OPTIONS=verify_asan_link_order=0:"
        f"log_path={shlex.quote(sanitizer_log_prefix)}"
        '${ASAN_OPTIONS:+:$ASAN_OPTIONS}\n'
        if address_sanitizer
        else ""
    )
    timeout_command = (
        f"timeout --kill-after=10s {shlex.quote(str(timeout) + 's')} "
        f"bash -lc {shlex.quote(test_cmd)}"
    )
    test_execution = (
        f"rm -f -- {shlex.quote(sanitizer_log_prefix)} "
        f"{shlex.quote(sanitizer_log_prefix)}.*\n"
        f"{timeout_command}\n"
        "udbg_test_returncode=$?\n"
        f"for udbg_asan_log in {shlex.quote(sanitizer_log_prefix)} "
        f"{shlex.quote(sanitizer_log_prefix)}.*; do\n"
        '  [ -f "$udbg_asan_log" ] || continue\n'
        '  printf "\\n[UDBG ASAN LOG: %s]\\n" "$udbg_asan_log"\n'
        '  cat -- "$udbg_asan_log"\n'
        '  rm -f -- "$udbg_asan_log"\n'
        "done\n"
        'exit "$udbg_test_returncode"\n'
        if address_sanitizer
        else timeout_command + "\n"
    )
    script = (
        f"cd {shlex.quote(container_repo)} || exit 2\n"
        f"rm -f -- {shlex.quote(container_trace)}\n"
        f"export UDBG_TRACE_FILE={shlex.quote(container_trace)}\n"
        f"export UDBG_TRACE_MAX_EVENTS={int(trace_max_events)}\n"
        f"export UDBG_TRACE_SCENARIO_WINDOW={1 if scenario_window else 0}\n"
        f"export UDBG_TRACE_PROBE_ONLY={1 if probe_only else 0}\n"
        f"export UDBG_TRACE_COVERAGE_ONLY={1 if coverage_only else 0}\n"
        f"export UDBG_TRACE_PROBE_LIMIT_PER_ID={max(0, int(slice_probe_limit))}\n"
        f"export UDBG_TRACE_SCOPE_FILE={shlex.quote(trace_scope_file)}\n"
        f"{sanitizer_environment}"
        f"export LD_PRELOAD={shlex.quote(trace_library)}"
        '${LD_PRELOAD:+:$LD_PRELOAD}\n'
        f"{test_execution}"
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

    output_path = os.path.join(
        host_artifact_dir, f"{artifact_slug}.output.log"
    )
    trace_path = os.path.join(
        host_artifact_dir, f"{artifact_slug}.trace"
    )
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

    record_counts = _trace_file_record_counts(trace_path)
    ordered_count = int(record_counts.get("ordered") or 0)
    trace_truncated = ordered_count >= int(trace_max_events)
    infrastructure_error = _trace_test_infrastructure_error(
        returncode=returncode,
        output=output,
        ordered_event_count=ordered_count,
    )
    failed_as_expected = (
        returncode not in {0, 124, 137}
        and not infrastructure_error
        and (
            ordered_count > 0
            or (
                coverage_only
                and int(record_counts.get("coverage") or 0) > 0
            )
        )
    )
    if trace_truncated and not summarize_truncated:
        summarized = _empty_trace_summary(
            diagnostics=["trace_summary_deferred_for_adaptive_retry"]
        )
        postprocess_seconds = 0.0
    else:
        postprocess_started = time.monotonic()
        print(
            "    [FL] Post-process "
            f"{'probe' if probe_only else 'census' if coverage_only else 'runtime'} "
            "trace "
            f"{test_id}: {ordered_count} ordered events...",
            flush=True,
        )
        raw_events = _parse_trace_file(trace_path)
        symbolized = _symbolize_events(
            container,
            raw_events,
            container_repo=container_repo,
        )
        summarized = _summarize_events(
            symbolized,
            container_repo=container_repo,
            trace_complete=not trace_truncated,
        )
        postprocess_seconds = time.monotonic() - postprocess_started
        print(
            "    [FL] Post-process trace hoàn tất trong "
            f"{postprocess_seconds:.1f}s.",
            flush=True,
        )
    trace_path = _compress_trace_artifact(trace_path)
    return {
        "test_id": test_id,
        "returncode": returncode,
        "timed_out": returncode in {124, 137},
        "failed_as_expected": failed_as_expected,
        "infrastructure_error": infrastructure_error,
        "test_executed": not bool(infrastructure_error),
        "fresh_output": output[-6000:],
        "output_artifact": output_path,
        "trace_artifact": trace_path,
        "raw_trace_event_count": ordered_count,
        "coverage_record_count": int(
            record_counts.get("coverage") or 0
        ),
        "coverage_function_count": int(
            summarized.get("coverage_function_count") or 0
        ),
        "trace_event_limit": int(trace_max_events),
        "scenario_window": bool(scenario_window),
        "probe_only": bool(probe_only),
        "coverage_only": bool(coverage_only),
        "edge_record_count": int(record_counts.get("edges") or 0),
        "postprocess_seconds": round(postprocess_seconds, 3),
        "trace_event_count": summarized["trace_event_count"],
        "trace_truncated": trace_truncated,
        "trace_complete": not trace_truncated,
        "persisted_event_count": len(summarized["events"]),
        "events_tail_truncated": (
            summarized["trace_event_count"] > len(summarized["events"])
        ),
        "functions": summarized["functions"],
        "dynamic_edges": summarized["dynamic_edges"],
        "dynamic_callsites": summarized["dynamic_callsites"],
        "exception_events": summarized["exception_events"],
        "value_observations": summarized["value_observations"],
        "slice_boundary_observations": summarized[
            "slice_boundary_observations"
        ],
        "active_stack": summarized["active_stack"],
        "events": summarized["events"],
        "diagnostics": (
            diagnostics
            + ([infrastructure_error] if infrastructure_error else [])
            + summarized["diagnostics"]
        ),
    }


def _compress_trace_artifact(path: str) -> str:
    """Keep the raw audit stream, but never leave it uncompressed on disk."""
    if not path or not os.path.isfile(path):
        return path
    destination = path + ".gz"
    temporary = destination + ".tmp"
    try:
        with open(path, "rb") as source, gzip.open(
            temporary,
            "wb",
            compresslevel=6,
        ) as target:
            shutil.copyfileobj(source, target, length=1024 * 1024)
        os.replace(temporary, destination)
        os.unlink(path)
        return destination
    except OSError:
        try:
            if os.path.isfile(temporary):
                os.unlink(temporary)
        except OSError:
            pass
        return path


def _trace_file_record_counts(path: str) -> Dict[str, int]:
    counts = {"ordered": 0, "coverage": 0, "edges": 0}
    try:
        stream = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        return counts
    with stream:
        for line in stream:
            prefix = line[:2]
            if prefix in {"E\t", "X\t", "T\t", "M\t", "V\t"}:
                counts["ordered"] += 1
            elif prefix == "C\t":
                counts["coverage"] += 1
            elif prefix == "D\t":
                counts["edges"] += 1
    return counts


def _trace_test_infrastructure_error(
    *,
    returncode: int,
    output: str,
    ordered_event_count: int,
) -> str:
    lowered = str(output or "").lower()
    if returncode in {126, 127} and ordered_event_count <= 0:
        return f"trace_test_command_failed:{returncode}"
    infrastructure_signals = (
        "no such file or directory",
        "command not found",
        "__ud_test_helper_missing__",
        "__ud_compile_fail__",
    )
    if ordered_event_count <= 0 and any(
        signal in lowered for signal in infrastructure_signals
    ):
        return "trace_test_infrastructure_failure"
    return ""


def _empty_trace_summary(
    *, diagnostics: List[str] | None = None
) -> Dict[str, Any]:
    return {
        "trace_event_count": 0,
        "persisted_event_count": 0,
        "events_tail_truncated": False,
        "coverage_function_count": 0,
        "functions": {},
        "dynamic_edges": [],
        "dynamic_callsites": [],
        "exception_events": [],
        "value_observations": [],
        "slice_boundary_observations": [],
        "active_stack": [],
        "events": [],
        "diagnostics": list(diagnostics or []),
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
            if len(parts) >= 7 and parts[0] == "C":
                try:
                    events.append({
                        "index": index,
                        "event": "C",
                        "pid": int(parts[1]),
                        "tid": 0,
                        "depth": 0,
                        "address": int(parts[2], 16),
                        "offset": int(parts[3], 16),
                        "module": parts[4],
                        "runtime_symbol": parts[5],
                        "coverage_count": int(parts[6]),
                    })
                except ValueError:
                    pass
                continue
            if len(parts) >= 11 and parts[0] == "D":
                try:
                    events.append({
                        "index": index,
                        "event": "D",
                        "pid": int(parts[1]),
                        "tid": 0,
                        "depth": 0,
                        # Reuse the normal function fields for the callee and
                        # call-site fields for the caller. Symbolization then
                        # remains a single batched addr2line pass per role.
                        "call_site": int(parts[2], 16),
                        "call_site_offset": int(parts[3], 16),
                        "call_site_module": parts[4],
                        "call_site_runtime_symbol": parts[5],
                        "address": int(parts[6], 16),
                        "offset": int(parts[7], 16),
                        "module": parts[8],
                        "runtime_symbol": parts[9],
                        "edge_count": int(parts[10]),
                    })
                except ValueError:
                    pass
                continue
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
        item = function_map.get(
            _event_address_location(
                event,
                container_repo=container_repo,
                module_field="module",
                offset_field="offset",
            ),
            {},
        )
        call_item = call_site_map.get(
            _event_address_location(
                event,
                container_repo=container_repo,
                module_field="call_site_module",
                offset_field="call_site_offset",
            ),
            {},
        )
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


def _event_address_location(
    event: Dict[str, Any],
    *,
    container_repo: str,
    module_field: str,
    offset_field: str,
) -> Tuple[str, int] | None:
    module = str(event.get(module_field) or "")
    if not module or event.get(offset_field) is None:
        return None
    resolved_module = (
        module
        if module.startswith("/")
        else f"{container_repo.rstrip('/')}/{module.lstrip('./')}"
    )
    return resolved_module, int(event[offset_field])


def _resolve_event_addresses(
    container: str,
    events: List[Dict[str, Any]],
    *,
    container_repo: str,
    module_field: str,
    offset_field: str,
    address_field: str,
) -> Dict[Tuple[str, int], Dict[str, Any]]:
    requests: Dict[str, Dict[int, int]] = defaultdict(dict)
    for event in events:
        location = _event_address_location(
            event,
            container_repo=container_repo,
            module_field=module_field,
            offset_field=offset_field,
        )
        if location is None:
            continue
        resolved_module, offset = location
        address = int(event.get(address_field) or 0)
        requests[resolved_module].setdefault(offset, address)

    symbol_map = {}
    for module, address_by_offset in requests.items():
        unique_offsets = list(address_by_offset)
        resolved = _addr2line_batch(container, module, unique_offsets)
        unresolved = {
            offset for offset, item in resolved.items()
            if not item.get("source_path")
        }
        if unresolved:
            actual_by_offset = {
                offset: address
                for offset, address in address_by_offset.items()
                if offset in unresolved
            }
            actual_result = _addr2line_batch(
                container, module, list(actual_by_offset.values())
            )
            for offset, address in actual_by_offset.items():
                if actual_result.get(address, {}).get("source_path"):
                    resolved[offset] = actual_result[address]
        for offset, item in resolved.items():
            symbol_map[(module, offset)] = item
    return symbol_map


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
    events: List[Dict[str, Any]],
    *,
    container_repo: str,
    trace_complete: bool = True,
) -> Dict[str, Any]:
    functions: Dict[str, Dict[str, Any]] = {}
    coverage_counts = Counter()
    coverage_records: Dict[str, Dict[str, Any]] = {}
    edges = Counter()
    callsites = Counter()
    stacks: Dict[Tuple[int, int], List[Dict[str, Any]]] = defaultdict(list)
    production_events = []
    exception_events = []
    value_observations = []
    slice_boundary_observations = []

    for event in events:
        if event.get("event") == "C":
            identity = _production_identity(
                event, container_repo=container_repo
            )
            key = str(identity.get("key") or "")
            if key:
                coverage_counts[key] += int(
                    event.get("coverage_count") or 0
                )
                coverage_record = coverage_records.setdefault(key, {
                    "function": identity.get("function"),
                    "source_path": identity.get("source_path"),
                    "source_line": int(
                        event.get("source_line") or 0
                    ),
                    "runtime_modules": [],
                })
                _append_identity_sample(
                    coverage_record["runtime_modules"],
                    str(event.get("module") or ""),
                )
            continue
        if event.get("event") == "D":
            callee_identity = _production_identity(
                event, container_repo=container_repo
            )
            caller_identity = _production_identity(
                {
                    "function": event.get("call_function"),
                    "source_path": event.get("call_source_path"),
                    "source_line": event.get("call_source_line"),
                },
                container_repo=container_repo,
            )
            caller = str(caller_identity.get("key") or "")
            callee = str(callee_identity.get("key") or "")
            if caller and callee and caller != callee:
                edges[(caller, callee)] += int(
                    event.get("edge_count") or 0
                )
            continue
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
            if record["marker_kind"] in {
                "slice_argument",
                "slice_return",
                "slice_write",
            }:
                slice_boundary_observations.append(record)
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
                    "invocation_count": 0,
                    "invocation_ids": [],
                    "callsite_ids": [],
                    "runtime_modules": [],
                })
                _append_identity_sample(
                    record["runtime_modules"],
                    str(event.get("module") or ""),
                )
                record["enter_count"] += 1
                record["invocation_count"] += 1
                record["max_depth"] = max(record["max_depth"], depth)
                record["last_enter_event_index"] = len(production_events)
                _append_identity_sample(
                    record["invocation_ids"],
                    invocation_id,
                )
                _append_identity_sample(
                    record["callsite_ids"],
                    callsite_id,
                )
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

    for key, count in coverage_counts.items():
        coverage = coverage_records.get(key) or {}
        record = functions.setdefault(key, {
            "key": key,
            "function": coverage.get("function"),
            "source_path": coverage.get("source_path"),
            "source_line": coverage.get("source_line"),
            "enter_count": 0,
            "max_depth": 0,
            "max_event_span": 0,
            "last_enter_event_index": -1,
            "active_at_failure": False,
            "reverse_distance": None,
            "invocation_count": 0,
            "invocation_ids": [],
            "callsite_ids": [],
            "runtime_modules": [],
        })
        for runtime_module in coverage.get("runtime_modules") or []:
            _append_identity_sample(
                record["runtime_modules"],
                runtime_module,
            )
        record["coverage_enter_count"] = int(count)
        record["enter_count"] = max(
            int(record.get("enter_count") or 0),
            int(count),
        )

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

    if trace_complete:
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
    if trace_complete:
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
        "coverage_function_count": len(coverage_counts),
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
        "slice_boundary_observations": slice_boundary_observations,
        "active_stack": active_stack,
        # Causal FL consumes the complete ordered stream in memory. The caller
        # compacts it only after producer slicing has finished.
        "events": production_events,
        "diagnostics": (
            (
                []
                if production_events or coverage_counts
                else ["no_project_source_events_symbolized"]
            )
            + (
                []
                if trace_complete
                else ["truncated_trace_not_failure_boundary"]
            )
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
    observation_fields = {
        "value_observations",
        "slice_boundary_observations",
    }
    compact = {
        key: value
        for key, value in runtime_evidence.items()
        if key != "tests" and key not in observation_fields
    }
    _persist_compact_observations(compact, runtime_evidence)
    compact_tests = []
    for test in runtime_evidence.get("tests") or []:
        if not isinstance(test, dict):
            continue
        events = test.get("events") or []
        item = {
            key: value
            for key, value in test.items()
            if key != "events" and key not in observation_fields
        }
        _persist_compact_observations(item, test)
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


def _persist_compact_observations(
    target: Dict[str, Any],
    source: Dict[str, Any],
) -> None:
    for field, count_field, summary_field in (
        (
            "value_observations",
            "value_observation_count",
            "value_observation_summary",
        ),
        (
            "slice_boundary_observations",
            "slice_boundary_observation_count",
            "slice_boundary_observation_summary",
        ),
    ):
        values = [
            item
            for item in source.get(field) or []
            if isinstance(item, dict)
        ]
        target[count_field] = len(values)
        target[field] = _bounded_probe_observations(
            values,
            per_id=PERSISTED_PROBE_SAMPLES_PER_ID,
        )
        target[summary_field] = _probe_observation_summary(values)


def _bounded_probe_observations(
    values: List[Dict[str, Any]],
    *,
    per_id: int,
) -> List[Dict[str, Any]]:
    """Retain bounded audit samples without losing distinct scalar outcomes."""
    limit = max(1, int(per_id))
    selected = set()
    selected_per_id = Counter()
    seen_values: Dict[str, set] = defaultdict(set)

    # Preserve the first occurrence of each distinct scalar value per probe.
    for index, item in enumerate(values):
        identity = _probe_observation_identity(item)
        scalar = item.get("value")
        if (
            scalar is None
            or scalar in seen_values[identity]
            or selected_per_id[identity] >= limit
        ):
            continue
        seen_values[identity].add(scalar)
        selected.add(index)
        selected_per_id[identity] += 1

    # Fill the remaining allowance with chronological examples.
    for index, item in enumerate(values):
        if index in selected:
            continue
        identity = _probe_observation_identity(item)
        if selected_per_id[identity] >= limit:
            continue
        selected.add(index)
        selected_per_id[identity] += 1
    return [values[index] for index in sorted(selected)]


def _probe_observation_summary(
    values: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    counts = Counter()
    value_counts: Dict[str, Counter] = defaultdict(Counter)
    for item in values:
        identity = _probe_observation_identity(item)
        counts[identity] += 1
        if item.get("value") is not None:
            value_counts[identity][str(item.get("value"))] += 1
    return [
        {
            "probe_id": identity,
            "count": int(counts[identity]),
            "value_counts": {
                value: int(count)
                for value, count in sorted(value_counts[identity].items())
            },
        }
        for identity in sorted(counts)
    ]


def _probe_observation_identity(item: Dict[str, Any]) -> str:
    return str(
        item.get("probe_id")
        or item.get("marker_id")
        or item.get("marker_kind")
        or "unknown"
    )


def _copy_compilation_database(
    *,
    container: str,
    container_repo: str,
    host_artifact_dir: str,
    host_source_root: str,
    captured_commands_path: str = "",
) -> str:
    """Persist a path-rewritten compilation database for host Clang.

    CMake projects can provide ``compile_commands.json`` directly. Autotools
    projects such as TCPdump use the trace compiler wrapper's bounded TSV
    capture as a fallback.
    """
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
    host_path = os.path.join(host_artifact_dir, "compile_commands.json")
    source_root = os.path.realpath(host_source_root) if host_source_root else ""
    try:
        payload = None
        if found.returncode == 0 and container_path:
            copied = subprocess.run(
                [
                    "docker",
                    "cp",
                    f"{container}:{container_path[0]}",
                    host_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=30,
            )
            if copied.returncode == 0:
                try:
                    with open(host_path, "r", encoding="utf-8") as stream:
                        payload = json.load(stream)
                except (
                    OSError,
                    TypeError,
                    UnicodeError,
                    json.JSONDecodeError,
                ):
                    payload = None
        if not isinstance(payload, list) or not payload:
            payload = _copy_captured_compilation_commands(
                container=container,
                container_path=captured_commands_path,
                host_artifact_dir=host_artifact_dir,
            )
        if not payload:
            try:
                os.unlink(host_path)
            except OSError:
                pass
            return ""
        rewritten = payload
        if source_root:
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
        database_identity = hashlib.sha256(
            json.dumps(
                rewritten,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        persisted = atomic_write_json(
            os.path.join(
                host_artifact_dir,
                "compilation_databases",
                database_identity + ".json",
            ),
            rewritten,
            indent=2,
        )
        if not persisted:
            try:
                os.unlink(host_path)
            except OSError:
                pass
            return ""
        try:
            os.unlink(host_path)
        except OSError:
            pass
        return persisted
    except (
        OSError,
        TypeError,
        UnicodeError,
        json.JSONDecodeError,
    ):
        try:
            os.unlink(host_path)
        except OSError:
            pass
        return ""


def _copy_captured_compilation_commands(
    *,
    container: str,
    container_path: str,
    host_artifact_dir: str,
) -> List[Dict[str, Any]]:
    """Convert compiler-wrapper TSV records into compile_commands entries."""
    if not container_path:
        return []
    host_path = os.path.join(
        host_artifact_dir,
        "compile_commands.captured.tsv",
    )
    copied = subprocess.run(
        ["docker", "cp", f"{container}:{container_path}", host_path],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if copied.returncode != 0:
        return []
    records = []
    seen = set()
    try:
        with open(
            host_path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as stream:
            for raw_line in stream:
                fields = raw_line.rstrip("\r\n").split("\t")
                if len(fields) < 3:
                    continue
                directory, compiler, *arguments = fields
                if not directory or not compiler:
                    continue
                sources = [
                    value
                    for value in arguments
                    if (
                        value
                        and not value.startswith("-")
                        and os.path.splitext(value)[1].lower()
                        in {".c", ".cc", ".cpp", ".cxx"}
                    )
                ]
                for source in sources:
                    source_path = (
                        source
                        if os.path.isabs(source)
                        else os.path.normpath(
                            os.path.join(directory, source)
                        )
                    )
                    identity = (
                        directory,
                        compiler,
                        tuple(arguments),
                        source_path,
                    )
                    if identity in seen:
                        continue
                    seen.add(identity)
                    records.append({
                        "directory": directory,
                        "arguments": [compiler, *arguments],
                        "file": source_path,
                    })
    except OSError:
        return []
    finally:
        try:
            os.unlink(host_path)
        except OSError:
            pass
    return records


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
    normalized_root = os.path.normpath(
        container_repo.rstrip("/").replace("\\", "/")
    )
    normalized_source = os.path.normpath(source)
    relative = ""
    if normalized_source.startswith(normalized_root + "/"):
        relative = os.path.relpath(
            normalized_source,
            normalized_root,
        ).replace("\\", "/")
    elif (
        not normalized_source.startswith("/")
        and normalized_source != ".."
        and not normalized_source.startswith("../")
    ):
        relative = normalized_source.lstrip("./")
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
