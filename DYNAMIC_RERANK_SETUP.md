# Dynamic Failure Rerank Setup for Defects4C

This reranker is designed around the common Defects4C metadata contract, not a
single project layout.

## Common Contract

For every dataset, the algorithm expects:

```text
Unified-Debugging/experiments/<dataset>/fault_localization_function_results.json
/out/unified_debugging/<dataset>/metadata/*_meta.json
```

Each metadata file should contain:

```text
compile_cmd
test_cmd_template = bash <repo>/run_one_test.sh {test_id}
tests[*].test_id
tests[*].outcome
tests[*].outcome_fixed
tests[*].actual_output / fail_reason
tests[*].covered_functions
ground_truth_functions / ground_truth
```

The reranker uses `test_cmd_template` as a black-box test replay API. It does
not assume a project-specific test framework. Optional GDB evidence is collected
only when the command can be safely unwrapped from metadata/script artifacts.

## Why Running on Windows Falls Back

The metadata stores container paths such as:

```text
/out/<project>/git_repo_dir_<id>/run_one_test.sh {test_id}
```

If the command is run directly from Windows, `/out/...` does not exist, so real
runtime evidence cannot be collected. In that case the algorithm intentionally
falls back:

```text
dynamic_failure_scores = tarantula_scores
```

Run inside a Defects4C Docker container where `/out` is mounted.

## Start a Defects4C Container with Unified-Debugging Mounted

PowerShell:

```powershell
cd D:\project\Forstudy\defects4c
docker build -t base/defect4c .

$D4C = (Get-Location).Path
docker rm -f my_defects4c_udbg
docker run -d --name my_defects4c_udbg `
  --ipc=host `
  --cap-add SYS_PTRACE `
  --security-opt seccomp=unconfined `
  -p 11111:80 `
  -v "${D4C}/defectsc_tpl:/src" `
  -v "${D4C}/out_tmp_dirs:/out" `
  -v "${D4C}/patche_dirs:/patches" `
  -v "${D4C}/../Unified-Debugging:/udbg" `
  base/defect4c:latest sleep infinity
```

If the image does not have GDB:

```powershell
docker exec my_defects4c_udbg bash -lc "command -v gdb || (apt-get update && apt-get install -y gdb)"
```

GDB is only needed for `--dynamic-use-gdb --dynamic-use-hit-order` or
`--dynamic-use-hotness`. Plain rerun/failure classification does not need it.

## Prepare Metadata

First check that metadata exists:

```powershell
docker exec my_defects4c_udbg bash -lc "ls /out/unified_debugging/fmt/metadata | head"
```

If a dataset has no metadata, build it with that project's metadata builder
under `/src/projects` or `/src/projects_v1`. Example for `fmt`:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /src/projects_v1/fmtlib___fmt && python3 build_meta_fmt.py --metadata-dir /out/unified_debugging/fmt/metadata --raw-dir /out/unified_debugging/fmt/raw --jobs 4 --skip-if-exists --clone"
```

For another project, use its own README/builder but keep the same output shape:

```text
/out/unified_debugging/<dataset>/metadata
/out/unified_debugging/<dataset>/raw
```

Do not hand-write `run_one_test.sh`; the project metadata builder should create
the wrapper that matches that project's test framework.

## Run Dynamic Rerank

First collect runtime data for the dataset:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /udbg && PYTHONIOENCODING=utf-8 python3 main.py --dynamic-collect-data --dynamic-dataset fmt --dynamic-use-gdb --dynamic-use-hit-order --dynamic-use-hotness --dynamic-timeout 120 --dynamic-candidate-limit 100"
```

For a quick single-bug check:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /udbg && PYTHONIOENCODING=utf-8 python3 main.py --dynamic-collect-data --dynamic-dataset fmt --dynamic-bug-id A.2 --dynamic-use-gdb --dynamic-use-hit-order --dynamic-use-hotness --dynamic-timeout 120"
```

Collected data is written to:

```text
Unified-Debugging/experiments/<dataset>/dynamic_failure_data.json
Unified-Debugging/experiments/<dataset>/dynamic_failure_data/<bug_id>.json
```

Inside the mounted Unified-Debugging repo:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /udbg && PYTHONIOENCODING=utf-8 python3 main.py --dynamic-rerank --dynamic-dataset fmt"
```

Full optional runtime evidence:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /udbg && PYTHONIOENCODING=utf-8 python3 main.py --dynamic-rerank --dynamic-dataset fmt --dynamic-use-gdb --dynamic-use-hit-order --dynamic-use-hotness --dynamic-timeout 120 --dynamic-candidate-limit 100"
```

For another dataset, replace only the dataset name, for example:

```powershell
docker exec my_defects4c_udbg bash -lc "cd /udbg && PYTHONIOENCODING=utf-8 python3 main.py --dynamic-rerank --dynamic-dataset cjson --dynamic-use-gdb --dynamic-use-hit-order"
```

The default metadata path inside Docker is:

```text
/out/unified_debugging/<dataset>/metadata
```

You can override it when needed:

```text
--dynamic-metadata-dir /out/unified_debugging/<dataset>/metadata
```

## What Is Generic

Always generic:

- Rerun true failing tests with `test_cmd_template`.
- Classify failure as assertion/output, crash, timeout, or unknown.
- Extract failure signal lines and stack-like lines from stdout/stderr.
- Combine runtime evidence with Tarantula only when evidence quality is high
  enough.

Optional and adaptive:

- Direct executable commands can be traced by GDB.
- `run_one_test.sh` scripts with explicit `TEST_CMD` / `TEST_CWD` case entries
  can be traced.
- `.build_meta*_tests` mappings can be used when they point to a real binary.
- `binary::case` wrappers can be traced when the script clearly exposes
  `--gtest_filter` or an environment filter variable.

If none of these applies, that bug/project still runs, but GDB hit-order/hotness
is skipped and the score falls back when evidence is too weak.

## Outputs

```text
Unified-Debugging/experiments/<dataset>/dynamic_failure_function_results.json
Unified-Debugging/experiments/<dataset>/dynamic_failure_evidence/<bug_id>.json
Unified-Debugging/experiments/<dataset>/dynamic_failure_data.json
Unified-Debugging/experiments/<dataset>/dynamic_failure_data/<bug_id>.json
```

The command prints:

```text
top3 / top5 / top10
improved / same / worse
```

## Verify Evidence

Open one evidence file:

```text
Unified-Debugging/experiments/<dataset>/dynamic_failure_evidence/<bug_id>.json
```

Good signs:

```text
fallback: null
evidence_quality: >= 0.10
stack_frames: non-empty, for crash/ASAN/assert stack output
candidate_last_hit_order: non-empty, when GDB hit-order works
candidate_hit_counts: non-empty, when GDB hotness works
```

Fallback signs:

```text
fallback: tarantula
fallback_reason: runtime_evidence_below_threshold
```

Common causes:

- The dataset has no FL result JSON under `experiments/<dataset>/`.
- Metadata is missing under `/out/unified_debugging/<dataset>/metadata`.
- The project workspace was not built, so `run_one_test.sh` cannot replay tests.
- GDB is not installed or the wrapper cannot be safely unwrapped.
- The failure is assertion/output with no stack and no executable-level trace.

## Current Rule

The dynamic algorithm does not use IR scores. It uses:

```text
Tarantula score + runtime evidence from rerun failed tests
```

If runtime evidence is weak, it keeps the original Tarantula ranking.
