import os
import json
import subprocess
from typing import Tuple

from configs.path import EXPERIMENTS_DIR, CODEFLAWS_SOURCE_DIR
from core.utils import (
    extract_function_code,
    get_codeflaws_accepted_cfile,
    normalize_code_for_edit_distance,
    parse_sbfl_qualified_name,
)
from data_loaders.base_loader import get_loader

try:
    import Levenshtein
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False

# ---------------------------------------------------------------------------
# Fix category labels (in display order)
# ---------------------------------------------------------------------------
# CleanFix : any number of init-fails fixed (including all), no regression
# NoiseFix : any number of init-fails fixed (including all), caused regression
# NoneFix  : nothing fixed, nothing broken
# NegFix   : nothing fixed, made things worse (regression)
#
# "Plausible" (all init-fails fixed + no regression) is a sub-set of CleanFix
# and is reported separately in the aggregated summary.

FIX_CATEGORIES = ["CleanFix", "NoiseFix", "NoneFix", "NegFix"]


def _classify_fix(init_failed: list, post_failed: list) -> str:
    """
    Classify the outcome of an APR attempt into one of four categories.

    Args:
        init_failed : list of test IDs that were failing before the patch.
        post_failed : list of test IDs that are failing after the patch.

    Returns:
        One of: "CleanFix", "NoiseFix", "NoneFix", "NegFix".

    Notes:
        CleanFix covers both partial and full fixes with no regression.
        NoiseFix covers both partial and full fixes that also caused regression.
        "Plausible" (all init-fails fixed, no regression) is a CleanFix sub-type
        tracked separately in the aggregated summary.
    """
    init_failed_set = set(init_failed)
    post_failed_set = set(post_failed)

    fixed      = init_failed_set - post_failed_set   # were failing, now pass
    regression = post_failed_set - init_failed_set   # were passing, now fail

    any_fixed = bool(fixed)
    has_reg   = bool(regression)

    if     any_fixed and not has_reg: return "CleanFix"
    if     any_fixed and     has_reg: return "NoiseFix"
    if not any_fixed and not has_reg: return "NoneFix"
    # not any_fixed and has_reg
    return "NegFix"


def evaluate_apr(dataset: str = "codeflaws"):
    """
    Evaluate APR results across all engines found in experiments/.

    Metrics per bug:
      - Fix category  (Plausible / PlausibleReg / CleanFix / NoiseFix / NoneFix / NegFix)
      - Edit Distance (function-level): patched_function vs accepted_function
      - Edit Distance (file-level):     patched_file     vs accepted_file

    Summary:
      - Count & rate for each fix category
      - Edit Distance statistics
    """
    print(f"\n{'='*80}")
    print(f"  APR EVALUATION REPORT — '{dataset}'")
    print(f"{'='*80}")

    if not HAS_LEVENSHTEIN:
        print("  [WARN] 'python-Levenshtein' not installed — Edit Distance will be skipped.")
        print("         Install with: pip install python-Levenshtein")

    apr_files = [
        ("LLM-based APR", "apr_results.json"),
    ]

    for label, filename in apr_files:
        filepath = os.path.join(EXPERIMENTS_DIR, filename)
        if os.path.exists(filepath):
            _evaluate_one_apr(label, filepath, dataset)

    print(f"{'='*80}\n")


def _evaluate_one_apr(label: str, apr_results_file: str, dataset: str):
    """Evaluate a single APR result file."""
    print(f"\n--- {label} ({os.path.basename(apr_results_file)}) ---")

    with open(apr_results_file, "r") as f:
        apr_results = json.load(f)

    if not apr_results:
        print("  (No results)")
        return

    edit_distances_func: list[int] = []
    edit_distances_file: list[int] = []
    edit_distance_errors = []
    rows_patch = []
    rows_real = []

    total_bugs = len(apr_results)
    for bug_id, bug_res in apr_results.items():
        status = bug_res.get("status", "skipped")
        context, context_err = _build_test_eval_context(bug_id, dataset)
        rows_patch.append(_build_fix_eval_row(bug_id, bug_res, status, context, context_err, exclude_fixed_fail=True))
        rows_real.append(_build_fix_eval_row(bug_id, bug_res, status, context, context_err, exclude_fixed_fail=False))

        if status not in ("skipped", "llm_failed"):
            edit_dist_func, func_err = _calc_func_edit_distance(bug_id, bug_res, dataset)
            if func_err:
                edit_distance_errors.append((bug_id, "function", func_err))
            else:
                edit_distances_func.append(edit_dist_func)

            edit_dist_file, file_err = _calc_file_edit_distance(bug_id, bug_res, dataset)
            if file_err:
                edit_distance_errors.append((bug_id, "file", file_err))
            else:
                edit_distances_file.append(edit_dist_file)

    llm_failed_count = sum(1 for r in apr_results.values() if r.get("status") == "llm_failed")
    skipped_count    = sum(1 for r in apr_results.values() if r.get("status") == "skipped")

    _print_fix_eval_report(
        title="Patch-comparison metrics (exclude tests with outcome=FAIL and outcome_fixed=FAIL)",
        rows=rows_patch,
        total_bugs=total_bugs,
        llm_failed_count=llm_failed_count,
        skipped_count=skipped_count,
    )
    _print_fix_eval_report(
        title="Real metrics (include all tests)",
        rows=rows_real,
        total_bugs=total_bugs,
        llm_failed_count=llm_failed_count,
        skipped_count=skipped_count,
    )

    attempted_for_ed = sum(1 for r in apr_results.values() if r.get("status") not in ("skipped", "llm_failed"))
    _print_edit_distance_stats(edit_distances_func, attempted_for_ed, level="function")
    _print_edit_distance_stats(edit_distances_file, attempted_for_ed, level="file")
    _print_edit_distance_errors(edit_distance_errors)


def _build_test_eval_context(bug_id: str, dataset: str) -> Tuple[dict, str]:
    record, err = _load_bug_record(bug_id, dataset)
    if err:
        return {}, err

    tests = getattr(record, "tests", None) or []
    test_ids = []
    init_failed = set()
    fixed_fail_excluded = set()
    for test in tests:
        if not isinstance(test, dict):
            continue
        tid = str(test.get("test_id", "")).strip()
        if not tid:
            continue
        test_ids.append(tid)
        outcome = str(test.get("outcome", "")).upper()
        outcome_fixed = str(test.get("outcome_fixed", "")).upper()
        if outcome in ("FAIL", "FAILED"):
            init_failed.add(tid)
            if outcome_fixed in ("FAIL", "FAILED"):
                fixed_fail_excluded.add(tid)

    if not test_ids:
        return {}, "metadata_tests_missing"

    test_ids = list(dict.fromkeys(test_ids))
    return {
        "test_ids": set(test_ids),
        "init_failed": init_failed,
        "fixed_fail_excluded": fixed_fail_excluded,
    }, ""


def _build_fix_eval_row(
    bug_id: str,
    bug_res: dict,
    status: str,
    context: dict,
    context_err: str,
    exclude_fixed_fail: bool,
) -> dict:
    excluded = context.get("fixed_fail_excluded", set()) if exclude_fixed_fail and context else set()
    test_ids = set(context.get("test_ids", set())) - set(excluded) if context else set()
    init_failed = set(context.get("init_failed", set())) - set(excluded) if context else set()

    row = {
        "bug_id": bug_id,
        "status": status,
        "init_pass": "ERR" if context_err else len(test_ids - init_failed),
        "init_fail": "ERR" if context_err else len(init_failed),
        "post_pass": "N/A",
        "post_fail": "N/A",
        "fix_label": "N/A",
        "plausible": False,
        "attempted": status not in ("skipped", "llm_failed"),
        "error": context_err,
        "excluded": len(excluded),
    }

    if status in ("skipped", "llm_failed"):
        return row
    if context_err:
        row["fix_label"] = f"ERR:{context_err}"
        return row

    post_failed, post_err = _post_failed_ids_from_result(bug_res)
    if post_err:
        row["post_pass"] = "ERR"
        row["post_fail"] = "ERR"
        row["fix_label"] = f"ERR:{post_err}"
        row["error"] = post_err
        return row

    unknown_failed = post_failed - set(context.get("test_ids", set()))
    if unknown_failed:
        sample = ",".join(sorted(unknown_failed)[:3])
        post_err = f"post_failed_tests_unknown:{sample}"
        row["post_pass"] = "ERR"
        row["post_fail"] = "ERR"
        row["fix_label"] = f"ERR:{post_err}"
        row["error"] = post_err
        return row

    post_failed = post_failed - set(excluded)
    row["post_pass"] = len(test_ids - post_failed)
    row["post_fail"] = len(post_failed)
    row["fix_label"] = _classify_fix(list(init_failed), list(post_failed))
    row["plausible"] = len(post_failed) == 0
    return row


def _post_failed_ids_from_result(bug_res: dict) -> Tuple[set, str]:
    values = bug_res.get("full_post_failed_tests")
    count = bug_res.get("full_post_failed_count")
    if not isinstance(values, list):
        values = bug_res.get("post_failed_tests")
        count = bug_res.get("post_failed_count")
    if values is None:
        return set(), "post_failed_tests_missing"
    if not isinstance(values, list):
        return set(), "post_failed_tests_invalid"
    if any(_is_compaction_marker(v) for v in values):
        return set(), "post_failed_tests_compacted"
    failed = {str(v).strip() for v in values if str(v).strip()}
    if isinstance(count, int) and count != len(failed):
        return set(), f"post_failed_tests_count_mismatch:{len(failed)}!={count}"
    return failed, ""


def _print_fix_eval_report(
    title: str,
    rows: list,
    total_bugs: int,
    llm_failed_count: int,
    skipped_count: int,
) -> None:
    print(f"\n  --- {title} ---")
    col_w = (35, 10, 10, 15, 8)
    sep = " | "
    total_w = sum(col_w) + len(sep) * (len(col_w) - 1)
    print(
        f"{'Bug ID':<{col_w[0]}}{sep}"
        f"{'Init P/F':<{col_w[1]}}{sep}"
        f"{'Post P/F':<{col_w[2]}}{sep}"
        f"{'Fix Category':<{col_w[3]}}{sep}"
        f"{'Excluded':<{col_w[4]}}"
    )
    print("-" * total_w)
    for row in rows:
        init_pf = f"{row['init_pass']}/{row['init_fail']}"
        post_pf = f"{row['post_pass']}/{row['post_fail']}"
        print(
            f"{row['bug_id']:<{col_w[0]}}{sep}"
            f"{init_pf:<{col_w[1]}}{sep}"
            f"{post_pf:<{col_w[2]}}{sep}"
            f"{row['fix_label']:<{col_w[3]}}{sep}"
            f"{row['excluded']:<{col_w[4]}}"
        )
    print("-" * total_w)

    attempted = sum(1 for row in rows if row["attempted"])
    valid_attempted = sum(1 for row in rows if row["attempted"] and not row.get("error"))
    errored = sum(1 for row in rows if row["attempted"] and row.get("error"))
    category_counts = {cat: 0 for cat in FIX_CATEGORIES}
    for row in rows:
        if row["attempted"] and not row.get("error") and row["fix_label"] in category_counts:
            category_counts[row["fix_label"]] += 1

    print(f"  Total bugs          : {total_bugs}")
    print(f"  Attempted           : {attempted}")
    print(f"  Valid attempted     : {valid_attempted}")
    print(f"  Evaluation errors   : {errored}")
    print(f"  LLM returned nothing: {llm_failed_count}  (API error / quota)")
    print(f"  Skipped             : {skipped_count}")
    if valid_attempted <= 0:
        return

    plausible_n = sum(1 for row in rows if row["attempted"] and not row.get("error") and row["plausible"])
    print(f"\n  Fix Category Breakdown (out of {valid_attempted} valid attempted):")
    print(f"  {'Category':<15} {'Count':>6}   {'Rate':>7}")
    print(f"  {'-'*32}")
    for cat in FIX_CATEGORIES:
        n = category_counts[cat]
        print(f"  {cat:<15} {n:>6}   {n/valid_attempted*100:>6.2f}%")

    cleanfix_n = category_counts["CleanFix"]
    noisefix_n = category_counts["NoiseFix"]
    any_reg_n = noisefix_n + category_counts["NegFix"]
    print(f"\n  --- Aggregated ---")
    print(f"  Plausible  (all considered tests pass) : {plausible_n}/{valid_attempted} ({plausible_n/valid_attempted*100:.2f}%)")
    print(f"  Any fix    (CleanFix + NoiseFix)       : {cleanfix_n + noisefix_n}/{valid_attempted} ({(cleanfix_n + noisefix_n)/valid_attempted*100:.2f}%)")
    print(f"  Regression (NoiseFix + NegFix)         : {any_reg_n}/{valid_attempted} ({any_reg_n/valid_attempted*100:.2f}%)")


def _result_count(result: dict, count_key: str, values: list) -> int:
    """Use explicit count fields from APR results. Do not infer success counts."""
    raw = result.get(count_key)
    if isinstance(raw, int):
        return raw
    if isinstance(values, list):
        return len([v for v in values if not _is_compaction_marker(v)])
    return 0


def _is_compaction_marker(value) -> bool:
    return isinstance(value, str) and value.startswith("...(+") and value.endswith(" more)")


def _format_ed(distance: int, error: str) -> str:
    if error == "not_attempted":
        return "N/A"
    if error:
        return f"ERR:{error}"
    return str(distance)


def _print_edit_distance_stats(edit_distances: list, attempted: int, level: str = "function"):
    """Print edit distance statistics."""
    n = len(edit_distances)
    if not n:
        if HAS_LEVENSHTEIN:
            print(f"\n  Edit Distance ({level}): no data available.")
        return

    avg_dist    = sum(edit_distances) / n
    sorted_d    = sorted(edit_distances)
    median_dist = sorted_d[n // 2]
    min_dist    = sorted_d[0]
    max_dist    = sorted_d[-1]

    label = "patched_function vs accepted_function" if level == "function" else "patched_file vs accepted_file"
    print(f"\n  --- Edit Distance [{level}-level] ({label}) ---")
    print(f"  Bugs with data : {n}/{attempted}")
    print(f"  Mean           : {avg_dist:.2f}")
    print(f"  Median         : {median_dist}")
    print(f"  Min            : {min_dist}")
    print(f"  Max            : {max_dist}")


def _print_edit_distance_errors(errors: list) -> None:
    if not errors:
        return
    print("\n  --- Edit Distance Errors ---")
    for bug_id, level, err in errors:
        print(f"  {bug_id} [{level}] {err}")


def _get_codeflaws_accepted_path(bug_id: str) -> str:
    cfilename = get_codeflaws_accepted_cfile(bug_id)
    if not cfilename:
        return ""
    return os.path.join(CODEFLAWS_SOURCE_DIR, bug_id, cfilename)


def _calc_func_edit_distance(bug_id: str, bug_res: dict, dataset: str) -> Tuple[int, str]:
    """
    Compute Levenshtein distance for function-level APR output.

    Rule:
    - Compare patched_function generated by APR against the accepted function
      of the benchmark bug.
    - If APR repaired a different function, keep the comparison anyway; the
      distance should be high rather than hidden as an error.
    """
    if not HAS_LEVENSHTEIN:
        return -1, "levenshtein_missing"

    patched_func = bug_res.get("patched_function")
    if not patched_func or not patched_func.strip():
        return -1, "patched_function_missing"

    accepted_code, _, accepted_func_name, err = _get_accepted_bug_code_and_function(bug_id, dataset)
    if err:
        return -1, err

    accepted_func, _, _ = extract_function_code(accepted_code, accepted_func_name)
    if not accepted_func or not accepted_func.strip():
        return -1, f"accepted_function_not_found:{accepted_func_name}"

    patched_norm = normalize_code_for_edit_distance(patched_func)
    accepted_norm = normalize_code_for_edit_distance(accepted_func)

    if not patched_norm or not accepted_norm:
        return -1, "normalized_function_empty"

    return Levenshtein.distance(patched_norm, accepted_norm), ""


def _calc_file_edit_distance(bug_id: str, bug_res: dict, dataset: str) -> Tuple[int, str]:
    """
    Compute Levenshtein distance between the full patched file content and
    the accepted file of the benchmark bug.  If APR repaired another file,
    the distance is still computed against the correct accepted file.
    """
    if not HAS_LEVENSHTEIN:
        return -1, "levenshtein_missing"

    patched_file_content = bug_res.get("patched_file")
    if not patched_file_content or not patched_file_content.strip():
        return -1, "patched_file_missing"

    accepted_content, _, _, err = _get_accepted_bug_code_and_function(bug_id, dataset)
    if err:
        return -1, err

    patched_norm = normalize_code_for_edit_distance(patched_file_content)
    accepted_norm = normalize_code_for_edit_distance(accepted_content)

    if not patched_norm or not accepted_norm:
        return -1, "normalized_file_empty"

    return Levenshtein.distance(patched_norm, accepted_norm), ""


def _get_accepted_bug_code_and_function(
    bug_id: str,
    dataset: str,
) -> Tuple[str, str, str, str]:
    """Return accepted code and accepted function for the benchmark bug."""
    record, err = _load_bug_record(bug_id, dataset)
    if err:
        return "", "", "", err
    accepted_func_name, accepted_file_hint, err = _accepted_ground_truth(record)
    if err:
        return "", "", "", err

    if (dataset or "").strip().lower() == "codeflaws":
        accepted_path = _get_codeflaws_accepted_path(bug_id)
        if not accepted_path:
            return "", "", "", "accepted_path_missing"
        if not os.path.isfile(accepted_path):
            return "", accepted_path, "", f"accepted_file_not_found:{accepted_path}"
        try:
            with open(accepted_path, "r") as f:
                return f.read(), accepted_path, accepted_func_name, ""
        except Exception as exc:
            return "", accepted_path, "", f"accepted_file_read_error:{exc}"

    raw = record.raw
    repo_dir = raw.get("source_repo_dir") or ""
    commit_after = raw.get("commit_after") or ""
    if not repo_dir or not os.path.isdir(repo_dir):
        return "", "", "", "source_repo_dir_missing"
    if not commit_after:
        return "", "", "", "commit_after_missing"

    relpath, rel_err = _resolve_accepted_bug_relpath(raw, accepted_file_hint)
    if rel_err:
        return "", "", "", rel_err

    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "show", f"{commit_after}:{relpath}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception as exc:
        return "", relpath, "", f"accepted_git_show_error:{exc}"
    if result.returncode != 0:
        stderr = (result.stderr or "").strip().splitlines()
        detail = stderr[-1] if stderr else "git_show_failed"
        return "", relpath, "", f"accepted_git_show_failed:{relpath}:{detail}"
    return result.stdout, relpath, accepted_func_name, ""


def _load_bug_record(bug_id: str, dataset: str):
    try:
        record = get_loader(dataset).load_one(bug_id)
    except Exception as exc:
        return None, f"loader_error:{exc}"
    if not record:
        return None, "bug_record_missing"
    if not record.raw:
        return None, "bug_raw_missing"
    return record, ""


def _accepted_ground_truth(record) -> Tuple[str, str, str]:
    gt_list = getattr(record, "ground_truth", None) or []
    if not gt_list:
        return "", "", "ground_truth_missing"
    for gt in gt_list:
        file_hint, func_name = parse_sbfl_qualified_name(gt)
        if func_name:
            return func_name, file_hint, ""
    return "", "", "ground_truth_function_missing"


def _resolve_accepted_bug_relpath(raw: dict, accepted_file_hint: str) -> Tuple[str, str]:
    src_files = _raw_src_files(raw)
    candidates = []

    hint = (accepted_file_hint or "").strip().replace("\\", "/")
    if hint:
        for rel in src_files:
            if rel == hint or os.path.basename(rel) == os.path.basename(hint):
                candidates.append(rel)

    source_relpath = raw.get("source_relpath")
    if isinstance(source_relpath, str) and source_relpath.strip():
        candidates.append(source_relpath.strip().replace("\\", "/"))

    accepted_file = raw.get("accepted_file")
    repo_dir = raw.get("source_repo_dir") or ""
    if isinstance(accepted_file, str) and accepted_file and repo_dir:
        try:
            rel = os.path.relpath(accepted_file, repo_dir).replace(os.sep, "/")
            if not rel.startswith("../") and rel != "..":
                candidates.append(rel)
        except ValueError:
            pass

    matches = [rel for rel in dict.fromkeys(candidates) if rel in src_files or not src_files]
    matches = list(dict.fromkeys(matches))
    if len(matches) == 1:
        return matches[0], ""
    if len(matches) > 1:
        return "", f"accepted_file_ambiguous:{matches}"
    return "", f"accepted_file_not_resolved:{accepted_file_hint or '<empty>'}"


def _raw_src_files(raw: dict) -> list:
    src_files = raw.get("src_files")
    if not isinstance(src_files, list) or not src_files:
        files = raw.get("files", {})
        if isinstance(files, dict):
            src_files = files.get("src", [])
    if not isinstance(src_files, list) or not src_files:
        rel = raw.get("source_relpath")
        src_files = [rel] if rel else []
    out = []
    for rel in src_files:
        if isinstance(rel, str) and rel.strip():
            out.append(rel.strip().replace("\\", "/"))
    return list(dict.fromkeys(out))
