import os
import json

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR, CODEFLAWS_SOURCE_DIR
from core.utils import (
    extract_function_code,
    get_codeflaws_accepted_cfile,
    normalize_code_for_edit_distance,
    parse_qualified_func,
)

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
        ("LLM-based APR",      "apr_results.json"),
        ("Mutation-based APR", "apr_mutation_results.json"),
        ("GenProg APR",        "apr_genprog_results.json"),
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

    total_bugs = len(apr_results)
    attempted  = 0

    category_counts = {cat: 0 for cat in FIX_CATEGORIES}
    edit_distances_func: list[int] = []
    edit_distances_file: list[int] = []

    # Column widths: Bug ID | Init P/F | Post P/F | Fix Category | ED(func) | ED(file)
    col_w = (35, 10, 10, 15, 10, 10)
    sep   = " | "
    total_w = sum(col_w) + len(sep) * (len(col_w) - 1)

    header = (
        f"{'Bug ID':<{col_w[0]}}{sep}"
        f"{'Init P/F':<{col_w[1]}}{sep}"
        f"{'Post P/F':<{col_w[2]}}{sep}"
        f"{'Fix Category':<{col_w[3]}}{sep}"
        f"{'ED(func)':<{col_w[4]}}{sep}"
        f"{'ED(file)':<{col_w[5]}}"
    )
    print(header)
    print("-" * total_w)

    for bug_id, bug_res in apr_results.items():
        status = bug_res.get("status", "skipped")

        init_passed_list = bug_res.get("init_passed_tests", [])
        init_failed_list = bug_res.get("init_failed_tests", [])
        init_pass = len(init_passed_list)
        init_fail = len(init_failed_list)

        post_pass      = 0
        post_fail      = 0
        fix_label      = "N/A"
        edit_dist_func = -1
        edit_dist_file = -1

        if status not in ("skipped", "llm_failed"):
            attempted += 1

            post_passed_tests = bug_res.get("post_passed_tests", [])
            post_failed_tests = bug_res.get("post_failed_tests", [])

            # For successful patches, fall back to full test count if lists are empty
            if status == "success" and not post_passed_tests:
                post_pass = init_pass + init_fail
                post_fail = 0
            else:
                post_pass = len(post_passed_tests)
                post_fail = len(post_failed_tests)

            fix_label = _classify_fix(init_failed_list, post_failed_tests)
            category_counts[fix_label] += 1

            edit_dist_func = _calc_func_edit_distance(bug_id, bug_res, dataset)
            if edit_dist_func >= 0:
                edit_distances_func.append(edit_dist_func)

            edit_dist_file = _calc_file_edit_distance(bug_id, bug_res, dataset)
            if edit_dist_file >= 0:
                edit_distances_file.append(edit_dist_file)

        print(
            f"{bug_id:<{col_w[0]}}{sep}"
            f"{f'{init_pass}/{init_fail}':<{col_w[1]}}{sep}"
            f"{f'{post_pass}/{post_fail}':<{col_w[2]}}{sep}"
            f"{fix_label:<{col_w[3]}}{sep}"
            f"{'N/A' if edit_dist_func < 0 else edit_dist_func:<{col_w[4]}}{sep}"
            f"{'N/A' if edit_dist_file < 0 else edit_dist_file:<{col_w[5]}}"
        )

    llm_failed_count = sum(1 for r in apr_results.values() if r.get("status") == "llm_failed")
    skipped_count    = sum(1 for r in apr_results.values() if r.get("status") == "skipped")

    print("-" * total_w)
    print(f"  Total bugs          : {total_bugs}")
    print(f"  Attempted           : {attempted}")
    print(f"  LLM returned nothing: {llm_failed_count}  (API error / quota)")
    print(f"  Skipped             : {skipped_count}")

    if attempted > 0:
        # Count Plausible as sub-metric: all init-fails fixed + no regression
        plausible_n = sum(
            1 for r in apr_results.values()
            if r.get("status") not in ("skipped", "llm_failed")
            and set(r.get("init_failed_tests", [])) - set(r.get("post_failed_tests", [])) == set(r.get("init_failed_tests", []))
            and bool(r.get("init_failed_tests", []))
            and not (set(r.get("post_failed_tests", [])) - set(r.get("init_failed_tests", [])))
        )

        print(f"\n  Fix Category Breakdown (out of {attempted} attempted):")
        print(f"  {'Category':<15} {'Count':>6}   {'Rate':>7}")
        print(f"  {'-'*32}")
        for cat in FIX_CATEGORIES:
            n = category_counts[cat]
            print(f"  {cat:<15} {n:>6}   {n/attempted*100:>6.2f}%")

        cleanfix_n  = category_counts["CleanFix"]
        noisefix_n  = category_counts["NoiseFix"]
        any_reg_n   = noisefix_n + category_counts["NegFix"]

        print(f"\n  --- Aggregated ---")
        print(f"  Plausible  (all fixed, no regression) : {plausible_n}/{attempted} ({plausible_n/attempted*100:.2f}%)  ← subset of CleanFix")
        print(f"  Any fix    (CleanFix + NoiseFix)      : {cleanfix_n + noisefix_n}/{attempted} ({(cleanfix_n + noisefix_n)/attempted*100:.2f}%)")
        print(f"  Regression (NoiseFix + NegFix)        : {any_reg_n}/{attempted} ({any_reg_n/attempted*100:.2f}%)")

    _print_edit_distance_stats(edit_distances_func, attempted, level="function")
    _print_edit_distance_stats(edit_distances_file, attempted, level="file")


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


def _get_accepted_path(bug_id: str) -> str:
    """Return the path to the benchmark accepted file for a given bug_id."""
    cfilename = get_codeflaws_accepted_cfile(bug_id)
    if not cfilename:
        return ""
    return os.path.join(CODEFLAWS_SOURCE_DIR, bug_id, cfilename)


def _calc_func_edit_distance(bug_id: str, bug_res: dict, dataset: str) -> int:
    """
    Compute Levenshtein distance between the patched function and the
    corresponding function extracted from the benchmark accepted file.
    Returns -1 if the distance cannot be computed.
    """
    if not HAS_LEVENSHTEIN:
        return -1

    patched_func  = bug_res.get("patched_function")
    selected_func = bug_res.get("selected_function", "")
    if not patched_func or not patched_func.strip() or not selected_func:
        return -1

    _, func_name = parse_qualified_func(selected_func)

    accepted_path = _get_accepted_path(bug_id)
    if not accepted_path or not os.path.exists(accepted_path):
        return -1

    try:
        with open(accepted_path, "r") as f:
            accepted_code = f.read()
    except Exception:
        return -1

    accepted_func, _, _ = extract_function_code(accepted_code, func_name)
    if not accepted_func:
        return -1

    patched_norm = normalize_code_for_edit_distance(patched_func)
    accepted_norm = normalize_code_for_edit_distance(accepted_func)

    if not patched_norm or not accepted_norm:
        return -1

    return Levenshtein.distance(patched_norm, accepted_norm)


def _calc_file_edit_distance(bug_id: str, bug_res: dict, dataset: str) -> int:
    """
    Compute Levenshtein distance between the full patched file content and
    the benchmark accepted file.  Useful when FL targeted the wrong function
    (func-level ED would be -1 but file-level ED is still measurable).
    Returns -1 if the distance cannot be computed.
    """
    if not HAS_LEVENSHTEIN:
        return -1

    patched_file_content = bug_res.get("patched_file")
    if not patched_file_content or not patched_file_content.strip():
        return -1

    accepted_path = _get_accepted_path(bug_id)
    if not accepted_path or not os.path.exists(accepted_path):
        return -1

    try:
        with open(accepted_path, "r") as f:
            accepted_content = f.read()
    except Exception:
        return -1

    patched_norm = normalize_code_for_edit_distance(patched_file_content)
    accepted_norm = normalize_code_for_edit_distance(accepted_content)

    if not patched_norm or not accepted_norm:
        return -1

    return Levenshtein.distance(patched_norm, accepted_norm)
