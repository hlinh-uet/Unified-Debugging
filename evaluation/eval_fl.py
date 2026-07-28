import os
import json
import re
from configs.path import EXPERIMENTS_DIR


FL_RESULT_FILES = {
    "combined": "fault_localization_results.json",
    "valid": "fault_localization_results_valid.json",
    "apr_feedback": "fault_localization_apr_feedback_results.json",
    "function": "fault_localization_function_results.json",
    "file": "fault_localization_file_results.json",
    "class": "fault_localization_class_results.json",
}


def evaluate_fl(dataset: str = "", level: str = "combined", results_dir: str = None):
    """
    Đánh giá Fault Localization với các metrics chuẩn:
      - Top-K accuracy (K=1, 3, 5): GT function xuất hiện trong top K?
      - MFR (Mean First Rank): trung bình rank đầu tiên của GT function
      - MAR (Mean Average Rank): trung bình rank của tất cả GT functions
      - EXAM score: % functions cần kiểm tra trước khi tìm thấy GT function

    Tie-breaking: khi nhiều hàm có cùng điểm, dùng worst-case rank
    (tất cả hàm cùng điểm được gán rank = vị trí cuối cùng trong nhóm).
    """
    if level == "all":
        for one_level in ("combined", "valid", "apr_feedback", "function", "file", "class"):
            evaluate_fl(dataset, level=one_level, results_dir=results_dir)
        return

    if level not in FL_RESULT_FILES:
        raise ValueError(
            f"FL evaluation level không hợp lệ: {level}. "
            "Chọn một trong: combined, valid, apr_feedback, function, file, class, all."
        )

    print(f"\n--- Báo cáo Đánh giá Fault Localization (FL - {level}) ---")
    fl_results_file = os.path.join(results_dir or EXPERIMENTS_DIR, FL_RESULT_FILES[level])
    if not os.path.exists(fl_results_file):
        print(f"Không tìm thấy file kết quả định vị lỗi {fl_results_file}")
        return

    with open(fl_results_file, 'r') as f:
        fl_results = json.load(f)

    top_1_hit = 0
    top_3_hit = 0
    top_5_hit = 0
    top_10_hit = 0

    all_first_ranks = []
    all_avg_ranks   = []
    all_exam_scores = []

    evaluated_bugs = 0
    skipped_no_gt  = 0
    skipped_no_scores = 0
    skipped_other_dataset = 0
    namespace_equivalent_matches = 0
    unmatched_ground_truths = 0
    total_bugs = 0

    dataset_key = (dataset or "").strip().lower()

    for bug_id, result_data in fl_results.items():
        if not isinstance(result_data, dict) or 'scores' not in result_data:
            skipped_no_scores += 1
            continue
        result_dataset = str(result_data.get("dataset") or "").strip().lower()
        if dataset_key and result_dataset and result_dataset != dataset_key:
            skipped_other_dataset += 1
            continue
        total_bugs += 1

        scores = result_data.get('scores', {})
        ground_truth = result_data.get('ground_truth', [])
        ground_truth = [
            item.strip()
            for item in ground_truth
            if isinstance(item, str) and item.strip()
        ] if isinstance(ground_truth, list) else []

        if not ground_truth:
            skipped_no_gt += 1
            continue

        if not scores:
            skipped_no_scores += 1
            continue

        evaluated_bugs += 1
        total_funcs = len(scores)

        sorted_funcs = sorted(scores.items(), key=lambda item: item[1], reverse=True)

        func_ranks = _assign_worst_case_ranks(sorted_funcs)

        gt_ranks = []
        any_ground_truth_matched = False
        for gt_func in ground_truth:
            matched_keys = _equivalent_score_keys(gt_func, func_ranks)
            if not matched_keys:
                gt_ranks.append(total_funcs + 1)
                unmatched_ground_truths += 1
                continue
            any_ground_truth_matched = True
            gt_ranks.append(min(func_ranks[key] for key in matched_keys))
            if gt_func not in func_ranks:
                namespace_equivalent_matches += 1

        first_rank = min(gt_ranks)
        avg_rank   = sum(gt_ranks) / len(gt_ranks)

        all_first_ranks.append(first_rank)
        all_avg_ranks.append(avg_rank)

        if total_funcs > 0:
            all_exam_scores.append(min(first_rank, total_funcs) / total_funcs)

        if any_ground_truth_matched and first_rank <= 1:
            top_1_hit += 1
        if any_ground_truth_matched and first_rank <= 3:
            top_3_hit += 1
        if any_ground_truth_matched and first_rank <= 5:
            top_5_hit += 1
        if any_ground_truth_matched and first_rank <= 10:
            top_10_hit += 1

    print(f"Tổng số bugs: {total_bugs}")
    print(f"  Đánh giá được (có GT + scores): {evaluated_bugs}")
    print(f"  Bỏ qua (thiếu ground truth):    {skipped_no_gt}")
    print(f"  Bỏ qua (thiếu scores/format):   {skipped_no_scores}")
    if skipped_other_dataset:
        print(f"  Bỏ qua (khác dataset):          {skipped_other_dataset}")
    print(f"  GT khớp qua namespace suffix:   {namespace_equivalent_matches}")
    print(f"  GT không có candidate tương ứng:{unmatched_ground_truths:5d}")
    print()

    if evaluated_bugs > 0:
        print(f"Top-1  Accuracy: {top_1_hit}/{evaluated_bugs} ({top_1_hit/evaluated_bugs*100:.2f}%)")
        print(f"Top-3  Accuracy: {top_3_hit}/{evaluated_bugs} ({top_3_hit/evaluated_bugs*100:.2f}%)")
        print(f"Top-5  Accuracy: {top_5_hit}/{evaluated_bugs} ({top_5_hit/evaluated_bugs*100:.2f}%)")
        print(f"Top-10 Accuracy: {top_10_hit}/{evaluated_bugs} ({top_10_hit/evaluated_bugs*100:.2f}%)")
        print()

        mfr = sum(all_first_ranks) / len(all_first_ranks)
        mar = sum(all_avg_ranks) / len(all_avg_ranks)
        print(f"MFR (Mean First Rank):   {mfr:.4f}")
        print(f"MAR (Mean Average Rank): {mar:.4f}")

        if all_exam_scores:
            avg_exam = sum(all_exam_scores) / len(all_exam_scores)
            print(f"EXAM Score (trung bình): {avg_exam:.4f}")

    print(f"--- Hoàn thành Đánh giá FL ({level}) ---\n")


def _assign_worst_case_ranks(sorted_funcs):
    """
    Gán rank cho mỗi hàm. Khi nhiều hàm có cùng score,
    tất cả đều nhận worst-case rank (vị trí cuối nhóm).
    Ví dụ: [A=0.8, B=0.8, C=0.5] → A=2, B=2, C=3
    """
    ranks = {}
    i = 0
    while i < len(sorted_funcs):
        j = i
        while j < len(sorted_funcs) and sorted_funcs[j][1] == sorted_funcs[i][1]:
            j += 1
        worst_rank = j
        for k in range(i, j):
            ranks[sorted_funcs[k][0]] = worst_rank
        i = j
    return ranks


def _normalize_ground_truth_for_score_keys(ground_truth, scores):
    """
    Chuẩn hóa GT khi score keys dùng schema Defects4C `file.c:function`.
    Codeflaws giữ nguyên vì score keys của nó thường là `path::function`.
    """
    if not isinstance(ground_truth, list):
        return []

    if not isinstance(scores, dict):
        return ground_truth
    uses_file_colon = any(
        isinstance(k, str) and "::" not in k and ":" in k for k in scores.keys()
    )
    if not uses_file_colon:
        return ground_truth

    normalized = []
    for item in ground_truth:
        if not isinstance(item, str):
            continue
        normalized.append(_normalize_gt_key(item))
    return normalized


def _equivalent_score_keys(ground_truth_key, score_keys):
    """Return score keys denoting the same source symbol as a GT key.

    Runtime symbolization retains complete namespaces such as ``lib::v7``.
    Dataset ground truth often omits those leading scopes. A prediction is
    therefore equivalent when it has the same source-file basename and its
    qualified symbol ends with the GT symbol at a ``::`` boundary.
    """
    if not isinstance(ground_truth_key, str):
        return []
    ground_truth_key = ground_truth_key.strip()
    if not ground_truth_key:
        return []

    keys = [key for key in score_keys if isinstance(key, str)]
    if ground_truth_key in keys:
        return [ground_truth_key]

    gt_file, gt_symbol = _split_localization_key(ground_truth_key)
    if not gt_file:
        return []
    matches = []
    for score_key in keys:
        score_file, score_symbol = _split_localization_key(score_key)
        if score_file != gt_file:
            continue
        if not gt_symbol or not score_symbol:
            if gt_symbol == score_symbol:
                matches.append(score_key)
            continue
        if _qualified_symbols_equivalent(gt_symbol, score_symbol):
            matches.append(score_key)
    return matches


def _split_localization_key(value):
    """Normalize ``path/file.ext:{:|::}symbol`` without losing C++ scopes."""
    value = str(value or "").strip().replace("\\", "/")
    match = re.match(
        r"^(?P<file>.+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx))"
        r"(?P<separator>::|:)(?P<symbol>.+)$",
        value,
        re.IGNORECASE,
    )
    if match:
        return (
            os.path.basename(match.group("file")),
            match.group("symbol").strip(),
        )
    if re.match(
        r"^.+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx)$",
        value,
        re.IGNORECASE,
    ):
        return os.path.basename(value), ""
    return "", value


def _qualified_symbols_equivalent(left, right):
    left = re.sub(r"\s+", "", str(left or ""))
    right = re.sub(r"\s+", "", str(right or ""))
    return (
        left == right
        or left.endswith("::" + right)
        or right.endswith("::" + left)
    )


def _normalize_gt_key(value: str) -> str:
    value = value.strip()
    path_func = re.match(
        r"^(?P<file>.+\.(?:c|cc|cpp|cxx|h|hh|hpp))::(?P<func>.+)$",
        value,
    )
    if path_func:
        return f"{os.path.basename(path_func.group('file'))}:{path_func.group('func')}"

    first_colon = value.find(":")
    if first_colon >= 0 and not value.startswith("::", first_colon):
        file_hint = value[:first_colon]
        func = value[first_colon + 1:]
        if file_hint and func:
            return f"{os.path.basename(file_hint)}:{func}"

    if "::" in value:
        src_path, func = value.rsplit("::", 1)
        return f"{os.path.basename(src_path)}:{func}"
    return value
