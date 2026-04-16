import os
import json
from configs.path import EXPERIMENTS_DIR


def evaluate_fl():
    """
    Đánh giá Fault Localization (Tarantula) với các metrics chuẩn:
      - Top-K accuracy (K=1, 3, 5): GT function xuất hiện trong top K?
      - MFR (Mean First Rank): trung bình rank đầu tiên của GT function
      - MAR (Mean Average Rank): trung bình rank của tất cả GT functions
      - EXAM score: % functions cần kiểm tra trước khi tìm thấy GT function

    Tie-breaking: khi nhiều hàm có cùng điểm, dùng worst-case rank
    (tất cả hàm cùng điểm được gán rank = vị trí cuối cùng trong nhóm).
    """
    print("\n--- Báo cáo Đánh giá Fault Localization (FL) ---")
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_file):
        print(f"Không tìm thấy file kết quả định vị lỗi {tarantula_file}")
        return

    with open(tarantula_file, 'r') as f:
        tarantula_results = json.load(f)

    total_bugs = len(tarantula_results)

    top_1_hit = 0
    top_3_hit = 0
    top_5_hit = 0

    all_first_ranks = []
    all_avg_ranks   = []
    all_exam_scores = []

    evaluated_bugs = 0
    skipped_no_gt  = 0
    skipped_no_scores = 0

    for bug_id, result_data in tarantula_results.items():
        if not isinstance(result_data, dict) or 'scores' not in result_data:
            skipped_no_scores += 1
            continue

        scores = result_data.get('scores', {})
        ground_truth = result_data.get('ground_truth', [])

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
        for gt_func in ground_truth:
            if gt_func in func_ranks:
                gt_ranks.append(func_ranks[gt_func])
            else:
                gt_ranks.append(total_funcs + 1)

        first_rank = min(gt_ranks)
        avg_rank   = sum(gt_ranks) / len(gt_ranks)

        all_first_ranks.append(first_rank)
        all_avg_ranks.append(avg_rank)

        if total_funcs > 0:
            all_exam_scores.append(first_rank / total_funcs)

        if first_rank <= 1:
            top_1_hit += 1
        if first_rank <= 3:
            top_3_hit += 1
        if first_rank <= 5:
            top_5_hit += 1

    print(f"Tổng số bugs: {total_bugs}")
    print(f"  Đánh giá được (có GT + scores): {evaluated_bugs}")
    print(f"  Bỏ qua (thiếu ground truth):    {skipped_no_gt}")
    print(f"  Bỏ qua (thiếu scores/format):   {skipped_no_scores}")
    print()

    if evaluated_bugs > 0:
        print(f"Top-1 Accuracy: {top_1_hit}/{evaluated_bugs} ({top_1_hit/evaluated_bugs*100:.2f}%)")
        print(f"Top-3 Accuracy: {top_3_hit}/{evaluated_bugs} ({top_3_hit/evaluated_bugs*100:.2f}%)")
        print(f"Top-5 Accuracy: {top_5_hit}/{evaluated_bugs} ({top_5_hit/evaluated_bugs*100:.2f}%)")
        print()

        mfr = sum(all_first_ranks) / len(all_first_ranks)
        mar = sum(all_avg_ranks) / len(all_avg_ranks)
        print(f"MFR (Mean First Rank):   {mfr:.4f}")
        print(f"MAR (Mean Average Rank): {mar:.4f}")

        if all_exam_scores:
            avg_exam = sum(all_exam_scores) / len(all_exam_scores)
            print(f"EXAM Score (trung bình): {avg_exam:.4f}")

    print("--- Hoàn thành Đánh giá FL ---\n")


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
