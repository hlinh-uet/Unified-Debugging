import os
import json
import argparse

from data_loaders.base_loader import get_loader
from core.fl_tarantula import calculate_tarantula, calculate_tarantula_file_level, _extract_file_from_key
from core.apr_baseline import run_apr_pipeline
from evaluation.eval_fl import evaluate_fl
from evaluation.eval_apr import evaluate_apr
from configs.path import EXPERIMENTS_DIR


def _extract_file_from_gt(gt_key):
    """
    Trích xuất tên file từ ground truth key.
    Hỗ trợ cả dạng 'file.c:function', 'file.h:class::method',
    và 'path/to/file.c::function'.
    """
    import re

    # Tìm dấu ':' đơn đầu tiên (không phải '::')
    match = re.search(r'(?<!:):(?!:)', gt_key)
    if match:
        file_part = gt_key[:match.start()]
        return os.path.basename(file_part) if file_part else gt_key

    # Fallback: chỉ có '::'
    if "::" in gt_key:
        src_path = gt_key.rsplit("::", 1)[0]
        return os.path.basename(src_path)

    return gt_key


def run_fl(dataset: str = "codeflaws"):
    """
    Bước 1 – Fault Localization (Tarantula).
    Tính điểm Tarantula ở 2 mức:
      - Function-level → tarantula_function_results.json
      - File-level     → tarantula_file_results.json
    Sau đó tổng hợp: combined_score = function_score*0.5 + file_score*0.5
      → tarantula_results.json
    """
    print(f"[FL] Đang load bugs từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bugs = loader.load_all()
    print(f"[FL] Đã load {len(bugs)} bugs.")

    if not bugs:
        print(f"[FL] Không tìm thấy bug nào. Kiểm tra lại đường dẫn dataset '{dataset}'.")
        return

    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    func_results = {}
    file_results = {}
    combined_results = {}

    for bug in bugs:
        print(f"[FL] Tính điểm Tarantula cho {bug.bug_id}...")

        # --- Function-level ---
        func_scores = calculate_tarantula(bug.tests)

        # --- File-level ---
        file_scores = calculate_tarantula_file_level(bug.tests)

        # --- Ground truth cho file-level ---
        gt_functions = bug.ground_truth  # list[str], ví dụ: ["file.c:func"]
        gt_files = list(set(_extract_file_from_gt(g) for g in gt_functions))

        # Lưu function-level
        func_results[bug.bug_id] = {
            "dataset":      dataset,
            "scores":       func_scores,
            "ground_truth": gt_functions,
        }

        # Lưu file-level
        file_results[bug.bug_id] = {
            "dataset":      dataset,
            "scores":       file_scores,
            "ground_truth": gt_files,
        }

        # --- Combined: function_score*0.5 + file_score*0.5 ---
        # Với mỗi function key, lấy file_score tương ứng rồi tính trung bình
        combined_scores = {}
        for func_key, f_score in func_scores.items():
            # Trích file từ function key
            file_key = _extract_file_from_key(func_key)
            fi_score = file_scores.get(file_key, 0.0)
            combined_scores[func_key] = f_score * 0.5 + fi_score * 0.5

        # Sort descending
        combined_scores = dict(
            sorted(combined_scores.items(), key=lambda item: item[1], reverse=True)
        )

        combined_results[bug.bug_id] = {
            "dataset":      dataset,
            "scores":       combined_scores,
            "ground_truth": gt_functions,
        }

    # --- Ghi file function-level ---
    func_file = os.path.join(EXPERIMENTS_DIR, "tarantula_function_results.json")
    with open(func_file, "w") as f:
        json.dump(func_results, f, indent=4)
    print(f"[FL] Function-level scores → {func_file}")

    # --- Ghi file file-level ---
    file_file = os.path.join(EXPERIMENTS_DIR, "tarantula_file_results.json")
    with open(file_file, "w") as f:
        json.dump(file_results, f, indent=4)
    print(f"[FL] File-level scores     → {file_file}")

    # --- Ghi file combined ---
    combined_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    with open(combined_file, "w") as f:
        json.dump(combined_results, f, indent=4)
    print(f"[FL] Combined scores (0.5*func + 0.5*file) → {combined_file}")


def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument(
        "--dataset", default="codeflaws",
        help="Tên dataset cần chạy: codeflaws (mặc định), defects4c, ..."
    )
    parser.add_argument("--fl",           action="store_true", help="Chỉ chạy Fault Localization (Tarantula)")
    parser.add_argument("--apr",          action="store_true", help="Chỉ chạy APR với LLM")
    parser.add_argument("--eval",         action="store_true", help="Chỉ chạy Evaluation")
    parser.add_argument("--all",          action="store_true", help="Chạy toàn bộ: FL → APR → Evaluation")
    parser.add_argument(
        "--llm",
        default=None,
        choices=["gemini", "openai", "claude", "qwen", "openrouter"],
        help="LLM provider cho APR: gemini, openai, claude, qwen/openrouter. "
             "Override biến môi trường LLM_PROVIDER.",
    )
    args = parser.parse_args()

    dataset      = args.dataset
    llm_provider = args.llm   # None → đọc từ LLM_PROVIDER trong .env

    # Nếu không truyền flag nào thì mặc định chạy toàn bộ
    run_all = args.all or (not args.fl and not args.apr and not args.eval)

    if run_all:
        print(f"[Pipeline] Chạy toàn bộ quy trình trên dataset '{dataset}' (FL → APR LLM → Evaluation)...")
        run_fl(dataset)
        run_apr_pipeline(dataset, llm_provider=llm_provider)
        evaluate_fl(dataset)
        evaluate_apr(dataset)
    else:
        if args.fl:
            print(f"[Pipeline] Chạy Fault Localization trên dataset '{dataset}'...")
            run_fl(dataset)
            evaluate_fl(dataset)

        if args.apr:
            print(f"[Pipeline] Chạy APR (LLM: {llm_provider or 'default'}) trên dataset '{dataset}'...")
            run_apr_pipeline(dataset, llm_provider=llm_provider)
            evaluate_apr(dataset)

        if args.eval:
            print("[Pipeline] Chạy Evaluation...")
            evaluate_fl(dataset)
            evaluate_apr(dataset)


if __name__ == "__main__":
    main()
