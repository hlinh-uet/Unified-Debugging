import os
import json
import argparse

from data_loaders.base_loader import get_loader
from core.fault_localization import (
    calculate_fault_localization,
    calculate_fault_localization_class_level,
    calculate_fault_localization_file_level,
    calculate_ir_reranked_class_scores,
    calculate_ir_reranked_file_scores,
    calculate_ir_reranked_function_scores,
    _extract_class_from_key,
    _extract_file_from_key,
)
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


def _extract_class_from_gt(gt_key):
    return _extract_class_from_key(gt_key)


def run_fl(dataset: str = "codeflaws"):
    """
    Bước 1 – Fault Localization (Tarantula).
    Tính điểm Tarantula ở 3 mức rồi rerank bằng IR metadata:
      - Function-level → fault_localization_function_results.json
      - File-level     → fault_localization_file_results.json
      - Class-level    → fault_localization_class_results.json
    Pipeline:
      1. Tarantula file → IR reranker → file_score
      2. Tarantula class + file_score → IR reranker → class_score
      3. Tarantula function + class/file_score → IR reranker → final function score
      → fault_localization_results.json
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
    class_results = {}
    combined_results = {}

    for bug in bugs:
        print(f"[FL] Tính điểm Tarantula cho {bug.bug_id}...")

        # --- Raw Tarantula scores ---
        tarantula_func_scores = calculate_fault_localization(bug.tests)
        tarantula_file_scores = calculate_fault_localization_file_level(bug.tests)
        tarantula_class_scores = calculate_fault_localization_class_level(bug.tests)

        functions_by_file = {}
        functions_by_class = {}
        for func_key in tarantula_func_scores:
            file_key = _extract_file_from_key(func_key)
            functions_by_file.setdefault(file_key, []).append(func_key)

            class_key = _extract_class_from_key(func_key)
            if class_key:
                functions_by_class.setdefault(class_key, []).append(func_key)

        # --- 1. File-level: Tarantula file → IR reranker → file_score ---
        file_scores = calculate_ir_reranked_file_scores(
            bug.tests,
            tarantula_file_scores,
            functions_by_file=functions_by_file,
        )

        # --- 2. Class-level: Tarantula class + file_score → IR reranker → class_score ---
        class_scores = calculate_ir_reranked_class_scores(
            bug.tests,
            tarantula_class_scores,
            file_scores,
            functions_by_class=functions_by_class,
        )

        # --- 3. Function-level: Tarantula function + class/file score → IR reranker ---
        func_scores = calculate_ir_reranked_function_scores(
            bug.tests,
            tarantula_func_scores,
            class_scores,
            file_scores,
        )

        # --- Ground truth cho file-level / class-level ---
        gt_functions = bug.ground_truth  # list[str], ví dụ: ["file.c:func"]
        gt_files = list(set(_extract_file_from_gt(g) for g in gt_functions))
        gt_classes = sorted(
            set(c for g in gt_functions for c in [_extract_class_from_gt(g)] if c)
        )

        # Lưu function-level
        func_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       func_scores,
            "tarantula_scores": tarantula_func_scores,
            "ground_truth": gt_functions,
        }

        # Lưu file-level
        file_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       file_scores,
            "tarantula_scores": tarantula_file_scores,
            "ground_truth": gt_files,
        }

        # Lưu class-level
        class_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       class_scores,
            "tarantula_scores": tarantula_class_scores,
            "ground_truth": gt_classes,
        }

        # Final FL score chính là function score sau pipeline 3 mức.
        combined_scores = func_scores

        combined_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       combined_scores,
            "tarantula_scores": tarantula_func_scores,
            "ground_truth": gt_functions,
        }

    # --- Ghi file function-level ---
    func_file = os.path.join(EXPERIMENTS_DIR, "fault_localization_function_results.json")
    with open(func_file, "w") as f:
        json.dump(func_results, f, indent=4)
    print(f"[FL] Function-level scores → {func_file}")

    # --- Ghi file file-level ---
    file_file = os.path.join(EXPERIMENTS_DIR, "fault_localization_file_results.json")
    with open(file_file, "w") as f:
        json.dump(file_results, f, indent=4)
    print(f"[FL] File-level scores     → {file_file}")

    # --- Ghi file class-level ---
    class_file = os.path.join(EXPERIMENTS_DIR, "fault_localization_class_results.json")
    with open(class_file, "w") as f:
        json.dump(class_results, f, indent=4)
    print(f"[FL] Class-level scores    → {class_file}")

    # --- Ghi file combined ---
    combined_file = os.path.join(EXPERIMENTS_DIR, "fault_localization_results.json")
    with open(combined_file, "w") as f:
        json.dump(combined_results, f, indent=4)
    print(f"[FL] Final FL scores (file→class→function IR rerank) → {combined_file}")


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
        "--fl-eval-level",
        default="combined",
        choices=["combined", "function", "file", "class", "all"],
        help=(
            "Mức kết quả FL dùng khi evaluation: combined "
            "(fault_localization_results.json), function "
            "(fault_localization_function_results.json), file "
            "(fault_localization_file_results.json), class "
            "(fault_localization_class_results.json), hoặc all."
        ),
    )
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
    fl_eval_level = args.fl_eval_level

    # Nếu không truyền flag nào thì mặc định chạy toàn bộ
    run_all = args.all or (not args.fl and not args.apr and not args.eval)

    if run_all:
        print(f"[Pipeline] Chạy toàn bộ quy trình trên dataset '{dataset}' (FL → APR LLM → Evaluation)...")
        run_fl(dataset)
        run_apr_pipeline(dataset, llm_provider=llm_provider)
        evaluate_fl(dataset, level=fl_eval_level)
        evaluate_apr(dataset)
    else:
        if args.fl:
            print(f"[Pipeline] Chạy Fault Localization trên dataset '{dataset}'...")
            run_fl(dataset)
            evaluate_fl(dataset, level=fl_eval_level)

        if args.apr:
            print(f"[Pipeline] Chạy APR (LLM: {llm_provider or 'default'}) trên dataset '{dataset}'...")
            run_apr_pipeline(dataset, llm_provider=llm_provider)
            evaluate_apr(dataset)

        if args.eval:
            print("[Pipeline] Chạy Evaluation...")
            evaluate_fl(dataset, level=fl_eval_level)
            evaluate_apr(dataset)


if __name__ == "__main__":
    main()
