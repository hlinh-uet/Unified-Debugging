import os
import json
import argparse
from data_loaders.codeflaws_loader import load_all_bugs
from core.fl_tarantula import calculate_tarantula
from core.dynamic_failure_rerank import (
    add_dynamic_rerank_args,
    collect_dynamic_failure_data,
    config_from_args,
    print_dynamic_data_summary,
    print_dynamic_summary,
    run_dynamic_failure_rerank,
)
from core.llm_semantic_rerank import (
    add_llm_semantic_args,
    llm_semantic_config_from_args,
    print_llm_semantic_summary,
    run_llm_semantic_rerank,
)
from configs.path import EXPERIMENTS_DIR

def run_fl():
    print("Loading bugs from Codeflaws...")
    bugs = load_all_bugs()
    print(f"Loaded {len(bugs)} bugs.")

    if not bugs:
        print("No bugs found. Make sure the CODEFLAWS_RESULTS_DIR is correct.")
        return

    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    results = {}

    for bug in bugs:
        bug_id = bug['bug_id']
        test_data_dict = bug['test_data']
        test_data = test_data_dict.get('tests', [])
        
        # Save info about ground truth functions straight in the dict
        ground_truth_funcs = test_data_dict.get('ground_truth_functions', [])
        
        print(f"Calculating Tarantula score for {bug_id}...")
        scores = calculate_tarantula(test_data)
        
        results[bug_id] = {
            'scores': scores,
            'ground_truth': ground_truth_funcs
        }

    output_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    with open(output_file, 'w') as f:
        json.dump(results, f, indent=4)
        
    print(f"Tarantula scores saved to {output_file}")

def _run_apr_pipeline():
    from core.apr_baseline import run_apr_pipeline
    return run_apr_pipeline()

def _run_mutation_pipeline():
    from core.apr_mutation import run_mutation_pipeline
    return run_mutation_pipeline()

def _evaluate_fl():
    from evaluation.eval_fl import evaluate_fl
    return evaluate_fl()

def _evaluate_apr():
    from evaluation.eval_apr import evaluate_apr
    return evaluate_apr()

def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument('--fl', action='store_true', help='Chỉ chạy Fault Localization (Tarantula)')
    parser.add_argument('--apr', action='store_true', help='Chỉ chạy Automated Program Repair (APR với LLM)')
    parser.add_argument('--apr-mutation', action='store_true', help='Chỉ chạy APR sử dụng Local Heuristic Mutation (Không cần LLM)')
    parser.add_argument('--eval', action='store_true', help='Chỉ chạy đánh giá kết quả từ cả FL và APR (Evaluation)')
    parser.add_argument('--all', action='store_true', help='Chạy toàn bộ quy trình: FL -> APR -> Evaluation')
    add_dynamic_rerank_args(parser)
    add_llm_semantic_args(parser)
    args = parser.parse_args()

    if args.llm_semantic_rerank:
        print("Running OpenRouter LLM Semantic Function Rerank...")
        output = run_llm_semantic_rerank(llm_semantic_config_from_args(args))
        print(f"LLM semantic rerank finished for {len(output)} bugs.")
        print_llm_semantic_summary(output)
        return

    if args.dynamic_collect_data:
        print("Collecting Dynamic Failure Data...")
        output = collect_dynamic_failure_data(config_from_args(args))
        print(f"Dynamic failure data collected for {len(output)} bugs.")
        print_dynamic_data_summary(output)
        return

    if args.dynamic_rerank:
        print("Running Dynamic Failure-Evidence Function Rerank...")
        output = run_dynamic_failure_rerank(config_from_args(args))
        print(f"Dynamic failure rerank finished for {len(output)} bugs.")
        print_dynamic_summary(output)
        return

    # Nếu chọn --all hoặc không truyền tham số nào thì chạy toàn bộ pipeline (ưu tiên LLM cho luồng chính)
    if args.all or (not args.fl and not args.apr and not args.apr_mutation and not args.eval):
        print("Đang chạy toàn bộ quy trình gốc (FL -> APR với LLM -> Evaluation)...")
        run_fl()
        _run_apr_pipeline()
        _evaluate_fl()
        _evaluate_apr()
    else:
        if args.fl:
            print("Đang chạy quy trình Fault Localization...")
            run_fl()
            _evaluate_fl()
        if args.apr:
            print("Đang chạy quy trình Automated Program Repair (LLM)...")
            _run_apr_pipeline()
            _evaluate_apr()
        if args.apr_mutation:
            print("Đang chạy quy trình APR (Mutation Local Baseline)...")
            _run_mutation_pipeline()
            # Báo cáo sẽ được sinh ra ở json riêng, nhưng nếu muốn evaluate có thể trỏ script evaluation vào file đó!
        if args.eval:
            print("Đang chạy riêng quy trình thông kê Evaluation...")
            _evaluate_fl()
            _evaluate_apr()

    print("\nCác tính năng mới đã được thêm vào:")
    print(
        "1. Tích hợp Sandbox (Cơ chế test bằng test case có sẵn của test-genprog.sh).\n"
        "2. Đánh giá Top-K Tarantula bằng Ground Truth file.\n"
        "3. Đánh giá APR nâng cao (Edit Distance Levenshtein, Pass/Fail Regressions).\n"
        "4. Cung cấp API có khả năng truy xuất model Gemini.\n"
    )
    print("Mọi tính năng mới đã được lưu vào INSTRUCTION.md và README.md")

if __name__ == "__main__":
    main()
