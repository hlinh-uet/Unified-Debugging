import os
import json
import argparse
from data_loaders.codeflaws_loader import load_all_bugs
from core.fl_tarantula import calculate_tarantula
from core.apr_baseline import run_apr_pipeline
from evaluation.eval_fl import evaluate_fl
from evaluation.eval_apr import evaluate_apr
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

def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument('--fl', action='store_true', help='Chỉ chạy Fault Localization (Tarantula)')
    parser.add_argument('--apr', action='store_true', help='Chỉ chạy Automated Program Repair (APR)')
    parser.add_argument('--eval', action='store_true', help='Chỉ chạy đánh giá kết quả từ cả FL và APR (Evaluation)')
    parser.add_argument('--all', action='store_true', help='Chạy toàn bộ quy trình: FL -> APR -> Evaluation')
    args = parser.parse_args()

    # Nếu chọn --all hoặc không truyền tham số nào thì chạy toàn bộ pipeline
    if args.all or (not args.fl and not args.apr and not args.eval):
        print("Đang chạy toàn bộ quy trình (FL -> APR -> Evaluation)...")
        run_fl()
        run_apr_pipeline()
        evaluate_fl()
        evaluate_apr()
    else:
        if args.fl:
            print("Đang chạy quy trình Fault Localization...")
            run_fl()
            evaluate_fl()
        if args.apr:
            print("Đang chạy quy trình Automated Program Repair...")
            run_apr_pipeline()
            evaluate_apr()
        if args.eval:
            print("Đang chạy riêng quy trình thông kê Evaluation...")
            evaluate_fl()
            evaluate_apr()

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
