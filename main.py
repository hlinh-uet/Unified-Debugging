import os
import json
import argparse

from data_loaders.base_loader import get_loader
from core.fl_tarantula import calculate_tarantula
from core.apr_baseline import run_apr_pipeline
from core.apr_genprog import run_genprog_pipeline
from core.apr_mutation import run_mutation_pipeline
from evaluation.eval_fl import evaluate_fl
from evaluation.eval_apr import evaluate_apr
from configs.path import EXPERIMENTS_DIR


def run_fl(dataset: str = "codeflaws"):
    """
    Bước 1 – Fault Localization (Tarantula).
    Load toàn bộ bug từ dataset được chỉ định, tính điểm Tarantula cho từng bug
    và lưu kết quả ra experiments/tarantula_results.json.
    """
    print(f"[FL] Đang load bugs từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bugs = loader.load_all()
    print(f"[FL] Đã load {len(bugs)} bugs.")

    if not bugs:
        print(f"[FL] Không tìm thấy bug nào. Kiểm tra lại đường dẫn dataset '{dataset}'.")
        return

    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    results = {}

    for bug in bugs:
        print(f"[FL] Tính điểm Tarantula cho {bug.bug_id}...")
        scores = calculate_tarantula(bug.tests)
        results[bug.bug_id] = {
            "scores":       scores,
            "ground_truth": bug.ground_truth,
        }

    output_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    with open(output_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"[FL] Điểm Tarantula đã được lưu vào {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument(
        "--dataset", default="codeflaws",
        help="Tên dataset cần chạy: codeflaws (mặc định), defects4c, ..."
    )
    parser.add_argument("--fl",           action="store_true", help="Chỉ chạy Fault Localization (Tarantula)")
    parser.add_argument("--apr",          action="store_true", help="Chỉ chạy APR với LLM")
    parser.add_argument("--apr-mutation", action="store_true", help="Chỉ chạy APR Heuristic Mutation (không cần LLM)")
    parser.add_argument("--apr-genprog",  action="store_true", help="Chỉ chạy APR sử dụng GenProg (cần cài genprog binary)")
    parser.add_argument("--eval",         action="store_true", help="Chỉ chạy Evaluation")
    parser.add_argument("--all",          action="store_true", help="Chạy toàn bộ: FL → APR → Evaluation")
    parser.add_argument(
        "--llm",
        default=None,
        choices=["gemini", "openai", "claude", "qwen", "kaggle_local"],
        help="LLM provider cho APR: 'gemini' (mặc định) hoặc 'openai' (gpt-4o-mini). "
             "Override biến môi trường LLM_PROVIDER.",
    )
    parser.add_argument(
        "--llm-model-path",
        default=None,
        help="Đường dẫn model local (vd /kaggle/input/...) khi dùng --llm kaggle_local.",
    )
    parser.add_argument(
        "--apr-phase",
        default="all",
        choices=["all", "generate", "validate"],
        help="Tách APR thành 2 phase: generate (sinh patch), validate (chấm patch), hoặc all.",
    )
    parser.add_argument(
        "--apr-artifacts-dir",
        default=None,
        help="Thư mục lưu/đọc artifacts patch khi tách phase APR.",
    )
    args = parser.parse_args()

    dataset      = args.dataset
    llm_provider = args.llm   # None → đọc từ LLM_PROVIDER trong .env

    # Nếu không truyền flag nào thì mặc định chạy toàn bộ
    run_all = args.all or (not args.fl and not args.apr and not args.apr_mutation
                          and not getattr(args, 'apr_genprog', False) and not args.eval)

    if run_all:
        print(f"[Pipeline] Chạy toàn bộ quy trình trên dataset '{dataset}' (FL → APR LLM → Evaluation)...")
        run_fl(dataset)
        run_apr_pipeline(dataset, llm_provider=llm_provider, phase=args.apr_phase, artifacts_dir=args.apr_artifacts_dir, llm_model_path=args.llm_model_path)
        evaluate_fl()
        evaluate_apr(dataset)
    else:
        if args.fl:
            print(f"[Pipeline] Chạy Fault Localization trên dataset '{dataset}'...")
            run_fl(dataset)
            evaluate_fl()

        if args.apr:
            print(f"[Pipeline] Chạy APR (LLM: {llm_provider or 'default'}) trên dataset '{dataset}'...")
            run_apr_pipeline(dataset, llm_provider=llm_provider, phase=args.apr_phase, artifacts_dir=args.apr_artifacts_dir, llm_model_path=args.llm_model_path)
            evaluate_apr(dataset)

        if args.apr_mutation:
            print(f"[Pipeline] Chạy APR Mutation trên dataset '{dataset}'...")
            run_mutation_pipeline(dataset)

        if getattr(args, 'apr_genprog', False):
            print(f"[Pipeline] Chạy APR GenProg trên dataset '{dataset}'...")
            run_genprog_pipeline(dataset)

        if args.eval:
            print("[Pipeline] Chạy Evaluation...")
            evaluate_fl()
            evaluate_apr(dataset)


if __name__ == "__main__":
    main()
