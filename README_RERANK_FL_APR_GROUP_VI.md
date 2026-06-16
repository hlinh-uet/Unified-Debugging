# Huong Dan Chay Rerank FL Bang APR Group Feedback

File script:

```text
scripts/rerank_fl_with_soft_apr_feedback.py
```

Script nay chi doc ket qua da co san. No khong chay FL, khong chay APR, khong validate patch, khong goi LLM, va khong can Docker.

## Dau Vao

Script doc data theo cau truc:

```text
experiments/<experiment>/<dataset>/
```

Vi du:

```text
experiments/Ver2.5_new/fmt/
experiments/Ver2.5_new/libyang/
experiments/Ver2.5_new/tcpdump/
```

Trong moi thu muc dataset can co cac file/thu muc:

```text
fault_localization_results.json
apr_results.json
llm_patches/<bug_id>/
```

Y nghia:

- `fault_localization_results.json`: diem FL goc cua cac function.
- `apr_results.json`: ket qua APR da validate, gom selected patch artifact va status.
- `llm_patches/<bug_id>/`: cac patch attempt da duoc LLM sinh va validate lai.

Script chi coi cac file sau la patch attempt chinh:

```text
llm_patches/<bug_id>/NN__<file>_<function>.json
```

Vi du:

```text
llm_patches/A.2/01__format.h_format_to.json
llm_patches/CVE-2017-12893/03__smbutil.c_name_len.json
```

Script bo qua cac file trung gian cua agent nhu:

```text
*__fix_agent.json
*__retrieval_context_agent.json
*__code_context_collector_agent.json
*.context.json
*.repair_evidence.json
```

## Cach Chay

Chay mot dataset:

```powershell
cd D:\Code-Second\Research\Unified-Debugging
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --dataset fmt
```

Chay libyang:

```powershell
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --dataset libyang
```

Chay tcpdump:

```powershell
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --dataset tcpdump
```

Chay tat ca dataset trong experiment:

```powershell
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --all-datasets
```

Doi weight:

```powershell
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --dataset fmt --group-weight 1.0
```

Doi ten output prefix:

```powershell
python scripts\rerank_fl_with_soft_apr_feedback.py --experiment Ver2.5_new --dataset fmt --output-prefix apr_feedback_group_only_test
```

## Dau Ra

Mac dinh script ghi output vao chinh thu muc dataset.

Voi prefix mac dinh `apr_feedback_group_only`, output gom:

```text
fault_localization_apr_feedback_group_only_results.json
apr_feedback_group_only_features.json
apr_feedback_group_only_rank_changes.csv
apr_feedback_group_only_summary.json
apr_feedback_group_only_fl_result.txt
```

Y nghia tung file:

- `fault_localization_apr_feedback_group_only_results.json`: ket qua FL moi sau khi rerank. Truong `scores` la diem moi, `base_scores` la diem FL goc.
- `apr_feedback_group_only_features.json`: file trace chi tiet. Cho biet moi bug dung attempt nao, function nao nhan group nao, diem cong/tru bao nhieu, rank cu/moi.
- `apr_feedback_group_only_rank_changes.csv`: bang CSV thay doi rank cua ground truth, de mo bang Excel.
- `apr_feedback_group_only_summary.json`: tong ket chay, gom so bug, so attempt dung, so attempt bi exclude, thong ke status, metrics before/after.
- `apr_feedback_group_only_fl_result.txt`: bao cao text de doc nhanh metrics va rank change.

## Cach Tinh Diem

Moi patch attempt co `status`, script map sang group:

```text
plausible -> Plausible
cleanfix  -> CleanFix
noisefix  -> NoiseFix
invalid   -> Invalid
nonefix   -> NoneFix
negfix    -> NegFix
```

Cong thuc:

```text
new_score = normalized_fl_score + group_weight * group_score
```

Group score:

```text
Plausible: 1.00
CleanFix : 0.85
NoiseFix : 0.55
Unknown  : 0.00
Invalid  : -0.05
NoneFix  : -0.10
NegFix   : -0.70
```

Mapping attempt vao FL function la exact match:

```text
attempt["function"] == key trong fault_localization_results.json["scores"]
```

Function trong FL khong co attempt thi group la `Unknown`, khong cong/tru diem.

