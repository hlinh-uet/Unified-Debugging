# CodeBERT Test-Code Similarity Ochiai

## Y tuong

Nhanh thu nghiem mot bien the giam test suite truoc khi tinh Ochiai:

1. Tach failing tests va passing tests tu metadata Defects4C.
2. Trich body code cua tung test case that tu checkout, vi du `TEST(...) { ... }` cua gtest.
3. Embed text test case bang `microsoft/codebert-base`.
4. Tinh cosine similarity giua tung passing test va failing test gan nhat.
5. Giu `top-k` passing tests gan failing tests nhat, sau do tinh Ochiai tren `failing + selected passing`.

Module chinh: `core/fl_codebert_ochiai.py`

## Lenh chay

Smoke test offline, khong can model:

```bash
python main.py --fl-codebert-ochiai --codebert-backend hash --codebert-dataset fmt --codebert-bug-id A.2
```

Chay CodeBERT that cho `fmt`:

```bash
python main.py --fl-codebert-ochiai --codebert-backend codebert --codebert-dataset fmt --codebert-selection topk --codebert-top-k 50 --codebert-device cuda --codebert-batch-size 8 --codebert-local-files-only
```

Neu model chua co cache local, bo `--codebert-local-files-only` de Hugging Face tai `microsoft/codebert-base`.

## Ket qua thu tren fmt

Lenh da chay:

```bash
python main.py --fl-codebert-ochiai --codebert-backend codebert --codebert-dataset fmt --codebert-selection topk --codebert-top-k 50 --codebert-device cuda --codebert-batch-size 8 --codebert-local-files-only --codebert-output-file experiments/fmt/codebert_ochiai_function_results.json
```

Ket qua:

- Bugs: 14/14 evaluated.
- Top1: 0/14.
- Top3: 2/14.
- Top5: 3/14.
- Top10: 8/14.
- Top20: 11/14.
- Top30: 14/14.
- Passing tests: selected 700/5296, trung binh 50 pass tests/bug.
- Test code extraction: 5309/5311 records co source test; chi 2 records fallback metadata.

So voi baseline hien co tren `fmt`:

- DStar: Top3 3/14, Top5 5/14, Top10 8/14, Top20 13/14, Top30 13/14.
- Jaccard-Ochiai: Top3 3/14, Top5 4/14, Top10 8/14, Top20 12/14, Top30 14/14.
- CodeBERT-Ochiai: Top3 2/14, Top5 3/14, Top10 8/14, Top20 11/14, Top30 14/14.

Nhan xet nhanh: embedding code test case hoat dong va trich source rat tot, nhung CodeBERT cosine tren test-body don thuan chua cai thien Top-K som. Cac similarity rat cao va sat nhau, nen buoc tiep theo nen thu fusion voi coverage similarity hoac rerank theo test-code + covered-function overlap thay vi dung CodeBERT cosine rieng le.

## Thu hybrid CodeBERT + coverage Jaccard

Cong thuc:

```text
final_similarity =
  0.5 * normalized_codebert_similarity
+ 0.5 * coverage_jaccard_similarity
```

Lenh da chay:

```bash
python main.py --fl-codebert-ochiai --codebert-backend codebert --codebert-dataset fmt --codebert-selection topk --codebert-top-k 50 --codebert-similarity-mode hybrid --codebert-code-weight 0.5 --codebert-coverage-weight 0.5 --codebert-device cuda --codebert-batch-size 8 --codebert-local-files-only --codebert-output-file experiments/fmt/codebert_hybrid_ochiai_function_results.json
```

Ket qua:

- Bugs: 14/14 evaluated.
- Top1: 0/14.
- Top3: 2/14.
- Top5: 2/14.
- Top10: 7/14.
- Top20: 12/14.
- Top30: 13/14.
- Passing tests: selected 700/5296, trung binh 50 pass tests/bug.
- Test code extraction: 5309/5311 records co source test; chi 2 records fallback metadata.

So voi CodeBERT-only, hybrid 0.5/0.5 cai thien Top20 tu 11/14 len 12/14, nhung giam Top5 tu 3/14 xuong 2/14, Top10 tu 8/14 xuong 7/14, va Top30 tu 14/14 xuong 13/14.

Mot so rank thay doi:

- Tot hon: `A.2` 21 -> 20, `A.3__c04fb91b03cb` 7 -> 6, `A.4` 17 -> 14, `C.3__cd7202e03996` 17 -> 14.
- Xau hon: `B__2b7a146fa1f9` 6 -> 10, `D.1__96c18b26c28b` 26 -> 46, `D.2__279d698e1b37` 5 -> 11.

Nhan xet: fusion 0.5/0.5 co ich o vai bug vi coverage Jaccard keo cac pass test ve gan failing trace hon, nhung trong mot so bug no lam over-select cac pass test co coverage giong failing test ma khong giup phan biet dung function loi. Vi vay ban 0.5/0.5 chua tot hon baseline Jaccard-Ochiai/DStar; nen thu tiep sweep weight, vi du 0.8/0.2 hoac rank-fusion thay vi cong diem raw.

## Sweep weight va rank-fusion

Da them `--codebert-similarity-mode rank_fusion`. Mode nay khong cong truc tiep raw similarity, ma chuyen CodeBERT similarity va coverage Jaccard thanh Borda rank score roi moi fusion:

```text
final_similarity =
  code_weight * codebert_rank_score
+ coverage_weight * coverage_rank_score
```

Sweep da chay cho ca `hybrid` va `rank_fusion` voi code weight tu `1.0` den `0.0`, buoc `0.1`. Aggregate: `experiments/fmt/codebert_weight_sweep_summary.json`.

Ket qua chinh:

| Mode | Code/Jaccard | Top1 | Top3 | Top5 | Top10 | Top20 | Top30 |
|---|---:|---:|---:|---:|---:|---:|---:|
| CodeBERT-only | 1.0/0.0 | 0 | 2 | 3 | 8 | 11 | 14 |
| Hybrid raw | 0.8/0.2 | 0 | 2 | 2 | 8 | 12 | 13 |
| Hybrid raw | 0.4/0.6 | 0 | 2 | 2 | 9 | 12 | 13 |
| Hybrid raw | 0.0/1.0 | 1 | 2 | 3 | 9 | 11 | 12 |
| Rank fusion | 0.8/0.2 | 0 | 2 | 2 | 7 | 11 | 14 |
| Rank fusion | 0.7/0.3 | 0 | 2 | 2 | 8 | 12 | 14 |
| Rank fusion | 0.5/0.5 | 0 | 2 | 2 | 8 | 12 | 14 |

Nhan xet:

- Neu uu tien Top10, hybrid raw voi coverage cao hon, dac biet `0.4/0.6`, dat Top10 `9/14`, tot hon CodeBERT-only `8/14`, DStar `8/14`, Jaccard-Ochiai `8/14`; nhung Top30 giam con `13/14`.
- Neu can can bang va khong mat Top30, rank-fusion `0.7/0.3` den `0.5/0.5` dang giu hon: Top10 `8/14`, Top20 `12/14`, Top30 `14/14`.
- Khong co cau hinh nao cai thien Top3/Top5 so voi DStar/Jaccard-Ochiai. Vi vay sweep nay huu ich de cai thien Top10/Top20, nhung chua giai quyet duoc early-rank.
