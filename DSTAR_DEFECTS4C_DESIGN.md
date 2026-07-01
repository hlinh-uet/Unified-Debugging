# DStar FL cho Defects4C

## Vi tri du lieu

Co 2 lop du lieu trong `defects4c`:

1. Metadata goc cua benchmark:
   `defects4c/defectsc_tpl/projects/<project>/bugs_list_new.json`

   File nay cho biet commit loi, commit fix, file source, file test va vi tri ground truth
   theo line/function. Vi du:
   `files.src0_location.func_start`, `func_end`, `commit_after`, `commit_before`.

2. Metadata da duoc Unified Debugging build/collect coverage:
   `defects4c/out_tmp_dirs/unified_debugging/<dataset>/metadata/*_meta.json`

   Day la nguon doc chinh cho DStar vi moi bug da co:
   - `tests[].outcome`: PASS/FAIL tren ban buggy.
   - `tests[].outcome_fixed`: PASS/FAIL tren ban fixed.
   - `tests[].covered_functions`: danh sach function duoc cover.
   - `ground_truth` hoac `ground_truth_functions`.

## Cach doc

Loader moi nam o:

`data_loaders/defects4c_loader.py`

Mac dinh no doc:

`../defects4c/out_tmp_dirs/unified_debugging/fmt/metadata/*_meta.json`

Co the doi dataset bang CLI:

```bash
python main.py --fl-dstar --dstar-dataset tcpdump
```

Hoac tro thang vao metadata dir:

```bash
python main.py --fl-dstar --dstar-metadata-dir ../defects4c/out_tmp_dirs/unified_debugging/cjson/metadata
```

Mac dinh loader loai cac test van FAIL tren ban fixed (`outcome_fixed == FAIL`) de tranh tinh ca flaky/unreproduced tests vao SBFL.

## Cong thuc DStar

Core nam o:

`core/fl_dstar.py`

Voi moi function `e`:

```text
DStar(e) = failed(e)^star / (passed(e) + failed_not_covered(e))
```

Mac dinh `star = 2`.

Neu denominator bang 0, function do duoc cover boi moi failing test va khong duoc cover boi passing test. Code gan diem finite sentinel lon hon diem huu han co the co trong bug do, de JSON output van hop le.

## Output

Mac dinh ket qua ghi vao:

`experiments/<dataset>/dstar_function_results.json`

Summary eval ghi vao:

`experiments/<dataset>/dstar_function_results_summary.json`

Moi record gom:

- `scores` va `dstar_scores`: ranking function theo DStar.
- `ground_truth`: ground truth da normalize ve dang `file:function`.
- `spectrum`: so passing/failing tests va so function co coverage.
- `metadata_path`: metadata goc da doc.
- `test_filter`: thong tin test bi loai do fixed version van fail.

Summary eval bao gom Top-1, Top-3, Top-5, Top-10, Top-20 va Top-30.

File nay khong ghi de `fault_localization_function_results.json` hay `tarantula_results.json`.
