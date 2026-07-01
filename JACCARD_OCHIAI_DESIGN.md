# Jaccard-reduced Ochiai FL cho Defects4C

## Y tuong

Pipeline nay khong doi cong thuc tren toan bo ma tran coverage nhu DStar.
No lam sach tap pass test truoc:

1. Moi test duoc xem nhu coverage vector nhi phan.
   Trong code, vector duoc luu bang `set(covered_functions)` de tinh nhanh,
   khong can sinh lai gcov vi metadata Defects4C da co coverage.
2. Voi moi pass test, tinh Jaccard voi cac fail test va lay diem cao nhat.
3. Giu lai pass tests bang mot trong hai chien luoc:
   - `threshold`: giu pass test co Jaccard >= theta.
   - `topk`: giu K pass tests co Jaccard cao nhat.
4. Tinh lai Ochiai tren tap test moi:
   `fail tests + selected pass tests`.

## File chinh

`core/fl_jaccard_ochiai.py`

## Lenh chay

Mac dinh dung threshold 0.5:

```powershell
python main.py --fl-jaccard-ochiai --jaccard-dataset fmt
```

Thu threshold khac:

```powershell
python main.py --fl-jaccard-ochiai --jaccard-dataset fmt --jaccard-threshold 0.3
```

Dung Top-K:

```powershell
python main.py --fl-jaccard-ochiai --jaccard-dataset fmt --jaccard-selection topk --jaccard-top-k 50
```

Chay mot bug:

```powershell
python main.py --fl-jaccard-ochiai --jaccard-dataset fmt --jaccard-bug-id A.2
```

## Output

Mac dinh ghi vao:

`experiments/<dataset>/jaccard_ochiai_function_results.json`

Summary eval:

`experiments/<dataset>/jaccard_ochiai_function_results_summary.json`

Summary bao gom Top-1, Top-3, Top-5, Top-10, Top-20, Top-30 va thong ke so pass tests duoc giu lai.

## Ket qua thu nhanh tren fmt

Voi 14 bug `fmt`:

- `threshold=0.5`: Top-1 1/14, Top-10 7/14, Top-30 13/14, giu 830/5296 pass tests.
- `threshold=0.3`: Top-1 0/14, Top-10 8/14, Top-30 14/14, giu 2371/5296 pass tests.
- `topk=50`: Top-1 1/14, Top-10 9/14, Top-30 12/14, giu 700/5296 pass tests.

Chua co cau hinh nao ap dao Tarantula/DStar tren moi top-k, nhung Top-K 50 cai thien Top-10 trong lan thu nhanh.
