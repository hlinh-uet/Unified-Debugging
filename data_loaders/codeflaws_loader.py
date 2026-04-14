"""
data_loaders/codeflaws_loader.py
---------------------------------
Concrete loader cho dataset Codeflaws.
Kế thừa BugLoader và trả về list[BugRecord] theo chuẩn DATASET_STANDARDS.md.

Cấu trúc thư mục kỳ vọng (xem configs/path.py):
    CODEFLAWS_RESULTS_DIR/
        {bug_id}.json        ←  file kết quả test chứa 'tests', 'ground_truth_functions'
"""

import os
import json
from typing import List

from data_loaders.base_loader import BugLoader, BugRecord
from configs.path import CODEFLAWS_RESULTS_DIR, CODEFLAWS_SOURCE_DIR
from core.utils import qualify_func, get_codeflaws_buggy_cfile


class CodeflawsLoader(BugLoader):
    """
    Loader cho dataset Codeflaws.
    Đọc toàn bộ file JSON trong CODEFLAWS_RESULTS_DIR và chuẩn hoá
    thành list[BugRecord] theo interface BugLoader.
    """

    def __init__(self, results_dir: str = CODEFLAWS_RESULTS_DIR,
                 source_dir: str = CODEFLAWS_SOURCE_DIR):
        self.results_dir = results_dir
        self.source_dir  = source_dir

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _qualify_names(self, names: List[str], source_file: str) -> List[str]:
        """
        Gắn đường dẫn file nguồn vào mỗi tên hàm.
        Nếu tên đã chứa "::" (đã được qualify) thì giữ nguyên.
        """
        return [
            fn if "::" in fn else qualify_func(source_file, fn)
            for fn in names
        ]

    def _qualify_tests(self, tests: List[dict], source_file: str) -> List[dict]:
        """
        Trả về bản sao của danh sách test với covered_methods đã được qualify.
        """
        result = []
        for t in tests:
            t_copy = dict(t)
            covered = t_copy.get("covered_methods", [])
            t_copy["covered_methods"] = self._qualify_names(covered, source_file)
            result.append(t_copy)
        return result

    def _resolve_source_file(self, bug_id: str) -> str:
        """
        Tính đường dẫn file .c lỗi của Codeflaws từ bug_id.
        Codeflaws đặt tên theo mẫu:  {prefix}-{version_id}.c
        bên trong thư mục:           {source_dir}/{bug_id}/
        """
        bug_dir  = os.path.join(self.source_dir, bug_id)
        cfilename = get_codeflaws_buggy_cfile(bug_id)
        if cfilename:
            return os.path.join(bug_dir, cfilename)
        # Fallback: trả về thư mục nếu không parse được
        return bug_dir

    # ------------------------------------------------------------------
    # BugLoader interface
    # ------------------------------------------------------------------

    def load_all(self) -> List[BugRecord]:
        """
        Tải toàn bộ bug từ CODEFLAWS_RESULTS_DIR.
        Trả về list[BugRecord] chuẩn hoá.
        """
        bugs: List[BugRecord] = []

        if not os.path.exists(self.results_dir):
            print(f"[CodeflawsLoader] Thư mục không tồn tại: {self.results_dir}")
            return bugs

        for filename in sorted(os.listdir(self.results_dir)):
            if not filename.endswith(".json"):
                continue

            file_path = os.path.join(self.results_dir, filename)
            try:
                with open(file_path, "r") as f:
                    raw = json.load(f)
            except Exception as e:
                print(f"[CodeflawsLoader] Lỗi đọc {file_path}: {e}")
                continue

            bug_id      = filename.replace(".json", "")
            source_file = self._resolve_source_file(bug_id)

            bugs.append(BugRecord(
                bug_id          = bug_id,
                dataset         = "codeflaws",
                tests           = self._qualify_tests(raw.get("tests", []), source_file),
                ground_truth    = self._qualify_names(raw.get("ground_truth_functions", []), source_file),
                source_file     = source_file,
                compile_cmd     = raw.get("compile_cmd"),
                test_cmd_template = raw.get("test_cmd_template"),
                raw             = raw,
            ))

        return bugs

    def load_one(self, bug_id: str) -> "BugRecord | None":
        """
        Tải một bug cụ thể theo bug_id (tối ưu hơn scan toàn bộ list).
        """
        file_path = os.path.join(self.results_dir, f"{bug_id}.json")
        if not os.path.exists(file_path):
            return None

        try:
            with open(file_path, "r") as f:
                raw = json.load(f)
        except Exception as e:
            print(f"[CodeflawsLoader] Lỗi đọc {file_path}: {e}")
            return None

        source_file = self._resolve_source_file(bug_id)
        return BugRecord(
            bug_id          = bug_id,
            dataset         = "codeflaws",
            tests           = self._qualify_tests(raw.get("tests", []), source_file),
            ground_truth    = self._qualify_names(raw.get("ground_truth_functions", []), source_file),
            source_file     = source_file,
            compile_cmd     = raw.get("compile_cmd"),
            test_cmd_template = raw.get("test_cmd_template"),
            raw             = raw,
        )
