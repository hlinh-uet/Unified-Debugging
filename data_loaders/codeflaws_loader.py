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

    def _resolve_source_file(self, bug_id: str) -> str:
        """
        Tính đường dẫn file .c lỗi của Codeflaws từ bug_id.
        Codeflaws đặt tên theo mẫu:  {prefix}-{version_id}.c
        bên trong thư mục:           {source_dir}/{bug_id}/
        """
        bug_dir = os.path.join(self.source_dir, bug_id)
        try:
            prefix  = "-".join(bug_id.split("-bug-")[0].split("-"))
            suffix  = bug_id.split("-bug-")[1].split("-")[0]
            return os.path.join(bug_dir, f"{prefix}-{suffix}.c")
        except (IndexError, ValueError):
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

            bug_id = filename.replace(".json", "")

            bugs.append(BugRecord(
                bug_id          = bug_id,
                dataset         = "codeflaws",
                tests           = raw.get("tests", []),
                ground_truth    = raw.get("ground_truth_functions", []),
                source_file     = self._resolve_source_file(bug_id),
                compile_cmd     = raw.get("compile_cmd"),       # tuỳ chọn
                test_cmd_template = raw.get("test_cmd_template"),  # tuỳ chọn
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

        return BugRecord(
            bug_id          = bug_id,
            dataset         = "codeflaws",
            tests           = raw.get("tests", []),
            ground_truth    = raw.get("ground_truth_functions", []),
            source_file     = self._resolve_source_file(bug_id),
            compile_cmd     = raw.get("compile_cmd"),
            test_cmd_template = raw.get("test_cmd_template"),
            raw             = raw,
        )
