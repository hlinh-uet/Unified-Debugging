"""
data_loaders/base_loader.py
---------------------------
Định nghĩa interface thống nhất cho việc load dữ liệu bug từ bất kỳ dataset nào
(Codeflaws, Defects4C, Defects4J, ...).

Cách sử dụng (FL & APR đều dùng chung một entry-point):
    from data_loaders.base_loader import get_loader

    loader = get_loader("codeflaws")          # hoặc "defects4c", ...
    bugs   = loader.load_all()                # -> list[BugRecord]

    for bug in bugs:
        bug.bug_id          # str
        bug.tests           # list[dict]  – chuẩn DATASET_STANDARDS
        bug.ground_truth    # list[str]   – tên hàm lỗi (nếu có)
        bug.source_file     # str         – đường dẫn file mã nguồn
        bug.dataset         # str         – tên dataset ("codeflaws", ...)
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


# ---------------------------------------------------------------------------
# Cấu trúc dữ liệu chuẩn cho một bug record
# ---------------------------------------------------------------------------

@dataclass
class BugRecord:
    """
    Đơn vị dữ liệu chuẩn mà mọi Loader phải trả về.
    Tuân theo định dạng DATASET_STANDARDS.md.
    """
    bug_id: str
    dataset: str
    tests: List[Dict[str, Any]] = field(default_factory=list)
    ground_truth: List[str] = field(default_factory=list)
    source_file: str = ""
    # Thông tin tuỳ chọn – dùng cho sandbox/adapter
    compile_cmd: Optional[str] = None
    test_cmd_template: Optional[str] = None
    # Metadata thô gốc (để các module nâng cao có thể truy xuất nếu cần)
    raw: Optional[Dict[str, Any]] = field(default=None, repr=False)


# ---------------------------------------------------------------------------
# Abstract interface – mọi dataset loader phải kế thừa class này
# ---------------------------------------------------------------------------

class BugLoader(abc.ABC):
    """
    Lớp cơ sở trừu tượng cho tất cả các data loader.

    Kế thừa lớp này và implement các phương thức để thêm hỗ trợ
    cho một dataset mới mà không thay đổi bất kỳ module cốt lõi nào.
    """

    @abc.abstractmethod
    def load_all(self) -> List[BugRecord]:
        """
        Tải toàn bộ bug từ dataset và trả về danh sách BugRecord chuẩn hoá.
        Không trả về raw dict – luôn wrapper qua BugRecord.
        """

    def load_one(self, bug_id: str) -> Optional[BugRecord]:
        """
        Tải một bug cụ thể theo bug_id.
        Mặc định: scan qua load_all() – các subclass có thể override để tối ưu.
        """
        for bug in self.load_all():
            if bug.bug_id == bug_id:
                return bug
        return None


# ---------------------------------------------------------------------------
# Factory – điểm entry-point duy nhất để lấy loader
# ---------------------------------------------------------------------------

def get_loader(dataset_name: str) -> BugLoader:
    """
    Trả về BugLoader tương ứng với tên dataset.

    Args:
        dataset_name: Tên dataset (không phân biệt hoa thường).
                      Ví dụ: "codeflaws", "defects4c", "defects4j"

    Returns:
        Một instance BugLoader cụ thể.

    Raises:
        ValueError: Nếu dataset_name chưa được hỗ trợ.
    """
    name = dataset_name.strip().lower()

    if name == "codeflaws":
        from data_loaders.codeflaws_loader import CodeflawsLoader
        return CodeflawsLoader()

    # Thêm dataset mới tại đây:
    # if name == "defects4c":
    #     from data_loaders.defects4c_loader import Defects4CLoader
    #     return Defects4CLoader()

    raise ValueError(
        f"Dataset '{dataset_name}' chưa có Loader tương ứng. "
        f"Hãy tạo một class kế thừa BugLoader trong data_loaders/ và đăng ký nó tại đây."
    )
