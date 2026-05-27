from typing import Optional

from data_loaders.sandbox_adapter import get_sandbox_adapter


def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws",
                   src_basename: Optional[str] = None,
                   src_relpath: Optional[str] = None,
                   exclude_fixed_fail_tests: bool = True):
    """Sử dụng Sandbox Adapter để kiểm chứng bản vá.

    ``src_relpath`` cho Defects4C biết chính xác file nào trong buggy version
    cần thay thế. ``src_basename`` chỉ còn dùng cho adapter cũ/tên hiển thị.
    """
    print(f"[APR] Validating patch cho {bug_id} với adapter '{dataset}'...")
    validate_patch.last_details = {}
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        result = adapter.validate(
            patched_file_path,
            src_basename=src_basename,
            src_relpath=src_relpath,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        validate_patch.last_details = getattr(adapter, "last_validation_details", {}) or {}
        return result
    except Exception as e:
        print(f"    [Error] Không thể validate: {e}")
        validate_patch.last_details = {
            "validation_error": f"validate_exception:{e}",
            "full_post_passed_tests": [],
            "full_post_failed_tests": [],
            "effective_post_passed_tests": [],
            "effective_post_failed_tests": [],
            "fixed_fail_excluded_tests": [],
        }
        return False, [], []


validate_patch.last_details = {}
