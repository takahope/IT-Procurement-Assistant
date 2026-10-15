import os
from datetime import UTC, datetime
from pathlib import Path

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.models import GateReport, RuntimePolicy
from procurement_review.storage.vault import _is_inside_repo


def _probe_filesystem_permissions(path: Path) -> bool:
    """測試目標路徑所在的檔案系統是否支援 POSIX 0700/0600 權限限制。"""
    try:
        path = path.resolve()
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(path, 0o700)
        st = path.stat().st_mode & 0o777
        if st != 0o700:
            return False

        probe_file = path / ".probe_perm"
        try:
            probe_file.write_bytes(b"probe")
            os.chmod(probe_file, 0o600)
            fst = probe_file.stat().st_mode & 0o777
            return fst == 0o600
        finally:
            probe_file.unlink(missing_ok=True)
    except (OSError, RuntimeError):
        return False


def check_runtime(policy: RuntimePolicy, operation: str) -> GateReport:
    """執行期安全檢核門。

    依據政策模式檢查：
    - synthetic 模式：合成測試模式，無須實體驗證核准。
    - real 模式：
      1. 儲存、保留政策、模型供應商等核准參照 (approval_ref) 必須齊備。
      2. 儲存路徑不得位於程式碼庫內部。
      3. 儲存路徑之檔案系統必須保證 0700 (目錄) 與 0600 (檔案) 安全權限。
    """
    now = datetime.now(UTC)
    issues: list[str] = []

    # 合成模式直接放行
    if policy.mode == RuntimeMode.SYNTHETIC:
        return GateReport(
            ok=True,
            operation=operation,
            issues=[],
            checked_at=now,
        )

    # 真實模式 (REAL) 嚴格檢驗
    data_root_path = Path(policy.data_root)

    # 1. 檢驗路徑安全：禁止位於 repo 內部
    if _is_inside_repo(data_root_path):
        issues.append(
            f"Storage root '{policy.data_root}' is located inside the repository, "
            "which is forbidden in real mode"
        )

    # 2. 檢驗權限保證：目錄 0700、檔案 0600
    if not _probe_filesystem_permissions(data_root_path):
        issues.append(
            f"Storage path '{policy.data_root}' filesystem cannot guarantee "
            "0700 directory and 0600 file permissions"
        )

    # 3. 檢驗必要核准
    if policy.storage_approval_ref is None:
        issues.append("Missing storage_approval_ref for real mode")

    if policy.retention_approval_ref is None:
        issues.append("Missing retention_approval_ref for real mode")

    if policy.provider_approval_ref is None:
        issues.append("Missing provider_approval_ref for real mode")

    ok = len(issues) == 0
    return GateReport(
        ok=ok,
        operation=operation,
        issues=issues,
        checked_at=now,
    )
