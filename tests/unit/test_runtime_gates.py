import logging
from datetime import UTC, datetime
from pathlib import Path

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.models import AuditEvent, GateReport, RuntimePolicy, VersionRef
from procurement_review.runtime.audit import audit_event, log_audit_failure
from procurement_review.runtime.gates import check_runtime


def test_synthetic_mode_passes(tmp_path: Path):
    """驗證 synthetic + mock 在無核准設定下依然可通過安全檢核門。"""
    policy = RuntimePolicy(
        mode=RuntimeMode.SYNTHETIC,
        data_root=str(tmp_path / "data"),
    )
    report = check_runtime(policy=policy, operation="ingest")

    assert isinstance(report, GateReport)
    assert report.ok is True
    assert len(report.issues) == 0
    assert report.operation == "ingest"
    assert report.checked_at is not None


def test_real_ingest_requires_storage_retention_approval(tmp_path: Path):
    """test_real_ingest_requires_storage_retention_approval 在原檔落盤前阻擋缺政策的 real 匯入。"""
    unapproved_real_policy = RuntimePolicy(
        mode=RuntimeMode.REAL,
        data_root=str(tmp_path / "data"),
        storage_approval_ref=None,
        retention_approval_ref=None,
    )
    report = check_runtime(policy=unapproved_real_policy, operation="ingest")

    assert isinstance(report, GateReport)
    assert not report.ok
    assert any("storage" in issue.lower() for issue in report.issues)
    assert any("retention" in issue.lower() for issue in report.issues)


def test_real_mode_approved_passes(tmp_path: Path):
    """具備完整核准與安全路徑時，真實模式檢核通過。"""
    approval = VersionRef(
        id="11111111-1111-4111-8111-111111111111",
        version="1.0.0",
        sha256="a" * 64,
    )
    approved_policy = RuntimePolicy(
        mode=RuntimeMode.REAL,
        data_root=str(tmp_path / "real_vault"),
        storage_approval_ref=approval,
        retention_approval_ref=approval,
        provider_approval_ref=approval,
    )
    report = check_runtime(policy=approved_policy, operation="ingest")

    assert report.ok is True
    assert len(report.issues) == 0


def test_real_mode_data_root_inside_repo_blocked():
    """真實模式下，若 data_root 位於 repo 內部，檢核門必須阻擋。"""
    repo_internal = str(Path(__file__).resolve().parent / "leak")
    approval = VersionRef(
        id="11111111-1111-4111-8111-111111111111",
        version="1.0.0",
        sha256="a" * 64,
    )
    policy = RuntimePolicy(
        mode=RuntimeMode.REAL,
        data_root=repo_internal,
        storage_approval_ref=approval,
        retention_approval_ref=approval,
        provider_approval_ref=approval,
    )
    report = check_runtime(policy=policy, operation="ingest")

    assert not report.ok
    assert any("repo" in issue.lower() for issue in report.issues)


def test_real_mode_insecure_filesystem_permissions_blocked(tmp_path: Path, monkeypatch):
    """若指定儲存裝置無法保證 0700/0600 權限，真實模式阻擋並顯示原因。"""
    approval = VersionRef(
        id="11111111-1111-4111-8111-111111111111",
        version="1.0.0",
        sha256="a" * 64,
    )
    policy = RuntimePolicy(
        mode=RuntimeMode.REAL,
        data_root=str(tmp_path / "fat32_mock"),
        storage_approval_ref=approval,
        retention_approval_ref=approval,
        provider_approval_ref=approval,
    )

    # 模擬無法支援 0700 權限的檔案系統（例如 FAT32 / exFAT）
    from procurement_review.runtime import gates

    monkeypatch.setattr(gates, "_probe_filesystem_permissions", lambda path: False)

    report = check_runtime(policy=policy, operation="ingest")
    assert not report.ok
    assert any("permission" in issue.lower() or "0700" in issue for issue in report.issues)


def test_audit_event_whitelist_fields(caplog):
    """驗證稽核日誌只輸出白名單欄位。"""
    caplog.set_level(logging.INFO, logger="procurement_review.audit")

    event = AuditEvent(
        event_id="33333333-3333-4333-8333-333333333333",
        timestamp=datetime.now(UTC),
        operator="reviewer_alice",
        action="ingest_contract",
        target_type="Review",
        target_version="1.0.0",
        result="success",
        evidence_hashes=["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"],
    )

    audit_event(event)

    log_output = caplog.text
    assert "reviewer_alice" in log_output
    assert "ingest_contract" in log_output
    assert "33333333-3333-4333-8333-333333333333" in log_output


def test_no_plaintext_in_logs(caplog):
    """test_no_plaintext_in_logs 捕捉含 prompt 的模擬例外，確認日誌無其內容。"""
    caplog.set_level(logging.DEBUG)

    secret_text = "SECRET_PROMPT_CONTAINING_CLASSIFIED_AGREEMENT_DATA_998877"

    # 模擬第三方或內部例外夾帶 prompt / 原文
    simulated_leak_exception = ValueError(f"Provider failed with prompt: {secret_text}")

    event = AuditEvent(
        event_id="44444444-4444-4444-8444-444444444444",
        timestamp=datetime.now(UTC),
        operator="system",
        action="llm_inference",
        target_type="ProviderCall",
        target_version=None,
        result="failure",
        evidence_hashes=[],
    )

    # 記錄審計失敗與例外，必須防護明文外洩
    log_audit_failure(event=event, exc=simulated_leak_exception)

    # 核心斷言：日誌絕對不可含有敏感字串
    assert secret_text not in caplog.text
