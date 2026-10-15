import uuid
from datetime import UTC, date, datetime
from pathlib import Path
from unittest.mock import patch

import httpx
import pytest

from procurement_review.cli import main
from procurement_review.domain.enums import ProcurementFamily, ReviewState, RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    GateReport,
    PurgePlan,
    Review,
    RuntimePolicy,
    VersionRef,
)
from procurement_review.runtime.lifecycle import (
    check_disaster_recovery_gate,
    create_backup,
    execute_purge,
    plan_purge,
    restore_backup,
)
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def secret_store() -> FakeSecretStore:
    return FakeSecretStore()


@pytest.fixture
def artifact_store(tmp_path: Path, secret_store: FakeSecretStore) -> ArtifactStore:
    vault_root = tmp_path / "vault"
    return ArtifactStore(root=vault_root, secrets=secret_store)


@pytest.fixture
def repo(tmp_path: Path, artifact_store: ArtifactStore) -> Repository:
    db_path = tmp_path / "procurement_review.db"
    return Repository(db=db_path, artifacts=artifact_store)


def make_sample_review(
    repo: Repository,
    case_id: str | None = None,
    title: str = "重大雲端服務採購案",
) -> Review:
    cid = case_id or str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資訊處",
        service_scope="核心雲端運算環境建置",
        unknown_fields=[],
    )
    rev = Review(
        case_id=cid,
        title=title,
        contract_type=ProcurementFamily.CLOUD,
        contract_version="1.0",
        original_file_hash="11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff",
        attachments=[],
        facts=facts,
        sensitivity_level="confidential",
        created_by="reviewer-1",
        created_at=datetime(2026, 10, 15, 8, 0, 0, tzinfo=UTC),
        state=ReviewState.IMPORTED,
    )
    repo.save_review(rev, expected_revision=None)
    return rev


def test_create_and_restore_backup_full_fidelity_and_zero_network(
    tmp_path: Path, repo: Repository, secret_store: FakeSecretStore
):
    """測試備份並還原到新目錄，驗證完整保真且零網路傳輸。

    核心斷言：
    - assert restored_repo.get_review(review.id) == review
    - assert captured_requests == [] (還原過程不送出任何網路請求)
    """
    review = make_sample_review(repo)

    # 模擬存入 original_document 及 snapshot 等 artifacts
    art_orig_id = repo.artifacts.put(
        case_id=review.id,
        kind="original_document",
        data=b"ORIGINAL CONTRACT DOCX CONTENT",
    )
    art_snap_id = repo.artifacts.put(
        case_id=review.id,
        kind="document_snapshot",
        data='{"blocks": [{"text": "條款一"}]}'.encode(),
    )

    backup_dir = tmp_path / "backups"
    backup_file = backup_dir / "backup.bundle"
    recovery_key = "secure-recovery-key-xyz-789"

    # 建立加密備份
    created_path = create_backup(repo, backup_file, recovery_key_ref=recovery_key)
    assert created_path.exists()
    assert created_path.stat().st_size > 0

    # 監聽所有可能的網路呼叫 (zero transmission guarantee)
    captured_requests: list[httpx.Request] = []

    def mock_transport_handle(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={})

    # 還原到全新獨立目錄與全新的金鑰庫
    restore_target = tmp_path / "new_machine_target"
    new_secrets = FakeSecretStore()

    with patch("httpx.Client.send", side_effect=mock_transport_handle):
        report = restore_backup(
            backup=created_path,
            target=restore_target,
            secrets=new_secrets,
            recovery_key=recovery_key,
        )

    # 斷言 1: 還原報告成功
    assert isinstance(report, GateReport)
    assert report.ok is True
    assert report.operation == "restore_backup"

    # 斷言 2: 零網路傳輸
    assert captured_requests == []

    # 斷言 3: 重建 Repository 並驗證完整保真
    restored_artifacts = ArtifactStore(
        root=restore_target / "vault",
        secrets=new_secrets,
    )
    restored_repo = Repository(
        db=restore_target / "procurement_review.db",
        artifacts=restored_artifacts,
    )

    restored_review = restored_repo.get_review(review.id)
    assert restored_review == review
    assert restored_repo.get_review(review.id) == review

    # 驗證原檔及快照內容亦可正確解密讀出
    assert restored_artifacts.get(review.id, art_orig_id) == b"ORIGINAL CONTRACT DOCX CONTENT"
    assert restored_artifacts.get(review.id, art_snap_id) == '{"blocks": [{"text": "條款一"}]}'.encode()


def test_wrong_recovery_key_rejected(tmp_path: Path, repo: Repository):
    """測試使用錯誤的 recovery key 還原時，必須拒絕並拋出 RECOVERY_KEY_INVALID。"""
    make_sample_review(repo)
    backup_path = tmp_path / "backup_wrong_key.bundle"
    correct_key = "correct-recovery-passphrase-456"
    create_backup(repo, backup_path, recovery_key_ref=correct_key)

    restore_target = tmp_path / "target_fail"
    new_secrets = FakeSecretStore()

    with pytest.raises(DomainError) as exc_info:
        restore_backup(
            backup=backup_path,
            target=restore_target,
            secrets=new_secrets,
            recovery_key="wrong-recovery-passphrase-000",
        )

    assert exc_info.value.code == "RECOVERY_KEY_INVALID"


def test_missing_key_stops_without_reinitializing(tmp_path: Path, repo: Repository):
    """測試遺失金鑰時立即中斷，不得靜默覆蓋、清空或重新初始化目標目錄。"""
    make_sample_review(repo)
    backup_path = tmp_path / "backup_missing_key.bundle"
    create_backup(repo, backup_path, recovery_key_ref="my-rec-key")

    target_dir = tmp_path / "target_missing_key"
    target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    canary_file = target_dir / "user_data_canary.txt"
    canary_file.write_text("important user data", encoding="utf-8")

    empty_secrets = FakeSecretStore()

    with pytest.raises(DomainError) as exc_info:
        # 不帶 recovery_key 且 secrets 內無金鑰
        restore_backup(
            backup=backup_path,
            target=target_dir,
            secrets=empty_secrets,
            recovery_key=None,
        )

    assert exc_info.value.code in ("RECOVERY_KEY_INVALID", "KEY_UNAVAILABLE")

    # 目標目錄未被靜默覆寫或初始化為空庫
    assert canary_file.exists()
    assert canary_file.read_text(encoding="utf-8") == "important user data"
    assert not (target_dir / "vault" / ".vault_init").exists()


def test_purge_plan_catalogs_all_categories_and_binds_hash(tmp_path: Path, repo: Repository):
    """測試 plan_purge 完整盤點所有類別產物，並強制綁定 confirmation_hash。

    刪除清單必須涵蓋：
    - 原檔 (original documents)
    - 轉換物 (converted documents / snapshots)
    - 映射 (masking mappings / tokens)
    - 輸出 (exports)
    - 快取 (cache / provider replies)
    - 備份到期政策 (expired backup retention policy)
    """
    review = make_sample_review(repo)
    cid = review.id

    # 模擬建立各類型 artifacts
    repo.artifacts.put(cid, "original_document", b"ORIGINAL_PDF_DATA")
    repo.artifacts.put(cid, "document_snapshot", b"SNAPSHOT_DATA")
    repo.artifacts.put(cid, "masking_session", b"MAPPING_DATA")
    repo.artifacts.put(cid, "run_contexts", b"RUN_CACHE_DATA")
    repo.artifacts.put(cid, "provider_reply", b"PROVIDER_REPLY_CACHE")

    # 1. 保存期限未過 (as_of 僅過 5 天，預設 30 天)
    as_of_early = date(2026, 10, 20)
    plan_early = plan_purge(cid, repo, as_of=as_of_early)
    assert isinstance(plan_early, PurgePlan)
    assert plan_early.retention_expired is False
    assert hasattr(plan_early, "confirmation_hash")
    assert len(plan_early.confirmation_hash) == 64

    # 盤點清單內容涵蓋各類別
    assert any("original" in t.lower() for t in plan_early.purge_targets)
    assert any("snapshot" in t.lower() or "converted" in t.lower() for t in plan_early.purge_targets)
    assert any("mapping" in t.lower() or "mask" in t.lower() for t in plan_early.purge_targets)
    assert any("cache" in t.lower() or "context" in t.lower() or "reply" in t.lower() for t in plan_early.purge_targets)
    assert any("export" in t.lower() for t in plan_early.purge_targets)
    assert any("backup" in t.lower() or "retention" in t.lower() for t in plan_early.purge_targets)

    # 2. 保存期限已過 (as_of 超過 30 天)
    as_of_expired = date(2026, 12, 1)
    plan_expired = plan_purge(cid, repo, as_of=as_of_expired)
    assert plan_expired.retention_expired is True
    assert plan_expired.confirmation_hash != plan_early.confirmation_hash


def test_purge_cannot_delete_last_original_without_confirmation(tmp_path: Path, repo: Repository):
    """測試受控刪除必須提供完全吻合的 confirmation_hash，否則拒絕刪除任何原檔。

    核心斷言：
    - with pytest.raises(DomainError): execute_purge(plan, 'wrong-hash')
    - 錯誤 hash 下原合約資料庫與 artifact 原檔完全未被刪除。
    """
    review = make_sample_review(repo)
    cid = review.id
    art_id = repo.artifacts.put(cid, "original_document", b"CONTRACT_DOCX_BYTES")

    as_of = date(2026, 12, 1)  # 已過保存期
    plan = plan_purge(cid, repo, as_of=as_of)

    # 核心斷言：錯誤 hash 拒絕執行
    with pytest.raises(DomainError) as exc_info:
        execute_purge(plan, "wrong-hash")

    assert exc_info.value.code in ("PURGE_CONFIRMATION_MISMATCH", "PURGE_CONFIRMATION_REQUIRED")

    # 驗證原檔案與案件完全完好
    assert repo.get_review(cid) == review
    assert repo.artifacts.get(cid, art_id) == b"CONTRACT_DOCX_BYTES"


def test_execute_purge_deletes_files_and_writes_tombstone(tmp_path: Path, repo: Repository):
    """測試提供正確 confirmation_hash 後，安全刪除檔案並寫入 tombstone 紀錄。"""
    review = make_sample_review(repo)
    cid = review.id
    art_orig = repo.artifacts.put(cid, "original_document", b"CONTRACT_DOCX_BYTES")
    repo.artifacts.put(cid, "document_snapshot", b"SNAPSHOT_DATA")

    plan = plan_purge(cid, repo, as_of=date(2026, 12, 1))
    valid_hash = plan.confirmation_hash

    report = execute_purge(plan, valid_hash)
    assert isinstance(report, GateReport)
    assert report.ok is True
    assert report.operation == "execute_purge"

    # 1. Artifact 檔案應已被刪除
    with pytest.raises(DomainError) as exc_get:
        repo.artifacts.get(cid, art_orig)
    assert exc_get.value.code in ("ARTIFACT_NOT_FOUND", "REVIEW_PURGED")

    # 2. 檢驗資料庫寫入 tombstone 且案件狀態反映已依保存期限清除
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT state FROM reviews WHERE case_id = ?", (cid,))
        row = cursor.fetchone()
        assert row is not None
        assert row["state"] == "purged"

        cursor.execute("SELECT case_id, confirmation_hash FROM purge_tombstones WHERE case_id = ?", (cid,))
        tombstone = cursor.fetchone()
        assert tombstone is not None
        assert tombstone["case_id"] == cid
        assert tombstone["confirmation_hash"] == valid_hash


def test_real_mode_gate_requires_rehearsal_and_retention_records(tmp_path: Path):
    """真實模式 gate 要求備份恢復演練與保存期限確認紀錄；synthetic fixture 不可偽造這些核准。"""
    # 1. 合成模式無條件通過
    synthetic_policy = RuntimePolicy(mode=RuntimeMode.SYNTHETIC, data_root=str(tmp_path))
    gate_syn = check_disaster_recovery_gate(synthetic_policy)
    assert gate_syn.ok is True

    # 2. 真實模式缺少演練核准 -> 拒絕
    real_policy_no_rehearsal = RuntimePolicy(
        mode=RuntimeMode.REAL,
        data_root=str(tmp_path),
        storage_approval_ref=VersionRef(
            id=str(uuid.uuid4()), version="1.0", sha256="a" * 64
        ),
        retention_approval_ref=VersionRef(
            id=str(uuid.uuid4()), version="1.0", sha256="b" * 64
        ),
        provider_approval_ref=VersionRef(
            id=str(uuid.uuid4()), version="1.0", sha256="c" * 64
        ),
    )
    gate_real_fail = check_disaster_recovery_gate(real_policy_no_rehearsal)
    assert gate_real_fail.ok is False
    assert any("rehearsal" in issue.lower() for issue in gate_real_fail.issues)

    # 3. 偽造全 0 synthetic fixture ID -> 拒絕
    fake_rehearsal_ref = VersionRef(
        id="00000000-0000-0000-0000-000000000000",
        version="1.0",
        sha256="0" * 64,
    )
    gate_fake = check_disaster_recovery_gate(real_policy_no_rehearsal, rehearsal_record_ref=fake_rehearsal_ref)
    assert gate_fake.ok is False
    assert any("synthetic" in issue.lower() or "forgery" in issue.lower() for issue in gate_fake.issues)

    # 4. 合法真實核准參照 -> 通過
    valid_rehearsal_ref = VersionRef(
        id=str(uuid.uuid4()),
        version="1.0",
        sha256="d" * 64,
    )
    gate_ok = check_disaster_recovery_gate(real_policy_no_rehearsal, rehearsal_record_ref=valid_rehearsal_ref)
    assert gate_ok.ok is True


def test_cli_lifecycle_commands(tmp_path: Path, repo: Repository):
    """測試 CLI subcommands: backup, restore, purge --dry-run。"""
    review = make_sample_review(repo)
    cid = review.id
    backup_file = tmp_path / "cli_backup.bundle"
    restore_dir = tmp_path / "cli_restored"

    # 儲存合成環境金鑰檔供 CLI 命令存取
    (repo.db.parent / ".synthetic_key").write_bytes(repo.artifacts.master_key)

    # 1. CLI backup
    main([
        "backup",
        "--data-dir", str(repo.db.parent),
        "--target", str(backup_file),
        "--recovery-key", "cli-test-recovery-key-123",
    ])
    assert backup_file.exists()

    # 2. CLI restore
    main([
        "restore",
        "--backup", str(backup_file),
        "--target", str(restore_dir),
        "--recovery-key", "cli-test-recovery-key-123",
    ])
    assert (restore_dir / "procurement_review.db").exists()

    # 3. CLI purge --dry-run
    # 預覽清單，不應刪除資料
    main([
        "purge",
        "--case-id", cid,
        "--data-dir", str(repo.db.parent),
        "--dry-run",
    ])
    assert repo.get_review(cid) == review
