import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from procurement_review.domain.enums import (
    ProcurementFamily,
    ReviewState,
    RunState,
)
from procurement_review.domain.models import (
    CaseFacts,
    Review,
    VersionRef,
)
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def artifact_store(tmp_path: Path) -> ArtifactStore:
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    return ArtifactStore(root=vault_root, secrets=secrets)


@pytest.fixture
def repo(tmp_path: Path, artifact_store: ArtifactStore) -> Repository:
    db_path = tmp_path / "app.db"
    return Repository(db=db_path, artifacts=artifact_store)


def make_sample_review(
    case_id: str | None = None,
    title: str = "雲端採購合約審查",
    file_hash: str = "hash_alpha_1111",
    revision: int = 1,
) -> Review:
    cid = case_id or str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資訊服務處",
        service_scope="雲端平台維運合約",
        unknown_fields=[],
    )
    return Review(
        case_id=cid,
        title=title,
        contract_type=ProcurementFamily.CLOUD,
        contract_version="1.0",
        original_file_hash=file_hash,
        facts=facts,
        sensitivity_level="confidential",
        created_by="tester",
        created_at=datetime.now(UTC),
        state=ReviewState.IMPORTED,
        revision=revision,
    )


def test_same_filename_new_content_invalidates_run(repo: Repository):
    """測試同一合約檔名但內容更新（hash 變更）時，舊 run 自動失效；改非實質排版或標題則不失效。"""
    review = repo.save_review(
        make_sample_review(file_hash="hash_initial_version_1111"),
        expected_revision=None,
    )
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="rule_hash_001")

    # 建立舊 run
    old_run = repo.create_run(review.case_id, rule_refs=[rule_ref])
    assert repo.get_run(old_run.id).stale is False

    # 情境一：非實質變更（例如僅修改標題或 UI 顯示設定，file_hash 不變）
    cosmetic_update = review.model_copy(update={"title": "修改後之顯示標題（排版調整）"})
    saved_cosmetic = repo.save_review(cosmetic_update, expected_revision=1)
    assert saved_cosmetic.revision == 2
    # 舊 run 仍應保持有效 (stale is False)
    assert repo.get_run(old_run.id).stale is False

    # 情境二：實質內容變更（同檔名但檔案內容更新，hash 變更）
    material_update = saved_cosmetic.model_copy(
        update={"original_file_hash": "hash_new_content_version_2222"}
    )
    saved_material = repo.save_review(material_update, expected_revision=2)
    assert saved_material.revision == 3

    # 核心斷言：舊 run 必須自動標記為 stale
    assert repo.get_run(old_run.id).stale is True


def test_interrupted_run_requires_new_run_id(repo: Repository):
    """驗證中斷或失敗的 run 保留原失敗紀錄，新 run 產生全新 ID 且不繼承先前的人工核准。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="rule_hash_001")

    # 建立初次 run 並模擬被中斷
    old_run = repo.create_run(review.case_id, rule_refs=[rule_ref])
    assert old_run.state == RunState.PLANNED

    # 模擬給予舊 run 人工出站核准
    approval_ref = VersionRef(
        id=str(uuid.uuid4()), version="1.0", sha256="approval_hash_001"
    )
    interrupted_run = old_run.model_copy(
        update={
            "state": RunState.INTERRUPTED,
            "egress_approval_ref": approval_ref,
            "error_message": "Network timeout during egress",
        }
    )
    repo.save_run(interrupted_run)

    # 啟動新 run，指定 parent_run_id
    new_run = repo.create_run(
        review.case_id,
        rule_refs=[rule_ref],
        parent_run_id=old_run.id,
    )

    # 驗證新 run 有全新 ID 且連結父 run
    assert new_run.id != old_run.id
    assert new_run.parent_run_id == old_run.id

    # 驗證舊 run 歷史紀錄完整保留
    fetched_old = repo.get_run(old_run.id)
    assert fetched_old.state == RunState.INTERRUPTED
    assert fetched_old.error_message == "Network timeout during egress"
    assert fetched_old.egress_approval_ref is not None
    assert fetched_old.egress_approval_ref.id == approval_ref.id

    # 核心斷言：新 run 重新開始，不繼承舊 run 的出站核准與狀態
    fetched_new = repo.get_run(new_run.id)
    assert fetched_new.state == RunState.PLANNED
    assert fetched_new.egress_approval_ref is None


def test_explicit_invalidation_marks_active_runs_stale(repo: Repository):
    """測試顯式 invalidate 方法能將該案件的所有 active runs 標記為 stale 並回傳被失效的 run ID 清單。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    run1 = repo.create_run(review.case_id, rule_refs=[])
    run2 = repo.create_run(review.case_id, rule_refs=[])

    assert repo.get_run(run1.id).stale is False
    assert repo.get_run(run2.id).stale is False

    invalidated = repo.invalidate(review.case_id, reason="User requested cancellation")
    assert set(invalidated) == {run1.id, run2.id}

    assert repo.get_run(run1.id).stale is True
    assert repo.get_run(run2.id).stale is True

    # 再次執行 invalidate 時，無其他 active runs 需要失效
    second_invalidation = repo.invalidate(review.case_id, reason="Second call")
    assert second_invalidation == []


def test_invalidate_by_revoked_rule(repo: Repository):
    """測試因規則撤銷透過反向參照使關聯 run 失效。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    rule_a = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="hash_a")
    rule_b = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="hash_b")

    # run1 依賴 rule_a
    run1 = repo.create_run(review.case_id, rule_refs=[rule_a])
    # run2 依賴 rule_a 與 rule_b
    run2 = repo.create_run(review.case_id, rule_refs=[rule_a, rule_b])
    # run3 僅依賴 rule_b
    run3 = repo.create_run(review.case_id, rule_refs=[rule_b])

    # 撤銷 rule_a
    invalidated = repo.invalidate_runs_by_rule(rule_a.id, reason="Rule A revoked by legal")
    assert set(invalidated) == {run1.id, run2.id}

    assert repo.get_run(run1.id).stale is True
    assert repo.get_run(run2.id).stale is True
    assert repo.get_run(run3.id).stale is False
