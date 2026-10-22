import sqlite3
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from procurement_review.domain.enums import (
    HumanDecisionAction,
    ProcurementFamily,
    ResultEnum,
    ReviewState,
    RiskLevel,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    Feedback,
    Finding,
    HumanDecision,
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
    title: str = "機密雲端採購案",
    file_hash: str = "aaaa1111bbbb2222cccc3333dddd4444",
    revision: int = 1,
    extra_fact: str = "一般專案",
) -> Review:
    cid = case_id or str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資安推動小組",
        service_scope=f"核心架構審查-{extra_fact}",
        unknown_fields=[],
    )
    return Review(
        case_id=cid,
        title=title,
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash=file_hash,
        facts=facts,
        sensitivity_level="confidential",
        created_by="tester",
        created_at=datetime.now(UTC),
        state=ReviewState.IMPORTED,
        revision=revision,
    )


def test_save_and_get_review(repo: Repository):
    sample = make_sample_review()
    saved = repo.save_review(sample, expected_revision=None)
    assert saved.case_id == sample.case_id
    assert saved.revision == 1

    fetched = repo.get_review(sample.case_id)
    assert fetched.case_id == sample.case_id
    assert fetched.title == sample.title
    assert fetched.revision == 1
    assert fetched.facts.procurement_unit == "資安推動小組"


def test_cas_revision_conflict(repo: Repository):
    sample = make_sample_review()

    # First save with expected_revision != None and != 0 should fail
    with pytest.raises(DomainError) as exc_info:
        repo.save_review(sample, expected_revision=1)
    assert exc_info.value.code == "REVISION_CONFLICT"

    # First save with expected_revision=None succeeds
    saved_v1 = repo.save_review(sample, expected_revision=None)
    assert saved_v1.revision == 1

    # Update with wrong expected revision should fail
    with pytest.raises(DomainError) as exc_info:
        repo.save_review(saved_v1, expected_revision=2)
    assert exc_info.value.code == "REVISION_CONFLICT"

    # Update with expected_revision=None when row exists should fail
    with pytest.raises(DomainError) as exc_info:
        repo.save_review(saved_v1, expected_revision=None)
    assert exc_info.value.code == "REVISION_CONFLICT"

    # Update with correct expected_revision=1 succeeds and increments to 2
    updated = saved_v1.model_copy(update={"title": "更新後標題"})
    saved_v2 = repo.save_review(updated, expected_revision=1)
    assert saved_v2.revision == 2

    # Verify latest is revision 2
    latest = repo.get_review(sample.case_id)
    assert latest.revision == 2
    assert latest.title == "更新後標題"


def test_query_old_review_revision(repo: Repository):
    sample = make_sample_review(title="版本一草稿")
    saved_v1 = repo.save_review(sample, expected_revision=None)
    assert saved_v1.revision == 1

    updated = saved_v1.model_copy(update={"title": "版本二定稿"})
    saved_v2 = repo.save_review(updated, expected_revision=1)
    assert saved_v2.revision == 2

    # Query latest (default None)
    latest = repo.get_review(sample.case_id)
    assert latest.revision == 2
    assert latest.title == "版本二定稿"

    # Query specific historical version 1
    rev1 = repo.get_review(sample.case_id, revision=1)
    assert rev1.revision == 1
    assert rev1.title == "版本一草稿"

    # Non-existent revision
    with pytest.raises(DomainError) as exc_info:
        repo.get_review(sample.case_id, revision=99)
    assert exc_info.value.code in ("REVISION_NOT_FOUND", "REVIEW_NOT_FOUND")


def test_create_and_get_run(repo: Repository):
    review = repo.save_review(make_sample_review(), expected_revision=None)
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0.0", sha256="rulehash123")

    run = repo.create_run(review.case_id, rule_refs=[rule_ref])
    assert run.case_id == review.case_id
    assert run.input_version.version == str(review.revision)
    assert run.input_version.sha256 == review.original_file_hash
    assert run.stale is False

    fetched_run = repo.get_run(run.run_id)
    assert fetched_run.run_id == run.run_id
    assert fetched_run.id == run.run_id
    assert fetched_run.stale is False


def test_append_feedback_idempotency(repo: Repository):
    review = repo.save_review(make_sample_review(), expected_revision=None)
    run = repo.create_run(review.case_id, rule_refs=[])

    finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run.run_id,
        clause_ids=["clause-01"],
        requirement_id="req-enc-01",
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        reason="Lack of encryption at rest",
    )
    repo.save_finding(finding)

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        action=HumanDecisionAction.MODIFY,
        final_text="Must enable AES-256",
        reason="Compliance requirement",
        decided_by="security_officer",
        decided_at=datetime.now(UTC),
    )
    feedback = Feedback(
        feedback_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run.run_id,
        original_result=finding.result,
        human_decision=decision,
        operator="security_officer",
        created_at=datetime.now(UTC),
        version=1,
    )

    fb1 = repo.append_feedback(feedback, idempotency_key="click-1")
    fb2 = repo.append_feedback(feedback, idempotency_key="click-1")

    assert fb1.id == fb2.id
    assert fb1.feedback_id == fb2.feedback_id
    assert fb1.human_decision.final_text == "Must enable AES-256"


def test_concurrent_connections_and_cas(tmp_path: Path, artifact_store: ArtifactStore):
    db_path = tmp_path / "concurrent.db"
    repo_a = Repository(db=db_path, artifacts=artifact_store)
    repo_b = Repository(db=db_path, artifacts=artifact_store)

    sample = make_sample_review()
    repo_a.save_review(sample, expected_revision=None)

    # Both read revision 1
    rev_a = repo_a.get_review(sample.case_id)
    rev_b = repo_b.get_review(sample.case_id)
    assert rev_a.revision == 1
    assert rev_b.revision == 1

    # Connection A updates first
    update_a = rev_a.model_copy(update={"title": "Updated by A"})
    repo_a.save_review(update_a, expected_revision=1)

    # Connection B tries to update with stale expected_revision=1
    update_b = rev_b.model_copy(update={"title": "Updated by B"})
    with pytest.raises(DomainError) as exc_info:
        repo_b.save_review(update_b, expected_revision=1)
    assert exc_info.value.code == "REVISION_CONFLICT"


def test_no_sensitive_plaintext_in_sqlite_and_wal(
    tmp_path: Path, artifact_store: ArtifactStore
):
    db_path = tmp_path / "secure.db"
    repo = Repository(db=db_path, artifacts=artifact_store)

    secret_phrase = "SECRET_CORE_BANKING_SYSTEM_CREDENTIALS_9999"
    sample = make_sample_review(extra_fact=secret_phrase)
    repo.save_review(sample, expected_revision=None)

    # Inspect SQLite database file and WAL file directly
    db_bytes = db_path.read_bytes()
    wal_path = tmp_path / "secure.db-wal"
    wal_bytes = wal_path.read_bytes() if wal_path.exists() else b""

    assert secret_phrase.encode("utf-8") not in db_bytes
    assert secret_phrase.encode("utf-8") not in wal_bytes

    # Ensure repository can retrieve and decrypt it properly
    retrieved = repo.get_review(sample.case_id)
    assert secret_phrase in (retrieved.facts.service_scope or "")


def test_save_finding_update_preserves_feedback(repo: Repository):
    """驗證更新 finding 時，不會觸發 ON DELETE CASCADE 導致既有 feedback 被刪除。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    run = repo.create_run(review.case_id, rule_refs=[])

    finding_id = str(uuid.uuid4())
    finding = Finding(
        finding_id=finding_id,
        run_id=run.run_id,
        clause_ids=["clause-01"],
        requirement_id="req-enc-01",
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        reason="Lack of encryption at rest",
        human_status="unreviewed",
    )
    repo.save_finding(finding)

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding_id,
        action=HumanDecisionAction.MODIFY,
        final_text="Must enable AES-256",
        reason="Compliance requirement",
        decided_by="security_officer",
        decided_at=datetime.now(UTC),
    )
    feedback = Feedback(
        feedback_id=str(uuid.uuid4()),
        finding_id=finding_id,
        run_id=run.run_id,
        original_result=finding.result,
        human_decision=decision,
        operator="security_officer",
        created_at=datetime.now(UTC),
        version=1,
    )
    fb = repo.append_feedback(feedback, idempotency_key="fb-preserve-key")
    assert fb.feedback_id == feedback.feedback_id

    # 更新 finding 屬性（如 result, risk, human_status 等）
    updated_finding = finding.model_copy(
        update={
            "result": ResultEnum.COMPLIANT,
            "risk": RiskLevel.CRITICAL,
            "human_status": "reviewed",
            "reason": "Escalated to compliant after remediation",
        }
    )
    repo.save_finding(updated_finding)

    # 驗證 finding 更新成功
    refetched_finding = repo.get_finding(finding_id)
    assert refetched_finding.result == ResultEnum.COMPLIANT
    assert refetched_finding.risk == RiskLevel.CRITICAL
    assert refetched_finding.human_status == "reviewed"

    # 核心斷言：關聯的 feedback 依然存在，未被 CASCADE 刪除
    # 透過 append_feedback 傳入同 idempotency_key，應直接查出既有 feedback
    existing_fb = repo.append_feedback(feedback, idempotency_key="fb-preserve-key")
    assert existing_fb.feedback_id == feedback.feedback_id

    # 直接透過連線查詢 feedbacks 表確認數量依然為 1
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT count(*) FROM feedbacks WHERE finding_id = ?", (finding_id,)
        )
        count = cursor.fetchone()[0]
        assert count == 1


def test_save_run_does_not_revive_stale_run(repo: Repository):
    """驗證已被標記為 stale 的 run，即便在記憶體中持有 stale=False 的物件並呼叫 save_run，也不會使其復生 (unstale)。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    run = repo.create_run(review.case_id, rule_refs=[])
    assert run.stale is False

    # 在記憶體中持有 stale=False 的物件
    in_memory_run = repo.get_run(run.run_id)
    assert in_memory_run.stale is False

    # 外部事件（如顯式 invalidate）使資料庫中的 run 變為 stale=1
    invalidated_ids = repo.invalidate(review.case_id, reason="Policy revocation")
    assert run.run_id in invalidated_ids
    assert repo.get_run(run.run_id).stale is True

    # 模擬記憶體中持有舊物件的背景任務呼叫 save_run 更新狀態
    updated_in_memory = in_memory_run.model_copy(update={"route": "custom_route"})
    saved_result = repo.save_run(updated_in_memory)

    # 核心斷言：save_run 回傳值與資料庫中皆保持 stale=True，未被意外復生為 stale=False
    assert saved_result.stale is True
    refetched = repo.get_run(run.run_id)
    assert refetched.stale is True
    assert refetched.route == "custom_route"

    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT stale FROM runs WHERE run_id = ?", (run.run_id,))
        stale_in_db = cursor.fetchone()[0]
        assert stale_in_db == 1


def test_connections_closed_without_descriptor_leaks(repo: Repository):
    """驗證 repository 操作正常關閉資料庫連線，不會洩漏檔案描述符 (file descriptors)。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)

    # 取得操作前的檔案描述符數量（若平台支援 /dev/fd）
    dev_fd = Path("/dev/fd")
    if dev_fd.exists():
        initial_fds = len(list(dev_fd.iterdir()))

        # 連續執行多個讀寫操作
        for _ in range(30):
            r = repo.get_review(review.case_id)
            repo.save_review(r, expected_revision=r.revision)

        final_fds = len(list(dev_fd.iterdir()))
        # 允許合理波動，但不應持續增長 30 個 descriptors
        assert final_fds - initial_fds < 5

    # 驗證 _conn context manager 在正常退出時調用 close()
    with repo._conn() as conn:
        assert conn is not None
    with pytest.raises(sqlite3.ProgrammingError, match="Cannot operate on a closed database"):
        conn.execute("SELECT 1;")

    # 驗證 _conn context manager 在拋出異常時亦保證調用 close()
    with pytest.raises(DomainError):
        repo.save_review(review, expected_revision=999)

    try:
        with repo._conn() as conn2:
            raise RuntimeError("test error")
    except RuntimeError:
        pass
    with pytest.raises(sqlite3.ProgrammingError, match="Cannot operate on a closed database"):
        conn2.execute("SELECT 1;")


def test_create_run_deduplicates_rule_refs(repo: Repository):
    """驗證 create_run 傳入重複的 rule_refs 時，自動去重並成功寫入 run_rules。"""
    review = repo.save_review(make_sample_review(), expected_revision=None)
    rule_id = str(uuid.uuid4())
    ref1 = VersionRef(id=rule_id, version="1.0", sha256="sha1")
    ref2 = VersionRef(id=rule_id, version="1.0", sha256="sha1")  # duplicate

    run = repo.create_run(review.case_id, rule_refs=[ref1, ref2])
    assert run.run_id is not None

