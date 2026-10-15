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
