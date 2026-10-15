import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from procurement_review.domain.enums import ProcurementFamily
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    MaskingSession,
    OutboundDraft,
    PreparedRequest,
    Review,
    VersionRef,
)
from procurement_review.egress.approvals import approve, revoke_approval
from procurement_review.egress.dispatcher import dispatch, get_delivery_state
from procurement_review.egress.payload import compute_egress_digest, prepare_egress
from procurement_review.masking.detector import RuleBasedDetector
from procurement_review.providers.mock import MockProviderAdapter
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def secret_store() -> FakeSecretStore:
    store = FakeSecretStore()
    store.set_key("mock_api_key", b"sk-mock-secret-key-1234567890abcdef")
    return store


@pytest.fixture
def artifact_store(tmp_path: Path, secret_store: FakeSecretStore) -> ArtifactStore:
    vault_root = tmp_path / "vault"
    return ArtifactStore(root=vault_root, secrets=secret_store)


@pytest.fixture
def repo(tmp_path: Path, artifact_store: ArtifactStore) -> Repository:
    db_path = tmp_path / "app.db"
    return Repository(db=db_path, artifacts=artifact_store)


@pytest.fixture
def detector() -> RuleBasedDetector:
    return RuleBasedDetector()


@pytest.fixture
def adapter() -> MockProviderAdapter:
    return MockProviderAdapter()


def make_review_and_run(repo: Repository) -> tuple[Review, str]:
    cid = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資安推動小組",
        service_scope="出站核准與防護測試",
        unknown_fields=[],
    )
    review = Review(
        case_id=cid,
        title="資安審查測試案",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="11112222333344445555666677778888",
        facts=facts,
        created_by="tester",
        created_at=datetime.now(UTC),
    )
    saved_review = repo.save_review(review, expected_revision=None)
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="rulehash123")
    run = repo.create_run(saved_review.case_id, rule_refs=[rule_ref])
    return saved_review, run.run_id


def test_prepare_egress_sequence_and_hash_integrity(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
):
    review, run_id = make_review_and_run(repo)
    draft_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())

    raw_text = "聯絡人：王小明（聯絡電話：0912-345-678）應於中央研究院指定地點履約。"
    draft = OutboundDraft(
        draft_id=draft_id,
        run_id=run_id,
        plaintext_body=raw_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=session_id,
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref=f"vault://masking/{review.case_id}/{session_id}",
        outbound_hash="",
    )

    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)

    # 1. Output must be a PreparedRequest
    assert isinstance(prepared, PreparedRequest)
    assert prepared.run_id == run_id
    assert prepared.endpoint == adapter.config.endpoint
    assert prepared.model == adapter.config.model

    # 2. Body must not leak raw PII (phone number or name)
    body_str = prepared.body.decode("utf-8")
    assert "0912-345-678" not in body_str
    assert "王小明" not in body_str

    # 3. Hash verification: sha256 must match compute_egress_digest
    expected_digest = compute_egress_digest(
        prepared.body,
        prepared.endpoint,
        prepared.model,
        prepared.masking_ref,
        prepared.rule_refs,
    )
    assert prepared.sha256 == expected_digest


def test_prepare_egress_rejects_sensitive_residual(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
):
    review, run_id = make_review_and_run(repo)
    draft_id = str(uuid.uuid4())
    session_id = str(uuid.uuid4())

    # Raw text containing high-confidence secret (AWS Key)
    raw_text = "系統設定檔：aws_key=AKIAIOSFODNN7EXAMPLE 應妥善保管。"
    draft = OutboundDraft(
        draft_id=draft_id,
        run_id=run_id,
        plaintext_body=raw_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=session_id,
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref=f"vault://masking/{review.case_id}/{session_id}",
        outbound_hash="",
    )

    with pytest.raises(DomainError) as exc_info:
        prepare_egress(run_id, draft, session, detector, adapter, repo)
    assert exc_info.value.code == "SENSITIVE_RESIDUAL_DETECTED"


def test_approve_request_and_stale_rejection(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="審查條款內容文字無敏感資訊",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)

    # 1. Normal approval
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)
    assert approval.request_id == prepared.request_id
    assert approval.request_sha256 == prepared.sha256
    assert approval.approved_by == "reviewer-alice"
    assert approval.max_resend_count == 1
    assert approval.current_send_count == 0

    # 2. Invalid max_attempts (> 3)
    with pytest.raises(DomainError) as exc_info:
        approve(prepared, actor="reviewer-alice", max_attempts=4, repo=repo)
    assert exc_info.value.code == "INVALID_ATTEMPTS"

    # 3. Missing actor
    with pytest.raises(DomainError) as exc_info:
        approve(prepared, actor="", max_attempts=1, repo=repo)
    assert exc_info.value.code == "ACTOR_REQUIRED"

    # 4. Stale run rejection
    run = repo.get_run(run_id)
    repo.save_run(run.model_copy(update={"stale": True}))
    with pytest.raises(DomainError) as exc_info:
        approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)
    assert exc_info.value.code == "RUN_STALE"


def test_tampered_payload_yields_zero_transmissions(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="完整合法條款",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(mock_handler)

    # 1. Tamper 1 byte of body in prepared request table / object
    # Update prepared request in SQLite directly to simulate tampering
    with repo._conn() as conn:
        conn.execute(
            "UPDATE prepared_requests SET sha256 = 'tamperedhash123' WHERE request_id = ?",
            (prepared.request_id,),
        )

    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code in ("REQUEST_TAMPERED", "DIGEST_MISMATCH")
    assert captured_requests == []


def test_tampered_endpoint_or_model_yields_zero_transmissions(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="條款內容測試",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(mock_handler)

    # Tamper endpoint in SQLite
    with repo._conn() as conn:
        conn.execute(
            "UPDATE prepared_requests SET endpoint = 'https://evil.endpoint.com/v1' WHERE request_id = ?",
            (prepared.request_id,),
        )

    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code in ("REQUEST_TAMPERED", "ENDPOINT_MISMATCH")
    assert captured_requests == []


def test_missing_or_revoked_approval_yields_zero_transmissions(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="核准狀態測試",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(mock_handler)

    # 1. Missing approval
    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            str(uuid.uuid4()),
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code == "APPROVAL_NOT_FOUND"
    assert captured_requests == []

    # 2. Revoked approval
    revoke_approval(approval.approval_id, reason="User cancelled", repo=repo)
    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code == "APPROVAL_REVOKED"
    assert captured_requests == []


def test_stale_run_yields_zero_transmissions(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="Stale run test",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    # Mark run stale after approval
    run = repo.get_run(run_id)
    repo.save_run(run.model_copy(update={"stale": True}))

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(mock_handler)

    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code == "RUN_STALE"
    assert captured_requests == []


def test_successful_dispatch_and_digest_match(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="正式出站審查測試",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test-ok",
                "choices": [
                    {
                        "message": {"role": "assistant", "content": '{"findings": []}'},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"total_tokens": 42},
            },
        )

    transport = httpx.MockTransport(mock_handler)

    reply = dispatch(
        prepared.request_id,
        approval.approval_id,
        repo,
        transport=transport,
        secrets=secret_store,
        adapter=adapter,
    )

    # 1. Request body captured must exactly equal prepared.body byte-for-byte
    assert len(captured_requests) == 1
    assert captured_requests[0].content == prepared.body

    # 2. Authorization header has secret from SecretStore
    auth_header = captured_requests[0].headers.get("Authorization")
    assert auth_header is not None
    assert "sk-mock-secret-key-1234567890abcdef" in auth_header

    # 3. Provider reply returned
    assert reply.request_id == prepared.request_id
    assert reply.finish_reason == "stop"


def test_duplicate_submit_and_uncertain_delivery(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="併發提交與送達未明測試",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    captured_requests: list[httpx.Request] = []
    barrier = threading.Barrier(2)

    def slow_mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        try:
            # Wait for both threads to hit this point or timeout
            barrier.wait(timeout=0.2)
        except threading.BrokenBarrierError:
            pass
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    transport = httpx.MockTransport(slow_mock_handler)

    # PART 1: Concurrency protection (Double-clicking)
    # Launch two dispatch calls in parallel
    results = []
    errors = []

    def run_dispatch():
        try:
            r = dispatch(
                prepared.request_id,
                approval.approval_id,
                repo,
                transport=transport,
                secrets=secret_store,
                adapter=adapter,
            )
            results.append(r)
        except DomainError as e:
            errors.append(e)

    with ThreadPoolExecutor(max_workers=2) as executor:
        f1 = executor.submit(run_dispatch)
        f2 = executor.submit(run_dispatch)
        f1.result()
        f2.result()

    # Core assertion: double-clicking dispatch yields only 1 actual HTTP request
    assert len(captured_requests) == 1
    assert len(results) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], DomainError)
    assert errors[0].code in ("CONCURRENT_DISPATCH_DISALLOWED", "MAX_ATTEMPTS_EXCEEDED")

    # PART 2: Uncertain delivery on timeout
    # Create another request with max_attempts=1
    draft2 = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="Timeout test",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    prepared2 = prepare_egress(run_id, draft2, session, detector, adapter, repo)
    approval2 = approve(prepared2, actor="reviewer-alice", max_attempts=1, repo=repo)

    timeout_requests: list[httpx.Request] = []

    def timeout_handler(request: httpx.Request) -> httpx.Response:
        timeout_requests.append(request)
        raise httpx.ReadTimeout("Simulated gateway read timeout after request sent")

    timeout_transport = httpx.MockTransport(timeout_handler)

    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared2.request_id,
            approval2.approval_id,
            repo,
            transport=timeout_transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code == "DELIVERY_UNKNOWN"

    # Status must be recorded as delivery_unknown
    state = get_delivery_state(prepared2.request_id, repo)
    assert state == "delivery_unknown"

    # Must NOT automatically retry without human confirmation!
    # Attempts was already reserved: another call fails without sending HTTP request
    with pytest.raises(DomainError) as exc_info2:
        dispatch(
            prepared2.request_id,
            approval2.approval_id,
            repo,
            transport=timeout_transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info2.value.code in ("DELIVERY_UNKNOWN_LOCKED", "MAX_ATTEMPTS_EXCEEDED")
    # Timeout requests count should remain 1 (no silent retry)
    assert len(timeout_requests) == 1


def test_redirect_and_malicious_endpoint_blocked(
    repo: Repository,
    detector: RuleBasedDetector,
    adapter: MockProviderAdapter,
    secret_store: FakeSecretStore,
):
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="安全轉址與惡意端點防護測試",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version=detector.version,
        mapping_vault_ref="vault://masking",
        outbound_hash="",
    )
    prepared = prepare_egress(run_id, draft, session, detector, adapter, repo)
    approval = approve(prepared, actor="reviewer-alice", max_attempts=1, repo=repo)

    # 1. Redirect test: transport returns 302
    def redirect_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"Location": "https://malicious-destination.com"})

    transport = httpx.MockTransport(redirect_handler)
    with pytest.raises(DomainError) as exc_info:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info.value.code == "REDIRECT_FORBIDDEN"

    # 2. Malicious endpoint test: userinfo in URL
    with repo._conn() as conn:
        conn.execute(
            "UPDATE prepared_requests SET endpoint = 'https://admin:secret@api.local/v1' WHERE request_id = ?",
            (prepared.request_id,),
        )
        conn.execute(
            "UPDATE egress_approvals SET endpoint = 'https://admin:secret@api.local/v1' WHERE approval_id = ?",
            (approval.approval_id,),
        )

    with pytest.raises(DomainError) as exc_info2:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo,
            transport=transport,
            secrets=secret_store,
            adapter=adapter,
        )
    assert exc_info2.value.code == "INVALID_ENDPOINT"
