import json
from datetime import UTC, datetime

import pytest

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import OutboundDraft, ProviderConfig, ProviderReply
from procurement_review.providers.base import ProviderAdapter
from procurement_review.providers.mock import MockProviderAdapter


def test_provider_adapter_protocol():
    """Verify MockProviderAdapter implements the ProviderAdapter protocol."""
    adapter = MockProviderAdapter()
    assert isinstance(adapter, ProviderAdapter)
    assert isinstance(adapter.config, ProviderConfig)
    assert adapter.config.endpoint.startswith("https://")
    assert adapter.config.model is not None


def test_mock_provider_encode_and_decode():
    """Verify encode and decode contract on MockProviderAdapter."""
    adapter = MockProviderAdapter()
    draft = OutboundDraft(
        draft_id="11111111-1111-4111-8111-111111111111",
        run_id="22222222-2222-4222-8222-222222222222",
        plaintext_body="檢驗條款：[ORGANIZATION_001] 應於三十日內通報資安事件。",
        sensitive_token_count=1,
        assembled_at=datetime.now(UTC),
    )

    # 1. Encode
    body_bytes = adapter.encode(draft)
    assert isinstance(body_bytes, bytes)
    payload = json.loads(body_bytes.decode("utf-8"))
    assert payload["model"] == adapter.config.model
    assert "messages" in payload
    # Verify encode does not add arbitrary document context
    assert any(draft.plaintext_body in m.get("content", "") for m in payload["messages"])

    # 2. Decode
    mock_reply_json = json.dumps(
        {
            "id": "chatcmpl-mock-123",
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": json.dumps({"findings": [{"result": "compliant"}]}),
                    },
                    "finish_reason": "stop",
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50, "total_tokens": 150},
        }
    ).encode("utf-8")

    reply = adapter.decode(mock_reply_json, request_id=draft.draft_id)
    assert isinstance(reply, ProviderReply)
    assert reply.request_id == draft.draft_id
    assert reply.finish_reason == "stop"
    assert reply.usage.get("total_tokens") == 150
    assert reply.provider_request_id == "chatcmpl-mock-123"


def test_mock_provider_rejected_in_real_mode():
    """MockProvider must not be allowed to pass verification in real runtime mode."""
    adapter = MockProviderAdapter()
    with pytest.raises(DomainError) as exc_info:
        adapter.validate_runtime_mode(RuntimeMode.REAL)
    assert exc_info.value.code == "MOCK_PROVIDER_DISALLOWED_IN_REAL"


def test_mock_provider_offline_contract():
    """Adapter only converts bytes and never initiates network requests directly."""
    adapter = MockProviderAdapter()
    draft = OutboundDraft(
        draft_id="11111111-1111-4111-8111-111111111111",
        run_id="22222222-2222-4222-8222-222222222222",
        plaintext_body="Hello offline world",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    # Calling encode and decode in an environment without network must succeed without error
    body = adapter.encode(draft)
    assert body is not None
    reply = adapter.decode(b'{"choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}]}')
    assert reply is not None
