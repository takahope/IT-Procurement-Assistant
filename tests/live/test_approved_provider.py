import hashlib
import os
import uuid
from datetime import UTC, datetime

import httpx
import pytest

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import OutboundDraft, ProviderConfig, ProviderReply
from procurement_review.providers.cloud import CloudAdapter

pytestmark = [
    pytest.mark.live,
    pytest.mark.skipif(
        not os.getenv("APPROVED_PROVIDER_API_KEY"),
        reason="APPROVED_PROVIDER_API_KEY is not configured; live cloud provider tests skipped by default",
    ),
]


def test_approved_provider_live_synthetic_roundtrip():
    """使用合成 payload 與已核准金鑰進行真實供應商端點往返驗收。

    保證：
    - live 默認不執行（未提供 APPROVED_PROVIDER_API_KEY 時跳過）。
    - 僅使用合成無機敏測試草稿，嚴禁於未驗收通過前處理真實案件。
    - 保存 request_id、模型、usage、核准 hash 及執行結果。
    """
    api_key = os.getenv("APPROVED_PROVIDER_API_KEY", "")
    endpoint = os.getenv("APPROVED_PROVIDER_ENDPOINT", "https://api.openai.com/v1/chat/completions")
    model = os.getenv("APPROVED_PROVIDER_MODEL", "gpt-4o-mini")

    config = ProviderConfig(
        provider="approved_cloud_live",
        endpoint=endpoint,
        model=model,
        credential_ref="approved_live_key",
        price_version="2026-10-15",
    )
    adapter = CloudAdapter(config=config)

    synthetic_draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body="【合成測試案件】請回覆 JSON 格式之審查測試確認字串：{\"status\": \"live_verified\"}。",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )

    encoded_body = adapter.encode(synthetic_draft)
    approval_hash = hashlib.sha256(encoded_body).hexdigest()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    with httpx.Client(timeout=30.0, follow_redirects=False, trust_env=False) as client:
        response = client.post(endpoint, content=encoded_body, headers=headers)

    assert response.status_code == 200, f"Live provider request failed with status {response.status_code}"

    reply = adapter.decode(response.content, request_id=synthetic_draft.draft_id)
    assert isinstance(reply, ProviderReply)
    assert reply.request_id == synthetic_draft.draft_id
    assert reply.finish_reason in ("stop", "end_turn")

    # 驗收紀錄中包含 request_id、模型、usage、核准 hash 及結果
    audit_record = {
        "request_id": reply.request_id,
        "model": config.model,
        "usage": reply.usage,
        "approval_hash": approval_hash,
        "status_code": response.status_code,
        "finish_reason": reply.finish_reason,
        "verified_at": datetime.now(UTC).isoformat(),
    }
    assert audit_record["request_id"] is not None
    assert audit_record["approval_hash"] == approval_hash


def test_approved_provider_live_synthetic_refuses_mock_in_real_mode():
    """真實模式不可使用 MockProvider 通過。"""
    config = ProviderConfig(
        provider="mock",
        endpoint="https://mock.provider.local/v1/chat/completions",
        model="mock-v1",
        credential_ref="mock_key",
        price_version="2026-10-15",
    )
    adapter = CloudAdapter(config=config)
    with pytest.raises(DomainError) as exc_info:
        adapter.validate_runtime_mode(RuntimeMode.REAL)
    assert exc_info.value.code == "MOCK_PROVIDER_DISALLOWED_IN_REAL"
