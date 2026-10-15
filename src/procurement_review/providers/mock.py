import json
import uuid

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import OutboundDraft, ProviderConfig, ProviderReply


class MockProviderAdapter:
    """離線預設 Mock 模型供應商適配器。

    保證：
    - 僅用於 synthetic 測試模式，禁止於 real 模式通過驗收。
    - 使用固定的 HTTPS 端點與 ProviderConfig。
    - 純本機轉換，不發起任何網路請求。
    """

    def __init__(
        self,
        config: ProviderConfig | None = None,
    ) -> None:
        self.config = config or ProviderConfig(
            provider="mock",
            endpoint="https://mock.provider.local/v1/chat/completions",
            model="mock-review-model-v1",
            credential_ref="mock_api_key",
            price_version="2026-10-15",
        )

    def validate_runtime_mode(self, mode: RuntimeMode) -> None:
        """真實模式不能指定 MockProvider 來通過驗收。"""
        if mode == RuntimeMode.REAL:
            raise DomainError(
                "MOCK_PROVIDER_DISALLOWED_IN_REAL",
                "MockProvider is strictly forbidden in real runtime mode; real provider approval required",
            )

    def encode(self, draft: OutboundDraft) -> bytes:
        """將 OutboundDraft 序列化為固定 JSON 格式，嚴格不得注入額外上下文。"""
        payload = {
            "model": self.config.model,
            "messages": [
                {
                    "role": "user",
                    "content": draft.plaintext_body,
                }
            ],
            "temperature": 0.0,
        }
        return json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")

    def decode(self, body: bytes, request_id: str | None = None) -> ProviderReply:
        """將回應 bytes 解析為 ProviderReply。"""
        req_id = request_id or str(uuid.uuid4())
        try:
            data = json.loads(body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            data = {}

        provider_req_id = data.get("id", f"mock-reply-{uuid.uuid4()}")
        finish_reason = "stop"
        if "choices" in data and len(data["choices"]) > 0:
            finish_reason = data["choices"][0].get("finish_reason", "stop")

        usage = data.get(
            "usage",
            {
                "prompt_tokens": 50,
                "completion_tokens": 50,
                "total_tokens": 100,
            },
        )

        reply_id = str(uuid.uuid4())
        return ProviderReply(
            reply_id=reply_id,
            request_id=req_id,
            artifact_ref=f"mock://reply/{reply_id}",
            usage=usage,
            finish_reason=finish_reason,
            latency_ms=50,
            provider_request_id=provider_req_id,
        )
