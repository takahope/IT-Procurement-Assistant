import json
import logging
import uuid
from decimal import Decimal
from typing import Any

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import OutboundDraft, ProviderConfig, ProviderReply

logger = logging.getLogger(__name__)


class CloudProviderReply(ProviderReply):
    """雲端供應商回應模型（支援 usage 欄位為 None 之情境）。"""

    usage: dict[str, int] | None = None


class CloudAdapter:
    """核准雲端模型供應商適配器 (Approved Cloud Provider Adapter)。

    保證：
    - 嚴格 Protocol 契約實作：純資料格式編碼與解碼（encode/decode），不自行發起網路連線。
    - 結構安全防護：嚴禁注入未核准上下文；模型嘗試 tool call 立即拋出 TOOL_CALL_REJECTED。
    - 零日誌洩漏 (Zero-Leak Logging)：解碼錯誤與例外處理絕不將原始 response bytes 或文字寫入標準日誌。
    - 正確處理 refusal、截斷 (length/max_tokens) 與 usage 缺失情境。
    - 成本未知原則：費率不明時成本為未知 (None / unknown)，嚴禁視為 0。
    """

    def __init__(self, config: ProviderConfig | None = None) -> None:
        self.config = config or ProviderConfig(
            provider="approved_cloud",
            endpoint="https://api.approved-cloud.example.com/v1/chat/completions",
            model="approved-review-v1",
            credential_ref="approved_cloud_api_key",
            price_version="2026-10-15",
            rate_limits={
                "rpm": 60,
                "tpm": 100000,
                "max_request_bytes": 1048576,
                "max_response_bytes": 2097152,
            },
        )

    def validate_runtime_mode(self, mode: RuntimeMode) -> None:
        """真實模式不可使用 MockProvider 通過。"""
        if mode == RuntimeMode.REAL and self.config.provider == "mock":
            raise DomainError(
                "MOCK_PROVIDER_DISALLOWED_IN_REAL",
                "MockProvider is strictly forbidden in real runtime mode; real provider approval required",
            )

    def encode(self, draft: OutboundDraft) -> bytes:
        """將 OutboundDraft 序列化為固定 JSON 格式，嚴格不得注入額外上下文。"""
        # 1. 檢查出站請求大小限制
        max_bytes = self.config.rate_limits.get("max_request_bytes", 1048576)
        raw_bytes = draft.plaintext_body.encode("utf-8")
        if len(raw_bytes) > max_bytes:
            raise DomainError(
                "PAYLOAD_TOO_LARGE",
                f"Outbound payload size ({len(raw_bytes)} bytes) exceeds maximum limit ({max_bytes} bytes)",
            )

        # 2. 依供應商格式建立 payload
        if self.config.provider == "anthropic":
            payload: dict[str, Any] = {
                "model": self.config.model,
                "max_tokens": 4096,
                "messages": [
                    {
                        "role": "user",
                        "content": draft.plaintext_body,
                    }
                ],
                "temperature": 0.0,
            }
        else:
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
        """將供應商回傳之原始回應 bytes 解析為 ProviderReply。

        安全保證：
        - 檢查回應大小，超過上限時拋出 RESPONSE_TOO_LARGE。
        - 遇 JSON 解析錯誤時，僅記錄長度與例外名稱，嚴禁將原始內容寫入日誌。
        - 偵測到 tool call 時拋出 TOOL_CALL_REJECTED。
        - 支援 usage 為 None 之情境。
        """
        if len(body) > self.config.limits.max_response_bytes:
            raise DomainError(
                "RESPONSE_TOO_LARGE",
                f"Response exceeded {self.config.limits.max_response_bytes} bytes",
            )

        req_id = request_id or str(uuid.uuid4())

        try:
            decoded_text = body.decode("utf-8")
            data = json.loads(decoded_text)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as e:
            logger.error(
                "Failed to decode provider response: %s (body_bytes_len=%d)",
                type(e).__name__,
                len(body),
            )
            raise DomainError(
                "DECODE_ERROR",
                f"Failed to decode provider response payload: {type(e).__name__}",
            ) from None

        if not isinstance(data, dict):
            logger.error("Provider response JSON is not an object (body_bytes_len=%d)", len(body))
            raise DomainError(
                "DECODE_ERROR",
                "Provider response payload is not a JSON object",
            )

        # 1. 檢查 Tool Call 拒絕機制（防止模型被提示注入觸發外發工具調用）
        # 檢查 Anthropic 格式的 tool_use
        if data.get("stop_reason") == "tool_use":
            logger.warning("Rejected tool calling attempt in Anthropic stop_reason")
            raise DomainError(
                "TOOL_CALL_REJECTED",
                "Model attempted tool calling, which is strictly forbidden in egress control",
            )
        for block in data.get("content", []):
            if isinstance(block, dict) and block.get("type") == "tool_use":
                logger.warning("Rejected tool calling attempt in Anthropic content block")
                raise DomainError(
                    "TOOL_CALL_REJECTED",
                    "Model attempted tool calling, which is strictly forbidden in egress control",
                )

        # 檢查 OpenAI 相容格式的 tool_calls 與 function_call
        choices = data.get("choices", [])
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                if choice.get("finish_reason") == "tool_calls":
                    logger.warning("Rejected tool calling attempt in OpenAI finish_reason")
                    raise DomainError(
                        "TOOL_CALL_REJECTED",
                        "Model attempted tool calling, which is strictly forbidden in egress control",
                    )
                msg = choice.get("message", {})
                if isinstance(msg, dict) and (msg.get("tool_calls") or msg.get("function_call")):
                    logger.warning("Rejected tool calling attempt in OpenAI message structure")
                    raise DomainError(
                        "TOOL_CALL_REJECTED",
                        "Model attempted tool calling, which is strictly forbidden in egress control",
                    )

        # 2. 提取 provider_request_id 與 finish_reason
        provider_req_id = data.get("id", f"cloud-reply-{uuid.uuid4()}")
        finish_reason = "stop"

        if data.get("stop_reason"):
            # Anthropic 格式
            sr = data["stop_reason"]
            if sr == "max_tokens":
                finish_reason = "length"
            elif sr in ("refusal", "stop_sequence"):
                finish_reason = sr
            else:
                finish_reason = "stop"
        elif choices and isinstance(choices, list) and len(choices) > 0 and isinstance(choices[0], dict):
            ch = choices[0]
            msg = ch.get("message", {})
            if isinstance(msg, dict) and msg.get("refusal"):
                finish_reason = "refusal"
            else:
                finish_reason = ch.get("finish_reason", "stop")

        # 3. 處理 Usage 欄位（缺失時為 None，不可預設為 0）
        usage: dict[str, int] | None = None
        raw_usage = data.get("usage")
        if isinstance(raw_usage, dict) and raw_usage:
            prompt_tokens = raw_usage.get("prompt_tokens", raw_usage.get("input_tokens", 0))
            completion_tokens = raw_usage.get("completion_tokens", raw_usage.get("output_tokens", 0))
            total_tokens = raw_usage.get("total_tokens", prompt_tokens + completion_tokens)
            usage = {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": total_tokens,
            }

        reply_id = str(uuid.uuid4())
        return CloudProviderReply(
            reply_id=reply_id,
            request_id=req_id,
            artifact_ref=f"cloud://reply/{reply_id}",
            usage=usage,
            finish_reason=finish_reason,
            latency_ms=0,
            provider_request_id=provider_req_id,
        )

    def estimate_cost(self, prompt_tokens: int, completion_tokens: int) -> Decimal | None:
        """估算 API 呼叫成本。

        依規格要求：成本資料不明時顯示未知 (None)，不能當成 0。
        """
        rates = self.config.rate_limits.get("pricing")
        if not rates or not isinstance(rates, dict):
            return None

        prompt_rate = rates.get("prompt_per_1k")
        completion_rate = rates.get("completion_per_1k")
        if prompt_rate is None or completion_rate is None:
            return None

        try:
            p_cost = (Decimal(str(prompt_tokens)) / Decimal(1000)) * Decimal(str(prompt_rate))
            c_cost = (Decimal(str(completion_tokens)) / Decimal(1000)) * Decimal(str(completion_rate))
            return p_cost + c_cost
        except (ArithmeticError, ValueError, TypeError):
            return None
