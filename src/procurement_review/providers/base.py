from typing import Protocol, runtime_checkable

from procurement_review.domain.models import OutboundDraft, ProviderConfig, ProviderReply


@runtime_checkable
class ProviderAdapter(Protocol):
    """供應商適配器協定介面。

    保證：
    - adapter 只做資料格式轉換（encode/decode），不自行發起網路請求。
    - endpoint 與 model 來自其固定的 ProviderConfig。
    - encode 不得任意增加未經審閱的文件上下文。
    """

    config: ProviderConfig

    def encode(self, draft: OutboundDraft) -> bytes:
        """將出站草稿轉換為目標模型供應商要求的傳輸 bytes。"""
        ...

    def decode(self, body: bytes, request_id: str | None = None) -> ProviderReply:
        """將供應商回傳之原始回應 bytes 解析為標準 ProviderReply。"""
        ...
