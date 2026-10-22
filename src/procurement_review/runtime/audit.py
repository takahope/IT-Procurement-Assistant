import json
import logging
from typing import Any

from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import AuditEvent

logger = logging.getLogger("procurement_review.audit")

# 抑制第三方套件 debug log 避免傾印 HTTP payload / prompt
_THIRD_PARTY_LOGGERS = [
    "urllib3",
    "requests",
    "httpx",
    "httpcore",
    "botocore",
    "boto3",
    "google",
    "openai",
    "anthropic",
]

for _name in _THIRD_PARTY_LOGGERS:
    logging.getLogger(_name).setLevel(logging.WARNING)


def audit_event(event: AuditEvent) -> None:
    """記錄安全稽核事件。

    安全約束：
    - 嚴格僅輸出白名單欄位 (event_id, timestamp, operator, action, target_type, target_version, result, evidence_hashes)。
    - 絕不輸出合約原文、提示詞 (prompt)、模型回覆 (reply)、對照表或明文金鑰。
    """
    record: dict[str, Any] = {
        "event_id": str(event.event_id),
        "timestamp": event.timestamp.isoformat(),
        "operator": event.operator,
        "action": event.action,
        "target_type": event.target_type,
        "target_version": event.target_version,
        "result": event.result,
        "evidence_hashes": event.evidence_hashes,
    }
    logger.info("AUDIT_EVENT: %s", json.dumps(record, ensure_ascii=False))


def log_audit_failure(event: AuditEvent, exc: Exception | None = None) -> None:
    """記錄稽核失敗事件，並安全遮蔽例外訊息。

    若包含未受控的外部例外（可能攜帶提示詞或合約文本），僅記錄例外型別，防止明文外洩。
    若為 DomainError，則僅記錄經領域定義保證安全的 safe_message 與 code。
    """
    record: dict[str, Any] = {
        "event_id": str(event.event_id),
        "timestamp": event.timestamp.isoformat(),
        "operator": event.operator,
        "action": event.action,
        "target_type": event.target_type,
        "target_version": event.target_version,
        "result": event.result,
        "evidence_hashes": event.evidence_hashes,
    }

    if exc is not None:
        if isinstance(exc, DomainError):
            record["error_code"] = exc.code
            record["error_message"] = exc.safe_message
        else:
            # 第三方或通用例外：僅記錄類別名稱，防範 repr(exc) 洩漏 prompt
            record["error_type"] = type(exc).__name__

    logger.warning("AUDIT_FAILURE: %s", json.dumps(record, ensure_ascii=False))
