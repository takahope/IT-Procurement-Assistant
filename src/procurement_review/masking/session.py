import hashlib
import re
import uuid
from dataclasses import dataclass, field

from procurement_review.domain.models import (
    DetectedSpan,
    MaskingSession,
    OutboundDraft,
)
from procurement_review.masking.detector import Detector


# 動態為 MaskingSession 擴充 blocked 與 block_reason 存取屬性，確保相容性
def _get_blocked(self: MaskingSession) -> bool:
    return "SECRET_DETECTED" in self.blocking_reasons or len(self.blocking_reasons) > 0


def _set_blocked(self: MaskingSession, val: bool) -> None:
    if val:
        if "SECRET_DETECTED" not in self.blocking_reasons:
            self.blocking_reasons.append("SECRET_DETECTED")
    else:
        self.blocking_reasons.clear()


def _get_block_reason(self: MaskingSession) -> str | None:
    return self.blocking_reasons[0] if self.blocking_reasons else None


def _set_block_reason(self: MaskingSession, reason: str | None) -> None:
    if reason and reason not in self.blocking_reasons:
        self.blocking_reasons.append(reason)


if not hasattr(MaskingSession, "blocked"):
    MaskingSession.blocked = property(_get_blocked, _set_blocked)

if not hasattr(MaskingSession, "block_reason"):
    MaskingSession.block_reason = property(_get_block_reason, _set_block_reason)


@dataclass
class SessionMapping:
    """本機遮罩對照表記錄"""

    session_id: str
    case_id: str
    token_to_original: dict[str, str] = field(default_factory=dict)
    original_to_token: dict[tuple[str, str], str] = field(default_factory=dict)
    literal_escapes: set[str] = field(default_factory=set)
    spans: list[DetectedSpan] = field(default_factory=list)


# 本機記憶體 Vault 儲存庫（以 session_id 為索引）
_VAULT_STORE: dict[str, SessionMapping] = {}


def get_session_mapping(session_id: str) -> SessionMapping | None:
    return _VAULT_STORE.get(session_id)


def save_session_mapping(mapping: SessionMapping) -> None:
    _VAULT_STORE[mapping.session_id] = mapping


LITERAL_TOKEN_PATTERNS = [
    re.compile(r"\[[A-Z_]+_[a-zA-Z0-9_-]+_[0-9]+\]"),
    re.compile(r"<[A-Z_]+_[0-9]+>"),
    re.compile(r"\[[A-Z_]+_[0-9]+\]"),
]


def mask(
    draft: OutboundDraft,
    session: MaskingSession,
    detector: Detector,
) -> tuple[OutboundDraft, MaskingSession]:
    """遮罩出站草稿中的 PII 與機敏資訊，並產生或更新遮罩會話。

    保證：
    - 分案／分會話獨立命名空間：[<TYPE>_<session_id[:8]>_<idx>]
    - 同一會話內同名實體共用相同 token
    - 轉義原文既有的假 token（例如 <PERSON_1>），避免還原污染
    - 高機密秘密（API key / 密碼 / 金鑰）發現即標記 blocked 並記錄 SECRET_DETECTED，不放行出站
    """
    mapping = get_session_mapping(session.session_id)
    if mapping is None:
        mapping = SessionMapping(session_id=session.session_id, case_id=session.case_id)

    # 1. 掃描原文既有的假 token / 標籤，記錄為 literal_escapes 避免誤還原
    for pat in LITERAL_TOKEN_PATTERNS:
        for m in pat.finditer(draft.plaintext_body):
            mapping.literal_escapes.add(m.group(0))

    # 2. 偵測 PII 與機敏資訊區間
    spans = detector.detect(draft.plaintext_body)
    mapping.spans = spans

    # 3. 檢查機密阻止條件 (Secret Blocking)
    has_secret = False
    for span in spans:
        if span.span_type == "SECRET" or span.entity_group == "SECRET":
            has_secret = True
            break

    if has_secret:
        if "SECRET_DETECTED" not in session.blocking_reasons:
            session.blocking_reasons.append("SECRET_DETECTED")
        session.roundtrip_ok = False

    # 4. 進行文字遮罩替換
    # 按照 start_offset 排序以精確切片組裝
    sorted_spans = sorted(spans, key=lambda s: s.source_span.start_offset)
    pieces: list[str] = []
    last_idx = 0

    for span in sorted_spans:
        pieces.append(draft.plaintext_body[last_idx : span.source_span.start_offset])
        key = (span.span_type, span.original_text)
        if key in mapping.original_to_token:
            token = mapping.original_to_token[key]
        else:
            idx = len(mapping.original_to_token)
            token = f"[{span.span_type}_{session.session_id[:8]}_{idx}]"
            mapping.original_to_token[key] = token
            mapping.token_to_original[token] = span.original_text

        span.masked_token = token
        pieces.append(token)
        last_idx = span.source_span.end_offset

    pieces.append(draft.plaintext_body[last_idx:])
    masked_body = "".join(pieces)

    # 5. 儲存對照映射至 Vault
    save_session_mapping(mapping)

    # 6. 計算出站內容雜湊
    session.outbound_hash = hashlib.sha256(masked_body.encode("utf-8")).hexdigest()

    # 7. 若未被機密阻擋，執行快速 Round-trip 校驗
    if not session.blocked:
        from procurement_review.masking.restoration import restore

        check_res = restore(masked_body, session)
        if check_res.text == draft.plaintext_body:
            session.roundtrip_ok = True

    # 8. 建立遮罩後的新 OutboundDraft
    new_draft = OutboundDraft(
        draft_id=draft.draft_id,
        run_id=draft.run_id,
        plaintext_body=masked_body,
        sensitive_token_count=len(spans),
        assembled_at=draft.assembled_at,
    )

    return new_draft, session


def apply_annotations(
    session: MaskingSession,
    spans: list[DetectedSpan],
    actor: str = "reviewer",
    manual_version: str | None = None,
) -> MaskingSession:
    """套用人工標註或修正（補遮／放回），建立全新 session_id 使舊出站核准失效。"""
    new_session_id = str(uuid.uuid4())
    version_label = manual_version or f"manual-{uuid.uuid4().hex[:6]}"

    old_mapping = get_session_mapping(session.session_id)
    new_mapping = SessionMapping(
        session_id=new_session_id,
        case_id=session.case_id,
        literal_escapes=set(old_mapping.literal_escapes) if old_mapping else set(),
        spans=spans,
    )

    # 針對人工修訂後的 spans 建立新 session 下的 token 命名空間映射
    for span in spans:
        key = (span.span_type, span.original_text)
        if key in new_mapping.original_to_token:
            token = new_mapping.original_to_token[key]
        else:
            idx = len(new_mapping.original_to_token)
            token = f"[{span.span_type}_{new_session_id[:8]}_{idx}]"
            new_mapping.original_to_token[key] = token
            new_mapping.token_to_original[token] = span.original_text
        span.masked_token = token

    save_session_mapping(new_mapping)

    return MaskingSession(
        session_id=new_session_id,
        case_id=session.case_id,
        detector_version=session.detector_version,
        manual_tagging_version=version_label,
        mapping_vault_ref=f"vault://masking/{session.case_id}/{new_session_id}",
        outbound_hash="",
        human_reviewed=True,
        roundtrip_ok=session.roundtrip_ok,
        blocking_reasons=list(session.blocking_reasons),
    )
