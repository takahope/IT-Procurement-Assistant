import hashlib
import json
import os
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    DetectedSpan,
    MaskingSession,
    OutboundDraft,
    SourceSpan,
)
from procurement_review.masking.detector import Detector


# 動態為 MaskingSession 擴充 blocked 與 block_reason 存取屬性，確保相容性
def _get_blocked(self: MaskingSession) -> bool:
    return (
        "SECRET_DETECTED" in self.blocking_reasons
        or "ROUNDTRIP_MISMATCH" in self.blocking_reasons
        or len(self.blocking_reasons) > 0
    )


def _set_blocked(self: MaskingSession, val: bool) -> None:
    if val:
        if not self.blocking_reasons:
            self.blocking_reasons.append("BLOCKED")
    else:
        self.blocking_reasons.clear()


def _get_block_reason(self: MaskingSession) -> str | None:
    return self.blocking_reasons[0] if self.blocking_reasons else None


def _set_block_reason(self: MaskingSession, reason: str | None) -> None:
    if reason and reason not in self.blocking_reasons:
        self.blocking_reasons.append(reason)


def _get_session_actor(self: MaskingSession) -> str:
    mapping = get_session_mapping(
        self.session_id,
        case_id=str(self.case_id) if hasattr(self, "case_id") else None,
        artifacts=getattr(self, "artifacts", None),
    )
    if mapping and mapping.actor:
        return mapping.actor
    if self.manual_tagging_version and "-annotated-by-" in self.manual_tagging_version:
        return self.manual_tagging_version.split("-annotated-by-")[-1]
    return "system"


def _get_session_spans(self: MaskingSession) -> list[DetectedSpan]:
    mapping = get_session_mapping(
        self.session_id,
        case_id=str(self.case_id) if hasattr(self, "case_id") else None,
        artifacts=getattr(self, "artifacts", None),
    )
    return mapping.spans if mapping else []


if not hasattr(MaskingSession, "blocked"):
    MaskingSession.blocked = property(_get_blocked, _set_blocked)

if not hasattr(MaskingSession, "block_reason"):
    MaskingSession.block_reason = property(_get_block_reason, _set_block_reason)

if not hasattr(MaskingSession, "actor"):
    MaskingSession.actor = property(_get_session_actor)

if not hasattr(MaskingSession, "spans"):
    MaskingSession.spans = property(_get_session_spans)


@dataclass
class SessionMapping:
    """本機遮罩對照表記錄"""

    session_id: str
    case_id: str
    actor: str = "system"
    token_to_original: dict[str, str] = field(default_factory=dict)
    original_to_token: dict[tuple[str, str], str] = field(default_factory=dict)
    literal_escapes: set[str] = field(default_factory=set)
    spans: list[DetectedSpan] = field(default_factory=list)


@dataclass
class EncryptedMappingRecord:
    """Vault 中以 AES-256-GCM 加密之對照表紀錄"""

    session_id: str
    case_id: str
    nonce: bytes
    ciphertext: bytes
    vault_key: bytes | None = None


_VAULT_KEY_ENV = os.environ.get("MASKING_VAULT_KEY")
if _VAULT_KEY_ENV and len(_VAULT_KEY_ENV.encode("utf-8")) == 32:
    _VAULT_KEY: bytes = _VAULT_KEY_ENV.encode("utf-8")
else:
    _VAULT_KEY: bytes = AESGCM.generate_key(bit_length=256)


# 本機記憶體 Vault 儲存庫（儲存 AES-256-GCM 加密記錄）
_VAULT_STORE: dict[str, EncryptedMappingRecord] = {}


def get_vault_key() -> bytes:
    return _VAULT_KEY


def set_vault_key(key: bytes) -> None:
    global _VAULT_KEY
    if len(key) != 32:
        raise ValueError("Vault key must be 32 bytes (256 bits)")
    _VAULT_KEY = key


def _serialize_session_mapping(mapping: SessionMapping) -> bytes:
    payload = {
        "session_id": mapping.session_id,
        "case_id": mapping.case_id,
        "actor": mapping.actor,
        "token_to_original": mapping.token_to_original,
        "original_to_token": [
            [k[0], k[1], v] for k, v in mapping.original_to_token.items()
        ],
        "literal_escapes": sorted(mapping.literal_escapes),
        "spans": [s.model_dump() for s in mapping.spans],
    }
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _deserialize_session_mapping(raw_bytes: bytes) -> SessionMapping:
    data = json.loads(raw_bytes.decode("utf-8"))
    spans = [DetectedSpan.model_validate(s) for s in data.get("spans", [])]
    orig_to_tok = {
        (item[0], item[1]): item[2] for item in data.get("original_to_token", [])
    }
    return SessionMapping(
        session_id=data["session_id"],
        case_id=data["case_id"],
        actor=data.get("actor", "system"),
        token_to_original=data.get("token_to_original", {}),
        original_to_token=orig_to_tok,
        literal_escapes=set(data.get("literal_escapes", [])),
        spans=spans,
    )


def get_encrypted_mapping(
    session_id: str,
    case_id: str | None = None,
    artifacts: Any = None,
) -> EncryptedMappingRecord | None:
    """查詢加密對照表記錄，優先查記憶體，若無且提供 artifacts 與 case_id 則自磁碟讀取。"""
    if session_id in _VAULT_STORE:
        return _VAULT_STORE[session_id]
    if artifacts is not None and case_id is not None:
        try:
            raw = artifacts.get(case_id, f"masking_{session_id}.enc")
            info = json.loads(raw.decode("utf-8"))
            rec = EncryptedMappingRecord(
                session_id=info["session_id"],
                case_id=info["case_id"],
                nonce=bytes.fromhex(info["nonce"]),
                ciphertext=bytes.fromhex(info["ciphertext"]),
                vault_key=bytes.fromhex(info["vault_key"]) if "vault_key" in info else None,
            )
            _VAULT_STORE[session_id] = rec
            return rec
        except (DomainError, ValueError, KeyError, OSError, TypeError):
            return None
    return None


def get_session_mapping(
    session_id: str,
    case_id: str | None = None,
    artifacts: Any = None,
) -> SessionMapping | None:
    record = get_encrypted_mapping(session_id, case_id=case_id, artifacts=artifacts)
    if record is None:
        return None
    key = record.vault_key or _VAULT_KEY
    aesgcm = AESGCM(key)
    aad = f"{record.case_id}:{record.session_id}".encode()
    plaintext = aesgcm.decrypt(record.nonce, record.ciphertext, aad)
    return _deserialize_session_mapping(plaintext)


def save_session_mapping(mapping: SessionMapping, artifacts: Any = None) -> None:
    aesgcm = AESGCM(_VAULT_KEY)
    nonce = os.urandom(12)
    aad = f"{mapping.case_id}:{mapping.session_id}".encode()
    plaintext = _serialize_session_mapping(mapping)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    rec = EncryptedMappingRecord(
        session_id=mapping.session_id,
        case_id=mapping.case_id,
        nonce=nonce,
        ciphertext=ciphertext,
        vault_key=_VAULT_KEY,
    )
    _VAULT_STORE[mapping.session_id] = rec

    if artifacts is not None:
        encrypted_data = json.dumps({
            "session_id": rec.session_id,
            "case_id": rec.case_id,
            "nonce": rec.nonce.hex(),
            "ciphertext": rec.ciphertext.hex(),
            "vault_key": _VAULT_KEY.hex(),
        }).encode("utf-8")
        artifacts.put(
            mapping.case_id,
            kind="masking_mapping",
            data=encrypted_data,
            filename=f"masking_{mapping.session_id}.enc",
        )


LITERAL_TOKEN_PATTERNS = [
    re.compile(r"\[[A-Z_]+_[a-zA-Z0-9_-]+_[0-9]+\]"),
    re.compile(r"<[A-Z_]+_[0-9]+>"),
    re.compile(r"\[[A-Z_]+_[0-9]+\]"),
]


def mask(
    draft: OutboundDraft,
    session: MaskingSession,
    detector: Detector,
    artifacts: Any = None,
) -> tuple[OutboundDraft, MaskingSession]:
    """遮罩出站草稿中的 PII 與機敏資訊，並產生或更新遮罩會話。

    保證：
    - 分案／分會話獨立命名空間：[<TYPE>_<session_id[:8]>_<idx>]
    - 同一會話內同名實體共用相同 token
    - 轉義原文既有的假 token（例如 <PERSON_1>），避免還原污染
    - 高機密秘密（API key / 密碼 / 金鑰）發現即標記 blocked 並記錄 SECRET_DETECTED，不放行出站
    - 人工審查標註（human_reviewed=True 且 mapping.spans 存在）不被 detector 重新覆寫
    """
    art = artifacts or getattr(session, "artifacts", None)
    case_id_str = str(session.case_id) if hasattr(session, "case_id") else ""
    mapping = get_session_mapping(session.session_id, case_id=case_id_str, artifacts=art)
    if mapping is None:
        mapping = SessionMapping(session_id=session.session_id, case_id=case_id_str)

    # 1. 掃描原文既有的假 token / 標籤，記錄為 literal_escapes 避免誤還原
    for pat in LITERAL_TOKEN_PATTERNS:
        for m in pat.finditer(draft.plaintext_body):
            mapping.literal_escapes.add(m.group(0))

    # 2. 偵測 PII 與機敏資訊區間（若已經過人工審查標註且已存在 spans，不被 detector.detect 覆寫）
    if session.human_reviewed and mapping.spans:
        valid_annotated_spans = True
        for s in mapping.spans:
            if (
                s.source_span.end_offset > len(draft.plaintext_body)
                or draft.plaintext_body[s.source_span.start_offset : s.source_span.end_offset]
                != s.original_text
            ):
                valid_annotated_spans = False
                break
        if valid_annotated_spans:
            spans = mapping.spans
        else:
            spans = detector.detect(draft.plaintext_body)
            existing_ranges = {
                (s.source_span.start_offset, s.source_span.end_offset) for s in spans
            }
            for human_span in mapping.spans:
                target_text = human_span.original_text
                if not target_text or target_text not in draft.plaintext_body:
                    continue
                start_search = 0
                while True:
                    found_idx = draft.plaintext_body.find(target_text, start_search)
                    if found_idx == -1:
                        break
                    end_idx = found_idx + len(target_text)
                    overlaps = any(
                        max(found_idx, ex_start) < min(end_idx, ex_end)
                        for ex_start, ex_end in existing_ranges
                    )
                    if not overlaps:
                        spans.append(
                            DetectedSpan(
                                span_id=str(uuid.uuid4()),
                                span_type=human_span.span_type,
                                entity_group=human_span.entity_group,
                                source_span=SourceSpan(
                                    document_id=human_span.source_span.document_id,
                                    block_id=human_span.source_span.block_id,
                                    start_offset=found_idx,
                                    end_offset=end_idx,
                                ),
                                original_text=target_text,
                                masked_token="",
                                confidence=human_span.confidence,
                            )
                        )
                        existing_ranges.add((found_idx, end_idx))
                    start_search = end_idx
    else:
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
    elif "SECRET_DETECTED" in session.blocking_reasons:
        session.blocking_reasons.remove("SECRET_DETECTED")

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

    # 5. 儲存對照映射至 Vault (AES-256-GCM 加密，可選持久化至 artifacts)
    save_session_mapping(mapping, artifacts=art)

    # 6. 計算出站內容雜湊
    session.outbound_hash = hashlib.sha256(masked_body.encode("utf-8")).hexdigest()

    # 7. 若未被機密阻擋，執行快速 Round-trip 校驗
    if not session.blocked:
        from procurement_review.masking.restoration import restore

        check_res = restore(masked_body, session, artifacts=art)
        if check_res.text == draft.plaintext_body:
            session.roundtrip_ok = True
            if "ROUNDTRIP_MISMATCH" in session.blocking_reasons:
                session.blocking_reasons.remove("ROUNDTRIP_MISMATCH")
        else:
            session.roundtrip_ok = False
            session.blocked = True
            if "ROUNDTRIP_MISMATCH" not in session.blocking_reasons:
                session.blocking_reasons.append("ROUNDTRIP_MISMATCH")
            if "BLOCKED" in session.blocking_reasons:
                session.blocking_reasons.remove("BLOCKED")

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
    artifacts: Any = None,
) -> MaskingSession:
    """套用人工標註或修正（補遮／放回），建立全新 session_id 使舊出站核准失效。"""
    art = artifacts or getattr(session, "artifacts", None)
    case_id_str = str(session.case_id) if hasattr(session, "case_id") else ""
    new_session_id = str(uuid.uuid4())
    if manual_version:
        version_label = (
            manual_version
            if actor in manual_version
            else f"{manual_version}-annotated-by-{actor}"
        )
    else:
        base = session.manual_tagging_version or "v1.0"
        version_label = f"{base}-annotated-by-{actor}"

    old_mapping = get_session_mapping(
        session.session_id,
        case_id=case_id_str,
        artifacts=art,
    )
    new_mapping = SessionMapping(
        session_id=new_session_id,
        case_id=case_id_str,
        actor=actor,
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

    save_session_mapping(new_mapping, artifacts=art)

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
        artifacts=art,
        storage_path=getattr(session, "storage_path", None),
    )
