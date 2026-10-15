import uuid
from datetime import UTC, datetime

from procurement_review.domain.models import (
    DetectedSpan,
    MaskingSession,
    OutboundDraft,
    SourceSpan,
)
from procurement_review.masking.detector import Detector, RuleBasedDetector
from procurement_review.masking.pii_guard_adapter import PIIGuardAdapter
from procurement_review.masking.restoration import restore
from procurement_review.masking.session import apply_annotations, mask


def _make_draft(text: str) -> OutboundDraft:
    return OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body=text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )


def _make_session() -> MaskingSession:
    sess_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    return MaskingSession(
        session_id=sess_id,
        case_id=case_id,
        detector_version="rule-based-0.1.0",
        mapping_vault_ref=f"vault://masking/{case_id}/{sess_id}",
        outbound_hash="",
        human_reviewed=False,
        roundtrip_ok=False,
        blocking_reasons=[],
    )


def test_detector_protocol():
    detector = RuleBasedDetector()
    assert isinstance(detector, Detector)
    adapter = PIIGuardAdapter()
    assert isinstance(adapter, Detector)


def test_rule_based_detection_entities():
    detector = RuleBasedDetector()
    text = (
        "立合約人：中央研究院（以下簡稱甲方）與鴻海精密工業股份有限公司（以下簡稱乙方）。"
        "乙方指派專案經理陳大文（身分證字號：A123456789），"
        "聯絡電話：0912-345-678，電子郵件：david.chen@example.com，"
        "送達地址：臺北市南港區研究院路二段128號。"
    )
    spans = detector.detect(text)
    assert len(spans) >= 4

    types = {s.span_type for s in spans}
    assert "ORGANIZATION" in types
    assert "PERSON" in types
    assert "ID_NUMBER" in types
    assert "PHONE" in types
    assert "EMAIL" in types
    assert "LOCATION" in types

    for span in spans:
        extracted = text[span.source_span.start_offset : span.source_span.end_offset]
        assert extracted == span.original_text


def test_number_overmasking_prevention():
    detector = RuleBasedDetector()
    text = (
        "本採購契約依據政府採購法第1條辦理，預算金額為新臺幣1,500,000元，"
        "履約保證金為契約金額之10%，審查基準日為113年12月26日（西元2026-10-15）。"
        "相關條款詳見第3.1條及第4.2項。"
    )
    spans = detector.detect(text)
    # None of the legal dates, amounts, percentages, or article numbers should be masked as phone/ID/card
    types = {s.span_type for s in spans}
    assert "PHONE" not in types
    assert "ID_NUMBER" not in types
    assert "CREDIT_CARD" not in types


def test_commercial_dictionary_preservation():
    detector = RuleBasedDetector()
    text = (
        "雙方應恪遵個人資料保護法、營業秘密法、著作權法及資通安全管理法之相關規定。"
    )
    spans = detector.detect(text)
    # Legal terms must not be detected as persons or secrets
    types = {s.span_type for s in spans}
    assert "PERSON" not in types
    assert "SECRET" not in types


def test_secret_blocking_api_key():
    detector = RuleBasedDetector()
    text = (
        "系統組態設定檔：\n"
        "api_key = 'sk-live-abcdef1234567890abcdef1234567890'\n"
        "此設定嚴禁外流。"
    )
    draft = _make_draft(text)
    session = _make_session()

    _masked_draft, updated_session = mask(draft, session, detector)
    assert updated_session.blocked is True
    assert updated_session.block_reason == "SECRET_DETECTED"
    assert "SECRET_DETECTED" in updated_session.blocking_reasons
    assert updated_session.roundtrip_ok is False


def test_secret_blocking_private_key():
    detector = RuleBasedDetector()
    text = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA0Y1234567890abcdefghijklmnopqrstuvwxyz\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    draft = _make_draft(text)
    session = _make_session()

    _masked_draft, updated_session = mask(draft, session, detector)
    assert updated_session.blocked is True
    assert updated_session.block_reason == "SECRET_DETECTED"


def test_mask_and_restore_roundtrip():
    detector = RuleBasedDetector()
    original_text = (
        "乙方指派專案經理陳大文負責，陳大文之電子郵件為 david@example.com，"
        "聯絡電話為 0912-345-678。公司為台灣積體電路製造股份有限公司。"
    )
    draft = _make_draft(original_text)
    session = _make_session()

    masked_draft, masked_session = mask(draft, session, detector)

    # All instances of the same name should map to the same token
    assert masked_draft.sensitive_token_count >= 4
    assert masked_session.roundtrip_ok is True
    assert not masked_session.blocked

    # Roundtrip equality
    restored = restore(masked_draft.plaintext_body, masked_session)
    assert restored.adoptable is True
    assert restored.text == original_text
    assert restored.unknown_tokens == []
    assert restored.wrong_case_tokens == []


def test_literal_token_escaping():
    detector = RuleBasedDetector()
    original_text = (
        "這是一份含有假標籤 <PERSON_1> 與 [PERSON_1] 的合約樣板，"
        "聯絡人為專案經理陳大文，電話 0912-345-678。"
    )
    draft = _make_draft(original_text)
    session = _make_session()

    masked_draft, masked_session = mask(draft, session, detector)

    # Restoring the masked text must restore back to original text exactly
    restored = restore(masked_draft.plaintext_body, masked_session)
    assert restored.text == original_text
    # And <PERSON_1> must NEVER be replaced by an entity name
    assert "<PERSON_1>" in restored.text
    assert "[PERSON_1]" in restored.text
    assert restored.adoptable is True


def test_cross_case_token_rejection():
    session = _make_session()
    foreign_token_text = "審查確認：由 [PERSON_othercase_1] 完成審查並簽署。"
    restored = restore(foreign_token_text, session)
    assert restored.adoptable is False
    assert "[PERSON_othercase_1]" in restored.wrong_case_tokens


def test_hallucinated_unknown_token_rejection():
    session = _make_session()
    # Hallucinated token within session prefix but non-existent index
    sess_prefix = session.session_id[:8]
    hallucinated_text = f"審查結論：[PERSON_{sess_prefix}_999] 應遵守資安規範。"
    restored = restore(hallucinated_text, session)
    assert restored.adoptable is False
    assert f"[PERSON_{sess_prefix}_999]" in restored.unknown_tokens


def test_apply_annotations_creates_new_session_invalidating_old():
    detector = RuleBasedDetector()
    text = "專案經理陳大文出席會議。"
    draft = _make_draft(text)
    session = _make_session()

    _masked_draft, masked_session = mask(draft, session, detector)
    old_session_id = masked_session.session_id

    # Manual annotation adding a new span or correcting false positive
    manual_span = DetectedSpan(
        span_id=str(uuid.uuid4()),
        span_type="PERSON",
        entity_group="PII",
        source_span=SourceSpan(
            document_id=str(uuid.uuid4()),
            block_id=str(uuid.uuid4()),
            start_offset=0,
            end_offset=4,
        ),
        original_text="專案經理",
        masked_token="",
        confidence=1.0,
    )

    new_session = apply_annotations(
        masked_session,
        [manual_span],
        actor="senior_reviewer",
        manual_version="v2.0",
    )

    assert new_session.session_id != old_session_id
    assert new_session.case_id == masked_session.case_id
    assert new_session.manual_tagging_version == "v2.0"
    assert new_session.human_reviewed is True
