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
from procurement_review.masking.session import (
    _VAULT_STORE,
    apply_annotations,
    get_session_mapping,
    mask,
)


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
    assert "v2.0" in new_session.manual_tagging_version
    assert "senior_reviewer" in new_session.manual_tagging_version
    assert new_session.human_reviewed is True


def test_mask_preserves_human_annotations_without_reset():
    detector = RuleBasedDetector()
    text = "專案經理陳大文出席會議，聯絡電話為 0912-345-678。"
    draft = _make_draft(text)
    session = _make_session()

    _raw_draft, first_session = mask(draft, session, detector)
    assert len(first_session.spans) >= 2  # detects 陳大文 and phone

    # Reviewer decides to ONLY annotate 陳大文 (e.g. phone is public hotline, or adds custom annotation)
    manual_span = DetectedSpan(
        span_id=str(uuid.uuid4()),
        span_type="PERSON",
        entity_group="PII",
        source_span=SourceSpan(
            document_id="00000000-0000-0000-0000-000000000000",
            block_id="00000000-0000-0000-0000-000000000000",
            start_offset=4,
            end_offset=7,
        ),
        original_text="陳大文",
        masked_token="",
        confidence=1.0,
    )

    annotated_session = apply_annotations(
        first_session,
        [manual_span],
        actor="lead_auditor",
        manual_version="v2.0",
    )
    assert annotated_session.human_reviewed is True

    # Re-run mask on the draft with annotated_session
    second_draft, second_session = mask(draft, annotated_session, detector)

    # Must preserve human annotations: only 1 sensitive token, phone remains unmasked
    assert second_draft.sensitive_token_count == 1
    assert "0912-345-678" in second_draft.plaintext_body
    assert "陳大文" not in second_draft.plaintext_body
    assert len(second_session.spans) == 1
    assert second_session.spans[0].original_text == "陳大文"


def test_actor_persisted_in_session_and_mapping():
    detector = RuleBasedDetector()
    text = "專案經理陳大文出席會議。"
    draft = _make_draft(text)
    session = _make_session()

    _masked_draft, masked_session = mask(draft, session, detector)

    manual_span = DetectedSpan(
        span_id=str(uuid.uuid4()),
        span_type="PERSON",
        entity_group="PII",
        source_span=SourceSpan(
            document_id="00000000-0000-0000-0000-000000000000",
            block_id="00000000-0000-0000-0000-000000000000",
            start_offset=4,
            end_offset=7,
        ),
        original_text="陳大文",
        masked_token="",
        confidence=1.0,
    )

    actor_name = "legal_officer_alice"
    new_session = apply_annotations(
        masked_session,
        [manual_span],
        actor=actor_name,
        manual_version="v1.1",
    )

    assert new_session.actor == actor_name
    assert actor_name in new_session.manual_tagging_version

    mapping = get_session_mapping(new_session.session_id)
    assert mapping is not None
    assert mapping.actor == actor_name


def test_chinese_adjacent_word_boundary_detection():
    detector = RuleBasedDetector()
    # No whitespace between Chinese characters and ROC ID / AWS Key
    text = "身分證A123456789與金鑰AKIAIOSFODNN7EXAMPLE不可洩漏。"
    spans = detector.detect(text)

    types = {s.span_type for s in spans}
    assert "ID_NUMBER" in types
    assert "SECRET" in types

    roc_span = next(s for s in spans if s.span_type == "ID_NUMBER")
    assert roc_span.original_text == "A123456789"
    assert roc_span.source_span.start_offset == text.index("A123456789")
    assert roc_span.source_span.end_offset == text.index("A123456789") + 10

    secret_span = next(s for s in spans if s.span_type == "SECRET")
    assert secret_span.original_text == "AKIAIOSFODNN7EXAMPLE"
    assert secret_span.source_span.start_offset == text.index("AKIAIOSFODNN7EXAMPLE")
    assert secret_span.source_span.end_offset == text.index("AKIAIOSFODNN7EXAMPLE") + 20


def test_vault_store_ciphertext_encryption():
    detector = RuleBasedDetector()
    entity_name = "張大千"
    text = f"承辦人：{entity_name}先生，電話：0912-345-678。"
    draft = _make_draft(text)
    session = _make_session()

    _masked_draft, masked_session = mask(draft, session, detector)

    # Check the underlying stored record in _VAULT_STORE
    assert masked_session.session_id in _VAULT_STORE
    record = _VAULT_STORE[masked_session.session_id]

    # Verify that the stored ciphertext is bytes and does not contain plaintext entity names or phone
    assert isinstance(record.ciphertext, bytes)
    assert entity_name.encode("utf-8") not in record.ciphertext
    assert b"0912-345-678" not in record.ciphertext
    assert "張大千".encode() not in record.ciphertext

    # Decrypting via get_session_mapping successfully returns original text
    mapping = get_session_mapping(masked_session.session_id)
    assert mapping is not None
    original_texts = [s.original_text for s in mapping.spans]
    assert any("張大千" in t for t in original_texts)


def test_roundtrip_mismatch_blocking(monkeypatch):
    detector = RuleBasedDetector()
    text = "專案經理陳大文確認。"
    draft = _make_draft(text)
    session = _make_session()

    # Simulate restoration returning corrupted text
    from procurement_review.domain.models import RestorationResult

    def corrupted_restore(*args, **kwargs):
        return RestorationResult(
            text="CORRUPTED TEXT",
            unknown_tokens=[],
            wrong_case_tokens=[],
            adoptable=True,
        )

    # Monkeypatch restore inside procurement_review.masking.restoration
    import procurement_review.masking.restoration as rest_module

    monkeypatch.setattr(rest_module, "restore", corrupted_restore)

    _masked_draft, updated_session = mask(draft, session, detector)
    assert updated_session.roundtrip_ok is False
    assert updated_session.blocked is True
    assert "ROUNDTRIP_MISMATCH" in updated_session.blocking_reasons
