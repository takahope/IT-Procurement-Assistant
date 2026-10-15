import socket
import uuid

from procurement_review.domain.models import DetectedSpan, SourceSpan
from procurement_review.masking.detector import Detector, RuleBasedDetector
from procurement_review.masking.pii_guard_adapter import PIIGuardAdapter


def _assert_valid_detected_spans(spans: list[DetectedSpan], text: str) -> None:
    for span in spans:
        assert isinstance(span.span_id, str)
        assert uuid.UUID(span.span_id)
        assert span.span_type in {
            "PERSON",
            "ORGANIZATION",
            "LOCATION",
            "PHONE",
            "EMAIL",
            "ID_NUMBER",
            "CREDIT_CARD",
            "SECRET",
        }
        assert isinstance(span.entity_group, str)
        assert isinstance(span.source_span, SourceSpan)
        assert 0 <= span.source_span.start_offset <= span.source_span.end_offset <= len(text)
        assert 0.0 <= span.confidence <= 1.0
        assert text[span.source_span.start_offset : span.source_span.end_offset] == span.original_text


def test_detector_contract_rule_based():
    detector: Detector = RuleBasedDetector()
    text = (
        "立約人：中央研究院與臺灣大學。聯絡人：王小明先生，"
        "電話：0912-345-678，信箱：ming.wang@gate.sinica.edu.tw，"
        "地址：臺北市南港區研究院路二段128號，身分證字號：A123456789。"
    )
    spans = detector.detect(text)
    assert len(spans) > 0
    _assert_valid_detected_spans(spans, text)


def test_detector_contract_pii_guard_adapter():
    adapter: Detector = PIIGuardAdapter()
    text = "專案聯絡人：林美麗專員，電話：0987-654-321，信箱：mei@test.org"
    spans = adapter.detect(text)
    assert len(spans) > 0
    _assert_valid_detected_spans(spans, text)


def test_detector_contract_pii_guard_adapter_mock_positive(monkeypatch):
    """模擬 pii_guard 模組已安裝並回傳偵測項目，驗證 PIIGuardAdapter 正確轉接為 DetectedSpan 物件。"""
    import sys
    from unittest.mock import MagicMock

    mock_module = MagicMock()
    text = "專案經理：林大華先生，聯絡電話：0912-345-678。"

    start_person = text.index("林大華")
    end_person = start_person + len("林大華")
    start_phone = text.index("0912-345-678")
    end_phone = start_phone + len("0912-345-678")

    # 模擬外部 pii_guard 庫回傳的偵測結果字典結構
    mock_module.detect.return_value = [
        {
            "type": "PERSON",
            "group": "PII",
            "start": start_person,
            "end": end_person,
            "text": "林大華",
            "score": 0.98,
        },
        {
            "type": "PHONE",
            "group": "CONTACT",
            "start": start_phone,
            "end": end_phone,
            "text": "0912-345-678",
            "score": 0.95,
        },
    ]

    monkeypatch.setitem(sys.modules, "pii_guard", mock_module)

    adapter = PIIGuardAdapter(enable_pii_guard=True)
    assert adapter.is_pii_guard_available() is True
    info = adapter.get_detector_info()
    assert info["engine"] == "pii-guard"
    assert info["fallback_active"] is False

    spans = adapter.detect(text)
    assert len(spans) == 2
    _assert_valid_detected_spans(spans, text)

    assert spans[0].span_type == "PERSON"
    assert spans[0].entity_group == "PII"
    assert spans[0].original_text == "林大華"
    assert spans[0].source_span.start_offset == start_person
    assert spans[0].source_span.end_offset == end_person
    assert spans[0].confidence == 0.98

    assert spans[1].span_type == "PHONE"
    assert spans[1].entity_group == "CONTACT"
    assert spans[1].original_text == "0912-345-678"
    assert spans[1].source_span.start_offset == start_phone
    assert spans[1].source_span.end_offset == end_phone
    assert spans[1].confidence == 0.95


def test_detector_contract_purely_offline(monkeypatch):
    # Ensure no network socket connections occur during detection
    def guarded_connect(*args, **kwargs):
        raise RuntimeError("Outbound network connection forbidden during masking detection!")

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)

    detector = RuleBasedDetector()
    adapter = PIIGuardAdapter()

    sample = (
        "專案負責人：陳經理，電話：0920-111-222，信箱：manager@company.com.tw，"
        "金鑰：api_key = 'sk-prod-1234567890abcdef1234567890'"
    )

    spans_rule = detector.detect(sample)
    spans_adapter = adapter.detect(sample)

    assert len(spans_rule) > 0
    assert len(spans_adapter) > 0


def test_synthetic_dataset_metrics_by_category():
    """已知合成資料各類偵測指標分開呈現，不以單一總分宣稱零漏失。"""
    # Ground truth test cases per category: (text, expected_type, expected_substr)
    dataset = [
        # PERSON
        ("會議由專案經理陳大文主持確認細節。", "PERSON", "陳大文"),
        ("聯絡人：林小華小姐負責系統維運。", "PERSON", "林小華"),
        ("代表簽署人王志明已確認條款內容。", "PERSON", "王志明"),
        # ORGANIZATION
        ("得標廠商為華碩電腦股份有限公司並提供保固。", "ORGANIZATION", "華碩電腦股份有限公司"),
        ("立契約人財團法人資訊工業策進會為受託單位。", "ORGANIZATION", "財團法人資訊工業策進會"),
        ("合作對象為中央研究院資訊科學研究所。", "ORGANIZATION", "中央研究院資訊科學研究所"),
        # LOCATION
        ("送達地址為臺北市南港區研究院路二段128號會議室。", "LOCATION", "臺北市南港區研究院路二段128號"),
        ("機房設於新北市板橋區縣民大道二段7號地下室。", "LOCATION", "新北市板橋區縣民大道二段7號"),
        # PHONE
        ("業務諮詢專線為 0912-345-678 請於上班時間撥打。", "PHONE", "0912-345-678"),
        ("市內電話代表號為 (02) 2789-8888 轉分機 123。", "PHONE", "(02) 2789-8888"),
        # EMAIL
        ("請寄送驗收文件至 legal.review@sinica.edu.tw 存查。", "EMAIL", "legal.review@sinica.edu.tw"),
        ("技術支援客服信箱為 support@vendor-service.com.tw 洽詢。", "EMAIL", "support@vendor-service.com.tw"),
        # ID_NUMBER
        ("承辦人身分證號：A123456789 供保險核對。", "ID_NUMBER", "A123456789"),
        ("公司統一編號為 03795153 登記在案。", "ID_NUMBER", "03795153"),
        # SECRET
        ("雲端設定：api_key = 'sk-test-abcdef1234567890abcdef12345678' 切勿外傳。", "SECRET", "sk-test-abcdef1234567890abcdef12345678"),
        ("金鑰：AKIAIOSFODNN7EXAMPLE 具完整權限。", "SECRET", "AKIAIOSFODNN7EXAMPLE"),
    ]

    detector = RuleBasedDetector()

    # Track metrics per category
    category_stats: dict[str, dict[str, int]] = {
        cat: {"tp": 0, "fn": 0, "fp": 0}
        for cat in [
            "PERSON",
            "ORGANIZATION",
            "LOCATION",
            "PHONE",
            "EMAIL",
            "ID_NUMBER",
            "SECRET",
        ]
    }

    for text, expected_type, expected_substr in dataset:
        spans = detector.detect(text)
        found = False
        for s in spans:
            if s.span_type == expected_type and expected_substr in s.original_text:
                category_stats[expected_type]["tp"] += 1
                found = True
                break
        if not found:
            category_stats[expected_type]["fn"] += 1

    # Verify per-category recall
    print("\n=== Synthetic PII Detection Category Metrics ===")
    for cat, stats in category_stats.items():
        tp = stats["tp"]
        fn = stats["fn"]
        total = tp + fn
        recall = tp / total if total > 0 else 0.0
        print(f"Category: {cat:15s} | TP: {tp} | FN: {fn} | Recall: {recall:.2%}")
        assert recall >= 0.8, f"Category {cat} recall {recall:.2%} must be at least 80%!"


def test_pii_guard_real_gate_and_fallback():
    adapter = PIIGuardAdapter()
    info = adapter.get_detector_info()
    assert isinstance(info, dict)
    assert "engine" in info
    assert "version" in info
    assert "offline" in info
    assert info["offline"] is True

    # Even without pii-guard installed, detection continues reliably via fallback
    spans = adapter.detect("專案經理陳大文電話 0912-345-678")
    assert len(spans) >= 2
