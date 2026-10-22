import uuid

import pytest

from procurement_review.domain.enums import ResultEnum, RiskLevel, SourceNature
from procurement_review.domain.models import Finding
from procurement_review.evaluation.metrics import (
    evaluate,
)


def make_finding(
    requirement_id: str,
    clause_ids: list[str],
    result: ResultEnum = ResultEnum.COMPLIANT,
    risk: RiskLevel = RiskLevel.LOW,
    citations: list[str] | None = None,
    review_scope: str | None = None,
    finding_id: str | None = None,
    run_id: str | None = None,
) -> Finding:
    return Finding(
        finding_id=finding_id or str(uuid.uuid4()),
        run_id=run_id or str(uuid.uuid4()),
        clause_ids=clause_ids,
        requirement_id=requirement_id,
        result=result,
        risk=risk,
        evidence=[],
        rule_refs=[],
        case_refs=[],
        reason="測試理由說明",
        unknowns=[],
        conclusion_nature=[SourceNature.APPLICABLE_LAW],
        citations=citations or [],
        review_scope=review_scope,
    )


def test_alignment_by_requirement_and_clause_not_index_or_id():
    """驗證比對依據 (requirement_id, tuple(sorted(clause_ids)))，不依賴 finding_id 或列表順序。"""
    # 建立順序相反、且 finding_id 不同的兩組 findings
    exp1 = make_finding(
        requirement_id="REQ-01",
        clause_ids=["c2", "c1"],  # 排序後為 ('c1', 'c2')
        result=ResultEnum.COMPLIANT,
    )
    exp2 = make_finding(
        requirement_id="REQ-02",
        clause_ids=["c3"],
        result=ResultEnum.CONCERN,
    )

    act1 = make_finding(
        requirement_id="REQ-02",
        clause_ids=["c3"],
        result=ResultEnum.CONCERN,
    )
    act2 = make_finding(
        requirement_id="REQ-01",
        clause_ids=["c1", "c2"],  # 排序後相同
        result=ResultEnum.COMPLIANT,
    )

    # 傳入順序不同
    report = evaluate(expected=[exp1, exp2], actual=[act1, act2])

    assert report.total_expected == 2
    assert report.total_actual == 2
    assert report.aligned_pairs == 2
    assert report.tp == 2
    assert report.fp == 0
    assert report.fn == 0
    assert report.precision == 1.0
    assert report.recall == 1.0


def test_tp_fp_fn_calculation():
    """以人工可算小樣本驗證 TP、FP、FN 及各類率值。"""
    # Expected:
    # 1. REQ-1 [c1] -> compliant
    # 2. REQ-2 [c2] -> concern
    # 3. REQ-3 [c3] -> missing
    exp1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    exp2 = make_finding("REQ-2", ["c2"], result=ResultEnum.CONCERN)
    exp3 = make_finding("REQ-3", ["c3"], result=ResultEnum.MISSING)

    # Actual:
    # 1. REQ-1 [c1] -> compliant (TP)
    # 2. REQ-2 [c2] -> compliant (Mismatch: expected concern, got compliant -> not TP)
    # 3. REQ-4 [c4] -> concern (Spurious finding -> FP)
    # (REQ-3 [c3] is omitted in actual -> FN)
    act1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    act2 = make_finding("REQ-2", ["c2"], result=ResultEnum.COMPLIANT)
    act3 = make_finding("REQ-4", ["c4"], result=ResultEnum.CONCERN)

    report = evaluate(expected=[exp1, exp2, exp3], actual=[act1, act2, act3])

    assert report.total_expected == 3
    assert report.total_actual == 3
    assert report.tp == 1  # 僅 REQ-1 吻合
    # REQ-2 預期 concern 但預測 compliant: mismatch
    # REQ-4 為多餘 actual: FP
    # REQ-3 為遺漏 expected: FN
    assert report.unmatched_expected == 1  # REQ-3
    assert report.unmatched_actual == 1    # REQ-4
    # fp = unmatched_actual (1) + misclassified actuals (1) = 2
    assert report.fp == 2
    # fn = unmatched_expected (1) + misclassified expected (1) = 2
    assert report.fn == 2
    assert report.precision == pytest.approx(1 / 3)
    assert report.recall == pytest.approx(1 / 3)
    assert report.omission_rate == pytest.approx(1 / 3)


def test_per_pack_denominators():
    """驗證四包（software_maintenance, custom_software, cloud_service, mixed）各自分母與指標。"""
    exp_sm = make_finding("REQ-SM", ["c1"], result=ResultEnum.COMPLIANT, review_scope="software_maintenance")
    act_sm = make_finding("REQ-SM", ["c1"], result=ResultEnum.COMPLIANT, review_scope="software_maintenance")

    exp_dev = make_finding("REQ-DEV", ["c2"], result=ResultEnum.CONCERN, review_scope="custom_software")
    act_dev = make_finding("REQ-DEV", ["c2"], result=ResultEnum.CONCERN, review_scope="custom_software")

    report = evaluate(
        expected=[exp_sm, exp_dev],
        actual=[act_sm, act_dev],
    )

    packs = report.per_pack_metrics
    assert "software_maintenance" in packs
    assert "custom_software" in packs
    assert "cloud_service" in packs
    assert "mixed" in packs

    assert packs["software_maintenance"]["total_expected"] == 1
    assert packs["software_maintenance"]["tp"] == 1
    assert packs["software_maintenance"]["precision"] == 1.0

    assert packs["custom_software"]["total_expected"] == 1
    assert packs["custom_software"]["tp"] == 1

    # cloud_service 與 mixed 無樣本，分母為 0，其 precision/recall 應為 None / N/A
    assert packs["cloud_service"]["total_expected"] == 0
    assert packs["cloud_service"]["precision"] is None
    assert packs["mixed"]["total_expected"] == 0
    assert packs["mixed"]["recall"] is None


def test_deduplication_of_overlapping_labels():
    """驗證重疊標籤或重複 finding 自動去重，不虛胖分母。"""
    f1 = make_finding("REQ-01", ["c1", "c2"], result=ResultEnum.COMPLIANT)
    f1_dup = make_finding("REQ-01", ["c2", "c1"], result=ResultEnum.COMPLIANT)

    report = evaluate(expected=[f1, f1_dup], actual=[f1])
    assert report.total_expected == 1  # 去重後為 1
    assert report.total_actual == 1
    assert report.tp == 1


def test_zero_denominator_handling():
    """驗證空樣本或分母為零時不拋出例外，precision/recall 回傳 None。"""
    report = evaluate(expected=[], actual=[])
    assert report.total_expected == 0
    assert report.total_actual == 0
    assert report.precision is None
    assert report.recall is None
    assert report.f1 is None
    assert report.omission_rate is None


def test_high_risk_false_compliant_detection():
    """驗證高風險誤判符合 (high-risk false compliant) 能被精確偵測且不被平均分掩蓋。"""
    # 預期為 high-risk CONCERN，但實際預測為 COMPLIANT
    exp_high = make_finding(
        requirement_id="REQ-SEC-CRIT",
        clause_ids=["c1"],
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
    )
    act_high = make_finding(
        requirement_id="REQ-SEC-CRIT",
        clause_ids=["c1"],
        result=ResultEnum.COMPLIANT,  # 致命誤判
        risk=RiskLevel.HIGH,
    )

    report = evaluate(expected=[exp_high], actual=[act_high])
    assert report.high_risk_false_compliant_count == 1
    assert report.safety_violations["high_risk_false_compliant"] == 1


def test_all_abstentions_detection():
    """驗證全棄答 (all abstentions / needs_confirmation) 能被精確檢測。"""
    exp1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    exp2 = make_finding("REQ-2", ["c2"], result=ResultEnum.CONCERN)

    # 實際輸出均為 needs_confirmation，無實質判斷
    act1 = make_finding("REQ-1", ["c1"], result=ResultEnum.NEEDS_CONFIRMATION)
    act2 = make_finding("REQ-2", ["c2"], result=ResultEnum.NEEDS_CONFIRMATION)

    report = evaluate(expected=[exp1, exp2], actual=[act1, act2])
    assert report.all_abstentions is True
    assert report.needs_confirmation_rate == 1.0


def test_masking_metrics_and_leakage():
    """驗證各類遮罩 precision/recall 與機敏外洩殘留量統計。"""
    artifacts = {
        "masking": {
            "total_entities": 10,
            "masked_entities": 9,
            "leakage_count": 1,
            "categories": {
                "vendor_name": {"tp": 4, "fp": 0, "fn": 0},
                "personal_id": {"tp": 5, "fp": 1, "fn": 1},
            },
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    assert report.masking_metrics["leakage_count"] == 1
    assert report.safety_violations["masking_leakage"] == 1
    assert "personal_id" in report.masking_metrics["per_category"]


def test_citation_validity_and_hallucination():
    """驗證引用存在性、人工支持率與捏造引用偵測。"""
    artifacts = {
        "citations": {
            "total_citations": 4,
            "valid_citations": 3,
            "supported_citations": 3,
            "hallucinated_citations": ["NON_EXISTENT_ARTICLE_999"],
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    assert report.citation_metrics["hallucinated_citations_count"] == 1
    assert report.citation_metrics["validity_rate"] == 0.75
    assert report.safety_violations["hallucinated_citations"] == 1


def test_roundtrip_fidelity_and_cross_case_swaps():
    """驗證還原完整度與跨案錯換偵測。"""
    artifacts = {
        "roundtrip": {
            "fidelity_rate": 0.98,
            "mismatches": 1,
            "cross_case_swaps": 1,
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    assert report.roundtrip_metrics["fidelity_rate"] == 0.98
    assert report.safety_violations["cross_case_swaps"] == 1


def test_draft_adoption_and_rewrites():
    """驗證草稿採用率、修改率統計。"""
    artifacts = {
        "drafts": {
            "total_drafts": 10,
            "adopted": 7,
            "modified": 2,
            "rejected": 1,
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    assert report.draft_metrics["adoption_rate"] == 0.7
    assert report.draft_metrics["rewrite_rate"] == 0.2


def test_human_time_and_cost():
    """驗證人工複核工時與成本統計。"""
    artifacts = {
        "human_effort": {
            "minutes": 45.0,
            "cost": 450.0,
            "cases_evaluated": 2,
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    assert report.human_effort["minutes_per_case"] == 22.5
    assert report.human_effort["cost_per_case"] == 225.0


def test_confusion_matrix():
    """驗證混淆矩陣 mapping 正確。"""
    exp1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    act1 = make_finding("REQ-1", ["c1"], result=ResultEnum.CONCERN)

    report = evaluate(expected=[exp1], actual=[act1])
    matrix = report.confusion_matrix
    assert matrix["compliant"]["concern"] == 1
