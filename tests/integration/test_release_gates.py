import json
import uuid
from pathlib import Path

import pytest

from procurement_review.domain.enums import ResultEnum, RiskLevel, SourceNature
from procurement_review.domain.models import Finding
from procurement_review.evaluation.metrics import (
    check_release,
    evaluate,
)
from procurement_review.evaluation.runner import run_evaluation


def make_finding(
    requirement_id: str,
    clause_ids: list[str],
    result: ResultEnum = ResultEnum.COMPLIANT,
    risk: RiskLevel = RiskLevel.LOW,
    citations: list[str] | None = None,
    review_scope: str | None = None,
) -> Finding:
    return Finding(
        finding_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
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


@pytest.fixture
def approved_policy() -> dict:
    return {
        "policy_id": "policy-m3-test",
        "approved": True,
        "approver": "資安長",
        "zero_tolerance": {
            "max_high_risk_false_compliant": 0,
            "max_hallucinated_citations": 0,
            "max_masking_leakage": 0,
            "max_unauthorized_egress": 0,
            "max_unauthorized_alterations": 0,
            "max_cross_case_swaps": 0,
            "allow_all_abstentions": False,
        },
        "thresholds": {
            "min_extraction_accuracy": 0.90,
            "min_masking_precision": 0.90,
            "min_roundtrip_fidelity": 1.0,
            "min_draft_adoption_rate": 0.60,
            "max_human_minutes_per_case": 30.0,
            "max_needs_confirmation_rate": 0.40,
        },
    }


def test_all_abstentions_cannot_pass_release(approved_policy):
    """驗證全棄答（所有條款皆待確認）絕不能通過發布關卡。"""
    exp = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    act = make_finding("REQ-1", ["c1"], result=ResultEnum.NEEDS_CONFIRMATION)

    all_abstention_report = evaluate(expected=[exp], actual=[act])
    assert all_abstention_report.all_abstentions is True

    gate = check_release(all_abstention_report, approved_policy)
    assert not gate.ok
    assert any("abstention" in f.lower() or "全棄答" in f for f in gate.failures)


def test_one_high_risk_false_compliant_cannot_pass_release(approved_policy):
    """驗證只要有 1 項高風險誤判符合，即刻拒絕發布，不被其他高分掩蓋。"""
    exp1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT, risk=RiskLevel.LOW)
    act1 = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT, risk=RiskLevel.LOW)

    # 1 項高風險瑕疵：預期 CONCERN，實際卻判 COMPLIANT
    exp2 = make_finding("REQ-2", ["c2"], result=ResultEnum.CONCERN, risk=RiskLevel.HIGH)
    act2 = make_finding("REQ-2", ["c2"], result=ResultEnum.COMPLIANT, risk=RiskLevel.HIGH)

    one_high_risk_false_compliant = evaluate(expected=[exp1, exp2], actual=[act1, act2])
    assert one_high_risk_false_compliant.high_risk_false_compliant_count == 1

    gate = check_release(one_high_risk_false_compliant, approved_policy)
    assert not gate.ok
    assert any("high-risk" in f.lower() or "高風險" in f for f in gate.failures)


def test_hallucinated_citations_cannot_pass_release(approved_policy):
    """驗證捏造或不存在的引用，直接觸發零容忍紅線。"""
    artifacts = {
        "citations": {
            "total_citations": 1,
            "valid_citations": 0,
            "supported_citations": 0,
            "hallucinated_citations": ["ARTICLE_HALLUCINATED_999"],
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    gate = check_release(report, approved_policy)
    assert not gate.ok
    assert any("citation" in f.lower() or "引用" in f for f in gate.failures)


def test_masking_leakage_cannot_pass_release(approved_policy):
    """驗證遮罩殘留或洩漏，直接觸發零容忍紅線。"""
    artifacts = {
        "masking": {
            "total_entities": 5,
            "masked_entities": 4,
            "leakage_count": 1,
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    gate = check_release(report, approved_policy)
    assert not gate.ok
    assert any("leakage" in f.lower() or "遮罩" in f or "外洩" in f for f in gate.failures)


def test_unauthorized_egress_or_change_cannot_pass_release(approved_policy):
    """驗證未授權出站或無據改動受保護內容，拒絕發布。"""
    artifacts = {
        "safety": {
            "unauthorized_egress_count": 1,
            "unauthorized_alterations_count": 0,
        }
    }
    report = evaluate(expected=[], actual=[], artifacts=artifacts)
    gate = check_release(report, approved_policy)
    assert not gate.ok
    assert any("egress" in f.lower() or "出站" in f for f in gate.failures)

    artifacts_alter = {
        "safety": {
            "unauthorized_egress_count": 0,
            "unauthorized_alterations_count": 1,
        }
    }
    report_alter = evaluate(expected=[], actual=[], artifacts=artifacts_alter)
    gate_alter = check_release(report_alter, approved_policy)
    assert not gate_alter.ok
    assert any("alteration" in f.lower() or "改動" in f for f in gate_alter.failures)


def test_unapproved_policy_or_missing_thresholds_cannot_default_to_pass():
    """驗證政策未經正式核准、或未設定人工接受率／工時門檻時，顯示未核准，絕不能默認 PASS。"""
    clean_report = evaluate(
        expected=[make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)],
        actual=[make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)],
        artifacts={
            "drafts": {"total_drafts": 1, "adopted": 1, "modified": 0, "rejected": 0},
            "human_effort": {"minutes": 10.0, "cost": 100.0, "cases_evaluated": 1},
        },
    )

    # 1. approved 為 False
    unapproved_policy = {
        "approved": False,
        "thresholds": {"min_draft_adoption_rate": 0.5, "max_human_minutes_per_case": 30.0},
    }
    gate1 = check_release(clean_report, unapproved_policy)
    assert not gate1.ok
    assert gate1.status == "unapproved"

    # 2. 缺少人工接受率門檻
    missing_draft_threshold = {
        "approved": True,
        "thresholds": {"max_human_minutes_per_case": 30.0},
    }
    gate2 = check_release(clean_report, missing_draft_threshold)
    assert not gate2.ok
    assert gate2.status == "unapproved"

    # 3. 缺少工時門檻
    missing_time_threshold = {
        "approved": True,
        "thresholds": {"min_draft_adoption_rate": 0.5},
    }
    gate3 = check_release(clean_report, missing_time_threshold)
    assert not gate3.ok
    assert gate3.status == "unapproved"


def test_clean_report_passes_release(approved_policy):
    """驗證完全符合標準且具備核准門檻之報告順利通過發布關卡。"""
    exp = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    act = make_finding("REQ-1", ["c1"], result=ResultEnum.COMPLIANT)
    artifacts = {
        "drafts": {"total_drafts": 1, "adopted": 1, "modified": 0, "rejected": 0},
        "human_effort": {"minutes": 10.0, "cost": 100.0, "cases_evaluated": 1},
        "citations": {"total_citations": 1, "valid_citations": 1, "supported_citations": 1, "hallucinated_citations": []},
        "masking": {"total_entities": 2, "masked_entities": 2, "leakage_count": 0},
        "roundtrip": {"fidelity_rate": 1.0, "mismatches": 0, "cross_case_swaps": 0},
        "safety": {"unauthorized_egress_count": 0, "unauthorized_alterations_count": 0},
    }
    report = evaluate(expected=[exp], actual=[act], artifacts=artifacts)
    gate = check_release(report, approved_policy)
    assert gate.ok
    assert gate.status == "passed"
    assert len(gate.failures) == 0


def test_cli_evaluate_end_to_end(tmp_path: Path):
    """驗證 runner 與 manifest 整合執行並輸出標準格式報告。"""
    manifest_path = Path("evaluations/synthetic-manifest.json")
    policy_path = Path("evaluations/acceptance-policy.example.json")
    output_path = tmp_path / "evaluation_report.json"

    result = run_evaluation(
        manifest_path=manifest_path,
        output_path=output_path,
        policy_path=policy_path,
    )

    assert output_path.exists()
    payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert "evaluation_report" in payload
    assert "gate_report" in payload
    assert payload["gate_report"]["ok"] is True
    assert result["gate_report"]["ok"] is True
