import uuid

from procurement_review.documents.structure import SourceSpan
from procurement_review.domain.enums import ResultEnum, RiskLevel, SourceNature
from procurement_review.domain.models import (
    ContextBundle,
    Finding,
    GateReport,
    ValidationReport,
    VersionRef,
)
from procurement_review.review.validation import (
    detect_cross_document_conflicts,
    validate_findings,
    validate_provider_response_json,
)


def make_test_span(
    doc_id: str,
    block_id: str | None = None,
    start: int = 0,
    end: int = 50,
    text: str = "第十條 保密義務：廠商對於機密資訊應採取嚴密資安防護措施。",
) -> SourceSpan:
    b_id = block_id or str(uuid.uuid4())
    return SourceSpan(
        document_id=doc_id,
        block_id=b_id,
        start_offset=start,
        end_offset=end,
        page_number=1,
        structural_path="第十條",
    )


def make_test_context(
    req_id: str,
    req_version: str = "1.0",
    rule_id: str | None = None,
    rule_version: str = "1.0",
    spans: list[SourceSpan] | None = None,
    citations: list[str] | None = None,
    doc_status: dict[str, str] | None = None,
    complete: bool = True,
) -> ContextBundle:
    req_ref = VersionRef(id=req_id, version=req_version, sha256="abc" * 21 + "a")
    return ContextBundle(
        requirement_ref=req_ref,
        source_spans=spans or [],
        definitions={},
        exceptions=[],
        citations=citations or [],
        document_retrieval_status=doc_status or {"doc1.docx": "retrieved"},
        complete=complete,
        unknowns=[],
    )


def make_test_finding(
    finding_id: str | None = None,
    run_id: str | None = None,
    requirement_id: str | None = None,
    clause_ids: list[str] | None = None,
    result: ResultEnum = ResultEnum.COMPLIANT,
    risk: RiskLevel = RiskLevel.MEDIUM,
    reason: str = "廠商合約第十條符合保密要求",
    evidence: list[SourceSpan] | None = None,
    rule_refs: list[VersionRef] | None = None,
    review_scope: str | None = None,
    human_status: str = "pending",
) -> Finding:
    f_id = finding_id or str(uuid.uuid4())
    r_id = run_id or str(uuid.uuid4())
    rq_id = requirement_id or str(uuid.uuid4())
    return Finding(
        finding_id=f_id,
        run_id=r_id,
        clause_ids=clause_ids or ["c-10"],
        requirement_id=rq_id,
        result=result,
        risk=risk,
        evidence=evidence or [],
        rule_refs=rule_refs or [],
        case_refs=[],
        reason=reason,
        unknowns=[],
        suggested_action=None,
        suggested_clause=None,
        validation_status="pending",
        human_status=human_status,
        conclusion_nature=[SourceNature.APPLICABLE_LAW],
        review_scope=review_scope,
    )


def test_structure_validation_success():
    """結構校驗：正常欄位與列舉值應順利通過。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    finding = make_test_finding(run_id=run_id, requirement_id=req_id)
    ctx = make_test_context(req_id=req_id)

    report = validate_findings([finding], [ctx])
    assert isinstance(report, ValidationReport)
    assert report.structure_ok is True
    assert isinstance(report.structure, GateReport)
    assert report.structure.ok is True


def test_structure_validation_empty_reason():
    """結構校驗：推理理由空白或純空白應被拒絕。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    finding = make_test_finding(run_id=run_id, requirement_id=req_id, reason="   ")
    ctx = make_test_context(req_id=req_id)

    report = validate_findings([finding], [ctx])
    assert report.structure_ok is False
    assert report.structure.ok is False
    assert any("[structure]" in issue for issue in report.issues)


def test_source_validation_non_existent_clause():
    """來源校驗：引用不存在之條款 ID 應校驗失敗。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    finding = make_test_finding(
        run_id=run_id,
        requirement_id=req_id,
        clause_ids=["c-nonexistent-999"],
    )
    # Context 僅包含 c-10
    span = make_test_span(doc_id=str(uuid.uuid4()))
    ctx = make_test_context(req_id=req_id, spans=[span])

    report = validate_findings([finding], [ctx])
    assert report.source_ok is False
    assert report.source.ok is False
    assert any("c-nonexistent-999" in issue for issue in report.issues)


def test_source_validation_rule_version_mismatch():
    """來源校驗：規則或要求版本不合應校驗失敗。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    rule_id = str(uuid.uuid4())

    ctx = make_test_context(req_id=req_id, req_version="1.0", rule_id=rule_id, rule_version="1.0")

    # Finding 附帶錯誤的 rule 版本 2.0
    finding = make_test_finding(
        run_id=run_id,
        requirement_id=req_id,
        rule_refs=[VersionRef(id=rule_id, version="2.0", sha256="wrong" * 12 + "abcd")],
    )

    report = validate_findings([finding], [ctx])
    assert report.source_ok is False
    assert any("version mismatch" in issue.lower() for issue in report.issues)


def test_source_validation_unconfirmed_source():
    """來源校驗：引用未確認來源文件應標記失敗。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    doc_id = str(uuid.uuid4())
    span = make_test_span(doc_id=doc_id)

    ctx = make_test_context(
        req_id=req_id,
        spans=[span],
        doc_status={"contract.docx": "unconfirmed"},
        complete=False,
    )
    finding = make_test_finding(run_id=run_id, requirement_id=req_id, evidence=[span])

    report = validate_findings([finding], [ctx])
    assert report.source_ok is False
    assert any("unconfirmed" in issue.lower() for issue in report.issues)


def test_substance_validation_remains_pending():
    """實質校驗：有效引用仍保持 human_status == 'pending'，不自動判定通過。"""
    run_id = str(uuid.uuid4())
    req_id = str(uuid.uuid4())
    doc_id = str(uuid.uuid4())
    span = make_test_span(doc_id=doc_id)

    ctx = make_test_context(req_id=req_id, spans=[span])
    finding = make_test_finding(
        run_id=run_id,
        requirement_id=req_id,
        evidence=[span],
        human_status="pending",
    )

    report = validate_findings([finding], [ctx])
    assert report.structure_ok is True
    assert report.source_ok is True
    # 人工實質審查必須維持 pending
    assert finding.human_status == "pending"
    assert report.substance_ok is True


def test_detect_cross_document_conflicts():
    """跨文件衝突：多文件對同一要求產生歧異時，保留兩側引用並建立待確認請求。"""
    req_id = str(uuid.uuid4())
    doc1_id = str(uuid.uuid4())
    doc2_id = str(uuid.uuid4())

    span1 = make_test_span(doc_id=doc1_id, text="主合約：不可委外複委託")
    span2 = make_test_span(doc_id=doc2_id, text="SLA 服務條款：得視需要複委託第三人")

    conflict = detect_cross_document_conflicts(
        requirement_id=req_id,
        spans=[span1, span2],
        statements=["不可委外複委託", "得視需要複委託第三人"],
    )

    assert conflict is not None
    assert conflict["requirement_id"] == req_id
    assert len(conflict["conflicting_spans"]) == 2
    assert conflict["status"] == "needs_approval"


def test_validate_provider_response_json():
    """驗證供應商回應 JSON 格式檢查函式。"""
    valid_payload = {
        "findings": [
            {
                "requirement_id": str(uuid.uuid4()),
                "clause_ids": ["c-1"],
                "result": "compliant",
                "risk": "low",
                "reason": "合約第一條符合規範",
            }
        ]
    }
    is_valid, errors = validate_provider_response_json(valid_payload)
    assert is_valid is True
    assert len(errors) == 0

    invalid_payload = {
        "findings": [
            {
                "requirement_id": str(uuid.uuid4()),
                "result": "invalid_enum_status",
                "risk": "low",
                "reason": "合約第一條符合規範",
            }
        ]
    }
    is_valid, errors = validate_provider_response_json(invalid_payload)
    assert is_valid is False
    assert len(errors) > 0
