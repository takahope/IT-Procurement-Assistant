import uuid

from procurement_review.documents.structure import Clause, DocumentBlock, DocumentSnapshot
from procurement_review.domain.enums import (
    ApplicabilityState,
    ResultEnum,
    RiskLevel,
    SourceNature,
)
from procurement_review.domain.models import (
    ApplicabilityDecision,
    Finding,
    VersionRef,
)
from procurement_review.review.coverage import build_coverage, get_coverage_summary


def make_test_decision(
    requirement_id: str | None = None,
    version: str = "1.0",
    state: ApplicabilityState = ApplicabilityState.APPLICABLE,
) -> ApplicabilityDecision:
    req_id = requirement_id or str(uuid.uuid4())
    return ApplicabilityDecision(
        requirement_ref=VersionRef(id=req_id, version=version, sha256="abc" * 21 + "a"),
        state=state,
        reasons=["依據採購標的與事實適用"],
    )


def make_test_finding(
    requirement_id: str,
    clause_ids: list[str],
    run_id: str,
    result: ResultEnum = ResultEnum.COMPLIANT,
) -> Finding:
    return Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=clause_ids,
        requirement_id=requirement_id,
        result=result,
        risk=RiskLevel.LOW,
        evidence=[],
        rule_refs=[],
        case_refs=[],
        reason="條款檢核結果",
        unknowns=[],
        conclusion_nature=[SourceNature.APPLICABLE_LAW],
    )


def make_test_doc_with_clauses(clauses: list[Clause]) -> DocumentSnapshot:
    doc_id = str(uuid.uuid4())
    blocks = [
        DocumentBlock(
            block_id=c.block_ids[0] if c.block_ids else f"b-{i}",
            block_type="paragraph",
            raw_text=c.text,
            page_number=1,
            structural_path=c.clause_number or "",
        )
        for i, c in enumerate(clauses)
    ]
    return DocumentSnapshot(
        document_id=doc_id,
        snapshot_id=str(uuid.uuid4()),
        original_filename="contract.docx",
        content_sha256="hash123",
        blocks=blocks,
        clauses=clauses,
        issues=[],
        manifest={"document_type": "main_contract"},
        confirmation_ref=VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="hash"),
    )


def test_build_coverage_dual_tables():
    """核心斷言：

    1. requirements 表以 requirement_id 為 key，全量包含所有 decisions：
       assert set(matrix.requirements) == {d.requirement_ref.id for d in decisions}
    2. clauses 表以 clause_id 為 key，包含合約所有條款。
    """
    c1 = Clause(clause_id="c-1", clause_number="第一條", title="總則", text="第一條 總則", block_ids=["b-1"])
    c2 = Clause(clause_id="c-2", clause_number="第二條", title="保密", text="第二條 保密", block_ids=["b-2"])
    c3 = Clause(clause_id="c-3", clause_number="第三條", title="附則", text="第三條 附則", block_ids=["b-3"])
    doc = make_test_doc_with_clauses([c1, c2, c3])

    d1 = make_test_decision()
    d2 = make_test_decision()
    decisions = [d1, d2]

    run_id = str(uuid.uuid4())
    f1 = make_test_finding(requirement_id=d1.requirement_ref.id, clause_ids=["c-2"], run_id=run_id)
    findings = [f1]

    matrix = build_coverage([doc], decisions, findings, run_id=run_id)

    # 核心斷言：requirements 表包含所有決策對應之 requirement ID
    assert set(matrix.requirements) == {d.requirement_ref.id for d in decisions}
    # 核心斷言：clauses 表包含所有文件條款
    assert set(matrix.clauses) == {"c-1", "c-2", "c-3"}


def test_build_coverage_uncovered_clauses():
    """無相關規則或發現之條款顯示 uncovered。"""
    c1 = Clause(clause_id="c-1", clause_number="第一條", title="總則", text="第一條 總則", block_ids=["b-1"])
    c2 = Clause(clause_id="c-2", clause_number="第二條", title="未涉資安條款", text="第二條 純行政流程", block_ids=["b-2"])
    doc = make_test_doc_with_clauses([c1, c2])

    d1 = make_test_decision()
    run_id = str(uuid.uuid4())
    f1 = make_test_finding(requirement_id=d1.requirement_ref.id, clause_ids=["c-1"], run_id=run_id)

    matrix = build_coverage([doc], [d1], [f1], run_id=run_id)

    assert matrix.clauses["c-1"].status == "covered"
    assert matrix.clauses["c-2"].status == "uncovered"


def test_build_coverage_unprocessed_empty_with_unresolved_coexistence():
    """核心斷言：

    所有條款均已完成審查掃描（unprocessed_ids 為空），
    但存在待確認或未解決之要求（unresolved_ids 非空），兩者可同時成立。
    """
    c1 = Clause(clause_id="c-1", clause_number="第一條", title="資安稽核", text="第一條 資安稽核", block_ids=["b-1"])
    doc = make_test_doc_with_clauses([c1])

    # d1 已解決 (compliant)
    d1 = make_test_decision()
    # d2 為未知或待確認狀態 (unknown)
    d2 = make_test_decision(state=ApplicabilityState.UNKNOWN)

    run_id = str(uuid.uuid4())
    f1 = make_test_finding(requirement_id=d1.requirement_ref.id, clause_ids=["c-1"], run_id=run_id)

    matrix = build_coverage([doc], [d1, d2], [f1], run_id=run_id)

    # unprocessed_ids（未處理條款）為空
    assert matrix.unprocessed_ids == []
    assert matrix.unprocessed_clause_ids == []

    # unresolved_ids（未解決要求）非空，包含 d2 的 requirement_id
    assert len(matrix.unresolved_ids) > 0
    assert d2.requirement_ref.id in matrix.unresolved_ids


def test_build_coverage_entry_version_result_processing_access():
    """驗證 matrix requirements 與 clauses 項目值支援 version、processing、result 屬性與鍵值存取。"""
    c1 = Clause(clause_id="c-1", clause_number="第一條", title="保密", text="第一條 保密條款", block_ids=["b-1"])
    doc = make_test_doc_with_clauses([c1])

    d1 = make_test_decision(version="2.1")
    run_id = str(uuid.uuid4())
    f1 = make_test_finding(
        requirement_id=d1.requirement_ref.id,
        clause_ids=["c-1"],
        run_id=run_id,
        result=ResultEnum.COMPLIANT,
    )

    matrix = build_coverage([doc], [d1], [f1], run_id=run_id)

    req_entry = matrix.requirements[d1.requirement_ref.id]
    assert req_entry.version == "2.1"
    assert req_entry.result == "compliant"
    assert req_entry.status in ("covered", "compliant")
    assert req_entry["version"] == "2.1"
    assert req_entry["result"] == "compliant"

    clause_entry = matrix.clauses["c-1"]
    assert clause_entry.status == "covered"
    assert clause_entry.result == "compliant"
    assert clause_entry["result"] == "compliant"


def test_build_coverage_summary_separates_processing_rate_and_unresolved():
    """報告須分開呈現處理率與未解決數。"""
    c1 = Clause(clause_id="c-1", clause_number="第一條", title="條款一", text="條款一", block_ids=["b-1"])
    c2 = Clause(clause_id="c-2", clause_number="第二條", title="條款二", text="條款二", block_ids=["b-2"])
    doc = make_test_doc_with_clauses([c1, c2])

    d1 = make_test_decision()
    d2 = make_test_decision(state=ApplicabilityState.UNKNOWN)

    run_id = str(uuid.uuid4())
    f1 = make_test_finding(requirement_id=d1.requirement_ref.id, clause_ids=["c-1"], run_id=run_id)

    matrix = build_coverage([doc], [d1, d2], [f1], run_id=run_id)
    summary = get_coverage_summary(matrix)

    assert "clause_processing_rate" in summary
    assert "unprocessed_clause_count" in summary
    assert "unresolved_requirement_count" in summary
    assert summary["unprocessed_clause_count"] == 0
    assert summary["unresolved_requirement_count"] == 1
    assert summary["clause_processing_rate"] == 1.0  # 兩條款均已掃描
