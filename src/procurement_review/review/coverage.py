"""Dual-Table Coverage Matrix Builder for Procurement Review.

同時追蹤契約條款（Clauses）與適用資安要求（Requirements）之雙表覆蓋，
明確區分未處理（unprocessed_ids）與待確認／未解決（unresolved_ids），
確保報告能分開呈現處理率與未解決數。
"""

import json
import uuid
from typing import Any

from procurement_review.documents.structure import DocumentSnapshot
from procurement_review.domain.enums import ApplicabilityState, ResultEnum
from procurement_review.domain.models import (
    ApplicabilityDecision,
    CoverageEntry,
    CoverageMatrix,
    Finding,
)


def build_coverage(
    documents: list[DocumentSnapshot],
    decisions: list[ApplicabilityDecision],
    findings: list[Finding],
    run_id: str | None = None,
) -> CoverageMatrix:
    """建構全份覆蓋雙表矩陣 (CoverageMatrix)

    1. requirements 表：以 requirement_id 為 key，全量覆蓋所有 decisions。
       值包含版本、處理狀態 (processing) 與結果 (result)。
    2. clauses 表：以 clause_id 為 key，涵蓋文件快照中所有條款。
       無相關規則或發現之條款明確標示為 status="uncovered"。
    3. 分離 unprocessed_ids（工作流程未處理）與 unresolved_ids（已處理但待確認或上下文不全）。
    """
    matrix_run_id = (
        run_id
        if run_id
        else (str(findings[0].run_id) if findings else str(uuid.uuid4()))
    )

    requirement_entries: list[CoverageEntry] = []
    unresolved_requirement_ids: list[str] = []

    # 1. 建構要求覆蓋項目 (Requirements Table)
    for dec in decisions:
        req_id = str(dec.requirement_ref.id)
        req_ver = str(dec.requirement_ref.version)

        # 檢索該要求關聯之審查發現
        req_findings = [f for f in findings if str(f.requirement_id) == req_id]

        if dec.state == ApplicabilityState.NOT_APPLICABLE:
            status = "not_applicable"
            processing = "processed"
            result = "not_applicable"
            is_unresolved = False
        elif dec.state == ApplicabilityState.UNKNOWN:
            status = "needs_confirmation"
            processing = "processed"
            result = "unknown"
            is_unresolved = True
        elif dec.state == ApplicabilityState.APPLICABLE:
            if req_findings:
                # 檢查是否有待確認或有 unknown 的發現
                has_pending = any(
                    f.result == ResultEnum.NEEDS_CONFIRMATION or len(f.unknowns) > 0
                    for f in req_findings
                )
                if has_pending:
                    status = "needs_confirmation"
                    processing = "processed"
                    result = "needs_confirmation"
                    is_unresolved = True
                else:
                    status = "covered"
                    processing = "processed"
                    result = req_findings[0].result.value
                    is_unresolved = False
            else:
                status = "unprocessed"
                processing = "unprocessed"
                result = "unreviewed"
                is_unresolved = True
        else:
            status = "unknown"
            processing = "processed"
            result = "unknown"
            is_unresolved = True

        if is_unresolved:
            unresolved_requirement_ids.append(req_id)

        details = json.dumps(
            {
                "version": req_ver,
                "processing": processing,
                "result": result,
                "status": status,
            },
            ensure_ascii=False,
        )

        entry = CoverageEntry(
            item_id=req_id,
            item_type="requirement",
            run_id=matrix_run_id,
            status=status,
            details=details,
            scope=None,
        )
        requirement_entries.append(entry)

    # 2. 建構條款覆蓋項目 (Clauses Table)
    clause_entries: list[CoverageEntry] = []
    unprocessed_clause_ids: list[str] = []

    # 匯集所有文件快照中的條款
    for doc in documents:
        doc_snap_id = str(doc.snapshot_id) if hasattr(doc, "snapshot_id") else "1.0"
        for clause in doc.clauses:
            cid = clause.clause_id

            # 檢查該條款是否被審查發現引用
            matching_findings = [f for f in findings if cid in f.clause_ids]

            if matching_findings:
                status = "covered"
                processing = "processed"
                result = matching_findings[0].result.value
            else:
                # 無相關規則條款顯示 uncovered
                status = "uncovered"
                processing = "processed"
                result = "uncovered"

            details = json.dumps(
                {
                    "version": doc_snap_id,
                    "processing": processing,
                    "result": result,
                    "status": status,
                    "clause_number": clause.clause_number,
                    "title": clause.title,
                },
                ensure_ascii=False,
            )

            entry = CoverageEntry(
                item_id=cid,
                item_type="clause",
                run_id=matrix_run_id,
                status=status,
                details=details,
                scope=clause.clause_number,
            )
            clause_entries.append(entry)

            if processing == "unprocessed":
                unprocessed_clause_ids.append(cid)

    return CoverageMatrix(
        run_id=matrix_run_id,
        clause_entries=clause_entries,
        requirement_entries=requirement_entries,
        unprocessed_clause_ids=unprocessed_clause_ids,
        unresolved_requirement_ids=unresolved_requirement_ids,
    )


def get_coverage_summary(matrix: CoverageMatrix) -> dict[str, Any]:
    """產出覆蓋摘要統計，分開呈現處理率與未解決數"""
    total_clauses = len(matrix.clause_entries)
    unprocessed_clauses = len(matrix.unprocessed_clause_ids)
    processed_clauses = total_clauses - unprocessed_clauses
    clause_rate = (processed_clauses / total_clauses) if total_clauses > 0 else 1.0

    total_reqs = len(matrix.requirement_entries)
    unresolved_reqs = len(matrix.unresolved_requirement_ids)
    resolved_reqs = total_reqs - unresolved_reqs
    req_rate = (resolved_reqs / total_reqs) if total_reqs > 0 else 1.0

    return {
        "total_clause_count": total_clauses,
        "processed_clause_count": processed_clauses,
        "unprocessed_clause_count": unprocessed_clauses,
        "clause_processing_rate": clause_rate,
        "total_requirement_count": total_reqs,
        "resolved_requirement_count": resolved_reqs,
        "unresolved_requirement_count": unresolved_reqs,
        "requirement_resolution_rate": req_rate,
    }
