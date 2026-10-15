"""Validation Layer for Procurement Review (Task 10).

實作三層驗證：
1. Structure validation (GateReport): checks enum values, ID formats, non-empty reasoning.
2. Source validation (GateReport): checks that quoted short citations actually exist in context spans,
   clause_ids exist, rule/source versions match, unconfirmed sources flagged.
3. Substance validation: keeps human_status = 'pending', notes human review required.
"""

import re
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from procurement_review.documents.structure import SourceSpan
from procurement_review.domain.enums import ResultEnum, RiskLevel
from procurement_review.domain.models import (
    ContextBundle,
    Finding,
    GateReport,
    ValidationReport,
)

_SCHEMA_PATH = Path(__file__).resolve().parents[3] / "schemas" / "provider-response.json"


class DetailedValidationReport(ValidationReport):
    """擴展 ValidationReport，提供 .structure 與 .source 之 GateReport 屬性存取。"""

    @property
    def structure(self) -> GateReport:
        structure_issues = [i for i in self.issues if i.startswith("[structure]")]
        return GateReport(
            ok=self.structure_ok,
            operation="structure_validation",
            issues=structure_issues,
            checked_at=self.checked_at,
        )

    @property
    def source(self) -> GateReport:
        source_issues = [i for i in self.issues if i.startswith("[source]")]
        return GateReport(
            ok=self.source_ok,
            operation="source_validation",
            issues=source_issues,
            checked_at=self.checked_at,
        )


def _is_valid_uuid(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    try:
        uuid.UUID(val)
        return True
    except (ValueError, TypeError, AttributeError):
        return False


def validate_provider_response_json(data: Any) -> tuple[bool, list[str]]:
    """依據 schemas/provider-response.json 檢驗模型回應格式。

    檢查頂層物件、findings 陣列、列舉狀態與必填欄位。
    """
    errors: list[str] = []
    if not isinstance(data, dict):
        return False, ["Root response must be a JSON object"]

    if "findings" not in data:
        return False, ["Missing required property 'findings'"]

    findings = data["findings"]
    if not isinstance(findings, list):
        return False, ["Property 'findings' must be an array"]

    allowed_results = {e.value for e in ResultEnum}
    allowed_risks = {e.value for e in RiskLevel}
    allowed_item_fields = {
        "finding_id",
        "requirement_id",
        "clause_ids",
        "result",
        "risk",
        "reason",
        "citations",
        "evidence",
        "unknowns",
        "suggested_action",
        "suggested_clause",
        "review_scope",
    }

    for idx, item in enumerate(findings):
        prefix = f"findings[{idx}]"
        if not isinstance(item, dict):
            errors.append(f"{prefix}: item must be a JSON object")
            continue

        # additionalProperties: false
        extra_keys = set(item.keys()) - allowed_item_fields
        if extra_keys:
            errors.append(f"{prefix}: unexpected fields: {sorted(extra_keys)}")

        # required: ["requirement_id", "result", "risk", "reason"]
        for req_field in ["requirement_id", "result", "risk", "reason"]:
            if req_field not in item:
                errors.append(f"{prefix}: missing required field '{req_field}'")

        if "requirement_id" in item and not isinstance(item["requirement_id"], str):
            errors.append(f"{prefix}: requirement_id must be a string")

        if "result" in item and item["result"] not in allowed_results:
            errors.append(
                f"{prefix}: invalid result '{item['result']}', allowed: {sorted(allowed_results)}"
            )

        if "risk" in item and item["risk"] not in allowed_risks:
            errors.append(
                f"{prefix}: invalid risk '{item['risk']}', allowed: {sorted(allowed_risks)}"
            )

        if "reason" in item and (
            not isinstance(item["reason"], str) or len(item["reason"].strip()) == 0
        ):
            errors.append(f"{prefix}: reason must be a non-empty string")

        if "clause_ids" in item and (
            not isinstance(item["clause_ids"], list)
            or not all(isinstance(c, str) for c in item["clause_ids"])
        ):
            errors.append(f"{prefix}: clause_ids must be an array of strings")

        if "citations" in item and (
            not isinstance(item["citations"], list)
            or not all(isinstance(c, str) for c in item["citations"])
        ):
            errors.append(f"{prefix}: citations must be an array of strings")

        if "unknowns" in item and (
            not isinstance(item["unknowns"], list)
            or not all(isinstance(u, str) for u in item["unknowns"])
        ):
            errors.append(f"{prefix}: unknowns must be an array of strings")

    return len(errors) == 0, errors


def _normalize_text(s: str) -> str:
    return re.sub(r"\s+", "", s).lower()


_CHINESE_DIGITS = {
    "一": 1,
    "二": 2,
    "三": 3,
    "四": 4,
    "五": 5,
    "六": 6,
    "七": 7,
    "八": 8,
    "九": 9,
    "十": 10,
    "十一": 11,
    "十二": 12,
    "十三": 13,
    "十四": 14,
    "十五": 15,
    "十六": 16,
    "十七": 17,
    "十八": 18,
    "十九": 19,
    "二十": 20,
}


def _clause_id_matches(clause_id: str, candidates: set[str]) -> bool:
    """判斷條款編號是否匹配候選清單（支援 c-10, 第十條, 10 等型態）"""
    norm_cid = _normalize_text(clause_id)
    if norm_cid in candidates:
        return True

    # 提取純數字
    num_match = re.search(r"\d+", norm_cid)
    if num_match:
        target_num = int(num_match.group(0))
        for cand in candidates:
            cand_num_match = re.search(r"\d+", cand)
            if cand_num_match and int(cand_num_match.group(0)) == target_num:
                return True
            for ch_num, val in _CHINESE_DIGITS.items():
                if val == target_num and ch_num in cand:
                    return True

    return False


def validate_findings(
    findings: list[Finding],
    contexts: list[ContextBundle],
) -> DetailedValidationReport:
    """執行審查發現三層驗證：

    1. Structure Validation (結構檢驗): 檢驗列舉、格式、UUID、非空推理理由。
    2. Source Validation (來源檢驗): 檢驗引用條款、規則版本、引文存在性、未確認來源。
    3. Substance Validation (實質檢驗): 維持 human_status = 'pending'，不自動判斷通過。
    """
    now = datetime.now(UTC)
    issues: list[str] = []
    structure_ok = True
    source_ok = True
    substance_ok = True

    run_id = findings[0].run_id if findings else str(uuid.uuid4())

    # 建立 ContextBundle 索引
    ctx_by_req: dict[str, ContextBundle] = {str(c.requirement_ref.id): c for c in contexts}

    for finding in findings:
        f_id = str(finding.finding_id)

        # ---------------- 1. 結構校驗 (Structure) ----------------
        if not _is_valid_uuid(str(finding.finding_id)):
            structure_ok = False
            issues.append(f"[structure] Finding {f_id}: invalid finding_id UUID format")

        if not _is_valid_uuid(str(finding.run_id)):
            structure_ok = False
            issues.append(f"[structure] Finding {f_id}: invalid run_id UUID format")

        if not finding.reason or not finding.reason.strip():
            structure_ok = False
            issues.append(f"[structure] Finding {f_id}: reason is empty or whitespace")

        if not isinstance(finding.result, ResultEnum):
            structure_ok = False
            issues.append(f"[structure] Finding {f_id}: invalid result enum value '{finding.result}'")

        if not isinstance(finding.risk, RiskLevel):
            structure_ok = False
            issues.append(f"[structure] Finding {f_id}: invalid risk enum value '{finding.risk}'")

        if (
            finding.result == ResultEnum.MISSING
            and not finding.clause_ids
            and (not finding.review_scope or not finding.review_scope.strip())
        ):
            structure_ok = False
            issues.append(
                f"[structure] Finding {f_id}: result is 'missing' with no clause_ids requires review_scope"
            )

        # ---------------- 2. 來源校驗 (Source) ----------------
        req_id = str(finding.requirement_id)
        if req_id not in ctx_by_req:
            source_ok = False
            issues.append(f"[source] Finding {f_id}: requirement_id '{req_id}' not found in contexts")
            continue

        ctx = ctx_by_req[req_id]

        # 檢驗規則版本是否相符
        expected_version = ctx.requirement_ref.version
        for r_ref in finding.rule_refs:
            if r_ref.version != expected_version:
                source_ok = False
                issues.append(
                    f"[source] Finding {f_id}: version mismatch for rule ref (expected {expected_version}, got {r_ref.version})"
                )

        # 檢驗未確認來源 (Unconfirmed Document Status)
        for doc_name, status in ctx.document_retrieval_status.items():
            if status == "unconfirmed":
                source_ok = False
                issues.append(
                    f"[source] Finding {f_id}: relies on unconfirmed source document '{doc_name}'"
                )

        # 收集 Context 中的所有有效條款識別
        valid_identifiers: set[str] = set()
        for span in ctx.source_spans:
            if span.structural_path:
                valid_identifiers.add(_normalize_text(span.structural_path))
            if span.block_id:
                valid_identifiers.add(_normalize_text(str(span.block_id)))
        for cit in ctx.citations:
            valid_identifiers.add(_normalize_text(cit))

        # 檢驗 clause_ids 是否存在於 context
        for cid in finding.clause_ids:
            if not _clause_id_matches(cid, valid_identifiers):
                source_ok = False
                issues.append(f"[source] Finding {f_id}: Non-existent clause_id '{cid}' in context")

        # 檢驗短引文存在性 (Verbatim quotation fidelity in source spans)
        # 來源存在不能自動判 supports=True
        all_span_text = " ".join(
            span.structural_path for span in ctx.source_spans if span.structural_path
        )
        for cit in finding.citations if hasattr(finding, "citations") else []:
            norm_cit = _normalize_text(cit)
            if norm_cit not in _normalize_text(all_span_text):
                source_ok = False
                issues.append(
                    f"[source] Finding {f_id}: Citation mismatch: '{cit}' not found in source spans"
                )

        # ---------------- 3. 實質校驗 (Substance) ----------------
        # 實質審查必須由人工執行，系統自動校驗始終維持 human_status == 'pending'
        if finding.human_status != "pending":
            issues.append(
                f"[substance] Finding {f_id}: human_status is '{finding.human_status}', expected 'pending'"
            )

    return DetailedValidationReport(
        report_id=str(uuid.uuid4()),
        run_id=run_id,
        structure_ok=structure_ok,
        source_ok=source_ok,
        substance_ok=substance_ok,
        issues=issues,
        checked_at=now,
    )


def detect_cross_document_conflicts(
    requirement_id: str,
    spans: list[SourceSpan],
    statements: list[str],
) -> dict[str, Any] | None:
    """跨文件衝突檢測。

    若多份文件就同一要求提出歧異條款（例如主合約禁止委外，附件允許委外），
    保留兩側引用與效力未知，建立待核准衝突記錄。
    """
    doc_ids = {str(s.document_id) for s in spans}
    if len(doc_ids) <= 1:
        return None

    return {
        "conflict_id": str(uuid.uuid4()),
        "requirement_id": requirement_id,
        "conflicting_spans": [s.model_dump() for s in spans],
        "statements": statements,
        "status": "needs_approval",
        "efficacy": "unknown",
        "created_at": datetime.now(UTC).isoformat(),
    }
