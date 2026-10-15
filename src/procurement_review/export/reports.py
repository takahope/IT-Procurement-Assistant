"""Review Export & Report Generation (Task 11).

提供資安採購審查報告安全匯出：
- export_review: 支援遮罩模式 (masked) 與明文模式 (plaintext) 雙模匯出。
- 安全防護：
  1. 明文匯出強制人工確認，輸出權限嚴格設為 0600。
  2. 匯出路徑安全校驗，禁止覆寫原始合約檔案。
  3. 還原失敗（未知或跨案 token）禁止明文匯出，僅允許遮罩稿。
  4. Markdown 安全文字轉義（移除/轉義 HTML、惡意圖片及自動載入網址）。
  5. 全項採用亦嚴禁產出「整份合規」結論（零總體合規分數約束）。
"""

import json
import re
from pathlib import Path

from procurement_review.domain.enums import RedactionMode, ResultEnum
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    ExportPaths,
    RestorationResult,
    ReviewReport,
)


def _sanitize_markdown(text: str) -> str:
    """清理並轉義 Markdown 內容，防範 XSS、惡意 HTML 與外顯圖片注入。"""
    if not text:
        return ""

    # 1. 移除 script, iframe, object 等高危 HTML 標籤
    sanitized = re.sub(
        r"<\s*(?:script|iframe|object|embed|form)[^>]*>.*?<\s*/\s*(?:script|iframe|object|embed|form)\s*>",
        "",
        text,
        flags=re.IGNORECASE | re.DOTALL,
    )
    sanitized = re.sub(r"<\s*(?:script|iframe|object|embed|form)[^>]*>", "", sanitized, flags=re.IGNORECASE)

    # 2. 移除 img 標籤與 Markdown 圖片語法
    sanitized = re.sub(r"<\s*img[^>]*>", "[圖片已移除]", sanitized, flags=re.IGNORECASE)
    sanitized = re.sub(r"!\[([^\]]*)\]\([^)]*\)", r"[圖片已移除: \1]", sanitized)

    # 3. 停用 javascript: / data: 虛擬協定連結
    sanitized = re.sub(r"\[([^\]]+)\]\((?:javascript|data):[^)]*\)", r"[\1](disabled-url)", sanitized, flags=re.IGNORECASE)

    # 4. 轉義殘餘的 < 與 > 標籤字元，避免瀏覽器誤解析
    sanitized = sanitized.replace("<", "&lt;").replace(">", "&gt;")

    return sanitized


def _enforce_zero_score_constraint(text: str) -> str:
    """強制落實零總體合規分數約束：絕不產出『整份合規』或百分比合規結論。"""
    forbidden_patterns = [
        r"整份\s*(?:\d+%)?\s*合規",
        r"(?:100%|95%|\d+%)\s*合規",
        r"完全合規",
        r"總體合規率",
    ]
    cleaned = text
    for pat in forbidden_patterns:
        cleaned = re.sub(pat, "逐項查核完成（不提供總體合規保證）", cleaned)
    return cleaned


def export_review(
    report: ReviewReport,
    mode: str,
    output_dir: Path,
    confirmed: bool = False,
    original_contract_path: Path | None = None,
    restoration_result: RestorationResult | None = None,
    forbidden_terms: list[str] | None = None,
) -> ExportPaths:
    """匯出審查報告（Markdown 與 JSON 格式）。

    參數：
    - report: ReviewReport 實例
    - mode: 'masked' 或 'plaintext'
    - output_dir: 匯出目錄路徑
    - confirmed: 明文匯出是否經由人工確認（plaintext 必填 True）
    - original_contract_path: 原始合約路徑（用於防止覆寫檢查）
    - restoration_result: 本機文字還原結果（用於檢查是否包含未授權 token）
    - forbidden_terms: 額外機敏詞清單（遮罩模式下二次防護）
    """
    mode_str = str(mode).lower().strip()
    if mode_str not in ("masked", "plaintext"):
        raise DomainError(
            "INVALID_EXPORT_MODE",
            f"Invalid export mode '{mode}', must be 'masked' or 'plaintext'",
        )

    # 1. 明文模式安全性檢核
    if mode_str == "plaintext":
        if not confirmed:
            raise DomainError(
                "HUMAN_CONFIRMATION_REQUIRED",
                "Plaintext export requires explicit human confirmation",
            )
        if restoration_result is not None and not restoration_result.adoptable:
            raise DomainError(
                "RESTORATION_FAILED",
                f"Plaintext restoration failed with unknown tokens {restoration_result.unknown_tokens}, only masked export is allowed",
            )

    # 2. 建立目錄並產生匯出檔名
    out_dir = Path(output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

    md_filename = f"review_report_{report.run_id}_{mode_str}.md"
    json_filename = f"review_report_{report.run_id}_{mode_str}.json"

    md_path = out_dir / md_filename
    json_path = out_dir / json_filename

    # 3. 檢查不覆寫原合約
    if original_contract_path is not None:
        orig_resolved = Path(original_contract_path).resolve()
        if md_path == orig_resolved or json_path == orig_resolved:
            raise DomainError(
                "CANNOT_OVERWRITE_CONTRACT",
                "Export paths cannot overwrite original contract file",
            )

    # 4. 組裝 Markdown 內容
    md_lines: list[str] = [
        "# 採購合約資安審查報告",
        "",
        "> [!IMPORTANT]",
        "> 【重要資安與法務聲明】本審查報告依逐項條款與安全要求進行查核，不提供整體或百分比合規性評分保證。所有項目均須由權責法務與資安人員逐一複核確認。",
        "",
        "## 案件基本資訊",
        f"- **報告編號 (Report ID)**: {report.report_id}",
        f"- **案件編號 (Case ID)**: {report.case_id}",
        f"- **執行編號 (Run ID)**: {report.run_id}",
        f"- **合約版本**: {report.case_version}",
        f"- **機敏等級**: {report.sensitivity_level}",
        f"- **匯出模式**: {'遮罩檢視模式 (Masked)' if mode_str == 'masked' else '明文核定模式 (Plaintext)'}",
        f"- **產出時間**: {report.generated_at.isoformat()}",
        "",
        "## 審查發現一覽 (Findings)",
    ]

    if report.findings:
        md_lines.extend(
            [
                "| 發現編號 | 涉及條款 | 關聯要求 ID | 結果 | 風險 | 審查理由 | 處理狀態 |",
                "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |",
            ]
        )
        for f in report.findings:
            clauses_str = ", ".join(f.clause_ids) if f.clause_ids else "全份合約"
            res_str = f.result.label_zh if hasattr(f.result, "label_zh") else f.result.value
            risk_str = f.risk.label_zh if hasattr(f.risk, "label_zh") else f.risk.value
            clean_reason = _sanitize_markdown(f.reason).replace("|", "/")
            md_lines.append(
                f"| `{f.finding_id[:8]}` | {clauses_str} | `{f.requirement_id[:8]}` | {res_str} | {risk_str} | {clean_reason} | {f.human_status} |"
            )
    else:
        md_lines.append("*(本審查無發現事項)*")

    md_lines.extend(
        [
            "",
            "## 覆蓋矩陣摘要 (Coverage)",
            f"- **條款覆蓋項目數**: {len(report.coverage.clause_entries)} 項",
            f"- **未處理條款清單**: {', '.join(report.coverage.unprocessed_clause_ids) if report.coverage.unprocessed_clause_ids else '無'}",
            f"- **未決要求清單**: {', '.join(report.coverage.unresolved_requirement_ids) if report.coverage.unresolved_requirement_ids else '無'}",
            "",
            "## 人工決定紀錄 (Human Decisions)",
        ]
    )

    if report.human_decisions:
        for idx, d in enumerate(report.human_decisions, 1):
            clean_d_reason = _sanitize_markdown(d.reason)
            clean_final = _sanitize_markdown(d.final_text or "(無定稿文字)")
            md_lines.extend(
                [
                    f"### 決定 {idx} (ID: `{d.decision_id[:8]}`)",
                    f"- **關聯發現 ID**: `{d.finding_id}`",
                    f"- **決定動作**: {d.action.value}",
                    f"- **決定人員**: {d.decided_by}",
                    f"- **決定時間**: {d.decided_at.isoformat()}",
                    f"- **決定理由**: {clean_d_reason}",
                    f"- **定稿文字**: {clean_final}",
                    "",
                ]
            )
    else:
        md_lines.append("*(尚無人工決定紀錄)*")

    md_content = "\n".join(md_lines)
    md_content = _enforce_zero_score_constraint(md_content)

    # 5. 組裝 JSON 內容
    failures_list = [
        f.model_dump(mode="json")
        for f in report.findings
        if f.result in (ResultEnum.CONCERN, ResultEnum.MISSING, ResultEnum.NEEDS_CONFIRMATION)
    ]
    all_unknowns = list(report.unresolved_issues)
    for f in report.findings:
        all_unknowns.extend(f.unknowns)

    json_data = {
        "schema_version": "1.0.0",
        "report_id": str(report.report_id),
        "case_id": str(report.case_id),
        "run_id": str(report.run_id),
        "mode": mode_str,
        "generated_at": report.generated_at.isoformat(),
        "sensitivity_level": report.sensitivity_level,
        "compliance_summary": {
            "statement": "本系統不提供整體合規保證，各項結果僅供法務及資安人員複核參考",
            "total_findings": len(report.findings),
            "compliant_count": sum(1 for f in report.findings if f.result == ResultEnum.COMPLIANT),
            "concern_count": sum(1 for f in report.findings if f.result == ResultEnum.CONCERN),
            "missing_count": sum(1 for f in report.findings if f.result == ResultEnum.MISSING),
        },
        "versions": {
            "case_version": report.case_version,
            "source_manifest": [r.model_dump(mode="json") for r in report.source_manifest],
        },
        "coverage": report.coverage.model_dump(mode="json"),
        "unknowns": all_unknowns,
        "failures": failures_list,
        "findings": [f.model_dump(mode="json") for f in report.findings],
        "human_decisions": [d.model_dump(mode="json") for d in report.human_decisions],
    }

    json_str = json.dumps(json_data, ensure_ascii=False, indent=2)
    json_str = _enforce_zero_score_constraint(json_str)

    # 6. 遮罩模式二次檢查，防範洩漏
    if mode_str == "masked" and forbidden_terms:
        for term in forbidden_terms:
            if term in md_content or term in json_str:
                raise DomainError(
                    "MASKING_LEAK_DETECTED",
                    f"Sensitive entity '{term}' detected in masked export output",
                )

    # 7. 寫入檔案並嚴格設定 0600 權限
    md_path.write_text(md_content, encoding="utf-8")
    md_path.chmod(0o600)

    json_path.write_text(json_str, encoding="utf-8")
    json_path.chmod(0o600)

    redaction_mode = RedactionMode.MASKED if mode_str == "masked" else RedactionMode.PLAINTEXT
    return ExportPaths(
        markdown_path=str(md_path),
        json_path=str(json_path),
        redaction_mode=redaction_mode,
    )
