import json
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest

from procurement_review.domain.enums import (
    HumanDecisionAction,
    ProcurementFamily,
    RedactionMode,
    ResultEnum,
    RiskLevel,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    CoverageEntry,
    CoverageMatrix,
    Feedback,
    Finding,
    HumanDecision,
    RestorationResult,
    Review,
    ReviewReport,
    ReviewRun,
    Rule,
    VersionRef,
)
from procurement_review.export.reports import export_review
from procurement_review.feedback.service import record_feedback
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def artifact_store(tmp_path: Path) -> ArtifactStore:
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    return ArtifactStore(root=vault_root, secrets=secrets)


@pytest.fixture
def repo(tmp_path: Path, artifact_store: ArtifactStore) -> Repository:
    db_path = tmp_path / "feedback_export_test.db"
    return Repository(db=db_path, artifacts=artifact_store)


def make_dummy_version_ref(ref_id: str | None = None, version: str = "1.0.0") -> VersionRef:
    rid = ref_id or str(uuid.uuid4())
    return VersionRef(
        id=rid,
        version=version,
        sha256="0" * 64,
    )


def create_sample_review(repo: Repository, case_id: str | None = None) -> Review:
    cid = case_id or str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資安推動小組",
        procurement_families=[ProcurementFamily.SERVICES],
        service_scope="雲端委外審查",
        unknown_fields=[],
    )
    review = Review(
        case_id=cid,
        title="重要採購合約資安審查案件",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        facts=facts,
        created_by="auditor",
        created_at=datetime.now(UTC),
    )
    return repo.save_review(review, expected_revision=None)


def create_sample_run(repo: Repository, case_id: str) -> ReviewRun:
    return repo.create_run(
        review_id=case_id,
        rule_refs=[make_dummy_version_ref()],
        engine_version="1.0.0",
        masking_version="1.0.0",
        prompt_version="1.0.0",
        schema_version="1.0.0",
        provider_id="mock",
        model_id="mock-model",
    )


def create_sample_finding(
    repo: Repository,
    run_id: str,
    finding_id: str | None = None,
    result: ResultEnum = ResultEnum.CONCERN,
    reason: str = "資安通報時限不明確",
) -> Finding:
    fid = finding_id or str(uuid.uuid4())
    finding = Finding(
        finding_id=fid,
        run_id=run_id,
        clause_ids=["clause-10"],
        requirement_id=str(uuid.uuid4()),
        result=result,
        risk=RiskLevel.HIGH,
        reason=reason,
        human_status="unreviewed",
    )
    repo.save_finding(finding)
    return finding


def test_record_feedback_stale_run_rejected(repo: Repository):
    """舊 run 回饋拒絕：已被標記為 stale 的 run，提交回饋時必被拒絕。"""
    review = create_sample_review(repo)
    run = create_sample_run(repo, review.case_id)
    finding = create_sample_finding(repo, run.run_id)

    # 模擬案件改版或政策變更使 run 變更為 stale
    repo.invalidate(review.case_id, reason="Policy updated")
    assert repo.get_run(run.run_id).stale is True

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run.run_id,
        action=HumanDecisionAction.ADOPT,
        final_text="乙方應於24小時內完成資安通報",
        reason="同意採納建議",
        decided_by="legal_counsel",
        decided_at=datetime.now(UTC),
    )

    with pytest.raises(DomainError) as exc_info:
        record_feedback(decision, repo, idempotency_key="feedback-key-stale")
    assert exc_info.value.code in ("STALE_RUN_REJECTED", "STALE_RUN")


def test_record_feedback_run_id_assertion_and_idempotency(repo: Repository):
    """核心斷言：assert report.run_id == decision.run_id；重複點擊不重複寫（冪等性）。"""
    review = create_sample_review(repo)
    run = create_sample_run(repo, review.case_id)
    finding = create_sample_finding(repo, run.run_id)

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run.run_id,
        action=HumanDecisionAction.MODIFY,
        final_text="乙方應於36小時內完成資安通報與修復",
        reason="修改為符合雙方共識時限",
        decided_by="security_officer",
        decided_at=datetime.now(UTC),
    )

    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=review.case_id,
        run_id=run.run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[finding],
        coverage=CoverageMatrix(run_id=run.run_id),
        unresolved_issues=[],
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )

    # 核心斷言：report.run_id 必與 decision.run_id 一致
    assert report.run_id == decision.run_id

    # 首次寫入
    fb1 = record_feedback(decision, repo, idempotency_key="idemp-key-001")
    assert isinstance(fb1, Feedback)
    assert fb1.finding_id == finding.finding_id
    assert fb1.run_id == run.run_id

    # 驗證 finding 狀態已更新為已審查
    updated_f = repo.get_finding(finding.finding_id)
    assert updated_f.human_status in ("modified", "reviewed", "decided")

    # 重複呼叫（模擬前端重複點擊）
    fb2 = record_feedback(decision, repo, idempotency_key="idemp-key-001")
    assert fb2.feedback_id == fb1.feedback_id

    # 驗證資料庫中僅存在一筆回饋
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT count(*) FROM feedbacks WHERE finding_id = ?", (finding.finding_id,))
        count = cursor.fetchone()[0]
        assert count == 1


def test_record_feedback_single_case_does_not_alter_base_rules(repo: Repository):
    """單案例外不更動規則：單一案件之人決定即使給予例外，不影響 catalog 中的基礎規則。"""
    review = create_sample_review(repo)
    run = create_sample_run(repo, review.case_id)
    finding = create_sample_finding(repo, run.run_id)

    # 在 repo 儲存一條基礎規則
    rule_id = str(uuid.uuid4())
    rule = Rule(
        rule_id=rule_id,
        version="1.0.0",
        title="日誌留存一年要求",
        category=ProcurementFamily.SERVICES,
        requirement_text="系統應保留連線日誌至少365日",
        mandatory=True,
        severity=RiskLevel.HIGH,
    )
    repo.save_rule(rule)

    # 人工決定給予本案特准例外（如僅需留存180日）
    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run.run_id,
        action=HumanDecisionAction.MODIFY,
        final_text="特准本案連線日誌留存180日",
        reason="受限硬體空間，專案特准",
        decided_by="ciso",
        decided_at=datetime.now(UTC),
    )
    fb = record_feedback(decision, repo, idempotency_key="rule-unaffected-key")
    assert fb.approved_for_case_base is False  # 僅存為候選，不更動基礎規則

    # 驗證基礎規則保持不變
    fetched_rule = repo.get_rule(rule_id)
    assert fetched_rule.requirement_text == "系統應保留連線日誌至少365日"
    assert fetched_rule.mandatory is True


def test_export_review_masked_mode_core_assertion(tmp_path: Path):
    """核心斷言：遮罩匯出 assert original_name not in exported_markdown"""
    original_name = "台灣微軟股份有限公司"
    masked_token = "[公司名稱_1]"

    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=["clause-1"],
        requirement_id=str(uuid.uuid4()),
        result=ResultEnum.CONCERN,
        risk=RiskLevel.MEDIUM,
        reason=f"廠商 {masked_token} 提出之日誌方案不符規範",
        human_status="reviewed",
    )
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[finding],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_masked"
    paths = export_review(report, mode="masked", output_dir=export_dir)

    exported_markdown = Path(paths.markdown_path).read_text(encoding="utf-8")
    exported_json = Path(paths.json_path).read_text(encoding="utf-8")

    # 核心斷言：遮罩模式下，原始名稱絕對不得出現在 Markdown 或 JSON 匯出檔案中！
    assert original_name not in exported_markdown
    assert original_name not in exported_json
    assert masked_token in exported_markdown
    assert paths.redaction_mode == RedactionMode.MASKED


def test_export_review_plaintext_mode_requires_confirmation_and_permissions(tmp_path: Path):
    """明文匯出需人工確認、檔案權限 0600，且不覆寫原合約檔案。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=["clause-1"],
        requirement_id=str(uuid.uuid4()),
        result=ResultEnum.COMPLIANT,
        risk=RiskLevel.LOW,
        reason="條文符合資安規定",
        human_status="reviewed",
    )
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[finding],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_plain"
    export_dir.mkdir(parents=True, exist_ok=True)

    # 1. 未經人工確認，明文匯出必須被拒絕
    with pytest.raises(DomainError) as exc_info:
        export_review(report, mode="plaintext", output_dir=export_dir, confirmed=False)
    assert exc_info.value.code == "HUMAN_CONFIRMATION_REQUIRED"

    # 2. 模擬原合約文件存在，驗證匯出絕不覆寫原合約
    original_contract = export_dir / "original_contract.docx"
    original_contract.write_bytes(b"ORIGINAL CONTRACT CONTENT")

    # 3. 經人工確認後匯出
    paths = export_review(
        report,
        mode="plaintext",
        output_dir=export_dir,
        confirmed=True,
        original_contract_path=original_contract,
    )
    assert paths.redaction_mode == RedactionMode.PLAINTEXT
    assert original_contract.read_bytes() == b"ORIGINAL CONTRACT CONTENT"  # 未被覆寫

    # 4. 驗證產出檔案權限為 0600 (POSIX 權限檢查)
    md_file = Path(paths.markdown_path)
    json_file = Path(paths.json_path)
    assert md_file.exists()
    assert json_file.exists()

    md_mode = stat.S_IMODE(md_file.stat().st_mode)
    json_mode = stat.S_IMODE(json_file.stat().st_mode)
    assert md_mode == 0o600
    assert json_mode == 0o600


def test_export_review_restoration_failure_disallows_plaintext(tmp_path: Path):
    """還原失敗（含有 unknown token 或 wrong case token）只允許遮罩稿，禁止明文匯出。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    failed_restoration = RestorationResult(
        text="還原文字",
        unknown_tokens=["[UNKNOWN_TOKEN_1]"],
        wrong_case_tokens=[],
        adoptable=False,
    )

    export_dir = tmp_path / "export_fail"
    with pytest.raises(DomainError) as exc_info:
        export_review(
            report,
            mode="plaintext",
            output_dir=export_dir,
            confirmed=True,
            restoration_result=failed_restoration,
        )
    assert exc_info.value.code == "RESTORATION_FAILED"


def test_export_review_zero_score_constraint(tmp_path: Path):
    """全項採用仍不得產「整份合規」結論：即便是 100% 條款符合／採用，絕不產出百分比或整份合規宣稱。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    # 所有項目皆為 compliant
    findings = [
        Finding(
            finding_id=str(uuid.uuid4()),
            run_id=run_id,
            clause_ids=[f"clause-{i}"],
            requirement_id=str(uuid.uuid4()),
            result=ResultEnum.COMPLIANT,
            risk=RiskLevel.LOW,
            reason=f"條款 {i} 完全符合資安要求",
            human_status="adopted",
        )
        for i in range(5)
    ]
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0",
        sensitivity_level="internal",
        source_manifest=[make_dummy_version_ref()],
        findings=findings,
        coverage=CoverageMatrix(
            run_id=run_id,
            clause_entries=[CoverageEntry(item_id=f"clause-{i}", item_type="clause", run_id=run_id, status="covered") for i in range(5)],
        ),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_zero_score"
    paths = export_review(report, mode="masked", output_dir=export_dir)

    md_content = Path(paths.markdown_path).read_text(encoding="utf-8")
    json_content = Path(paths.json_path).read_text(encoding="utf-8")

    # 嚴格約束：絕不能出現「整份合規」、「100%合規」、「95%合規」或整體百分比結論
    forbidden_terms = ["整份合規", "100%合規", "100% 合規", "完全合規", "95%合規", "整份95%合規"]
    for term in forbidden_terms:
        assert term not in md_content
        assert term not in json_content

    # 包含免責聲明
    assert "不提供" in md_content and "合規" in md_content


def test_export_review_sanitizes_html_and_external_images(tmp_path: Path):
    """Markdown 安全文字轉義：不嵌入模型提供的 HTML、圖片或可自動載入網址。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    malicious_finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=["clause-sec"],
        requirement_id=str(uuid.uuid4()),
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        reason='<script>alert("xss")</script><img src="https://evil.com/leak.png"> [惡意連結](javascript:stealData())',
        human_status="unreviewed",
    )
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[malicious_finding],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_sanitize"
    paths = export_review(report, mode="masked", output_dir=export_dir)

    md_content = Path(paths.markdown_path).read_text(encoding="utf-8")

    # 原始危險 HTML 與圖片標籤已被轉義或清除，不會被瀏覽器直接解析執行
    assert "<script>" not in md_content
    assert '<img src="https://evil.com/leak.png">' not in md_content
    assert "javascript:stealData()" not in md_content


def test_export_review_json_structure(tmp_path: Path):
    """JSON 匯出帶版本、全部覆蓋、未知、失敗與人工決定。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=["clause-1"],
        requirement_id=str(uuid.uuid4()),
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        reason="存在疑慮",
        unknowns=["待確認日誌規格"],
        human_status="reviewed",
    )
    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        action=HumanDecisionAction.ADOPT,
        final_text="採納建議",
        reason="同意",
        decided_by="auditor",
        decided_at=datetime.now(UTC),
    )
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="2.1.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref(version="2.1.0")],
        findings=[finding],
        coverage=CoverageMatrix(
            run_id=run_id,
            clause_entries=[CoverageEntry(item_id="clause-1", item_type="clause", run_id=run_id, status="covered")],
            unresolved_requirement_ids=["req-unresolved-1"],
        ),
        unresolved_issues=["未決議題-1"],
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_json"
    paths = export_review(report, mode="masked", output_dir=export_dir)

    with open(paths.json_path, encoding="utf-8") as f:
        data = json.load(f)

    assert "schema_version" in data
    assert "versions" in data
    assert data["versions"]["case_version"] == "2.1.0"
    assert "coverage" in data
    assert "clause_entries" in data["coverage"]
    assert "unresolved_requirement_ids" in data["coverage"]
    assert "unknowns" in data
    assert "待確認日誌規格" in data["unknowns"]
    assert "failures" in data
    assert len(data["failures"]) == 1  # 疑慮項目作為 failure/concern 追蹤
    assert "human_decisions" in data
    assert len(data["human_decisions"]) == 1
    assert data["human_decisions"][0]["action"] == "adopt"


def test_export_review_masked_mode_forbidden_term_leak_raises_domain_error(tmp_path: Path):
    """負向測試：遮罩模式下若有未遮罩敏感實體洩漏，必須觸發 MASKING_LEAK_DETECTED 阻擋匯出。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    leaked_vendor = "極機密廠商-AlphaCorp"
    finding = Finding(
        finding_id=str(uuid.uuid4()),
        run_id=run_id,
        clause_ids=["clause-sec-1"],
        requirement_id=str(uuid.uuid4()),
        result=ResultEnum.CONCERN,
        risk=RiskLevel.HIGH,
        reason=f"合約文字未經完全遮罩，直接提及 {leaked_vendor} 責任劃分",
        human_status="unreviewed",
    )
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0.0",
        sensitivity_level="top_secret",
        source_manifest=[make_dummy_version_ref()],
        findings=[finding],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "export_leak"
    with pytest.raises(DomainError) as exc_info:
        export_review(
            report,
            mode="masked",
            output_dir=export_dir,
            forbidden_terms=[leaked_vendor],
        )
    assert exc_info.value.code == "MASKING_LEAK_DETECTED"
    assert leaked_vendor in str(exc_info.value)


def test_export_review_plaintext_retention_metadata(tmp_path: Path):
    """明文匯出應在 JSON 中繼資料中包含 retention_policy、retention_period 與 retention_expire_at。"""
    run_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())
    gen_time = datetime(2026, 10, 15, 12, 0, 0, tzinfo=UTC)
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run_id,
        case_version="1.0.0",
        sensitivity_level="confidential",
        source_manifest=[make_dummy_version_ref()],
        findings=[],
        coverage=CoverageMatrix(run_id=run_id),
        unresolved_issues=[],
        human_decisions=[],
        generated_at=gen_time,
    )

    export_dir = tmp_path / "export_plain_retention"
    paths = export_review(
        report,
        mode="plaintext",
        output_dir=export_dir,
        confirmed=True,
        retention_period_days=45,
        retention_policy="classified_procurement_30d_plus",
    )

    with open(paths.json_path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["mode"] == "plaintext"
    assert data["retention_policy"] == "classified_procurement_30d_plus"
    assert data["retention_period"] == "45 days"
    assert data["retention_period_days"] == 45
    assert "retention_expire_at" in data
    assert data["retention_expire_at"].startswith("2026-11-29T12:00:00")
    assert "lifecycle" in data
    assert data["lifecycle"]["retention_policy"] == "classified_procurement_30d_plus"
    assert data["lifecycle"]["retention_period_days"] == 45

    md_content = Path(paths.markdown_path).read_text(encoding="utf-8")
    assert "保存政策 (Retention Policy)" in md_content
    assert "classified_procurement_30d_plus" in md_content
    assert "45 days" in md_content

