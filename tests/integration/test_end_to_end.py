import json
import uuid
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from procurement_review.cli import main
from procurement_review.documents.ingest import confirm_text, ingest, segment
from procurement_review.documents.structure import SourceSpan
from procurement_review.domain.enums import (
    HumanDecisionAction,
    ProcurementFamily,
    ResultEnum,
    RiskLevel,
    RuleStatus,
    RunState,
    RuntimeMode,
    SourceNature,
)
from procurement_review.domain.models import (
    CaseFacts,
    ContextBundle,
    CoverageMatrix,
    DetectedSpan,
    ExportPaths,
    HumanDecision,
    MaskingSession,
    OutboundDraft,
    ProviderReply,
    Review,
    ReviewReport,
    Rule,
    RuntimePolicy,
    SourceReference,
    SuggestedChange,
    VersionRef,
)
from procurement_review.egress.approvals import approve
from procurement_review.egress.dispatcher import dispatch
from procurement_review.egress.payload import prepare_egress
from procurement_review.export.reports import export_review
from procurement_review.feedback.service import record_feedback
from procurement_review.masking.detector import RuleBasedDetector
from procurement_review.masking.session import apply_annotations, mask
from procurement_review.providers.mock import MockProviderAdapter
from procurement_review.review.drafting import validate_change
from procurement_review.review.workflow import (
    accept_review_reply,
    finalize_run,
    plan_review,
)
from procurement_review.rules.applicability import evaluate_applicability
from procurement_review.rules.catalog import compute_rule_hash, rule_to_requirement
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore
from procurement_review.web.app import create_app

ExportPaths.markdown = property(lambda self: Path(self.markdown_path))
ExportPaths.json = property(lambda self: Path(self.json_path))


@pytest.fixture
def env(tmp_path: Path):
    vault_root = tmp_path / "vault"
    db_path = tmp_path / "e2e_integration.db"
    secrets = FakeSecretStore()
    secrets.set_key("artifact_master_key", b"0" * 32)
    artifacts = ArtifactStore(root=vault_root, secrets=secrets)
    repo = Repository(db=db_path, artifacts=artifacts)
    policy = RuntimePolicy(mode=RuntimeMode.SYNTHETIC, data_root=str(tmp_path))
    return {
        "repo": repo,
        "policy": policy,
        "secrets": secrets,
        "tmp_path": tmp_path,
        "artifacts": artifacts,
    }


def _seed_active_rule(
    repo: Repository,
    category: ProcurementFamily,
    title: str,
    requirement_text: str,
    severity: RiskLevel = RiskLevel.HIGH,
) -> tuple[Rule, SourceReference]:
    src_id = str(uuid.uuid4())
    rule_id = str(uuid.uuid4())
    source = SourceReference(
        source_id=src_id,
        kind=SourceNature.STANDARD_TEMPLATE,
        title=f"{title} - 依據標準",
        issuer="資通安全主管機關",
        locator="第10條第1項",
        section="資安專章",
        version="1.0",
        verified_at=datetime.now(UTC),
        verified_by="資安查核員",
        content_hash="hash_verified_source_12345",
    )
    repo.save_source(source)

    rule = Rule(
        rule_id=rule_id,
        version="1.0",
        status=RuleStatus.ACTIVE,
        category=category,
        title=title,
        requirement_text=requirement_text,
        severity=severity,
        mandatory=True,
        source_refs=[
            VersionRef(id=source.source_id, version=source.version, sha256=source.content_hash)
        ],
        approved_by="法務主管",
    )
    repo.save_rule(rule)
    req = rule_to_requirement(rule)
    repo.save_requirement(req)
    return rule, source


def test_doctor_command_synthetic_mode(tmp_path: Path, capsys):
    """驗證 procurement-review doctor 命令：

    檢查工具／依賴／資料根／權限／SQLite／SecretStore／規則包／供應商，
    絕不洩漏密鑰，退出碼為 0。
    """
    data_dir = tmp_path / "doctor_data"
    main(["doctor", "--mode", "synthetic", "--data-dir", str(data_dir)])
    captured = capsys.readouterr().out

    # 驗證必要診斷項目呈現
    assert "中央研究院資訊採購合約資安審查助手" in captured
    assert "系統自我診斷" in captured or "Doctor" in captured or "診斷" in captured
    assert "Python" in captured
    assert "SQLite" in captured
    assert "SecretStore" in captured
    assert "規則包" in captured or "Rules" in captured
    assert "供應商" in captured or "Provider" in captured
    assert "[OK]" in captured

    # 驗證零機敏洩漏：絕不印出金鑰原文或十六進位敏感密文
    assert "0" * 32 not in captured
    assert "artifact_master_key:" not in captured or "artifact_master_key: [PROTECTED]" in captured


def test_end_to_end_software_maintenance(env):
    """四類採購之一：軟體維護 (software_maintenance) 全流程驗收

    流程：
    1. 建立案件與設定事實
    2. 文件解析與人工確認
    3. 規則適用性評估
    4. 本機遮罩與人工補標
    5. 出站預覽與核准
    6. 執行審查（MockProvider / CloudAdapter）
    7. 建議修訂條款草稿產製與三層校驗
    8. 人工決定記錄 (ADOPT)
    9. 雙模匯出 (masked 與 plaintext)
    核心斷言：
    - assert matrix.unprocessed_ids == []
    - assert export_paths.markdown.exists() and export_paths.json.exists()
    """
    repo: Repository = env["repo"]
    policy: RuntimePolicy = env["policy"]
    artifacts: ArtifactStore = env["artifacts"]
    tmp_path: Path = env["tmp_path"]

    rule, _ = _seed_active_rule(
        repo,
        category=ProcurementFamily.SERVICES,
        title="定期弱點修補與維護管理",
        requirement_text="廠商應每月進行弱點掃描，重大弱點應於30日內完成修補修正。",
    )
    req = repo.get_requirement(rule.rule_id)

    # 1. 建立案件與設定事實 (Case creation & facts setting)
    case_id = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="中央研究院資訊處",
        statutory_category="勞務採購",
        procurement_families=[ProcurementFamily.SERVICES],
        service_scope="套裝軟體與核心資料庫日常維護",
        personal_data_involved=False,
        sensitive_data_involved=True,
        unknown_fields=[],
    )
    review = Review(
        case_id=case_id,
        title="中研院核心系統軟體維護採購合約",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="a" * 64,
        attachments=[],
        facts=facts,
        sensitivity_level="confidential",
        created_by="reviewer_sm",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)

    # 2. 文件擷取與確認 (Document ingestion & confirmation)
    sample_doc = Path("tests/fixtures/synthetic/documents/normal.docx")
    assert sample_doc.exists()
    snapshot = ingest(sample_doc, review_id=case_id, policy=policy, artifacts=artifacts)
    snapshot = segment(snapshot)
    assert len(snapshot.blocks) > 0

    confirmed_snapshot = confirm_text(
        snapshot,
        corrected_blocks=[
            {
                "block_id": snapshot.blocks[0].block_id,
                "raw_text": "中央研究院資訊處軟體維護服務採購合約（已完成承辦人文字校對確認）",
            }
        ],
        actor="reviewer_sm",
    )
    assert confirmed_snapshot.confirmation_ref is not None

    # 3. 規則適用性查核 (Rule applicability check)
    app_decision = evaluate_applicability(rule, facts)
    assert app_decision.state.value == "applicable"

    # 4. 遮罩與補標 (Masking & annotation)
    contract_text = "\n".join(b.raw_text for b in confirmed_snapshot.blocks)
    sess_id = str(uuid.uuid4())
    sess = MaskingSession(
        session_id=sess_id,
        case_id=case_id,
        detector_version="rule-based-0.1.0",
        mapping_vault_ref=f"vault://masking/{case_id}/{sess_id}",
        outbound_hash="",
        human_reviewed=False,
        roundtrip_ok=True,
        blocking_reasons=[],
    )
    draft_initial = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body=contract_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    detector = RuleBasedDetector()
    _masked_draft, sess = mask(draft_initial, sess, detector)

    anno_span = DetectedSpan(
        span_id=str(uuid.uuid4()),
        span_type="ORG",
        entity_group="ORG",
        source_span=SourceSpan(
            document_id=confirmed_snapshot.document_id,
            block_id=confirmed_snapshot.blocks[0].block_id,
            start_offset=0,
            end_offset=8,
        ),
        original_text="中央研究院資訊處",
        masked_token="",
    )
    session = apply_annotations(sess, [anno_span], actor="reviewer_sm")
    assert session.session_id is not None

    # 5. 出站預覽與核准 (Egress payload generation & user approval)
    r_hash = compute_rule_hash(rule)
    rule_ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
    run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run.run_id,
        plaintext_body=contract_text,
        sensitive_token_count=1,
        assembled_at=datetime.now(UTC),
    )
    adapter = MockProviderAdapter()
    prepared = prepare_egress(
        run_id=run.run_id,
        draft=draft,
        session=session,
        detector=detector,
        adapter=adapter,
        repo=repo,
    )
    approval = approve(prepared, actor="reviewer_sm", repo=repo)
    assert approval.approval_id is not None

    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            json={"id": "mock-reply-1", "choices": [{"message": {"content": "ok"}}]},
        )
    )
    dispatch_reply = dispatch(
        prepared.request_id,
        approval.approval_id,
        repo=repo,
        adapter=adapter,
        transport=transport,
    )
    assert dispatch_reply.finish_reason == "stop"

    span = SourceSpan(
        document_id=confirmed_snapshot.document_id,
        block_id=confirmed_snapshot.blocks[0].block_id,
        start_offset=0,
        end_offset=len(contract_text),
        page_number=1,
        structural_path="第一條",
        text=contract_text[:120],
    )
    ctx = ContextBundle(
        requirement_ref=rule_ref,
        source_spans=[span],
        definitions={},
        exceptions=[],
        citations=["第一條 軟體維護服務"],
        document_retrieval_status={"main_contract.docx": "retrieved"},
        complete=True,
        unknowns=[],
    )
    plan_review(run, [ctx], repo=repo)

    review_payload = {
        "run_id": run.run_id,
        "findings": [
            {
                "requirement_id": rule.rule_id,
                "clause_ids": ["clause-1"],
                "result": "concern",
                "risk": "high",
                "reason": "合約未明訂弱點修補時限，建議增訂30日內修補義務。",
                "suggested_action": "增訂弱點修補時限",
                "suggested_clause": "廠商應每月進行弱點掃描，重大弱點應於30日內完成修補修正，違約金為 [待填金額]。",
                "citations": ["第一條 軟體維護服務"],
                "review_scope": "軟體維護",
            }
        ],
    }
    art_id = repo.artifacts.put(
        case_id=case_id, kind="provider_reply", data=json.dumps(review_payload).encode("utf-8")
    )
    reply = ProviderReply(
        reply_id=str(uuid.uuid4()),
        request_id=prepared.request_id,
        artifact_ref=art_id,
        finish_reason="stop",
        latency_ms=80,
    )
    findings = accept_review_reply(run.run_id, reply, repo)
    assert len(findings) == 1
    finding = findings[0]

    # 收尾並計算全量覆蓋矩陣
    matrix = finalize_run(run.run_id, repo)
    assert isinstance(matrix, CoverageMatrix)
    # 核心斷言：條款全數處理完畢，無遺漏
    assert matrix.unprocessed_ids == []

    # 7. 建議修訂條款草稿產製與三層校驗 (Suggested change drafting & validation)
    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run.run_id,
        purpose="增訂弱點修補條款",
        proposed_text="廠商應每月進行弱點掃描，重大弱點應於30日內完成修補修正，違約金為 [待填金額]。",
        affected_clause_ids=["clause-1"],
        basis_rule_refs=[rule_ref],
    )
    val_report = validate_change(change, finding, req)
    assert val_report.structure.ok is True
    assert val_report.source.ok is True
    # 核心設計：實質語意校驗一律保留予人工決定，程式檢驗不擅自標記為 True
    assert val_report.substance.ok is False

    # 8. 人工決定記錄 (Human decision recording: ADOPT)
    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        action=HumanDecisionAction.ADOPT,
        final_text=change.proposed_text,
        reason="採納建議增訂30日修補與違約金規定",
        decided_by="reviewer_sm",
        decided_at=datetime.now(UTC),
        run_id=run.run_id,
    )
    feedback = record_feedback(decision, repo, idempotency_key=f"sm-{case_id}")
    assert feedback.feedback_id is not None

    # 9. 雙模匯出 (Dual-mode export: masked & plaintext)
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run.run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[run.rule_set_snapshot],
        findings=[finding],
        coverage=matrix,
        unresolved_issues=[],
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )

    export_dir = tmp_path / "exports" / case_id
    # 遮罩模式匯出
    export_paths = export_review(report, mode="masked", output_dir=export_dir)
    # 核心斷言：檔案必須實際存在
    assert export_paths.markdown.exists() and export_paths.json.exists()

    # 明文模式匯出 (需經人工確認)
    export_paths_pt = export_review(
        report, mode="plaintext", output_dir=export_dir, confirmed=True
    )
    assert export_paths_pt.markdown.exists() and export_paths_pt.json.exists()


def test_end_to_end_custom_software_missing_attachment(env):
    """四類採購之二：委外開發 (custom_software) 全流程驗收

    注入場景：
    - 刻意缺少必要附件（如資安規範專章 / EULA 授權條款）
    核心斷言：
    - assert matrix.unresolved_ids (驗證缺少附件案之要求處於未解決/待確認狀態)
    - 覆核動作：REJECT 駁回
    """
    repo: Repository = env["repo"]
    policy: RuntimePolicy = env["policy"]
    artifacts: ArtifactStore = env["artifacts"]
    tmp_path: Path = env["tmp_path"]

    rule, _ = _seed_active_rule(
        repo,
        category=ProcurementFamily.DEVELOPMENT,
        title="原始碼與SSDLC安全開發規範",
        requirement_text="委外開發專案應交付完整原始碼並檢附資安專章所列SSDLC掃描報告。",
    )

    # 1. 建立案件與事實 (Case creation)
    case_id = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="計算中心開發組",
        statutory_category="財物暨勞務採購",
        procurement_families=[ProcurementFamily.DEVELOPMENT],
        service_scope="客製化差勤管理系統委外開發",
        personal_data_involved=True,
        sensitive_data_involved=True,
        unknown_fields=["source_code_escrow"],
    )
    review = Review(
        case_id=case_id,
        title="差勤系統委外開發合約",
        contract_type=ProcurementFamily.DEVELOPMENT,
        contract_version="1.0",
        original_file_hash="b" * 64,
        attachments=[],  # 刻意未附資安規範專章附件！
        facts=facts,
        created_by="reviewer_dev",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)

    # 2. 文件擷取與確認
    sample_doc = Path("tests/fixtures/synthetic/documents/normal.docx")
    snapshot = ingest(sample_doc, review_id=case_id, policy=policy, artifacts=artifacts)
    snapshot = segment(snapshot)
    confirmed_snapshot = confirm_text(
        snapshot,
        corrected_blocks=[
            {"block_id": snapshot.blocks[0].block_id, "raw_text": "委外開發契約草案"}
        ],
        actor="reviewer_dev",
    )

    # 3. 規則適用性
    app_decision = evaluate_applicability(rule, facts)
    assert app_decision.state.value == "applicable"

    # 4. 遮罩與標記
    sess_id = str(uuid.uuid4())
    sess = MaskingSession(
        session_id=sess_id,
        case_id=case_id,
        detector_version="rule-based-0.1.0",
        mapping_vault_ref=f"vault://masking/{case_id}/{sess_id}",
        outbound_hash="",
        human_reviewed=False,
        roundtrip_ok=True,
        blocking_reasons=[],
    )
    draft_init = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body=confirmed_snapshot.blocks[0].raw_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    detector = RuleBasedDetector()
    _masked_draft, session = mask(draft_init, sess, detector)

    # 5. 出站審查
    r_hash = compute_rule_hash(rule)
    rule_ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
    run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run.run_id,
        plaintext_body=confirmed_snapshot.blocks[0].raw_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    prepared = prepare_egress(
        run_id=run.run_id,
        draft=draft,
        session=session,
        detector=detector,
        adapter=MockProviderAdapter(),
        repo=repo,
    )
    approval = approve(prepared, actor="reviewer_dev", repo=repo)
    transport = httpx.MockTransport(
        lambda req: httpx.Response(
            200,
            json={"id": "mock-reply-dev", "choices": [{"message": {"content": "ok"}}]},
        )
    )
    dispatch(
        prepared.request_id,
        approval.approval_id,
        repo=repo,
        adapter=MockProviderAdapter(),
        transport=transport,
    )

    # 注入缺少附件情境：ContextBundle 標記 complete=False 與缺少必要文件
    span = SourceSpan(
        document_id=confirmed_snapshot.document_id,
        block_id=confirmed_snapshot.blocks[0].block_id,
        start_offset=0,
        end_offset=len(confirmed_snapshot.blocks[0].raw_text),
        page_number=1,
        structural_path="條文前言",
        text=confirmed_snapshot.blocks[0].raw_text,
    )
    ctx = ContextBundle(
        requirement_ref=rule_ref,
        source_spans=[span],
        definitions={},
        exceptions=[],
        citations=["委外開發契約"],
        document_retrieval_status={"資安規範專章.docx": "missing"},
        complete=False,
        unknowns=["缺少必要文件: 資安規範專章.docx"],
    )
    plan_review(run, [ctx], repo=repo)

    # 模型回覆標示 missing，因缺文件自動轉為 needs_confirmation
    reply_payload = {
        "run_id": run.run_id,
        "findings": [
            {
                "requirement_id": rule.rule_id,
                "clause_ids": [],
                "result": "missing",
                "risk": "high",
                "reason": "合約主文未見原始碼交付條款，且缺少資安規範專章附件。",
                "citations": [],
                "review_scope": "委外開發",
            }
        ],
    }
    art_id = repo.artifacts.put(
        case_id=case_id, kind="provider_reply", data=json.dumps(reply_payload).encode("utf-8")
    )
    reply = ProviderReply(
        reply_id=str(uuid.uuid4()),
        request_id=prepared.request_id,
        artifact_ref=art_id,
        finish_reason="stop",
    )
    findings = accept_review_reply(run.run_id, reply, repo)
    assert findings[0].result == ResultEnum.NEEDS_CONFIRMATION

    # 執行收尾計算覆蓋矩陣
    matrix = finalize_run(run.run_id, repo)

    # 核心斷言：刻意缺件案中，unresolved_ids 必須非空（記錄未解決之要求）
    assert matrix.unresolved_ids
    assert rule.rule_id in matrix.unresolved_ids

    # 人工決定：REJECT 駁回（要求補件重審）
    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=findings[0].finding_id,
        action=HumanDecisionAction.REJECT,
        reason="退件：請承辦單位補附完整資安專章後重新送審",
        decided_by="reviewer_dev",
        decided_at=datetime.now(UTC),
        run_id=run.run_id,
    )
    record_feedback(decision, repo, idempotency_key=f"dev-{case_id}")

    # 匯出報告
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run.run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[run.rule_set_snapshot],
        findings=findings,
        coverage=matrix,
        unresolved_issues=matrix.unresolved_ids,
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )
    export_paths = export_review(report, mode="masked", output_dir=tmp_path / "exports" / case_id)
    assert export_paths.markdown.exists() and export_paths.json.exists()


def test_end_to_end_cloud_service_input_update_invalidation(env):
    """四類採購之三：雲端服務 (cloud_service) 全流程驗收

    注入場景：
    - 輸入改版（Input Update Scenario）：合約改版使舊 Run 標記為 stale，
      新 Run 重新執行，產製新報告。
    核心斷言：
    - assert report.run_id != stale_run.id
    """
    repo: Repository = env["repo"]
    policy: RuntimePolicy = env["policy"]
    artifacts: ArtifactStore = env["artifacts"]
    tmp_path: Path = env["tmp_path"]

    rule, _ = _seed_active_rule(
        repo,
        category=ProcurementFamily.CLOUD,
        title="雲端服務資料在地化儲存",
        requirement_text="雲端運算服務提供者應保證公務機敏資料儲存地點限於我國境內。",
        severity=RiskLevel.CRITICAL,
    )

    # 1. 建立初始案件
    case_id = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="總辦事處資通安全組",
        statutory_category="財物採購",
        procurement_families=[ProcurementFamily.CLOUD],
        service_scope="公有雲端平台運算資源訂閱",
        personal_data_involved=True,
        unknown_fields=[],
    )
    review = Review(
        case_id=case_id,
        title="公有雲端運算採購合約",
        contract_type=ProcurementFamily.CLOUD,
        contract_version="1.0",
        original_file_hash="c" * 64,
        attachments=[],
        facts=facts,
        created_by="reviewer_cloud",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)

    # 文件擷取
    sample_doc = Path("tests/fixtures/synthetic/documents/normal.docx")
    snapshot = ingest(sample_doc, review_id=case_id, policy=policy, artifacts=artifacts)
    snapshot = segment(snapshot)
    confirmed_snapshot = confirm_text(
        snapshot,
        corrected_blocks=[
            {"block_id": snapshot.blocks[0].block_id, "raw_text": "雲端服務條款 v1.0"}
        ],
        actor="reviewer_cloud",
    )

    # 第一輪審查執行 (Run 1 -> 隨後將被廢棄)
    r_hash = compute_rule_hash(rule)
    rule_ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
    stale_run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    # 注入輸入改版場景：使用者上傳更新版合約或修改案件事實
    # 觸發失效機制
    repo.invalidate(case_id, reason="INPUT_REVISION_V2")
    stale_run_reloaded = repo.get_run(stale_run.run_id)
    assert stale_run_reloaded.stale is True

    # 重新發起第二輪審查 (Run 2)
    new_run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])
    assert new_run.stale is False
    assert new_run.run_id != stale_run.run_id

    # 執行第二輪審查管線
    span = SourceSpan(
        document_id=confirmed_snapshot.document_id,
        block_id=confirmed_snapshot.blocks[0].block_id,
        start_offset=0,
        end_offset=len(confirmed_snapshot.blocks[0].raw_text),
        page_number=1,
        structural_path="第三條",
        text="第三條 資料儲存地點：全球多區域伺服器動態調配。",
    )
    ctx = ContextBundle(
        requirement_ref=rule_ref,
        source_spans=[span],
        definitions={},
        exceptions=[],
        citations=["第三條 資料儲存地點"],
        document_retrieval_status={"main_contract.docx": "retrieved"},
        complete=True,
        unknowns=[],
    )
    plan_review(new_run, [ctx], repo=repo)

    reply_payload = {
        "run_id": new_run.run_id,
        "findings": [
            {
                "requirement_id": rule.rule_id,
                "clause_ids": ["clause-3"],
                "result": "concern",
                "risk": "critical",
                "reason": "合約約定全球動態調配，違反機敏資料限我國境內儲存之規定。",
                "suggested_action": "修改條款限制於境內資料中心",
                "suggested_clause": "雲端運算服務提供者應保證公務機敏資料儲存地點限於我國境內資料中心。",
                "citations": ["第三條 資料儲存地點"],
                "review_scope": "雲端服務",
            }
        ],
    }
    art_id = repo.artifacts.put(
        case_id=case_id, kind="provider_reply", data=json.dumps(reply_payload).encode("utf-8")
    )
    reply = ProviderReply(
        reply_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        artifact_ref=art_id,
        finish_reason="stop",
    )
    findings = accept_review_reply(new_run.run_id, reply, repo)
    matrix = finalize_run(new_run.run_id, repo)
    assert matrix.unprocessed_ids == []

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=findings[0].finding_id,
        action=HumanDecisionAction.ADOPT,
        final_text=findings[0].suggested_clause,
        reason="採納建議修正儲存地限制",
        decided_by="reviewer_cloud",
        decided_at=datetime.now(UTC),
        run_id=new_run.run_id,
    )
    record_feedback(decision, repo, idempotency_key=f"cloud-{case_id}")

    # 產製報告
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=new_run.run_id,
        case_version="2.0",
        sensitivity_level="confidential",
        source_manifest=[new_run.rule_set_snapshot],
        findings=findings,
        coverage=matrix,
        unresolved_issues=[],
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )

    # 核心斷言：報告綁定新 Run ID，舊 Run 不得混入新報告
    assert report.run_id != stale_run.id
    assert report.run_id == new_run.run_id

    export_paths = export_review(report, mode="masked", output_dir=tmp_path / "exports" / case_id)
    assert export_paths.markdown.exists() and export_paths.json.exists()


def test_end_to_end_mixed_procurement_interruption_recovery(env):
    """四類採購之四：混合型採購 (mixed procurement) 全流程驗收

    涵蓋：服務維護 ＋ 雲端託管之混合情境
    注入場景：
    - 程序中斷情境（Process Interruption Scenario）：
      Run 處於 RUNNING 狀態時系統崩潰或重啟，重啟後自動標記為 INTERRUPTED，
      系統乾淨復原，承辦人可復原後順利收尾。
    核心斷言：
    - assert interrupted_run.state == RunState.INTERRUPTED
    - 人工決定：MODIFY 修改條款
    - assert matrix.unprocessed_ids == []
    - assert export_paths.markdown.exists() and export_paths.json.exists()
    """
    repo: Repository = env["repo"]
    policy: RuntimePolicy = env["policy"]
    artifacts: ArtifactStore = env["artifacts"]
    tmp_path: Path = env["tmp_path"]

    rule, _ = _seed_active_rule(
        repo,
        category=ProcurementFamily.SERVICES,
        title="混合雲存取日誌側錄稽核",
        requirement_text="混合雲維運連線應啟用雙因子驗證並留存操作稽核日誌至少一年。",
    )

    # 1. 建立混合案件 (Mixed facts: services + cloud)
    case_id = str(uuid.uuid4())
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        procurement_unit="資訊科學研究所",
        statutory_category="財物暨勞務混合採購",
        procurement_families=[ProcurementFamily.SERVICES, ProcurementFamily.CLOUD],
        service_scope="核心地端機房與混合雲端平台整合維運",
        personal_data_involved=False,
        sensitive_data_involved=True,
        unknown_fields=[],
    )
    review = Review(
        case_id=case_id,
        title="中研院混合雲維運勞務採購合約",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="d" * 64,
        attachments=[],
        facts=facts,
        created_by="reviewer_mixed",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)

    # 2. 文件擷取與確認
    sample_doc = Path("tests/fixtures/synthetic/documents/normal.docx")
    snapshot = ingest(sample_doc, review_id=case_id, policy=policy, artifacts=artifacts)
    snapshot = segment(snapshot)
    confirmed_snapshot = confirm_text(
        snapshot,
        corrected_blocks=[
            {"block_id": snapshot.blocks[0].block_id, "raw_text": "混合雲維運管理合約本文"}
        ],
        actor="reviewer_mixed",
    )

    # 3. 建立執行管線並模擬執行中
    r_hash = compute_rule_hash(rule)
    rule_ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
    run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    running_run = run.model_copy(update={"state": RunState.RUNNING})
    repo.save_run(running_run)
    assert repo.get_run(run.run_id).state == RunState.RUNNING

    # 注入程序中斷情境：模擬伺服器崩潰中斷重啟
    # 建立新 app 實例執行重啟恢復檢查
    create_app(policy=policy, repo=repo)

    interrupted_run = repo.get_run(run.run_id)
    # 核心斷言：中斷之 run 乾淨標示為 interrupted
    assert interrupted_run.state == RunState.INTERRUPTED
    assert interrupted_run.invalidation_reason == "SERVER_RESTARTED"

    # 復原重新執行 (Recovery)
    recovered_run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])
    assert recovered_run.state == RunState.PLANNED

    span = SourceSpan(
        document_id=confirmed_snapshot.document_id,
        block_id=confirmed_snapshot.blocks[0].block_id,
        start_offset=0,
        end_offset=len(confirmed_snapshot.blocks[0].raw_text),
        page_number=1,
        structural_path="第八條",
        text=confirmed_snapshot.blocks[0].raw_text,
    )
    ctx = ContextBundle(
        requirement_ref=rule_ref,
        source_spans=[span],
        definitions={},
        exceptions=[],
        citations=["第八條 混合雲維運管理"],
        document_retrieval_status={"main_contract.docx": "retrieved"},
        complete=True,
        unknowns=[],
    )
    plan_review(recovered_run, [ctx], repo=repo)

    reply_payload = {
        "run_id": recovered_run.run_id,
        "findings": [
            {
                "requirement_id": rule.rule_id,
                "clause_ids": ["clause-8"],
                "result": "concern",
                "risk": "high",
                "reason": "合約僅約定日誌留存半年，低於院內要求之一年。",
                "suggested_action": "延長日誌留存期限為一年並要求雙因子驗證",
                "suggested_clause": "混合雲維運連線應啟用雙因子驗證並留存操作稽核日誌至少一年，違約金為 [待填金額]。",
                "citations": ["第八條 混合雲維運管理"],
                "review_scope": "混合型採購",
            }
        ],
    }
    art_id = repo.artifacts.put(
        case_id=case_id, kind="provider_reply", data=json.dumps(reply_payload).encode("utf-8")
    )
    reply = ProviderReply(
        reply_id=str(uuid.uuid4()),
        request_id=str(uuid.uuid4()),
        artifact_ref=art_id,
        finish_reason="stop",
    )
    findings = accept_review_reply(recovered_run.run_id, reply, repo)
    matrix = finalize_run(recovered_run.run_id, repo)
    # 核心斷言：全量條款均已涵蓋處理
    assert matrix.unprocessed_ids == []

    # 人工決定：MODIFY 自行修訂條款
    custom_modified_text = "混合雲維運連線應啟用雙因子驗證並留存操作稽核日誌至少二年，並定期送交稽核。"
    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=findings[0].finding_id,
        action=HumanDecisionAction.MODIFY,
        final_text=custom_modified_text,
        reason="基於資安考量，主動由一年加嚴延長為二年",
        decided_by="reviewer_mixed",
        decided_at=datetime.now(UTC),
        run_id=recovered_run.run_id,
    )
    record_feedback(decision, repo, idempotency_key=f"mixed-{case_id}")

    # 產製報告並匯出
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=recovered_run.run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[recovered_run.rule_set_snapshot],
        findings=findings,
        coverage=matrix,
        unresolved_issues=[],
        human_decisions=[decision],
        generated_at=datetime.now(UTC),
    )
    export_paths = export_review(report, mode="masked", output_dir=tmp_path / "exports" / case_id)
    assert export_paths.markdown.exists() and export_paths.json.exists()
