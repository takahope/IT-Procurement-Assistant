import uuid
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from procurement_review.domain.enums import (
    ProcurementFamily,
    RiskLevel,
    RuleStatus,
    RunState,
    RuntimeMode,
    SourceNature,
)
from procurement_review.domain.models import (
    CaseFacts,
    Review,
    Rule,
    RuntimePolicy,
    SourceReference,
    VersionRef,
)
from procurement_review.rules.catalog import compute_rule_hash
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore
from procurement_review.web.app import create_app


@pytest.fixture
def e2e_env(tmp_path: Path):
    vault_root = tmp_path / "vault"
    db_path = tmp_path / "e2e_test.db"
    secrets = FakeSecretStore()
    artifacts = ArtifactStore(root=vault_root, secrets=secrets)
    repo = Repository(db=db_path, artifacts=artifacts)
    policy = RuntimePolicy(mode=RuntimeMode.SYNTHETIC, data_root=str(tmp_path))
    app = create_app(policy=policy, repo=repo)
    client = TestClient(app, base_url="http://localhost:8765")
    return {
        "app": app,
        "repo": repo,
        "policy": policy,
        "client": client,
        "tmp_path": tmp_path,
        "bootstrap_token": app.state.bootstrap_token,
    }


def test_complete_review_journey(e2e_env):
    """端到端完整審查流程：

    建混合案件 -> 匯入/確認 -> 補遮 -> 預覽核准 -> mock審查 -> 驗證變更 -> 人工決定 -> 匯出
    """
    client: TestClient = e2e_env["client"]
    token: str = e2e_env["bootstrap_token"]
    repo: Repository = e2e_env["repo"]

    # 1. Local session bootstrap
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200
    csrf_token = resp.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 2. 建立混合案件 (Create mixed case)
    case_payload = {
        "title": "中研院資訊系統混合雲維運勞務採購合約",
        "contract_type": "services",
        "contract_version": "1.0",
        "facts": {
            "procurement_unit": "中央研究院資訊科學研究所",
            "review_baseline_date": "2026-10-15",
            "statutory_category": "勞務採購",
            "procurement_families": ["services"],
            "service_scope": "核心雲端伺服器與地端網路系統日常維運",
            "personal_data_involved": False,
            "sensitive_data_involved": True,
            "unknown_fields": ["remote_access"],
        },
    }
    resp_create = client.post("/api/cases", headers=headers, json=case_payload)
    assert resp_create.status_code == 200
    case_data = resp_create.json()
    case_id = case_data["case_id"]
    assert case_id is not None

    # 3. 匯入文件 (Ingest document)
    sample_doc_path = Path("tests/fixtures/synthetic/documents/normal.docx")
    assert sample_doc_path.exists(), "Sample docx fixture must exist"

    with open(sample_doc_path, "rb") as f:
        resp_upload = client.post(
            f"/api/cases/{case_id}/documents/upload",
            headers=headers,
            files={
                "file": (
                    sample_doc_path.name,
                    f,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
        )
    assert resp_upload.status_code == 200
    doc_info = resp_upload.json()
    assert "blocks" in doc_info
    assert len(doc_info["blocks"]) > 0

    # 檢查 documents 頁面呈現，確認包含待確認或正常區塊
    resp_doc_page = client.get(f"/cases/{case_id}/documents")
    assert resp_doc_page.status_code == 200
    assert "待確認" in resp_doc_page.text

    # 4. 人工文字確認 (Confirm text)
    # 取出第一個 block 進行人工校正與確認
    first_block = doc_info["blocks"][0]
    corrected_text = "資訊科學研究所採購契約 【人工已查核校正】"
    resp_confirm = client.post(
        f"/api/cases/{case_id}/documents/confirm",
        headers=headers,
        json={
            "corrected_blocks": [{"block_id": first_block["block_id"], "raw_text": corrected_text}]
        },
    )
    assert resp_confirm.status_code == 200
    confirm_data = resp_confirm.json()
    assert confirm_data["confirmation_ref"] is not None

    # 5. 補遮 / 標記 (Annotate & Masking)
    resp_mask = client.get(f"/api/cases/{case_id}/masking")
    assert resp_mask.status_code == 200

    # 手動增加標記
    resp_anno = client.post(
        f"/api/cases/{case_id}/masking/annotate",
        headers=headers,
        json={
            "annotations": [
                {
                    "entity_type": "ORG",
                    "original_text": "資訊科學研究所",
                    "start": 0,
                    "end": 7,
                }
            ]
        },
    )
    assert resp_anno.status_code == 200
    anno_data = resp_anno.json()
    assert "session_id" in anno_data

    # 6. 預覽與核准出站 (Preview & Approve Egress)
    resp_draft = client.get(f"/api/cases/{case_id}/egress/draft")
    assert resp_draft.status_code == 200
    draft_data = resp_draft.json()
    assert "request_id" in draft_data

    # 執行核准
    resp_approve = client.post(
        f"/api/cases/{case_id}/egress/approve",
        headers=headers,
        json={"request_id": draft_data["request_id"]},
    )
    assert resp_approve.status_code == 200
    approval_data = resp_approve.json()
    assert "approval_id" in approval_data

    # 7. 執行 mock 審查 (Run mock review)
    # 註冊一條 active 規則以供審查引用
    src_id = str(uuid.uuid4())
    rule_id = str(uuid.uuid4())
    source = SourceReference(
        source_id=src_id,
        kind=SourceNature.STANDARD_TEMPLATE,
        title="資通安全合約範本標準",
        issuer="資通安全處",
        locator="第10條",
        section="資安稽核",
        version="1.0",
        verified_at=datetime.now(UTC),
        verified_by="審核法務A",
        content_hash="hash123",
    )
    repo.save_source(source)
    rule = Rule(
        rule_id=rule_id,
        version="1.0",
        status=RuleStatus.ACTIVE,
        category=ProcurementFamily.SERVICES,
        title="廠商委外資安稽核要求",
        requirement_text="廠商應配合甲方每年定期資安稽核，並於30日內提交改善報告。",
        severity=RiskLevel.HIGH,
        mandatory=True,
        source_refs=[
            VersionRef(id=source.source_id, version=source.version, sha256=source.content_hash)
        ],
        approved_by="法務主管",
    )
    repo.save_rule(rule)

    resp_run = client.post(
        f"/api/cases/{case_id}/review/start",
        headers=headers,
        json={},
    )
    assert resp_run.status_code == 200
    run_data = resp_run.json()
    run_id = run_data["run_id"]
    assert run_id is not None
    assert run_data.get("status") == "running"
    task_id = run_data.get("task_id")
    assert task_id is not None

    # 等待背景任務執行完成
    import time

    for _ in range(50):
        t_resp = client.get(f"/api/tasks/{task_id}")
        assert t_resp.status_code == 200
        t_data = t_resp.json()
        if t_data.get("status") == "completed":
            break
        time.sleep(0.05)
    else:
        pytest.fail("Background review task did not complete in time")

    # 檢視審查狀態與 findings
    resp_findings = client.get(f"/api/cases/{case_id}/review/findings")
    assert resp_findings.status_code == 200
    findings_data = resp_findings.json()
    assert "findings" in findings_data
    assert len(findings_data["findings"]) > 0
    target_finding = findings_data["findings"][0]

    # 8. 條款修改草稿驗證 (Validate change)
    resp_validate = client.post(
        f"/api/cases/{case_id}/review/validate-change",
        headers=headers,
        json={
            "finding_id": target_finding["finding_id"],
            "proposed_text": "廠商應配合每年資安稽核，並於30日內提交改善報告，違約金為 [待填金額]。",
        },
    )
    assert resp_validate.status_code == 200
    val_data = resp_validate.json()
    assert val_data["structure"]["ok"] is True

    # 驗證違規偷改天數（如 30日 偷改為 3日）應被擋下
    resp_validate_bad = client.post(
        f"/api/cases/{case_id}/review/validate-change",
        headers=headers,
        json={
            "finding_id": target_finding["finding_id"],
            "proposed_text": "廠商應配合每年資安稽核，並於3日提交改善報告。",
        },
    )
    assert resp_validate_bad.status_code == 200
    val_bad_data = resp_validate_bad.json()
    assert val_bad_data["structure"]["ok"] is False

    # 9. 記錄人工決定 (Record human decision)
    resp_decision = client.post(
        f"/api/cases/{case_id}/review/decision",
        headers=headers,
        json={
            "finding_id": target_finding["finding_id"],
            "run_id": run_id,
            "status": "accepted",
            "clause_id": target_finding.get("clause_id", "clause-1"),
            "modified_clause_text": "廠商應配合每年資安稽核，並於30日內提交改善報告，違約金為 [待填金額]。",
            "note": "採納審查建議並補入待填金額標籤",
            "idempotency_key": "decision-k1",
        },
    )
    assert resp_decision.status_code == 200
    decision_data = resp_decision.json()
    assert decision_data["status"] == "ok"

    # 10. 報告安全匯出 (Export report - masked & plaintext)
    # 遮罩模式匯出
    resp_export_masked = client.post(
        f"/api/cases/{case_id}/export",
        headers=headers,
        json={"mode": "masked", "confirmed": False},
    )
    assert resp_export_masked.status_code == 200
    masked_export = resp_export_masked.json()
    assert "download_token" in masked_export

    # 明文模式未確認 -> 400
    resp_export_pt_unconfirmed = client.post(
        f"/api/cases/{case_id}/export",
        headers=headers,
        json={"mode": "plaintext", "confirmed": False},
    )
    assert resp_export_pt_unconfirmed.status_code == 400

    # 明文模式明確確認 -> 200
    resp_export_pt = client.post(
        f"/api/cases/{case_id}/export",
        headers=headers,
        json={"mode": "plaintext", "confirmed": True},
    )
    assert resp_export_pt.status_code == 200
    pt_export = resp_export_pt.json()
    assert "download_token" in pt_export

    # 下載匯出報告
    resp_dl = client.get(
        f"/api/cases/{case_id}/export/download",
        params={"file": pt_export["filename"]},
    )
    assert resp_dl.status_code == 200
    assert len(resp_dl.text) > 0


def test_rules_page_and_lifecycle_management(e2e_env):
    """規則頁提供原文對照、人工送審、核准發布及撤銷，且撤銷會使引用該規則之 run 標記為 stale。"""
    client: TestClient = e2e_env["client"]
    token: str = e2e_env["bootstrap_token"]
    repo: Repository = e2e_env["repo"]

    # Bootstrap session
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    csrf_token = resp.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 1. 建立已查核法源
    src_id = str(uuid.uuid4())
    rule_id = str(uuid.uuid4())
    source = SourceReference(
        source_id=src_id,
        kind=SourceNature.STANDARD_TEMPLATE,
        title="政府採購共通性資安規範",
        issuer="數位發展部",
        locator="第5條",
        section="雲端服務",
        version="1.0",
        verified_at=datetime.now(UTC),
        verified_by="法務查核員A",
        content_hash="abc12345",
    )
    repo.save_source(source)

    # 2. 建立 pending_approval 規則
    pending_rule = Rule(
        rule_id=rule_id,
        version="1.0",
        status=RuleStatus.PENDING_APPROVAL,
        category=ProcurementFamily.SERVICES,
        title="雲端服務儲存地限制",
        requirement_text="雲端運算服務資料儲存地點應於我國境內。",
        severity=RiskLevel.CRITICAL,
        mandatory=True,
        source_refs=[
            VersionRef(id=source.source_id, version=source.version, sha256=source.content_hash)
        ],
    )
    repo.save_rule(pending_rule)

    # 檢視 rules 頁面
    resp_page = client.get("/rules")
    assert resp_page.status_code == 200
    assert "政府採購共通性資安規範" in resp_page.text

    # 3. 核准發布規則 (Release rule)
    resp_rel = client.post(
        "/api/rules/release",
        headers=headers,
        json={
            "rules": [pending_rule.model_dump(mode="json")],
            "sources": [source.model_dump(mode="json")],
        },
    )
    assert resp_rel.status_code == 200

    # 驗證規則已被發布為 active
    released = repo.get_rule(pending_rule.rule_id, pending_rule.version)
    assert released.status == RuleStatus.ACTIVE
    assert released.approved_by == "local_reviewer"

    # 測試透過 release-btn 格式之 payload ({ "rule_id": rule_id, "version": ver }) 核准發布
    pending_rule_btn = Rule(
        rule_id=str(uuid.uuid4()),
        version="1.0",
        status=RuleStatus.PENDING_APPROVAL,
        category=ProcurementFamily.SERVICES,
        title="按鈕發布測試規則",
        requirement_text="系統應每年進行弱點掃描。",
        severity=RiskLevel.MEDIUM,
        mandatory=False,
        source_refs=[
            VersionRef(id=source.source_id, version=source.version, sha256=source.content_hash)
        ],
    )
    repo.save_rule(pending_rule_btn)

    resp_rel_btn = client.post(
        "/api/rules/release",
        headers=headers,
        json={"rule_id": pending_rule_btn.rule_id, "version": pending_rule_btn.version},
    )
    assert resp_rel_btn.status_code == 200
    released_btn = repo.get_rule(pending_rule_btn.rule_id, pending_rule_btn.version)
    assert released_btn.status == RuleStatus.ACTIVE

    # 4. 建立使用該規則之 Case & Run
    r_hash = compute_rule_hash(released)
    rule_ref = VersionRef(id=released.rule_id, version=released.version, sha256=r_hash)
    case_resp = client.post(
        "/api/cases",
        headers=headers,
        json={
            "title": "雲端儲存測試案",
            "contract_type": "services",
            "facts": {
                "procurement_unit": "計算中心",
                "review_baseline_date": "2026-10-15",
                "procurement_families": ["services"],
            },
        },
    )
    c_id = case_resp.json()["case_id"]
    test_run = repo.create_run(review_id=c_id, rule_refs=[rule_ref])
    assert test_run.stale == 0

    # 5. 撤銷規則 (Revoke rule)
    resp_revoke = client.post(
        f"/api/rules/{released.rule_id}/revoke",
        headers=headers,
        json={"version": released.version, "reason": "法規已於新年度廢止修訂"},
    )
    assert resp_revoke.status_code == 200
    revoke_data = resp_revoke.json()
    assert test_run.run_id in revoke_data["invalidated_runs"]

    # 驗證 run 已被標記為 stale
    reloaded_run = repo.get_run(test_run.run_id)
    assert reloaded_run.stale == 1


def test_server_restart_recovers_cleanly_and_marks_interrupted(tmp_path: Path):
    """伺服器重啟或崩潰：自動將 running 之 runs 標記為 interrupted，乾淨恢復。"""
    vault_root = tmp_path / "vault"
    db_path = tmp_path / "restart_test.db"
    secrets = FakeSecretStore()
    artifacts = ArtifactStore(root=vault_root, secrets=secrets)
    repo = Repository(db=db_path, artifacts=artifacts)
    policy = RuntimePolicy(mode=RuntimeMode.SYNTHETIC, data_root=str(tmp_path))

    # 建立一個 review 與處於 running 的 run
    case_id = str(uuid.uuid4())
    review = Review(
        case_id=case_id,
        title="重啟復原測試案",
        contract_type=ProcurementFamily.SERVICES,
        contract_version="1.0",
        original_file_hash="feedbeef" * 8,
        attachments=[],
        facts=CaseFacts(
            review_baseline_date="2026-10-15",
            procurement_unit="測試部",
            procurement_families=[ProcurementFamily.SERVICES],
        ),
        created_by="tester",
        created_at=datetime.now(UTC),
    )
    repo.save_review(review, expected_revision=None)
    rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="abc" * 21 + "1")
    run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    # 模擬該 run 正在執行中 (running)
    running_run = run.model_copy(update={"state": RunState.RUNNING})
    repo.save_run(running_run)
    assert repo.get_run(run.run_id).state == RunState.RUNNING

    # 重啟服務：呼叫 create_app 重新初始化
    app = create_app(policy=policy, repo=repo)
    _ = TestClient(app, base_url="http://localhost:8765")

    # 驗證先前處於 running 的 run 已被標記為 interrupted
    restored_run = repo.get_run(run.run_id)
    assert restored_run.state == RunState.INTERRUPTED
    assert restored_run.invalidation_reason == "SERVER_RESTARTED"


def test_document_snapshot_restored_from_vault_after_restart(e2e_env):
    """驗證重啟伺服器或清空記憶體快取後，文件快照與條款能自 Vault 恢復載入並正常呈現。"""
    from procurement_review.web.routes import _document_snapshots

    client: TestClient = e2e_env["client"]
    token: str = e2e_env["bootstrap_token"]

    # 1. Bootstrap session
    resp = client.post("/api/auth/bootstrap", json={"token": token})
    assert resp.status_code == 200
    csrf_token = resp.json()["csrf_token"]
    headers = {"X-CSRF-Token": csrf_token}

    # 2. 建立案件
    case_resp = client.post(
        "/api/cases",
        headers=headers,
        json={
            "title": "快照持久化與重啟恢復測試案",
            "contract_type": "services",
            "facts": {
                "procurement_unit": "計算中心",
                "review_baseline_date": "2026-10-15",
                "procurement_families": ["services"],
            },
        },
    )
    assert case_resp.status_code == 200
    case_id = case_resp.json()["case_id"]

    # 3. 上傳文件
    sample_doc_path = Path("tests/fixtures/synthetic/documents/normal.docx")
    assert sample_doc_path.exists()
    with open(sample_doc_path, "rb") as f:
        resp_upload = client.post(
            f"/api/cases/{case_id}/documents/upload",
            headers=headers,
            files={
                "file": (
                    sample_doc_path.name,
                    f,
                    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                )
            },
        )
    assert resp_upload.status_code == 200
    assert case_id in _document_snapshots

    # 4. 模擬伺服器重啟：清空記憶體中的 _document_snapshots 快取
    _document_snapshots.clear()
    assert case_id not in _document_snapshots

    # 5. 存取 documents 頁面，驗證從 Vault 解密還原 snapshot 與條款
    resp_doc_page = client.get(f"/cases/{case_id}/documents")
    assert resp_doc_page.status_code == 200
    assert "待確認" in resp_doc_page.text
    assert "區塊 ID:" in resp_doc_page.text
    assert "文件結構與區塊清單" in resp_doc_page.text

    # 6. 驗證快取已被重建，且 API 能正常取得還原後的文件區塊
    assert case_id in _document_snapshots
    resp_doc_api = client.get(f"/api/cases/{case_id}/documents", headers=headers)
    assert resp_doc_api.status_code == 200
    doc_json = resp_doc_api.json()
    assert len(doc_json["blocks"]) > 0
    assert doc_json["content_sha256"] is not None

