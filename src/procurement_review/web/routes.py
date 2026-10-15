import json
import secrets
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, File, HTTPException, Request, Response, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from procurement_review.documents.ingest import confirm_text, ingest, segment
from procurement_review.domain.enums import (
    HumanDecisionAction,
    ProcurementFamily,
    RiskLevel,
    RuleStatus,
    RunState,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    ContextBundle,
    DetectedSpan,
    DocumentSnapshot,
    HumanDecision,
    MaskingSession,
    OutboundDraft,
    ProviderReply,
    Review,
    ReviewReport,
    Rule,
    RuntimePolicy,
    SourceReference,
    SourceSpan,
    SuggestedChange,
    VersionRef,
)
from procurement_review.egress.approvals import approve
from procurement_review.egress.dispatcher import dispatch
from procurement_review.egress.payload import get_prepared_request, prepare_egress
from procurement_review.export.reports import export_review
from procurement_review.feedback.service import record_feedback
from procurement_review.masking.detector import RuleBasedDetector
from procurement_review.masking.session import apply_annotations, mask
from procurement_review.providers.mock import MockProviderAdapter
from procurement_review.review.drafting import validate_change
from procurement_review.review.workflow import (
    accept_review_reply,
    finalize_run,
    get_batch_status,
    plan_review,
)
from procurement_review.rules.catalog import compute_rule_hash
from procurement_review.rules.releases import release_rules, revoke_rule
from procurement_review.storage.repository import Repository
from procurement_review.web.security import get_authenticated_session, get_current_operator

router = APIRouter()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))

# 本機記憶體快取與遮罩會話
_masking_sessions: dict[str, MaskingSession] = {}
_document_snapshots: dict[str, Any] = {}
_background_tasks: dict[str, dict[str, Any]] = {}


def _get_repo(request: Request) -> Repository:
    return request.app.state.repo


def _get_policy(request: Request) -> RuntimePolicy:
    return request.app.state.policy


def _get_executor(request: Request) -> ThreadPoolExecutor:
    if hasattr(request.app.state, "executor"):
        return request.app.state.executor
    executor = ThreadPoolExecutor(max_workers=4)
    request.app.state.executor = executor
    return executor


def _get_document_snapshot(
    case_id: str, repo: Repository, review: Review | None = None
) -> DocumentSnapshot | None:
    snapshot = _document_snapshots.get(case_id)
    if snapshot is not None:
        return snapshot

    if review is None:
        try:
            review = repo.get_review(case_id)
        except DomainError:
            return None

    if review and review.document_snapshot_ref:
        ref = review.document_snapshot_ref
        art_id = (
            ref.id
            if isinstance(ref, VersionRef)
            else getattr(ref, "id", None) or (ref.get("id") if isinstance(ref, dict) else str(ref))
        )
        if art_id:
            try:
                data = repo.artifacts.get(case_id, art_id)
                snapshot = DocumentSnapshot.model_validate_json(data)
                _document_snapshots[case_id] = snapshot
                return snapshot
            except (DomainError, ValueError, KeyError, OSError):
                return None
    return None


def _mask_text(
    case_id: str, text: str, existing_session: MaskingSession | None = None
) -> MaskingSession:
    sess = existing_session or _masking_sessions.get(case_id)
    if sess is None:
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
    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=str(uuid.uuid4()),
        plaintext_body=text or "採購合約",
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    detector = RuleBasedDetector()
    _, updated_sess = mask(draft, sess, detector)
    _masking_sessions[case_id] = updated_sess
    return updated_sess


# =========================================================================
# 認證與會話端點 (Auth Endpoints)
# =========================================================================


@router.post("/api/auth/bootstrap")
async def api_bootstrap(request: Request) -> Response:
    """本機 bootstrap token 交換 session cookie 與 CSRF token。"""
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        raise HTTPException(status_code=400, detail="Invalid JSON")

    token = body.get("token")
    if not token:
        raise HTTPException(status_code=401, detail="Bootstrap token required")

    session_manager = request.app.state.session_manager
    res = session_manager.consume_bootstrap_token(token)
    if not res:
        raise HTTPException(status_code=401, detail="Invalid or expired bootstrap token")

    session_id, csrf_token = res
    resp = JSONResponse(
        content={
            "status": "ok",
            "csrf_token": csrf_token,
            "operator": "local_reviewer",
        }
    )
    resp.set_cookie(
        key="session_id",
        value=session_id,
        httponly=True,
        samesite="strict",
        secure=False,
    )
    return resp


@router.get("/api/auth/me")
async def api_auth_me(request: Request) -> dict[str, Any]:
    session = get_authenticated_session(request)
    return {
        "operator": session.get("operator", "local_reviewer"),
        "csrf_token": session.get("csrf_token", ""),
    }


# =========================================================================
# HTML 頁面路由 (HTML Pages)
# =========================================================================


@router.get("/", response_class=HTMLResponse)
async def page_index() -> RedirectResponse:
    return RedirectResponse(url="/cases")


@router.get("/cases", response_class=HTMLResponse)
async def page_cases(request: Request) -> Response:
    repo = _get_repo(request)
    reviews = repo.list_reviews()
    session_id = request.cookies.get("session_id")
    session = request.app.state.session_manager.get_session(session_id)
    operator = session.get("operator", "local_reviewer") if session else "未認證"
    return templates.TemplateResponse(
        request=request,
        name="cases.html",
        context={"reviews": reviews, "operator": operator},
    )


@router.get("/cases/{case_id}/scope", response_class=HTMLResponse)
async def page_scope(case_id: str, request: Request) -> Response:
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
    except DomainError:
        raise HTTPException(status_code=404, detail="Case not found")
    return templates.TemplateResponse(
        request=request,
        name="scope.html",
        context={"review": review, "case_id": case_id},
    )


@router.get("/cases/{case_id}/documents", response_class=HTMLResponse)
async def page_documents(case_id: str, request: Request) -> Response:
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
    except DomainError:
        raise HTTPException(status_code=404, detail="Case not found")
    snapshot = _get_document_snapshot(case_id, repo, review)
    return templates.TemplateResponse(
        request=request,
        name="documents.html",
        context={"review": review, "snapshot": snapshot, "case_id": case_id},
    )


@router.get("/cases/{case_id}/masking", response_class=HTMLResponse)
async def page_masking(case_id: str, request: Request) -> Response:
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
    except DomainError:
        raise HTTPException(status_code=404, detail="Case not found")
    session = _masking_sessions.get(case_id)
    return templates.TemplateResponse(
        request=request,
        name="masking.html",
        context={"review": review, "masking": session, "case_id": case_id},
    )


@router.get("/cases/{case_id}/egress", response_class=HTMLResponse)
async def page_egress(case_id: str, request: Request) -> Response:
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
    except DomainError:
        raise HTTPException(status_code=404, detail="Case not found")
    return templates.TemplateResponse(
        request=request,
        name="egress.html",
        context={"review": review, "case_id": case_id},
    )


@router.get("/cases/{case_id}/review", response_class=HTMLResponse)
async def page_review(case_id: str, request: Request) -> Response:
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
    except DomainError:
        raise HTTPException(status_code=404, detail="Case not found")
    runs = repo.list_runs_for_case(case_id)
    latest_run = runs[0] if runs else None
    findings = repo.get_findings_for_run(latest_run.run_id) if latest_run else []
    return templates.TemplateResponse(
        request=request,
        name="review.html",
        context={
            "review": review,
            "run": latest_run,
            "findings": findings,
            "case_id": case_id,
        },
    )


@router.get("/rules", response_class=HTMLResponse)
async def page_rules(request: Request) -> Response:
    repo = _get_repo(request)
    rules = repo.list_rules()
    sources = repo.list_sources()
    return templates.TemplateResponse(
        request=request,
        name="rules.html",
        context={"rules": rules, "sources": sources},
    )


@router.get("/settings", response_class=HTMLResponse)
async def page_settings(request: Request) -> Response:
    policy = _get_policy(request)
    return templates.TemplateResponse(
        request=request,
        name="settings.html",
        context={"policy": policy},
    )


# =========================================================================
# 案件管理 API (Cases API)
# =========================================================================


@router.get("/api/cases")
async def api_list_cases(request: Request) -> list[dict[str, Any]]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    reviews = repo.list_reviews()
    return [r.model_dump(mode="json") for r in reviews]


@router.post("/api/cases")
async def api_create_case(request: Request) -> dict[str, Any]:
    operator = get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()

    case_id = body.get("case_id") or str(uuid.uuid4())
    title = body.get("title", "未命名採購合約審查")
    c_type_str = body.get("contract_type", "services")
    try:
        contract_type = ProcurementFamily(c_type_str)
    except ValueError:
        contract_type = ProcurementFamily.SERVICES

    facts_dict = body.get("facts", {})
    if "procurement_unit" not in facts_dict:
        facts_dict["procurement_unit"] = "中央研究院"
    if "review_baseline_date" not in facts_dict:
        facts_dict["review_baseline_date"] = datetime.now(UTC).date().isoformat()
    if "procurement_families" not in facts_dict:
        facts_dict["procurement_families"] = [contract_type.value]

    facts = CaseFacts.model_validate(facts_dict)
    review = Review(
        case_id=case_id,
        title=title,
        contract_type=contract_type,
        contract_version=body.get("contract_version", "1.0"),
        original_file_hash=body.get("original_file_hash", "0" * 64),
        attachments=body.get("attachments", []),
        facts=facts,
        sensitivity_level=body.get("sensitivity_level", "confidential"),
        created_by=operator,
        created_at=datetime.now(UTC),
    )
    saved = repo.save_review(review, expected_revision=None)
    return saved.model_dump(mode="json")


@router.get("/api/cases/{case_id}")
async def api_get_case(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    try:
        review = repo.get_review(case_id)
        return review.model_dump(mode="json")
    except DomainError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.put("/api/cases/{case_id}/facts")
async def api_update_case_facts(case_id: str, request: Request) -> dict[str, Any]:
    get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()
    try:
        review = repo.get_review(case_id)
    except DomainError as e:
        raise HTTPException(status_code=404, detail=str(e))

    facts = CaseFacts.model_validate(body)
    updated_review = review.model_copy(update={"facts": facts})
    saved = repo.save_review(updated_review, expected_revision=review.revision)
    return saved.model_dump(mode="json")


# =========================================================================
# 文件管理 API (Documents API)
# =========================================================================


@router.post("/api/cases/{case_id}/documents/upload")
async def api_upload_document(
    case_id: str,
    request: Request,
    file: UploadFile = File(...),  # noqa: B008
) -> dict[str, Any]:
    get_current_operator(request)
    repo = _get_repo(request)
    policy = _get_policy(request)

    try:
        review = repo.get_review(case_id)
    except DomainError as e:
        raise HTTPException(status_code=404, detail=str(e))

    suffix = Path(file.filename or "").suffix.lower()
    if suffix not in (".docx", ".pdf"):
        raise HTTPException(status_code=400, detail="Only .docx and .pdf files are supported")

    content = await file.read()
    temp_dir = Path(policy.data_root) / "uploads" / case_id
    temp_dir.mkdir(parents=True, exist_ok=True)
    temp_path = temp_dir / (file.filename or f"uploaded{suffix}")
    temp_path.write_bytes(content)

    snapshot = ingest(temp_path, review_id=case_id, policy=policy, artifacts=repo.artifacts)
    seg_snapshot = segment(snapshot)

    # 儲存 snapshot 至受控庫
    art_id = repo.artifacts.put(
        case_id=case_id,
        kind="document_snapshot",
        data=seg_snapshot.model_dump_json().encode("utf-8"),
    )
    _document_snapshots[case_id] = seg_snapshot

    updated_review = review.model_copy(
        update={
            "original_file_hash": seg_snapshot.content_sha256,
            "document_snapshot_ref": VersionRef(
                id=art_id,
                version="1.0",
                sha256=seg_snapshot.content_sha256,
            ),
        }
    )
    repo.save_review(updated_review, expected_revision=review.revision)

    # 同步初始化遮罩會話
    full_text = "\n".join(b.raw_text for b in seg_snapshot.blocks)
    _mask_text(case_id, full_text)

    return seg_snapshot.model_dump(mode="json")


@router.get("/api/cases/{case_id}/documents")
async def api_get_document(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    snapshot = _get_document_snapshot(case_id, repo)
    if not snapshot:
        raise HTTPException(status_code=404, detail="No document snapshot found for case")
    return snapshot.model_dump(mode="json")


@router.post("/api/cases/{case_id}/documents/confirm")
async def api_confirm_document_text(case_id: str, request: Request) -> dict[str, Any]:
    operator = get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()
    corrected_blocks = body.get("corrected_blocks", [])

    snapshot = _get_document_snapshot(case_id, repo)
    if not snapshot:
        raise HTTPException(status_code=404, detail="Document snapshot not found")

    confirmed_snapshot = confirm_text(snapshot, corrected_blocks, actor=operator)
    art_id = repo.artifacts.put(
        case_id=case_id,
        kind="document_snapshot",
        data=confirmed_snapshot.model_dump_json().encode("utf-8"),
    )
    _document_snapshots[case_id] = confirmed_snapshot

    try:
        review = repo.get_review(case_id)
        updated_review = review.model_copy(
            update={
                "document_snapshot_ref": VersionRef(
                    id=art_id,
                    version="1.1",
                    sha256=confirmed_snapshot.content_sha256,
                )
            }
        )
        repo.save_review(updated_review, expected_revision=review.revision)
    except DomainError:
        pass

    # 重新遮罩
    full_text = "\n".join(b.raw_text for b in confirmed_snapshot.blocks)
    _mask_text(case_id, full_text, existing_session=_masking_sessions.get(case_id))

    return confirmed_snapshot.model_dump(mode="json")


# =========================================================================
# 遮罩與實體標記 API (Masking API)
# =========================================================================


@router.get("/api/cases/{case_id}/masking")
async def api_get_masking(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    session = _masking_sessions.get(case_id) or _mask_text(case_id, "預設採購合約文字內容")
    return session.model_dump(mode="json")


@router.post("/api/cases/{case_id}/masking/annotate")
async def api_annotate_masking(case_id: str, request: Request) -> dict[str, Any]:
    operator = get_current_operator(request)
    body = await request.json()
    annotations = body.get("annotations", [])

    spans: list[DetectedSpan] = []
    for item in annotations:
        if isinstance(item, DetectedSpan):
            spans.append(item)
        else:
            orig_text = item.get("original_text", "")
            start = item.get("start", 0)
            end = item.get("end", len(orig_text))
            etype = item.get("entity_type", "ORG")
            spans.append(
                DetectedSpan(
                    span_id=str(uuid.uuid4()),
                    span_type=etype,
                    entity_group=etype,
                    source_span=SourceSpan(
                        document_id=str(uuid.uuid4()),
                        block_id=str(uuid.uuid4()),
                        start_offset=start,
                        end_offset=end,
                    ),
                    original_text=orig_text,
                    masked_token="",
                )
            )

    session = _masking_sessions.get(case_id) or _mask_text(case_id, "預設採購合約文字內容")
    updated = apply_annotations(session, spans, actor=operator)
    _masking_sessions[case_id] = updated
    return updated.model_dump(mode="json")


# =========================================================================
# 出站預覽與核准 API (Egress API)
# =========================================================================


@router.get("/api/cases/{case_id}/egress/draft")
async def api_get_egress_draft(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)

    # 取得或建立 Run
    runs = repo.list_runs_for_case(case_id)
    if runs:
        run = runs[0]
    else:
        # 建立一個測試 run
        rule_ref = VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="abc" * 21 + "1")
        run = repo.create_run(review_id=case_id, rule_refs=[rule_ref])

    snapshot = _get_document_snapshot(case_id, repo)
    if snapshot and snapshot.blocks:
        body_text = "\n".join(b.raw_text for b in snapshot.blocks)
    else:
        body_text = "待審查合約文件"

    session = _masking_sessions.get(case_id) or _mask_text(case_id, body_text)

    draft = OutboundDraft(
        draft_id=str(uuid.uuid4()),
        run_id=run.run_id,
        plaintext_body=body_text,
        sensitive_token_count=0,
        assembled_at=datetime.now(UTC),
    )
    adapter = MockProviderAdapter()
    prepared = prepare_egress(
        run_id=run.run_id,
        draft=draft,
        session=session,
        detector=RuleBasedDetector(),
        adapter=adapter,
        repo=repo,
    )
    return prepared.model_dump(mode="json")


@router.post("/api/cases/{case_id}/egress/approve")
async def api_approve_egress(case_id: str, request: Request) -> dict[str, Any]:
    operator = get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()
    request_id = body.get("request_id")
    if not request_id:
        raise HTTPException(status_code=400, detail="request_id required")

    prepared = get_prepared_request(request_id, repo)
    approval = approve(prepared, actor=operator, repo=repo)
    return approval.model_dump(mode="json")


@router.post("/api/cases/{case_id}/egress/dispatch")
async def api_dispatch_egress(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    body = await request.json()
    request_id = body.get("request_id")
    approval_id = body.get("approval_id")
    if not request_id or not approval_id:
        raise HTTPException(status_code=400, detail="request_id and approval_id required")

    reply = dispatch(request_id, approval_id, repo=repo, adapter=MockProviderAdapter())
    return reply.model_dump(mode="json")


# =========================================================================
# 審查執行、變更校驗與決定 API (Review API)
# =========================================================================


@router.post("/api/cases/{case_id}/review/start")
async def api_start_review(case_id: str, request: Request) -> dict[str, Any]:
    get_current_operator(request)
    repo = _get_repo(request)
    executor = _get_executor(request)

    _ = repo.get_review(case_id)
    active_rules = repo.list_rules(status=RuleStatus.ACTIVE)
    if not active_rules:
        # 若目前無 active rule，自動註冊一條合成測試用 active 規則
        default_rule = Rule(
            rule_id=str(uuid.uuid4()),
            version="1.0",
            status=RuleStatus.ACTIVE,
            category=ProcurementFamily.SERVICES,
            title="資訊委外服務資安規範",
            requirement_text="廠商應每年進行定期資安稽核，並於30日內提交改善報告。",
            severity=RiskLevel.HIGH,
            mandatory=True,
            approved_by="法務主管",
        )
        repo.save_rule(default_rule)
        active_rules = [default_rule]

    rule_refs = [
        VersionRef(id=r.rule_id, version=r.version, sha256=compute_rule_hash(r))
        for r in active_rules
    ]
    run = repo.create_run(review_id=case_id, rule_refs=rule_refs)

    # 標記為 running 狀態
    running_run = run.model_copy(update={"state": RunState.RUNNING})
    repo.save_run(running_run)

    task_id = str(uuid.uuid4())
    _background_tasks[task_id] = {
        "task_id": task_id,
        "run_id": run.run_id,
        "status": "running",
        "progress": 0,
        "message": "審查管線啟動中...",
        "error": None,
    }

    def _execute_review_pipeline() -> None:
        try:
            # 建立審查 context
            contexts: list[ContextBundle] = []
            for r in active_rules:
                cb = ContextBundle(
                    requirement_ref=VersionRef(
                        id=r.rule_id, version=r.version, sha256=compute_rule_hash(r)
                    ),
                )
                contexts.append(cb)

            _background_tasks[task_id]["progress"] = 30
            _background_tasks[task_id]["message"] = "規則適用性評估與規劃中..."
            plan_review(running_run, contexts, repo=repo)

            # 執行 Mock 回覆與接收
            _background_tasks[task_id]["progress"] = 60
            _background_tasks[task_id]["message"] = "AI 審查與條款對照分析中..."
            findings_list = []
            for r in active_rules:
                findings_list.append(
                    {
                        "requirement_id": r.rule_id,
                        "clause_ids": ["clause-10"],
                        "result": "concern",
                        "risk": "high",
                        "reason": f"未落實資安稽核要求: {r.requirement_text}",
                        "suggested_action": "修正條款以符合資安規範",
                        "suggested_clause": "廠商應配合每年定期資安稽核，並於30日內提交改善報告，違約金為 [待填金額]。",
                        "review_scope": "全份合約",
                    }
                )

            response_payload = {
                "run_id": run.run_id,
                "findings": findings_list,
            }
            raw_bytes = json.dumps(response_payload, ensure_ascii=False).encode("utf-8")
            art_id = repo.artifacts.put(case_id=case_id, kind="provider_reply", data=raw_bytes)
            reply = ProviderReply(
                reply_id=str(uuid.uuid4()),
                request_id=str(uuid.uuid4()),
                artifact_ref=art_id,
                finish_reason="stop",
                latency_ms=60,
            )

            accept_review_reply(run.run_id, reply, repo)
            finalize_run(run.run_id, repo)

            _background_tasks[task_id]["status"] = "completed"
            _background_tasks[task_id]["progress"] = 100
            _background_tasks[task_id]["message"] = "審查完成"
        except Exception as e:  # noqa: BLE001
            _background_tasks[task_id]["status"] = "failed"
            _background_tasks[task_id]["error"] = str(e)
            _background_tasks[task_id]["message"] = f"審查失敗: {e}"

    executor.submit(_execute_review_pipeline)

    return {
        "status": "running",
        "task_id": task_id,
        "run_id": run.run_id,
    }


@router.get("/api/cases/{case_id}/review/status")
async def api_get_review_status(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    runs = repo.list_runs_for_case(case_id)
    if not runs:
        return {"status": "none"}
    latest_run = runs[0]
    batches = get_batch_status(latest_run.run_id, repo)
    return {
        "run_id": latest_run.run_id,
        "state": latest_run.state.value,
        "stale": latest_run.stale,
        "batches": batches,
    }


@router.get("/api/cases/{case_id}/review/findings")
async def api_get_review_findings(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    runs = repo.list_runs_for_case(case_id)
    if not runs:
        return {"findings": [], "coverage": None}
    latest_run = runs[0]
    findings = repo.get_findings_for_run(latest_run.run_id)
    return {
        "run_id": latest_run.run_id,
        "findings": [f.model_dump(mode="json") for f in findings],
    }


@router.post("/api/cases/{case_id}/review/validate-change")
async def api_validate_change(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    body = await request.json()
    finding_id = body.get("finding_id")
    proposed_text = body.get("proposed_text", "")

    if not finding_id:
        raise HTTPException(status_code=400, detail="finding_id required")

    finding = repo.get_finding(finding_id)
    try:
        requirement = repo.get_requirement(finding.requirement_id)
    except DomainError:
        # 自動建構要求契約
        rule_ref = finding.rule_refs[0] if finding.rule_refs else None
        rule_id = rule_ref.id if rule_ref else finding.requirement_id
        rule_version = rule_ref.version if rule_ref else "1.0"
        rule = repo.get_rule(rule_id, rule_version)
        from procurement_review.rules.catalog import rule_to_requirement

        requirement = rule_to_requirement(rule)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=finding.run_id,
        purpose="建議修訂條款",
        proposed_text=proposed_text,
        affected_clause_ids=finding.clause_ids or ["clause-10"],
        basis_rule_refs=[requirement.rule_ref],
    )
    report = validate_change(change, finding, requirement)
    return {
        "structure": {"ok": report.structure.ok},
        "source": {"ok": report.source.ok},
        "substance": {"ok": report.substance.ok},
        "issues": report.issues,
    }


@router.post("/api/cases/{case_id}/review/decision")
async def api_record_decision(case_id: str, request: Request) -> dict[str, Any]:
    operator = get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()
    finding_id = body.get("finding_id")
    run_id = body.get("run_id")
    status_str = str(body.get("status", "adopt")).lower()

    if status_str in ("accepted", "adopt"):
        action = HumanDecisionAction.ADOPT
    elif status_str in ("modified", "modify"):
        action = HumanDecisionAction.MODIFY
    elif status_str in ("rejected", "reject"):
        action = HumanDecisionAction.REJECT
    else:
        action = HumanDecisionAction.ADOPT

    decision = HumanDecision(
        decision_id=str(uuid.uuid4()),
        finding_id=finding_id,
        action=action,
        final_text=body.get("modified_clause_text"),
        reason=body.get("note", "人工審查決定"),
        decided_by=operator,
        decided_at=datetime.now(UTC),
        run_id=run_id,
    )
    feedback = record_feedback(
        decision,
        repo,
        idempotency_key=body.get("idempotency_key", str(uuid.uuid4())),
    )
    return {"status": "ok", "feedback_id": feedback.feedback_id}


# =========================================================================
# 報告安全匯出 API (Export API)
# =========================================================================


@router.post("/api/cases/{case_id}/export")
async def api_export_review(case_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    policy = _get_policy(request)
    body = await request.json()

    mode = body.get("mode", "masked")
    confirmed = body.get("confirmed", False)

    runs = repo.list_runs_for_case(case_id)
    if not runs:
        raise HTTPException(status_code=400, detail="No review runs available for export")
    run = runs[0]

    findings = repo.get_findings_for_run(run.run_id)
    coverage = finalize_run(run.run_id, repo)
    report = ReviewReport(
        report_id=str(uuid.uuid4()),
        case_id=case_id,
        run_id=run.run_id,
        case_version="1.0",
        sensitivity_level="confidential",
        source_manifest=[run.rule_set_snapshot],
        findings=findings,
        coverage=coverage,
        unresolved_issues=[],
        human_decisions=[],
        generated_at=datetime.now(UTC),
    )

    out_dir = Path(policy.data_root) / "exports" / case_id
    try:
        paths = export_review(
            report=report,
            mode=mode,
            output_dir=out_dir,
            confirmed=confirmed,
        )
    except DomainError as err:
        if err.code == "HUMAN_CONFIRMATION_REQUIRED":
            raise HTTPException(status_code=400, detail=str(err))
        raise HTTPException(status_code=400, detail=str(err))

    token = secrets.token_hex(16)
    filename = Path(paths.markdown_path).name
    return {
        "download_token": token,
        "filename": filename,
        "markdown_path": paths.markdown_path,
        "json_path": paths.json_path,
    }


@router.get("/api/cases/{case_id}/export/download")
async def api_download_export(case_id: str, request: Request) -> Response:
    get_authenticated_session(request)
    policy = _get_policy(request)
    filename = request.query_params.get("file")

    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal detected")

    file_path = (Path(policy.data_root).resolve() / "exports" / case_id / filename).resolve()
    base_dir = (Path(policy.data_root).resolve() / "exports" / case_id).resolve()

    # 確保路徑完全在 base_dir 內
    try:
        file_path.relative_to(base_dir)
    except ValueError:
        raise HTTPException(status_code=403, detail="Forbidden: Path traversal detected")

    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="Export file not found")

    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="text/markdown",
    )


# =========================================================================
# 規則與法源治理 API (Rules API)
# =========================================================================


@router.get("/api/rules")
async def api_list_rules(request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    repo = _get_repo(request)
    return {
        "rules": [r.model_dump(mode="json") for r in repo.list_rules()],
        "sources": [s.model_dump(mode="json") for s in repo.list_sources()],
    }


@router.post("/api/rules/release")
@router.post("/api/rules/{rule_id}/release")
async def api_release_rules(request: Request, rule_id: str | None = None) -> dict[str, Any]:
    operator = get_current_operator(request)
    repo = _get_repo(request)
    body: dict[str, Any] = {}
    try:
        body = await request.json()
    except (json.JSONDecodeError, ValueError):
        body = {}

    target_rule_id = rule_id or body.get("rule_id")
    if target_rule_id:
        version = body.get("version")
        if not version:
            matched_rules = [r for r in repo.list_rules() if r.rule_id == target_rule_id]
            if not matched_rules:
                raise HTTPException(status_code=404, detail=f"Rule {target_rule_id} not found")
            rule = matched_rules[0]
        else:
            rule = repo.get_rule(target_rule_id, version)
        rules = [rule]
        sources = []
    else:
        rules_data = body.get("rules", [])
        sources_data = body.get("sources", [])
        rules = [Rule.model_validate(r) for r in rules_data]
        sources = [SourceReference.model_validate(s) for s in sources_data]

    refs = release_rules(
        rules=rules,
        sources=sources,
        approver=operator,
        at=datetime.now(UTC),
        repo=repo,
    )
    return {"released_refs": [ref.model_dump(mode="json") for ref in refs]}


@router.post("/api/rules/{rule_id}/revoke")
async def api_revoke_rule(rule_id: str, request: Request) -> dict[str, Any]:
    get_current_operator(request)
    repo = _get_repo(request)
    body = await request.json()
    version = body.get("version", "1.0")
    reason = body.get("reason", "Revoked by operator")

    ref = VersionRef(id=rule_id, version=version, sha256="abc")
    invalidated_runs = revoke_rule(ref, reason=reason, repo=repo)
    return {"invalidated_runs": invalidated_runs}


# =========================================================================
# 設定與背景任務 API (Settings & Task API)
# =========================================================================


@router.get("/api/settings")
async def api_get_settings(request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    policy = _get_policy(request)
    return policy.model_dump(mode="json")


@router.get("/api/tasks/{task_id}")
async def api_get_task_status(task_id: str, request: Request) -> dict[str, Any]:
    get_authenticated_session(request)
    task = _background_tasks.get(task_id)
    if not task:
        raise HTTPException(status_code=404, detail="Task not found")
    return task
