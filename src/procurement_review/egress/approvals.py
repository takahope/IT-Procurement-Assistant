import uuid
from datetime import UTC, datetime

from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import EgressApproval, PreparedRequest, VersionRef
from procurement_review.egress.payload import _init_egress_tables
from procurement_review.storage.repository import Repository


def approve(
    request: PreparedRequest,
    actor: str,
    max_attempts: int = 1,
    repo: Repository | None = None,
    scope: str = "procurement_review_egress",
) -> EgressApproval:
    """為不可變出站請求建立出站核准 artifact。

    規則：
    - 檢查執行管線是否已被標記為 stale（若失效則拒絕核准）。
    - 預設 max_attempts=1，最多允許 3 次。
    - 核准嚴格綁定請求之 SHA-256 digest、endpoint 與 model。
    - 儲存核准參照至 ReviewRun.egress_approval_ref。
    """
    if repo is None:
        raise DomainError("REPO_REQUIRED", "Repository instance is required for approval")

    _init_egress_tables(repo)

    if not actor or not actor.strip():
        raise DomainError("ACTOR_REQUIRED", "Approval requires an explicit non-empty actor")

    if max_attempts < 1 or max_attempts > 3:
        raise DomainError(
            "INVALID_ATTEMPTS",
            f"max_attempts must be between 1 and 3, got {max_attempts}",
        )

    run = repo.get_run(request.run_id)
    if run.stale:
        raise DomainError(
            "RUN_STALE",
            f"Cannot approve egress request for stale run '{request.run_id}'",
        )

    approval_id = str(uuid.uuid4())
    now = datetime.now(UTC)

    approval = EgressApproval(
        approval_id=approval_id,
        request_id=request.request_id,
        request_sha256=request.sha256,
        endpoint=request.endpoint,
        model=request.model,
        approved_by=actor.strip(),
        approved_at=now,
        scope=scope,
        max_resend_count=max_attempts,
        current_send_count=0,
        revocation_reason=None,
    )

    artifact_id = repo.artifacts.put(
        case_id=run.case_id,
        kind="egress_approval",
        data=approval.model_dump_json().encode("utf-8"),
    )

    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            """
            INSERT INTO egress_approvals (
                approval_id, request_id, request_sha256, endpoint, model,
                approved_by, approved_at, scope, max_resend_count,
                current_send_count, revocation_reason, artifact_ref
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                approval.approval_id,
                approval.request_id,
                approval.request_sha256,
                approval.endpoint,
                approval.model,
                approval.approved_by,
                approval.approved_at.isoformat(),
                approval.scope,
                approval.max_resend_count,
                approval.current_send_count,
                approval.revocation_reason,
                artifact_id,
            ),
        )
        conn.commit()

    # 更新 Run 之 egress_approval_ref
    approval_ref = VersionRef(
        id=approval.approval_id,
        version="1.0",
        sha256=approval.request_sha256,
    )
    updated_run = run.model_copy(update={"egress_approval_ref": approval_ref})
    repo.save_run(updated_run)

    return approval


def get_approval(approval_id: str, repo: Repository) -> EgressApproval:
    """取得出站核准記錄，並疊加 SQLite 即時中繼狀態。"""
    _init_egress_tables(repo)
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT a.approval_id, a.request_id, a.request_sha256, a.endpoint, a.model,
                   a.approved_by, a.approved_at, a.scope, a.max_resend_count,
                   a.current_send_count, a.revocation_reason, a.artifact_ref,
                   p.run_id
            FROM egress_approvals a
            JOIN prepared_requests p ON a.request_id = p.request_id
            WHERE a.approval_id = ?
            """,
            (approval_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise DomainError(
                "APPROVAL_NOT_FOUND",
                f"Egress approval '{approval_id}' not found",
            )

        run_id = row["run_id"]
        db_send_count = row["current_send_count"]
        db_revocation = row["revocation_reason"]
        db_endpoint = row["endpoint"]
        db_model = row["model"]
        db_sha256 = row["request_sha256"]
        artifact_ref = row["artifact_ref"]

    run = repo.get_run(run_id)
    raw_data = repo.artifacts.get(case_id=run.case_id, artifact_id=artifact_ref)
    appr = EgressApproval.model_validate_json(raw_data)
    return appr.model_copy(
        update={
            "endpoint": db_endpoint,
            "model": db_model,
            "request_sha256": db_sha256,
            "current_send_count": db_send_count,
            "revocation_reason": db_revocation,
        }
    )


def revoke_approval(
    approval_id: str,
    reason: str,
    repo: Repository,
) -> EgressApproval:
    """撤銷特定出站核准。"""
    _init_egress_tables(repo)
    appr = get_approval(approval_id, repo)
    updated = appr.model_copy(update={"revocation_reason": reason})

    run = repo.get_run_by_request_id(appr.request_id) if hasattr(repo, "get_run_by_request_id") else None
    if run is None:
        with repo._conn() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT run_id FROM prepared_requests WHERE request_id = ?", (appr.request_id,))
            r_row = cursor.fetchone()
            if r_row:
                run = repo.get_run(r_row["run_id"])

    if run is not None:
        repo.artifacts.put(
            case_id=run.case_id,
            kind="egress_approval",
            data=updated.model_dump_json().encode("utf-8"),
        )

    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            "UPDATE egress_approvals SET revocation_reason = ? WHERE approval_id = ?",
            (reason, approval_id),
        )
        conn.commit()

    return updated
