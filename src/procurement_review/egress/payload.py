import hashlib
import uuid
from datetime import UTC, datetime

from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    MaskingSession,
    OutboundDraft,
    PreparedRequest,
    VersionRef,
)
from procurement_review.masking.detector import Detector
from procurement_review.masking.session import mask
from procurement_review.providers.base import ProviderAdapter
from procurement_review.storage.repository import Repository


def compute_egress_digest(
    body: bytes,
    endpoint: str,
    model: str,
    masking_ref: VersionRef,
    rule_refs: list[VersionRef],
) -> str:
    """計算出站請求不可變全量 SHA-256 摘要。

    綁定：實際傳輸之 body bytes、目的端點、模型名稱、遮罩會話參照與規則版本集合。
    任何欄位異動 1 byte 均保證產生截然不同的雜湊值。
    """
    hasher = hashlib.sha256()
    hasher.update(body)
    hasher.update(b"\n")
    hasher.update(endpoint.encode("utf-8"))
    hasher.update(b"\n")
    hasher.update(model.encode("utf-8"))
    hasher.update(b"\n")
    hasher.update(
        f"{masking_ref.id}:{masking_ref.version}:{masking_ref.sha256}\n".encode()
    )
    for ref in sorted(rule_refs, key=lambda r: (r.id, r.version)):
        hasher.update(f"{ref.id}:{ref.version}:{ref.sha256}\n".encode())
    return hasher.hexdigest()


def _init_egress_tables(repo: Repository) -> None:
    """初始化出站與核准資料表（若不存在）。"""
    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS prepared_requests (
                request_id TEXT PRIMARY KEY,
                run_id TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                model TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                artifact_ref TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS egress_approvals (
                approval_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                request_sha256 TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                model TEXT NOT NULL,
                approved_by TEXT NOT NULL,
                approved_at TEXT NOT NULL,
                scope TEXT NOT NULL,
                max_resend_count INTEGER NOT NULL,
                current_send_count INTEGER NOT NULL DEFAULT 0,
                revocation_reason TEXT,
                artifact_ref TEXT NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS egress_dispatches (
                dispatch_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL,
                approval_id TEXT NOT NULL,
                attempt_number INTEGER NOT NULL,
                state TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """
        )
        conn.commit()


def prepare_egress(
    run_id: str,
    draft: OutboundDraft,
    session: MaskingSession,
    detector: Detector,
    adapter: ProviderAdapter,
    repo: Repository,
    rule_refs: list[VersionRef] | None = None,
) -> PreparedRequest:
    """依照嚴格組裝次序建立不可變出站請求 (PreparedRequest)。

    組裝順序：
    1. T8 遮罩全部 OutboundDraft
    2. adapter encode 為實際傳輸 bytes
    3. 掃描 encode 後之 body 檢查是否有未被遮罩之機敏殘留
    4. 嚴禁對已雜湊 bytes 再作任何替換
    5. 計算實際 body bytes + endpoint + model + refs 之 SHA256 digest
    6. 儲存並回傳 PreparedRequest
    """
    _init_egress_tables(repo)

    run = repo.get_run(run_id)
    if run.stale:
        raise DomainError("RUN_STALE", f"Cannot prepare egress for stale run {run_id}")

    # 1. 遮罩出站草稿
    masked_draft, updated_session = mask(draft, session, detector)
    if updated_session.blocked or updated_session.blocking_reasons:
        reasons = ", ".join(updated_session.blocking_reasons)
        raise DomainError(
            "SENSITIVE_RESIDUAL_DETECTED",
            f"Egress blocked due to sensitive secrets or masking failure: {reasons}",
        )

    # 2. adapter encode
    body_bytes = adapter.encode(masked_draft)

    # 3. 檢查 encode 後之 body 是否有敏感殘留
    try:
        decoded_text = body_bytes.decode("utf-8")
    except UnicodeDecodeError as e:
        raise DomainError(
            "SENSITIVE_RESIDUAL_DETECTED",
            "Encoded body is not valid UTF-8",
        ) from e

    residuals = detector.detect(decoded_text)
    if residuals:
        types = [s.span_type for s in residuals]
        raise DomainError(
            "SENSITIVE_RESIDUAL_DETECTED",
            f"Sensitive residuals detected in encoded egress payload: {types}",
        )

    # 4. 嚴格不對已產生之 bytes 進行替換或修改
    # 5. 計算完整 SHA-256 摘要
    masking_ref = VersionRef(
        id=updated_session.session_id,
        version=updated_session.manual_tagging_version or updated_session.detector_version,
        sha256=updated_session.outbound_hash,
    )
    final_rule_refs = rule_refs if rule_refs is not None else [run.rule_set_snapshot]

    digest = compute_egress_digest(
        body=body_bytes,
        endpoint=adapter.config.endpoint,
        model=adapter.config.model,
        masking_ref=masking_ref,
        rule_refs=final_rule_refs,
    )

    request_id = str(uuid.uuid4())
    now_iso = datetime.now(UTC).isoformat()

    prepared = PreparedRequest(
        request_id=request_id,
        run_id=run_id,
        endpoint=adapter.config.endpoint,
        model=adapter.config.model,
        body=body_bytes,
        sha256=digest,
        masking_ref=masking_ref,
        rule_refs=final_rule_refs,
    )

    # 加密儲存至 ArtifactStore
    artifact_id = repo.artifacts.put(
        case_id=run.case_id,
        kind="prepared_request",
        data=prepared.model_dump_json().encode("utf-8"),
    )

    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            """
            INSERT INTO prepared_requests (
                request_id, run_id, endpoint, model, sha256, artifact_ref, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                prepared.request_id,
                prepared.run_id,
                prepared.endpoint,
                prepared.model,
                prepared.sha256,
                artifact_id,
                now_iso,
            ),
        )
        conn.commit()

    return prepared


def get_prepared_request(request_id: str, repo: Repository) -> PreparedRequest:
    """取得已遮罩之出站請求，並疊加 SQLite 即時中繼狀態。"""
    _init_egress_tables(repo)
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT request_id, run_id, endpoint, model, sha256, artifact_ref
            FROM prepared_requests WHERE request_id = ?
            """,
            (request_id,),
        )
        row = cursor.fetchone()
        if row is None:
            raise DomainError(
                "REQUEST_NOT_FOUND",
                f"Prepared request '{request_id}' not found",
            )

        run_id = row["run_id"]
        db_endpoint = row["endpoint"]
        db_model = row["model"]
        db_sha256 = row["sha256"]
        artifact_ref = row["artifact_ref"]

    run = repo.get_run(run_id)
    raw_data = repo.artifacts.get(case_id=run.case_id, artifact_id=artifact_ref)
    req = PreparedRequest.model_validate_json(raw_data)
    # 疊加資料庫之即時數值（防範資料庫紀錄與 artifact 不一致之篡改行為）
    return req.model_copy(
        update={
            "endpoint": db_endpoint,
            "model": db_model,
            "sha256": db_sha256,
        }
    )
