import uuid
from datetime import UTC, datetime
from urllib.parse import urlsplit

import httpx

from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import ProviderReply
from procurement_review.egress.approvals import get_approval
from procurement_review.egress.payload import (
    _init_egress_tables,
    compute_egress_digest,
    get_prepared_request,
)
from procurement_review.providers.base import ProviderAdapter
from procurement_review.providers.mock import MockProviderAdapter
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import SecretStore


def get_delivery_state(request_id: str, repo: Repository) -> str | None:
    """查詢出站請求最新傳輸交付狀態。"""
    _init_egress_tables(repo)
    with repo._conn() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT state FROM egress_dispatches
            WHERE request_id = ?
            ORDER BY rowid DESC LIMIT 1
            """,
            (request_id,),
        )
        row = cursor.fetchone()
        return row["state"] if row else None


def _update_dispatch_state(
    dispatch_id: str,
    request_id: str,
    state: str,
    error_message: str | None,
    repo: Repository,
) -> None:
    now_iso = datetime.now(UTC).isoformat()
    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            """
            UPDATE egress_dispatches
            SET state = ?, error_message = ?, updated_at = ?
            WHERE dispatch_id = ?
            """,
            (state, error_message, now_iso, dispatch_id),
        )
        conn.commit()


def dispatch(
    request_id: str,
    approval_id: str,
    repo: Repository,
    transport: httpx.BaseTransport | None = None,
    secrets: SecretStore | None = None,
    adapter: ProviderAdapter | None = None,
) -> ProviderReply:
    """受控出站分派發送器。

    保證：
    - 嚴格出站校驗：核准遺失、已撤銷、body 變更 1 byte、端點／模型不符或 run stale 均零傳輸 (zero network egress)。
    - HTTPX 安全設置：集中限制 follow_redirects=False, trust_env=False。
    - 嚴格端點限制：僅允許核准之 HTTPS，嚴禁 URL userinfo 或 query secret。
    - 併發防護與原子次數預約：雙擊或併發請求僅發出 1 次 HTTP 請求；次數用罄即阻擋。
    - 交付未明狀態：遇 timeout 或例外，記錄為 delivery_unknown，不自動無聲重試。
    - 認證金鑰：僅在發送當下自 SecretStore 取出注入 Header，不進預覽、資料庫或日誌。
    """
    _init_egress_tables(repo)

    # 1. 取得核准並驗證有效性
    approval = get_approval(approval_id, repo)
    if approval.revocation_reason:
        raise DomainError(
            "APPROVAL_REVOKED",
            f"Approval '{approval_id}' was revoked: {approval.revocation_reason}",
        )

    # 2. 取得不可變請求
    prepared = get_prepared_request(request_id, repo)

    # 3. 端點安全性檢核 (URL 安全規則：僅允許 HTTPS，嚴禁 userinfo 或 query secret)
    parsed = urlsplit(prepared.endpoint)
    if parsed.scheme.lower() != "https":
        raise DomainError(
            "INVALID_ENDPOINT",
            f"Egress endpoint must use HTTPS, got scheme '{parsed.scheme}'",
        )
    if parsed.username or parsed.password:
        raise DomainError(
            "INVALID_ENDPOINT",
            "Egress endpoint contains userinfo (username/password), which is strictly forbidden",
        )
    if parsed.query:
        raise DomainError(
            "INVALID_ENDPOINT",
            "Egress endpoint contains URL query parameters/secrets, which is strictly forbidden",
        )

    # 4. 檢查 ReviewRun 狀態（stale 標記檢查）
    run = repo.get_run(prepared.run_id)
    if run.stale:
        raise DomainError(
            "RUN_STALE",
            f"Cannot dispatch egress for stale run '{prepared.run_id}'",
        )

    # 5. 核准與請求一致性與完整性校驗
    if approval.request_id != prepared.request_id:
        raise DomainError(
            "REQUEST_TAMPERED",
            "Approval request_id does not match prepared request",
        )
    if approval.endpoint != prepared.endpoint:
        raise DomainError(
            "ENDPOINT_MISMATCH",
            f"Approval endpoint '{approval.endpoint}' does not match request '{prepared.endpoint}'",
        )
    if approval.model != prepared.model:
        raise DomainError(
            "MODEL_MISMATCH",
            f"Approval model '{approval.model}' does not match request '{prepared.model}'",
        )

    # 重新計算實際 body 與中繼資料之 SHA-256 digest
    computed_digest = compute_egress_digest(
        body=prepared.body,
        endpoint=prepared.endpoint,
        model=prepared.model,
        masking_ref=prepared.masking_ref,
        rule_refs=prepared.rule_refs,
    )
    if prepared.sha256 != computed_digest or approval.request_sha256 != computed_digest:
        raise DomainError(
            "REQUEST_TAMPERED",
            "Egress request body, endpoint, or metadata has been tampered with; digest verification failed",
        )

    # 6. 交付未明狀態鎖定檢查（人工確認前禁止重送）
    current_delivery_state = get_delivery_state(request_id, repo)
    if current_delivery_state == "delivery_unknown":
        raise DomainError(
            "DELIVERY_UNKNOWN_LOCKED",
            f"Request '{request_id}' is locked in 'delivery_unknown' state; requires human confirmation before retrying",
        )

    # 7. 原子次數預約與雙重點擊併發防護
    dispatch_id = str(uuid.uuid4())
    now_iso = datetime.now(UTC).isoformat()

    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        cursor = conn.cursor()

        # 檢查是否有正在進行中之 dispatch (in_flight)
        cursor.execute(
            """
            SELECT dispatch_id FROM egress_dispatches
            WHERE request_id = ? AND state = 'in_flight'
            """,
            (request_id,),
        )
        if cursor.fetchone() is not None:
            conn.rollback()
            raise DomainError(
                "CONCURRENT_DISPATCH_DISALLOWED",
                f"Another dispatch attempt is currently in flight for request '{request_id}'",
            )

        # 檢查次數限制
        cursor.execute(
            """
            SELECT current_send_count, max_resend_count
            FROM egress_approvals WHERE approval_id = ?
            """,
            (approval_id,),
        )
        row = cursor.fetchone()
        current_count = row["current_send_count"]
        max_count = row["max_resend_count"]

        if current_count >= max_count:
            conn.rollback()
            raise DomainError(
                "MAX_ATTEMPTS_EXCEEDED",
                f"Maximum allowed egress attempts ({max_count}) reached for approval '{approval_id}'",
            )

        # 原子保留次數並登記 in_flight 狀態
        new_count = current_count + 1
        cursor.execute(
            """
            UPDATE egress_approvals
            SET current_send_count = ?
            WHERE approval_id = ?
            """,
            (new_count, approval_id),
        )
        cursor.execute(
            """
            INSERT INTO egress_dispatches (
                dispatch_id, request_id, approval_id, attempt_number, state,
                error_message, created_at, updated_at
            ) VALUES (?, ?, ?, ?, 'in_flight', NULL, ?, ?)
            """,
            (dispatch_id, request_id, approval_id, new_count, now_iso, now_iso),
        )
        conn.commit()

    # 更新 Run 嘗試次數
    run = repo.get_run(prepared.run_id)
    repo.save_run(run.model_copy(update={"attempts": run.attempts + 1}))

    # 8. 認證憑證提取（僅在送出時自 SecretStore 取得，不進預覽／日誌）
    headers = {"Content-Type": "application/json"}
    if secrets is not None:
        cred_ref = "mock_api_key"
        if adapter and hasattr(adapter, "config"):
            cred_ref = adapter.config.credential_ref
        key_bytes = secrets.get_key(cred_ref)
        if key_bytes:
            headers["Authorization"] = f"Bearer {key_bytes.decode('utf-8', errors='replace')}"

    # 9. 發起 HTTP 請求
    effective_adapter = adapter or MockProviderAdapter()

    with httpx.Client(
        transport=transport,
        follow_redirects=False,
        trust_env=False,
        timeout=10.0,
    ) as client:
        try:
            response = client.post(
                prepared.endpoint,
                content=prepared.body,
                headers=headers,
            )
        except httpx.TimeoutException as e:
            _update_dispatch_state(dispatch_id, request_id, "delivery_unknown", str(e), repo)
            latest_run = repo.get_run(prepared.run_id)
            repo.save_run(latest_run.model_copy(update={"error_message": "delivery_unknown"}))
            raise DomainError(
                "DELIVERY_UNKNOWN",
                f"Dispatch to '{prepared.endpoint}' timed out; delivery status is unknown",
            ) from e
        except (httpx.RequestError, OSError) as e:
            _update_dispatch_state(dispatch_id, request_id, "delivery_unknown", str(e), repo)
            latest_run = repo.get_run(prepared.run_id)
            repo.save_run(latest_run.model_copy(update={"error_message": "delivery_unknown"}))
            raise DomainError(
                "DELIVERY_UNKNOWN",
                f"Dispatch network error: {e}; delivery status is unknown",
            ) from e

    # 10. 處理伺服器回應狀態
    # 檢查是否為轉址 (Redirect)
    if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
        _update_dispatch_state(dispatch_id, request_id, "failed", f"Redirect status {response.status_code}", repo)
        raise DomainError(
            "REDIRECT_FORBIDDEN",
            f"Provider returned HTTP redirect status {response.status_code}; HTTP redirects are strictly forbidden",
        )

    # 檢查 429 Rate Limit
    if response.status_code == 429:
        _update_dispatch_state(dispatch_id, request_id, "failed", "HTTP 429 Rate limit", repo)
        raise DomainError(
            "RATE_LIMITED",
            "Provider returned HTTP 429 (rate limited)",
        )

    if response.status_code >= 400:
        _update_dispatch_state(dispatch_id, request_id, "failed", f"HTTP {response.status_code}", repo)
        raise DomainError(
            "PROVIDER_ERROR",
            f"Provider returned error status {response.status_code}",
        )

    # 傳輸成功
    _update_dispatch_state(dispatch_id, request_id, "delivered", None, repo)

    # 11. 將原始受控回應落盤至 ArtifactStore
    repo.artifacts.put(
        case_id=run.case_id,
        kind="provider_reply",
        data=response.content,
    )

    # 12. Adapter 解碼為 ProviderReply（嚴禁回應工具要求觸發任何網路或程式碼）
    reply = effective_adapter.decode(response.content, request_id=prepared.request_id)
    return reply
