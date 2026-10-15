import hmac
import secrets
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, Request, Response
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "[::1]", "testserver"}

CSP_HEADER = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "frame-ancestors 'none';"
)


def _apply_security_headers(response: Response) -> Response:
    response.headers["Content-Security-Policy"] = CSP_HEADER
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    return response


class SessionManager:
    """本機安全會話管理器。

    - 啟動時產出一次性 bootstrap token，供本機瀏覽器透過 URL fragment 換取會話。
    - 換取成功後派發 HttpOnly、SameSite=Strict cookie 與對應 CSRF token。
    - token 僅限單次使用，不進日誌、不放 query。
    """

    def __init__(self) -> None:
        self._bootstrap_tokens: dict[str, float] = {}
        self._sessions: dict[str, dict[str, Any]] = {}

    def generate_bootstrap_token(self) -> str:
        token = secrets.token_urlsafe(32)
        self._bootstrap_tokens[token] = 1.0
        return token

    def consume_bootstrap_token(
        self, token: str, operator: str = "local_reviewer"
    ) -> tuple[str, str] | None:
        if token not in self._bootstrap_tokens:
            return None
        # 單次使用即刪除
        del self._bootstrap_tokens[token]
        session_id = secrets.token_hex(32)
        csrf_token = secrets.token_hex(32)
        self._sessions[session_id] = {
            "operator": operator,
            "csrf_token": csrf_token,
        }
        return session_id, csrf_token

    def get_session(self, session_id: str | None) -> dict[str, Any] | None:
        if not session_id:
            return None
        return self._sessions.get(session_id)

    def validate_csrf(self, session_id: str | None, csrf_token: str | None) -> bool:
        session = self.get_session(session_id)
        if not session or not csrf_token:
            return False
        expected_csrf = session.get("csrf_token", "")
        return hmac.compare_digest(expected_csrf, csrf_token)


def is_loopback_host(host_header: str | None) -> bool:
    if not host_header:
        return False
    # Host 可能帶有 port，例如 localhost:8765
    host_clean = host_header.split(":", 1)[0].strip()
    return host_clean in LOOPBACK_HOSTS


def is_loopback_origin(origin_header: str | None) -> bool:
    if not origin_header:
        return True
    parsed = urlparse(origin_header)
    hostname = parsed.hostname
    if not hostname:
        return False
    return hostname in LOOPBACK_HOSTS


class SecurityMiddleware(BaseHTTPMiddleware):
    """安全檢核中介軟體：

    1. 嚴格 Loopback Host 檢核（非 loopback 一律 403）。
    2. 變更性請求之 Origin / Referer 檢核（非 loopback 一律 403）。
    3. 變更性請求之 CSRF 檢核（缺或錯 CSRF 一律 403，bootstrap 換取端點除外）。
    4. 回應強制注入嚴格 CSP、X-Frame-Options、X-Content-Type-Options 標頭。
    """

    def __init__(self, app: Any, session_manager: SessionManager) -> None:
        super().__init__(app)
        self.session_manager = session_manager

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # 1. Host 檢核
        host = request.headers.get("host")
        if not is_loopback_host(host):
            return _apply_security_headers(
                JSONResponse(
                    status_code=403, content={"detail": "Forbidden: Invalid loopback host"}
                )
            )

        # 2. Origin 檢核 (針對 POST, PUT, DELETE, PATCH)
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            origin = request.headers.get("origin")
            if origin and not is_loopback_origin(origin):
                return _apply_security_headers(
                    JSONResponse(status_code=403, content={"detail": "Forbidden: Invalid Origin"})
                )

            referer = request.headers.get("referer")
            if not origin and referer and not is_loopback_origin(referer):
                return _apply_security_headers(
                    JSONResponse(status_code=403, content={"detail": "Forbidden: Invalid Referer"})
                )

            # 3. CSRF 檢核 (排除 bootstrap 端點)
            path = request.url.path
            if path != "/api/auth/bootstrap":
                session_id = request.cookies.get("session_id")
                # 從 Header (X-CSRF-Token) 取得
                csrf_token = request.headers.get("X-CSRF-Token") or request.headers.get(
                    "x-csrf-token"
                )
                if not self.session_manager.validate_csrf(session_id, csrf_token):
                    return _apply_security_headers(
                        JSONResponse(
                            status_code=403,
                            content={"detail": "Forbidden: CSRF validation failed"},
                        )
                    )

        response = await call_next(request)
        return _apply_security_headers(response)


def get_authenticated_session(request: Request) -> dict[str, Any]:
    """取得已驗證會話，未通過者回傳 401。"""
    session_id = request.cookies.get("session_id")
    session_manager: SessionManager = request.app.state.session_manager
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=401, detail="Unauthorized: Session required")
    return session


def get_current_operator(request: Request) -> str:
    """取得操作者名稱，禁止由前端請求任意偽造。"""
    session = get_authenticated_session(request)
    return session.get("operator", "local_reviewer")
