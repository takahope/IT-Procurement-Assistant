from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from procurement_review.domain.models import RuntimePolicy
from procurement_review.storage.repository import Repository
from procurement_review.web.routes import router
from procurement_review.web.security import SecurityMiddleware, SessionManager


def create_app(policy: RuntimePolicy, repo: Repository) -> FastAPI:
    """建立並配置採購審查本機 Web 應用程式實例。

    安全約束：
    - 停用外連 CDN 之 OpenAPI / Swagger / ReDoc 文件頁。
    - 啟動時產出一次性 bootstrap token，供本機瀏覽器透過 URL fragment 換取會話。
    - 伺服器啟動或崩潰重啟時，自動將前次殘留之 running 執行管線標記為 interrupted。
    - 套用嚴格 Loopback Host、Origin、CSRF 與 CSP 安全中介軟體。
    """
    # 1. 執行重啟恢復檢查：將所有 running runs 標記為 interrupted
    now_iso = datetime.now(UTC).isoformat()
    with repo._conn() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute(
            """
            UPDATE runs
            SET state = 'interrupted',
                invalidation_reason = 'SERVER_RESTARTED',
                updated_at = ?
            WHERE state = 'running'
            """,
            (now_iso,),
        )
        conn.commit()

    # 2. 建立 FastAPI 實例，停用外部 CDN 文件頁
    app = FastAPI(
        title="中央研究院資訊採購合約資安審查助手",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # 3. 初始化會話管理器與單次 bootstrap token
    session_manager = SessionManager()
    bootstrap_token = session_manager.generate_bootstrap_token()

    app.state.session_manager = session_manager
    app.state.bootstrap_token = bootstrap_token
    app.state.policy = policy
    app.state.repo = repo
    app.state.executor = ThreadPoolExecutor(max_workers=4)

    # 4. 加入安全中介軟體 (Host, Origin, CSRF, CSP)
    app.add_middleware(SecurityMiddleware, session_manager=session_manager)

    # 5. 掛載靜態資源目錄
    static_dir = Path(__file__).parent / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    # 6. 註冊路由
    app.include_router(router)

    return app
