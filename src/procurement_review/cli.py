import argparse
from pathlib import Path

import uvicorn

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.models import RuntimePolicy
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore, KeyringSecretStore
from procurement_review.storage.vault import ArtifactStore
from procurement_review.web.app import create_app


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="procurement-review",
        description="中央研究院資訊採購合約資安審查助手 CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    serve_parser = subparsers.add_parser("serve", help="啟動本機審查 Web 服務")
    serve_parser.add_argument(
        "--mode",
        choices=["synthetic", "production"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    serve_parser.add_argument(
        "--data-dir",
        default="./data",
        help="資料儲存根目錄路徑 (預設: ./data)",
    )
    serve_parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="監聽 IP 位址 (預設: 127.0.0.1，僅限 loopback)",
    )
    serve_parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="監聽埠號 (預設: 8765)",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        data_dir = Path(args.data_dir).resolve()
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        vault_root = data_dir / "vault"
        vault_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        db_path = data_dir / "procurement_review.db"

        mode = RuntimeMode.SYNTHETIC if args.mode == "synthetic" else RuntimeMode.PRODUCTION
        policy = RuntimePolicy(mode=mode, data_root=str(data_dir))

        secrets = FakeSecretStore() if mode == RuntimeMode.SYNTHETIC else KeyringSecretStore()
        artifacts = ArtifactStore(root=vault_root, secrets=secrets)
        repo = Repository(db=db_path, artifacts=artifacts)

        app = create_app(policy=policy, repo=repo)
        bootstrap_token = app.state.bootstrap_token

        # 僅限輸出於本機終端機，作為 URL fragment 供瀏覽器初次載入時單次換取會話
        loopback_url = f"http://{args.host}:{args.port}/#token={bootstrap_token}"
        print("=" * 70)
        print("中央研究院資訊採購合約資安審查助手 啟動中...")
        print(f"模式: {mode.value}")
        print(f"資料目錄: {data_dir}")
        print("請在受信任的本機瀏覽器開啟下列連結以初始化操作會話：")
        print(f"👉  {loopback_url}")
        print("注意：安全 token 僅存在於 URL fragment，單次使用後立即失效，不留存於日誌。")
        print("=" * 70)

        # 單一 worker / process
        uvicorn.run(app, host=args.host, port=args.port, workers=1, access_log=False)


if __name__ == "__main__":
    main()
