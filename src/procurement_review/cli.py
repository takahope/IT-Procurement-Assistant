import argparse
import os
from datetime import UTC, date, datetime
from pathlib import Path

import uvicorn

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import RuntimePolicy
from procurement_review.runtime.lifecycle import (
    create_backup,
    execute_purge,
    plan_purge,
    restore_backup,
)
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore, OSKeychainSecretStore, SecretStore
from procurement_review.storage.vault import ArtifactStore
from procurement_review.web.app import create_app


def _get_cli_secrets(
    mode: RuntimeMode,
    data_dir: Path,
    vault_root: Path,
    master_key_arg: str | None = None,
    provided_secrets: SecretStore | None = None,
) -> SecretStore:
    """根據模式與環境取得對應之金鑰管理庫。"""
    if provided_secrets is not None:
        return provided_secrets

    if mode == RuntimeMode.SYNTHETIC:
        secrets = FakeSecretStore()
        # 1. 優先從命令列參數提取
        if master_key_arg:
            k = bytes.fromhex(master_key_arg) if len(master_key_arg) == 64 else master_key_arg.encode("utf-8")
            secrets.set_key("artifact_master_key", k)
        # 2. 從環境變數提取
        elif os.environ.get("PROCUREMENT_REVIEW_MASTER_KEY"):
            k_env = os.environ["PROCUREMENT_REVIEW_MASTER_KEY"]
            k = bytes.fromhex(k_env) if len(k_env) == 64 else k_env.encode("utf-8")
            secrets.set_key("artifact_master_key", k)
        # 3. 從本地金鑰紀錄檔提取 (供本機 CLI / 測試工具跨命令共用)
        elif (data_dir / ".synthetic_key").exists():
            secrets.set_key("artifact_master_key", (data_dir / ".synthetic_key").read_bytes())
        elif (vault_root / ".synthetic_key").exists():
            secrets.set_key("artifact_master_key", (vault_root / ".synthetic_key").read_bytes())
        return secrets

    return OSKeychainSecretStore()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="procurement-review",
        description="中央研究院資訊採購合約資安審查助手 CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # 1. serve 命令
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
    serve_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    # 2. backup 命令
    backup_parser = subparsers.add_parser("backup", help="產製加密備份封包")
    backup_parser.add_argument(
        "--data-dir",
        default="./data",
        help="來源資料儲存目錄 (預設: ./data)",
    )
    backup_parser.add_argument(
        "--target",
        required=True,
        help="目標備份檔案或目錄路徑",
    )
    backup_parser.add_argument(
        "--recovery-key",
        required=True,
        help="備援恢復金鑰 (Recovery Key)",
    )
    backup_parser.add_argument(
        "--mode",
        choices=["synthetic", "production"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    backup_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    # 3. restore 命令
    restore_parser = subparsers.add_parser("restore", help="還原加密備份封包至指定目錄")
    restore_parser.add_argument(
        "--backup",
        required=True,
        help="備份檔案路徑",
    )
    restore_parser.add_argument(
        "--target",
        required=True,
        help="還原目標資料目錄",
    )
    restore_parser.add_argument(
        "--recovery-key",
        required=True,
        help="備援恢復金鑰 (Recovery Key)",
    )
    restore_parser.add_argument(
        "--mode",
        choices=["synthetic", "production"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    restore_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    # 4. purge 命令
    purge_parser = subparsers.add_parser("purge", help="依保存政策受控清除案件產物")
    purge_parser.add_argument(
        "--case-id",
        required=True,
        help="欲清除之案件 ID (UUID)",
    )
    purge_parser.add_argument(
        "--data-dir",
        default="./data",
        help="資料儲存目錄 (預設: ./data)",
    )
    purge_parser.add_argument(
        "--as-of",
        default=None,
        help="盤點基準日期 (YYYY-MM-DD，預設為今日)",
    )
    purge_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="僅預覽欲清除之產物清單與 confirmation_hash，不實際刪除",
    )
    purge_parser.add_argument(
        "--confirmation-hash",
        default=None,
        help="確認執行雜湊值 (非 dry-run 模式下必填)",
    )
    purge_parser.add_argument(
        "--approved-by",
        default=None,
        help="手動核准人員簽署 (未滿保存期案件必填)",
    )
    purge_parser.add_argument(
        "--mode",
        choices=["synthetic", "production"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    purge_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    return parser


def main(argv: list[str] | None = None, secrets: SecretStore | None = None) -> None:
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

        active_secrets = _get_cli_secrets(
            mode=mode,
            data_dir=data_dir,
            vault_root=vault_root,
            master_key_arg=getattr(args, "master_key", None),
            provided_secrets=secrets,
        )
        artifacts = ArtifactStore(root=vault_root, secrets=active_secrets)
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

    elif args.command == "backup":
        data_dir = Path(args.data_dir).resolve()
        vault_root = data_dir / "vault"
        db_path = data_dir / "procurement_review.db"
        if not db_path.exists() and (data_dir / "app.db").exists():
            db_path = data_dir / "app.db"

        mode = RuntimeMode.SYNTHETIC if args.mode == "synthetic" else RuntimeMode.PRODUCTION
        active_secrets = _get_cli_secrets(
            mode=mode,
            data_dir=data_dir,
            vault_root=vault_root,
            master_key_arg=getattr(args, "master_key", None),
            provided_secrets=secrets,
        )
        artifacts = ArtifactStore(root=vault_root, secrets=active_secrets)
        repo = Repository(db=db_path, artifacts=artifacts)

        target_path = Path(args.target).resolve()
        created_backup = create_backup(repo=repo, target=target_path, recovery_key_ref=args.recovery_key)
        print(f"[OK] 加密備份產製完成: {created_backup}")

    elif args.command == "restore":
        backup_path = Path(args.backup).resolve()
        target_dir = Path(args.target).resolve()
        vault_root = target_dir / "vault"
        mode = RuntimeMode.SYNTHETIC if args.mode == "synthetic" else RuntimeMode.PRODUCTION

        active_secrets = _get_cli_secrets(
            mode=mode,
            data_dir=target_dir,
            vault_root=vault_root,
            master_key_arg=getattr(args, "master_key", None),
            provided_secrets=secrets,
        )

        report = restore_backup(
            backup=backup_path,
            target=target_dir,
            secrets=active_secrets,
            recovery_key=args.recovery_key,
        )
        if report.ok:
            # 合成模式下將還原後的金鑰存檔以便後續 CLI 指令存取
            if mode == RuntimeMode.SYNTHETIC and isinstance(active_secrets, FakeSecretStore):
                restored_k = active_secrets.get_key("artifact_master_key")
                if restored_k:
                    (target_dir / ".synthetic_key").write_bytes(restored_k)
            print(f"[OK] 備份還原完成至目標目錄: {target_dir}")
        else:
            print(f"[FAIL] 備份還原失敗: {report.issues}")

    elif args.command == "purge":
        data_dir = Path(args.data_dir).resolve()
        vault_root = data_dir / "vault"
        db_path = data_dir / "procurement_review.db"
        if not db_path.exists() and (data_dir / "app.db").exists():
            db_path = data_dir / "app.db"

        mode = RuntimeMode.SYNTHETIC if args.mode == "synthetic" else RuntimeMode.PRODUCTION
        active_secrets = _get_cli_secrets(
            mode=mode,
            data_dir=data_dir,
            vault_root=vault_root,
            master_key_arg=getattr(args, "master_key", None),
            provided_secrets=secrets,
        )
        artifacts = ArtifactStore(root=vault_root, secrets=active_secrets)
        repo = Repository(db=db_path, artifacts=artifacts)

        as_of_date = date.fromisoformat(args.as_of) if args.as_of else datetime.now(UTC).date()
        plan = plan_purge(
            review_id=args.case_id,
            repo=repo,
            as_of=as_of_date,
            approved_by=args.approved_by,
        )

        if args.dry_run:
            print("=" * 70)
            print(f"案件受控清除預覽計畫 (Case ID: {plan.case_id})")
            print(f"基準日期: {as_of_date.isoformat()}")
            print(f"保存期限已逾期: {'是' if plan.retention_expired else '否 (需手動核准)'}")
            print(f"確認執行 Hash: {plan.confirmation_hash}")
            print("預計清除與盤點標的：")
            for t in plan.purge_targets:
                print(f"  - {t}")
            print("=" * 70)
            print("提示：若欲執行實際刪除，請執行相同命令並帶入:")
            print(f"  --confirmation-hash {plan.confirmation_hash}")
        else:
            if not args.confirmation_hash:
                raise DomainError(
                    "PURGE_CONFIRMATION_REQUIRED",
                    "Purge execution requires --confirmation-hash. Use --dry-run to preview.",
                )
            report = execute_purge(plan, confirmation_hash=args.confirmation_hash, repo=repo)
            if report.ok:
                print(f"[OK] 案件 {plan.case_id} 產物已成功安全清除並寫入 tombstone。")
            else:
                print(f"[FAIL] 清除失敗: {report.issues}")


if __name__ == "__main__":
    main()
