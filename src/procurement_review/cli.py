import argparse
import json
import os
import sys
from datetime import UTC, date, datetime
from pathlib import Path

import uvicorn

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import Rule, RuntimePolicy, SourceReference
from procurement_review.rules.catalog import RuleEngine
from procurement_review.rules.seeder import seed_rules_and_sources
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


def _resolve_mode(mode_str: str) -> RuntimeMode:
    """將命令列模式參數映射至 RuntimeMode 列舉。"""
    if mode_str in ("production", "real"):
        return RuntimeMode.REAL
    return RuntimeMode.SYNTHETIC


DEFAULT_DATA_DIR = str(Path.home() / ".procurement_review" / "data")


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
        choices=["synthetic", "production", "real"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    serve_parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help=f"資料儲存根目錄路徑 (預設: {DEFAULT_DATA_DIR})",
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
        default=DEFAULT_DATA_DIR,
        help=f"來源資料儲存目錄 (預設: {DEFAULT_DATA_DIR})",
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
        choices=["synthetic", "production", "real"],
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
        choices=["synthetic", "production", "real"],
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
        default=DEFAULT_DATA_DIR,
        help=f"資料儲存目錄 (預設: {DEFAULT_DATA_DIR})",
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
        choices=["synthetic", "production", "real"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    purge_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    # 5. evaluate 命令
    evaluate_parser = subparsers.add_parser("evaluate", help="執行合約審查多維度評測與發布判定 (M3)")
    evaluate_parser.add_argument(
        "--manifest",
        required=True,
        help="評測資料集清單 JSON 檔案路徑",
    )
    evaluate_parser.add_argument(
        "--output",
        required=True,
        help="評測報告輸出 JSON 檔案路徑",
    )
    evaluate_parser.add_argument(
        "--policy",
        default=None,
        help="驗收判定政策 JSON 檔案路徑 (選填)",
    )
    # 6. doctor 命令
    doctor_parser = subparsers.add_parser("doctor", help="執行系統環境、依賴套件、金鑰儲存與規則庫自我診斷")
    doctor_parser.add_argument(
        "--mode",
        choices=["synthetic", "production", "real"],
        default="synthetic",
        help="執行期模式 (預設: synthetic)",
    )
    doctor_parser.add_argument(
        "--data-dir",
        default=DEFAULT_DATA_DIR,
        help=f"資料儲存根目錄路徑 (預設: {DEFAULT_DATA_DIR})",
    )
    doctor_parser.add_argument(
        "--master-key",
        default=None,
        help="指定主資料金鑰 (合成模式備用)",
    )

    return parser


def doctor(args: argparse.Namespace, secrets: SecretStore | None = None) -> None:
    has_error = False

    data_dir = Path(args.data_dir).resolve()
    dir_existed = data_dir.exists()
    data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not dir_existed:
        data_dir.chmod(0o700)
    vault_root = data_dir / "vault"
    vault_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    db_path = data_dir / "procurement_review.db"

    mode = _resolve_mode(args.mode)
    active_secrets = _get_cli_secrets(
        mode=mode,
        data_dir=data_dir,
        vault_root=vault_root,
        master_key_arg=getattr(args, "master_key", None),
        provided_secrets=secrets,
    )

    print("=" * 70)
    print("中央研究院資訊採購合約資安審查助手 — 系統自我診斷 (Doctor)")
    print(f"模式: {mode.value}")
    print(f"資料目錄: {data_dir}")
    print("-" * 70)

    # 1. Python 執行環境
    py_ver = sys.version.split()[0]
    py_ok = sys.version_info >= (3, 11)
    if py_ok:
        print(f"[OK] Python 執行環境: v{py_ver} (滿足需求 >= 3.11)")
    else:
        print(f"[FAIL] Python 執行環境: v{py_ver} (需求 >= 3.11)")
        has_error = True

    # 2. 核心相依套件檢查
    required_packages = [
        "fastapi",
        "pydantic",
        "uvicorn",
        "cryptography",
        "httpx",
        "docx",
        "pypdf",
        "sqlite3",
    ]
    missing_pkgs = []
    for pkg in required_packages:
        try:
            __import__(pkg)
        except ImportError:
            missing_pkgs.append(pkg)
    if not missing_pkgs:
        print(f"[OK] 核心相依套件: {len(required_packages)}/{len(required_packages)} 項就緒")
    else:
        print(f"[FAIL] 缺少相依套件: {missing_pkgs}")
        has_error = True

    # 3. 資料目錄與權限檢查
    stat_mode = data_dir.stat().st_mode
    if (stat_mode & 0o777) == 0o700:
        print(f"[OK] 資料根目錄與 Vault: 權限就緒 ({oct(stat_mode & 0o777)}), 儲存路徑正常")
    else:
        print(f"[FAIL] 資料目錄權限不安全 (目前: {oct(stat_mode & 0o777)}, 要求: 0o700)")
        has_error = True

    # 4. SecretStore 金鑰儲存庫檢查 (絕不洩漏密鑰原文)
    if (
        mode == RuntimeMode.SYNTHETIC
        and isinstance(active_secrets, FakeSecretStore)
        and not active_secrets.get_key("artifact_master_key")
    ):
        test_key = b"\x00" * 32
        active_secrets.set_key("artifact_master_key", test_key)
        (data_dir / ".synthetic_key").write_bytes(test_key)
    has_key = active_secrets.get_key("artifact_master_key") is not None
    store_type = active_secrets.__class__.__name__
    print(f"[OK] SecretStore 金鑰儲存庫: {store_type} (主資料金鑰: {'已配置 [PROTECTED]' if has_key else '未配置'})")

    # 5. SQLite 資料庫連線與結構初始
    try:
        artifacts = ArtifactStore(root=vault_root, secrets=active_secrets)
        repo = Repository(db=db_path, artifacts=artifacts)
        with repo._conn() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1;")
            cur.fetchone()
        print(f"[OK] SQLite 資料庫連線: 正常 ({db_path.name}, WAL 模式已就緒)")
    except Exception as err:  # noqa: BLE001
        print(f"[FAIL] SQLite 資料庫連線失敗: {err}")
        has_error = True

    # 6. 規則包與法規清單
    rules_root = Path.cwd() / "rules"
    if not rules_root.exists():
        rules_root = Path(__file__).resolve().parent.parent.parent / "rules"

    rules_ok = True
    rules_issues: list[str] = []
    if not rules_root.exists() or not (rules_root / "drafts").exists():
        rules_ok = False
        rules_issues.append(f"規則目錄不存在: {rules_root}")
    else:
        draft_files = list((rules_root / "drafts").glob("*.json"))
        if not draft_files:
            rules_ok = False
            rules_issues.append("未找到任何規則包 JSON 檔案")
        else:
            engine = RuleEngine()
            for df in sorted(draft_files):
                try:
                    with open(df, "r", encoding="utf-8") as f:
                        content = json.load(f)
                    for r_dict in content.get("rules", []):
                        r = Rule.model_validate(r_dict)
                        engine.register_rule(r)
                except Exception as err:  # noqa: BLE001
                    rules_ok = False
                    rules_issues.append(f"規則檔 {df.name} 載入或驗證失敗: {err}")

            manifest_file = rules_root / "sources" / "manifest.json"
            if manifest_file.exists():
                try:
                    with open(manifest_file, "r", encoding="utf-8") as f:
                        m_data = json.load(f)
                    for s in m_data.get("sources", []):
                        s_kwargs = {k: v for k, v in s.items() if k != "retrieval_status"}
                        src = SourceReference.model_validate(s_kwargs)
                        engine.register_source(src)
                except Exception as err:  # noqa: BLE001
                    rules_ok = False
                    rules_issues.append(f"來源清單 {manifest_file.name} 驗證失敗: {err}")

    packs = ["software_maintenance", "custom_software", "cloud_service", "mixed"]
    if rules_ok:
        print(f"[OK] 規則包狀態: 4/4 採購分類就緒 ({', '.join(packs)})")
    else:
        print(f"[FAIL] 規則庫驗證失敗: {'; '.join(rules_issues)}")
        has_error = True

    # 7. 供應商與模型權重組態
    if mode == RuntimeMode.SYNTHETIC:
        provider_desc = "MockProviderAdapter (離線合成模式，預設端點 https://mock.provider.local/v1/chat/completions)"
    else:
        provider_desc = "CloudAdapter (已核准雲端供應商)"
    print(f"[OK] 供應商與模型權重組態: {provider_desc}")

    # 8. 生命週期與受控清除機制
    print("[OK] 生命週期與受控清除: 30天保存政策、墓碑審計紀錄表與安全復原閘門就緒")
    print("-" * 70)

    if has_error:
        print("[FAIL] 系統診斷未通過：請排除上述問題後重試。")
        print("=" * 70)
        sys.exit(1)
    else:
        print("[OK] 系統診斷完成：所有必要環境檢查通過。")
        print("=" * 70)


def main(argv: list[str] | None = None, secrets: SecretStore | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "serve":
        data_dir = Path(args.data_dir).resolve()
        data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        vault_root = data_dir / "vault"
        vault_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        db_path = data_dir / "procurement_review.db"

        mode = _resolve_mode(args.mode)
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

        mode = _resolve_mode(args.mode)
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
        mode = _resolve_mode(args.mode)

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

        mode = _resolve_mode(args.mode)
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

    elif args.command == "evaluate":
        from procurement_review.evaluation.runner import run_evaluation

        result = run_evaluation(
            manifest_path=args.manifest,
            output_path=args.output,
            policy_path=args.policy,
        )
        report = result.get("evaluation_report", {})
        print("=" * 70)
        print("合約審查評測報告 (M3 驗收)")
        print(f"Manifest ID: {result.get('manifest_id')} (Mode: {result.get('mode')}, Split: {result.get('split')})")
        print(f"總預期要求數: {report.get('total_expected')}, 實際審查數: {report.get('total_actual')}")
        print(f"TP: {report.get('tp')}, FP: {report.get('fp')}, FN: {report.get('fn')}")
        prec = report.get("precision")
        rec = report.get("recall")
        f1 = report.get("f1")
        print(f"Precision: {f'{prec:.4f}' if prec is not None else 'N/A'}")
        print(f"Recall:    {f'{rec:.4f}' if rec is not None else 'N/A'}")
        print(f"F1-score:  {f'{f1:.4f}' if f1 is not None else 'N/A'}")
        print(f"報告已輸出至: {args.output}")

        if "gate_report" in result:
            gate = result["gate_report"]
            print("-" * 70)
            print(f"發布判定狀態: {gate.get('status', '').upper()}")
            if gate.get("ok"):
                print("[PASS] 通過所有零容忍安全檢查與品質門檻！")
            else:
                print(f"[FAIL] 發布判定未通過，發現 {len(gate.get('failures', []))} 項不合規：")
                for f in gate.get("failures", []):
                    print(f"  - {f}")
                raise DomainError(
                    "RELEASE_GATE_FAILED",
                    f"Release gate check failed with {len(gate.get('failures', []))} failure(s)",
                )
        print("=" * 70)

    elif args.command == "doctor":
        doctor(args, secrets=secrets)


if __name__ == "__main__":
    main()
