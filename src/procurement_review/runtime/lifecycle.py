"""Procurement Review Lifecycle & Disaster Recovery Management (Task 14).

提供加密備份、災難還原、保存期限盤點與受控清除：
1. create_backup:
   - 使用 SQLite backup API 產製一致性資料庫快照。
   - 提取 schema version 與 artifact 雜湊清單置入 manifest。
   - 以獨立 recovery key (HKDF-SHA256) 包裝 artifact 資料金鑰 (AES-256-GCM)。
   - 整體封包 AES-256-GCM 加密，產製不可竄改的備份束。
2. restore_backup:
   - 驗證 recovery key 完整性，錯誤時拋出 RECOVERY_KEY_INVALID。
   - 金鑰遺失時直接中斷，絕不靜默重置或初始化目標目錄。
   - 還原資料庫、artifacts 與資料金鑰至新機 SecretStore。
   - 零網路傳輸保證（zero network transmission）。
3. plan_purge:
   - 盤點原檔、轉換物、映射、快取、匯出與過期備份政策。
   - 綁定確定性 confirmation_hash。
4. execute_purge:
   - 嚴格比對 confirmation_hash，錯誤拋出例外。
   - 安全清除檔案並於資料庫寫入 tombstone 紀錄，標記狀態為 purged。
5. check_disaster_recovery_gate:
   - 真實模式強制要求災難復原演練與保留政策核准紀錄，拒絕合成 fixture 偽造。
"""

import contextlib
import hashlib
import io
import os
import shutil
import sqlite3
import struct
import zipfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    GateReport,
    PurgePlan,
    RuntimePolicy,
    VersionRef,
)
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import SecretStore

BACKUP_MAGIC = b"PRBKP001"
BACKUP_INFO_KDF = b"procurement_review_backup_recovery"
AAD_DATA_KEY_WRAP = b"artifact_master_key_wrap"
AAD_PAYLOAD = b"backup_payload"

# 快取活動中的刪除計畫與對應的 Repository 與 Hash
_active_purge_plans: dict[str, tuple[PurgePlan, Repository, str]] = {}


def _derive_recovery_key(recovery_key_ref: str, salt: bytes) -> bytes:
    """使用 HKDF-SHA256 由 recovery_key_ref 字串衍生 256 位元 (32 bytes) 加密金鑰。"""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=BACKUP_INFO_KDF,
    )
    return hkdf.derive(recovery_key_ref.encode("utf-8"))


def _compute_file_sha256(path: Path) -> str:
    """計算指定檔案的 SHA-256 雜湊值。"""
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def _snapshot_sqlite(src_db_path: Path, dest_db_path: Path) -> None:
    """使用 SQLite backup API 建立唯讀安全快照，確保 WAL 交易一致性。"""
    src_conn = sqlite3.connect(f"file:{src_db_path.resolve()}?mode=ro", uri=True)
    try:
        dest_conn = sqlite3.connect(str(dest_db_path))
        try:
            src_conn.backup(dest_conn)
        finally:
            dest_conn.close()
    finally:
        src_conn.close()


def create_backup(
    repo: Repository,
    target: Path,
    recovery_key_ref: str,
) -> Path:
    """建立加密備份封包。

    - 一致性 SQLite snapshot。
    - 收集 schema 版本與各 artifact 雜湊清單置於 manifest。
    - 以 recovery key 包裝 data key。
    - 整包 AES-256-GCM 加密寫出至 target。
    """
    if not recovery_key_ref or not isinstance(recovery_key_ref, str):
        raise DomainError("RECOVERY_KEY_INVALID", "Recovery key cannot be empty")

    target_path = Path(target).resolve()
    if target_path.is_dir() or target.name.endswith("/") or (not target_path.suffix and not target_path.exists()):
        target_path.mkdir(parents=True, exist_ok=True, mode=0o700)
        target_file = target_path / f"procurement_backup_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.bundle"
    else:
        target_file = target_path
        target_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

    # 1. 取得 SQLite snapshot
    tmp_snapshot_db = target_file.parent / f".tmp_{os.urandom(8).hex()}.db"
    try:
        _snapshot_sqlite(repo.db, tmp_snapshot_db)
        db_hash = _compute_file_sha256(tmp_snapshot_db)

        # 2. 查詢 schema_migrations
        schema_version = "unknown"
        with sqlite3.connect(str(tmp_snapshot_db)) as snap_conn:
            cursor = snap_conn.cursor()
            try:
                cursor.execute("SELECT version FROM schema_migrations ORDER BY version DESC LIMIT 1")
                row = cursor.fetchone()
                if row:
                    schema_version = str(row[0])
            except sqlite3.OperationalError:
                pass

        # 3. 收集 artifacts 檔案與雜湊
        artifact_hashes: dict[str, str] = {
            f"database/{repo.db.name}": db_hash,
        }
        vault_root = repo.artifacts.root
        artifact_files: list[tuple[str, Path]] = []

        if vault_root.exists():
            for root, _, files in os.walk(vault_root):
                for f in sorted(files):
                    full_p = Path(root) / f
                    rel_p = full_p.relative_to(vault_root).as_posix()
                    file_sha = _compute_file_sha256(full_p)
                    artifact_hashes[f"vault/{rel_p}"] = file_sha
                    artifact_files.append((rel_p, full_p))

        # 4. 產生 manifest
        manifest = {
            "backup_version": "1.0",
            "schema_version": schema_version,
            "db_filename": repo.db.name,
            "key_name": repo.artifacts.key_name,
            "created_at": datetime.now(UTC).isoformat(),
            "artifact_hashes": artifact_hashes,
        }
        import json

        manifest_json = json.dumps(manifest, indent=2, sort_keys=True).encode()

        # 5. 打包成內層 zip archive
        zip_buf = io.BytesIO()
        with zipfile.ZipFile(zip_buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("manifest.json", manifest_json)
            zf.write(tmp_snapshot_db, arcname=f"database/{repo.db.name}")
            for rel_name, f_path in artifact_files:
                zf.write(f_path, arcname=f"vault/{rel_name}")

        zip_payload = zip_buf.getvalue()

    finally:
        if tmp_snapshot_db.exists():
            tmp_snapshot_db.unlink(missing_ok=True)

    # 6. 金鑰衍生與包裝
    salt = os.urandom(16)
    k_recovery = _derive_recovery_key(recovery_key_ref, salt)

    nonce_wrap = os.urandom(12)
    wrapped_master_key = AESGCM(k_recovery).encrypt(
        nonce_wrap, repo.artifacts.master_key, AAD_DATA_KEY_WRAP
    )

    nonce_payload = os.urandom(12)
    ciphertext = AESGCM(k_recovery).encrypt(
        nonce_payload, zip_payload, AAD_PAYLOAD
    )

    # 7. 打包 Header
    # Format: Magic (8B) + Salt (16B) + Nonce_wrap (12B) + Wrap_len (2B) + WrappedKey + Nonce_payload (12B) + Ciphertext
    header = struct.pack(
        ">8s16s12sH",
        BACKUP_MAGIC,
        salt,
        nonce_wrap,
        len(wrapped_master_key),
    )
    bundle_data = header + wrapped_master_key + nonce_payload + ciphertext

    # 原子性寫入檔案
    tmp_out = target_file.parent / f".tmp_{target_file.name}_{os.urandom(6).hex()}"
    tmp_out.write_bytes(bundle_data)
    os.chmod(tmp_out, 0o600)
    tmp_out.replace(target_file)
    os.chmod(target_file, 0o600)

    return target_file


def restore_backup(
    backup: Path,
    target: Path,
    secrets: SecretStore,
    recovery_key: str | None = None,
    recovery_key_ref: str = "recovery_key",
) -> GateReport:
    """還原加密備份封包。

    - 嚴格驗證 recovery key，金鑰不合拋出 RECOVERY_KEY_INVALID。
    - 金鑰遺失中斷且不重置目標目錄。
    - 驗證所有 artifacts 與資料庫雜湊完整性。
    - 匯入資料金鑰至 SecretStore。
    - 零網路傳輸保證。
    """
    backup_path = Path(backup).resolve()
    if not backup_path.exists() or not backup_path.is_file():
        raise DomainError("BACKUP_NOT_FOUND", f"Backup file '{backup_path}' does not exist")

    # 1. 取得 recovery key
    effective_key = recovery_key
    if effective_key is None:
        key_bytes = secrets.get_key(recovery_key_ref)
        if key_bytes is not None:
            effective_key = key_bytes.decode("utf-8", errors="replace")
        else:
            effective_key = os.environ.get("RECOVERY_KEY") or os.environ.get("PROCUREMENT_REVIEW_RECOVERY_KEY")

    if not effective_key:
        raise DomainError(
            "RECOVERY_KEY_INVALID",
            "Missing recovery key required for backup restoration. Target directory remains untouched.",
        )

    # 2. 讀取封包標頭
    raw_bundle = backup_path.read_bytes()
    header_size = 8 + 16 + 12 + 2  # 38 bytes
    if len(raw_bundle) < header_size + 12 + 16:
        raise DomainError("CORRUPT_BACKUP", "Corrupt backup file: header size too small")

    magic, salt, nonce_wrap, wrap_len = struct.unpack(">8s16s12sH", raw_bundle[:header_size])
    if magic != BACKUP_MAGIC:
        raise DomainError("CORRUPT_BACKUP", "Invalid backup magic header")

    offset = header_size
    if len(raw_bundle) < offset + wrap_len + 12:
        raise DomainError("CORRUPT_BACKUP", "Truncated backup envelope")

    wrapped_master_key = raw_bundle[offset : offset + wrap_len]
    offset += wrap_len

    nonce_payload = raw_bundle[offset : offset + 12]
    offset += 12

    ciphertext = raw_bundle[offset:]

    # 3. 衍生金鑰並解密
    k_recovery = _derive_recovery_key(effective_key, salt)
    aesgcm = AESGCM(k_recovery)

    try:
        master_key = aesgcm.decrypt(nonce_wrap, wrapped_master_key, AAD_DATA_KEY_WRAP)
        zip_payload = aesgcm.decrypt(nonce_payload, ciphertext, AAD_PAYLOAD)
    except InvalidTag as e:
        raise DomainError(
            "RECOVERY_KEY_INVALID",
            "Recovery key verification failed or backup bundle is corrupted or tampered",
        ) from e

    # 4. 解壓縮並驗證 manifest 與雜湊
    import json
    zip_buf = io.BytesIO(zip_payload)
    with zipfile.ZipFile(zip_buf, "r") as zf:
        if "manifest.json" not in zf.namelist():
            raise DomainError("CORRUPT_BACKUP", "Missing manifest.json in backup payload")

        manifest_data = json.loads(zf.read("manifest.json").decode("utf-8"))
        db_filename = manifest_data.get("db_filename", "procurement_review.db")
        key_name = manifest_data.get("key_name", "artifact_master_key")
        expected_hashes: dict[str, str] = manifest_data.get("artifact_hashes", {})

        target_dir = Path(target).resolve()
        target_dir.parent.mkdir(parents=True, exist_ok=True, mode=0o700)

        # 檢查 manifest 的 db_filename 避免路徑穿越
        db_target_path = target_dir / db_filename
        if not db_target_path.resolve().is_relative_to(target_dir.resolve()):
            raise DomainError("CORRUPT_BACKUP", f"Unsafe path traversal in backup: {db_filename}")

        # 使用暫存隔離目錄 (staging) 解壓縮並校驗，確保失敗時目標目錄完全不被部分污染
        staging_dir = target_dir.parent / f".tmp_restore_{target_dir.name}_{os.urandom(8).hex()}"
        staging_dir.mkdir(parents=True, exist_ok=True, mode=0o700)

        try:
            # 解壓縮並驗證
            for name in zf.namelist():
                if name == "manifest.json" or name.endswith("/"):
                    continue

                if name.startswith("database/"):
                    out_path = target_dir / db_filename
                    stage_path = staging_dir / db_filename
                elif name.startswith("vault/"):
                    rel_vault_path = name[len("vault/") :]
                    out_path = target_dir / "vault" / rel_vault_path
                    stage_path = staging_dir / "vault" / rel_vault_path
                else:
                    out_path = target_dir / name
                    stage_path = staging_dir / name

                # Zip Slip (Path Traversal) 防護：驗證 out_path 是否在 target_dir 之內
                if not out_path.resolve().is_relative_to(target_dir.resolve()):
                    raise DomainError("CORRUPT_BACKUP", f"Unsafe path traversal in backup: {name}")

                file_bytes = zf.read(name)
                expected_hash = expected_hashes.get(name)
                if expected_hash:
                    actual_hash = hashlib.sha256(file_bytes).hexdigest()
                    if actual_hash != expected_hash:
                        raise DomainError(
                            "ARTIFACT_TAMPERED",
                            f"Integrity check failed for restored file '{name}': hash mismatch",
                        )

                stage_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                stage_path.write_bytes(file_bytes)
                os.chmod(stage_path, 0o600)

            # 全部檔案校驗通過後，才原子性/受控移入 target_dir
            target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(target_dir, 0o700)

            for item in staging_dir.iterdir():
                dest = target_dir / item.name
                if item.is_file():
                    item.replace(dest)
                    os.chmod(dest, 0o600)
                elif item.is_dir():
                    dest.mkdir(parents=True, exist_ok=True, mode=0o700)
                    os.chmod(dest, 0o700)
                    for root, _, files in os.walk(item):
                        rel_dir = Path(root).relative_to(item)
                        sub_dest = dest / rel_dir
                        sub_dest.mkdir(parents=True, exist_ok=True, mode=0o700)
                        os.chmod(sub_dest, 0o700)
                        for f in files:
                            src_f = Path(root) / f
                            dest_f = sub_dest / f
                            src_f.replace(dest_f)
                            os.chmod(dest_f, 0o600)
        finally:
            if staging_dir.exists():
                shutil.rmtree(staging_dir, ignore_errors=True)

    # 5. 匯入 master_key 至目標 SecretStore
    secrets.set_key(key_name, master_key)

    report = GateReport(
        ok=True,
        operation="restore_backup",
        issues=[],
        checked_at=datetime.now(UTC),
    )
    return report


def _compute_plan_hash(
    review_id: str,
    retention_expired: bool,
    as_of: date,
    purge_targets: list[str],
) -> str:
    """計算確定性 confirmation_hash 綁定計畫與所有盤點項目。"""
    hasher = hashlib.sha256()
    hasher.update(f"{review_id}|{retention_expired}|{as_of.isoformat()}|".encode())
    for target in sorted(purge_targets):
        hasher.update(f"{target}\n".encode())
    return hasher.hexdigest()


def _get_purge_plan_hash(self: PurgePlan) -> str:
    val = getattr(self, "_confirmation_hash", None)
    if val:
        return str(val)
    cached = _active_purge_plans.get(str(self.case_id))
    if cached and cached[0] is self:
        return cached[2]
    # 預設由自身資料產生
    return _compute_plan_hash(
        str(self.case_id),
        self.retention_expired,
        self.planned_at.date(),
        self.purge_targets,
    )


if not hasattr(PurgePlan, "confirmation_hash"):
    PurgePlan.confirmation_hash = property(_get_purge_plan_hash)


def plan_purge(
    review_id: str,
    repo: Repository,
    as_of: date,
    retention_days: int = 30,
    approved_by: str | None = None,
) -> PurgePlan:
    """盤點案件所有相關產物，產製受控刪除計畫。

    盤點項目包括：
    - 原檔 (original documents)
    - 轉換物 (converted snapshots / blocks)
    - 映射 (masking mappings / tokens)
    - 快取 (run contexts / provider replies)
    - 輸出 (tracked exports)
    - 備份到期政策 (expired backup retention policy)
    """
    review = repo.get_review(review_id)
    review_created_date = review.created_at.date()
    expire_cutoff_date = review_created_date + timedelta(days=retention_days)
    retention_expired = as_of >= expire_cutoff_date

    purge_targets: list[str] = []

    # 1. 盤點 Vault 中的 Artifacts
    case_vault_dir = repo.artifacts.root / review_id
    if case_vault_dir.exists():
        for f in sorted(case_vault_dir.glob("*.enc")):
            # 讀取封套 kind (若可讀)
            kind_label = "artifact"
            with contextlib.suppress(struct.error, OSError, UnicodeDecodeError):
                data = f.read_bytes()
                if len(data) >= 24 and data[:8] == b"PRVAULT1":
                    cid_len, kind_len = struct.unpack(">HH", data[8:12])
                    offset = 24 + cid_len
                    kind_label = data[offset : offset + kind_len].decode("utf-8", errors="replace")
            purge_targets.append(f"artifact:{kind_label}:{f.name}")

    # 2. 盤點資料庫內的關聯物件 (Snapshot, Mappings, Cache, Egress)
    purge_targets.append(f"converted_snapshots: Document snapshots and parsed clauses for case {review_id}")
    purge_targets.append(f"masking_mappings: Masking tokens and de-identification mappings for case {review_id}")
    purge_targets.append(f"cache_and_replies: LLM provider replies and context bundles for case {review_id}")

    # 3. 外部匯出盤點（僅追蹤路徑與人工責任聲明，不隨意掃描硬碟）
    purge_targets.append(
        f"tracked_exports: Tracked export paths for case {review_id}. "
        "User or external filesystem copies require manual disposition under CRI policy; "
        "agent does not scan arbitrary disk locations."
    )

    # 4. 備份到期政策聲明
    retention_status_str = "EXPIRED" if retention_expired else "ACTIVE"
    purge_targets.append(
        f"backup_retention_policy: Retention policy status as of {as_of.isoformat()}: {retention_status_str}. "
        f"Retention window: {retention_days} days (cutoff: {expire_cutoff_date.isoformat()}). "
        "Scheduled for retirement upon expiration. Unexpired backups are preserved; "
        "system makes no claim of immediate SSD hardware secure erase."
    )

    # 5. 計算確定性 confirmation_hash
    conf_hash = _compute_plan_hash(review_id, retention_expired, as_of, purge_targets)

    plan = PurgePlan(
        case_id=review_id,
        purge_targets=purge_targets,
        retention_expired=retention_expired,
        approved_by=approved_by,
        planned_at=datetime.now(UTC),
    )
    object.__setattr__(plan, "_confirmation_hash", conf_hash)

    _active_purge_plans[review_id] = (plan, repo, conf_hash)
    return plan


def execute_purge(
    plan: PurgePlan,
    confirmation_hash: str,
    repo: Repository | None = None,
) -> GateReport:
    """執行受控刪除計畫。

    - 比對 confirmation_hash，不符時拋出 PURGE_CONFIRMATION_MISMATCH。
    - 期限未過且未經核准時拋出 PURGE_CONFIRMATION_REQUIRED。
    - 刪除 artifacts 實體檔案。
    - 資料庫寫入 tombstone 紀錄，標記案件狀態為 purged。
    """
    if not confirmation_hash or confirmation_hash != plan.confirmation_hash:
        raise DomainError(
            "PURGE_CONFIRMATION_MISMATCH",
            f"Confirmation hash mismatch. Expected '{plan.confirmation_hash}', got '{confirmation_hash}'.",
        )

    if not plan.retention_expired and not plan.approved_by:
        raise DomainError(
            "PURGE_CONFIRMATION_REQUIRED",
            "Cannot purge unexpired case artifacts without explicit human approval",
        )

    # 取得 Repository 實例
    active_repo = repo
    if active_repo is None:
        cached = _active_purge_plans.get(str(plan.case_id))
        if cached:
            active_repo = cached[1]

    if active_repo is None:
        raise DomainError("REPOSITORY_UNAVAILABLE", "Repository reference required to execute purge")

    cid = str(plan.case_id)

    # 1. 刪除 Vault 中的該案件所有實體檔案
    case_vault_dir = active_repo.artifacts.root / cid
    if case_vault_dir.exists():
        for f in case_vault_dir.glob("*.enc"):
            f.unlink(missing_ok=True)
        # 若目錄已空則清除目錄
        try:
            case_vault_dir.rmdir()
        except OSError:
            pass

    # 2. 資料庫更新狀態並寫入 tombstone
    now_iso = datetime.now(UTC).isoformat()
    with active_repo._conn() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS purge_tombstones (
                case_id TEXT PRIMARY KEY,
                purged_at TEXT NOT NULL,
                confirmation_hash TEXT NOT NULL,
                retention_expired INTEGER NOT NULL,
                approved_by TEXT,
                target_count INTEGER NOT NULL
            );
            """
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO purge_tombstones
            (case_id, purged_at, confirmation_hash, retention_expired, approved_by, target_count)
            VALUES (?, ?, ?, ?, ?, ?);
            """,
            (
                cid,
                now_iso,
                confirmation_hash,
                1 if plan.retention_expired else 0,
                plan.approved_by,
                len(plan.purge_targets),
            ),
        )
        conn.execute(
            "UPDATE reviews SET state = 'purged', updated_at = ? WHERE case_id = ?;",
            (now_iso, cid),
        )

    # 清除快取紀錄
    _active_purge_plans.pop(cid, None)

    return GateReport(
        ok=True,
        operation="execute_purge",
        issues=[],
        checked_at=datetime.now(UTC),
    )


def check_disaster_recovery_gate(
    policy: RuntimePolicy,
    rehearsal_record_ref: VersionRef | None = None,
) -> GateReport:
    """真實模式安全檢核門：要求備份還原演練與保存期限紀錄，拒絕合成 fixture 偽造。"""
    now = datetime.now(UTC)
    issues: list[str] = []

    # 合成模式直接通過
    if policy.mode == RuntimeMode.SYNTHETIC:
        return GateReport(
            ok=True,
            operation="check_disaster_recovery_gate",
            issues=[],
            checked_at=now,
        )

    # 真實模式 (REAL / PRODUCTION)
    if rehearsal_record_ref is None:
        issues.append("Real mode requires verified disaster recovery backup-restore rehearsal record")
    else:
        # 檢驗是否為合成虛擬 ID 偽造 (如全 0 UUID 或全 0 雜湊)
        ref_id = str(rehearsal_record_ref.id).lower()
        sha = rehearsal_record_ref.sha256.lower()
        if (
            ref_id == "00000000-0000-0000-0000-000000000000"
            or sha == "0" * 64
            or sha == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        ):
            issues.append(
                "Synthetic fixture detected: disaster recovery rehearsal record cannot be forged with dummy ID"
            )

    if policy.retention_approval_ref is None:
        issues.append("Missing retention_approval_ref for real mode")

    ok = len(issues) == 0
    return GateReport(
        ok=ok,
        operation="check_disaster_recovery_gate",
        issues=issues,
        checked_at=now,
    )
