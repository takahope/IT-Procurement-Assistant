import glob
import os
import struct
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from procurement_review.domain.errors import DomainError
from procurement_review.storage.secrets import SecretStore

ENVELOPE_MAGIC = b"PRVAULT1"


def _is_inside_repo(path: Path) -> bool:
    """判斷路徑是否位於專案程式碼庫 (Git repo / pyproject.toml 所在根目錄) 內部。"""
    try:
        resolved = path.resolve()
    except (OSError, RuntimeError):
        return False

    curr = Path(__file__).resolve().parent
    repo_root = None
    while curr != curr.parent:
        if (curr / ".git").exists() or (curr / "pyproject.toml").exists():
            repo_root = curr
            break
        curr = curr.parent

    if repo_root is None:
        return False

    try:
        resolved.relative_to(repo_root)
        return True
    except ValueError:
        return False


def pack_envelope(case_id: str, kind: str, nonce: bytes, ciphertext: bytes) -> bytes:
    """打包加密封套：包含 magic、長度前綴、case_id、kind、nonce 與密文。"""
    cid_bytes = case_id.encode("utf-8")
    kind_bytes = kind.encode("utf-8")
    header = struct.pack(">8sHH12s", ENVELOPE_MAGIC, len(cid_bytes), len(kind_bytes), nonce)
    return header + cid_bytes + kind_bytes + ciphertext


def unpack_envelope(data: bytes) -> tuple[str, str, bytes, bytes]:
    """解開封套，檢驗結構完整性。"""
    if len(data) < 24:  # 8 (magic) + 2 + 2 + 12 (nonce)
        raise DomainError("ARTIFACT_TAMPERED", "Invalid artifact header size")

    magic, cid_len, kind_len, nonce = struct.unpack(">8sHH12s", data[:24])
    if magic != ENVELOPE_MAGIC:
        raise DomainError("ARTIFACT_TAMPERED", "Invalid artifact magic header")

    offset = 24
    if len(data) < offset + cid_len + kind_len:
        raise DomainError("ARTIFACT_TAMPERED", "Truncated artifact envelope")

    try:
        cid = data[offset : offset + cid_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise DomainError("ARTIFACT_TAMPERED", "Corrupted case_id in envelope") from e
    offset += cid_len

    try:
        kind = data[offset : offset + kind_len].decode("utf-8")
    except UnicodeDecodeError as e:
        raise DomainError("ARTIFACT_TAMPERED", "Corrupted kind in envelope") from e
    offset += kind_len

    ciphertext = data[offset:]
    return cid, kind, nonce, ciphertext


class ArtifactStore:
    """安全加密 Artifact 儲存庫。

    保證：
    - AES-256-GCM 加密，每次寫入獨立隨機 12-byte Nonce。
    - AAD 綁定 "{case_id}:{kind}"，防止跨案替換或分類篡改。
    - 本機目錄權限強制 0700、檔案權限強制 0600、寫入採原子置換 (rename)。
    - 禁止資料儲存於 Git Repo 內部，防禦路徑穿越與符號連結攻擊。
    - 既有 artifact 對應金鑰遺失時，拒絕覆蓋並拋出 KEY_UNAVAILABLE。
    """

    def __init__(
        self,
        root: Path,
        secrets: SecretStore,
        key_name: str = "artifact_master_key",
    ) -> None:
        self.root = Path(root).resolve()
        self.secrets = secrets
        self.key_name = key_name

        # 安全檢核：禁止儲存於 repo 內部
        if _is_inside_repo(self.root):
            raise DomainError(
                "STORAGE_INSIDE_REPO",
                f"Storage root '{self.root}' cannot be located inside repository",
            )

        # 檢核是否已有既有 artifacts 或初始化標記
        init_marker = self.root / ".vault_init"
        has_existing_artifacts = init_marker.exists() or any(self.root.glob("*/*.enc"))

        if has_existing_artifacts:
            # 既有 storage：不允許自動產生新金鑰，金鑰遺失需拋 KEY_UNAVAILABLE
            self.master_key = self.secrets.get_or_create_key(self.key_name, allow_create=False)
        else:
            # 首次初始化：允許產生新金鑰
            self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
            os.chmod(self.root, 0o700)
            self.master_key = self.secrets.get_or_create_key(self.key_name, allow_create=True)
            init_marker.write_text(
                f'{{"version": 1, "key_name": "{self.key_name}"}}\n',
                encoding="utf-8",
            )
            os.chmod(init_marker, 0o600)

    def _validate_identifier(self, ident: str, param_name: str) -> None:
        if not ident or not isinstance(ident, str):
            raise DomainError("PATH_TRAVERSAL", f"{param_name} cannot be empty")
        if ".." in ident or "/" in ident or "\\" in ident or "\0" in ident:
            raise DomainError(
                "PATH_TRAVERSAL",
                f"Path traversal characters detected in {param_name}: {ident!r}",
            )

    def put(
        self,
        case_id: str,
        kind: str,
        data: bytes,
        artifact_id: str | None = None,
        filename: str | None = None,
    ) -> str:
        """寫入加密 artifact，回傳生成的 artifact_id。"""
        self._validate_identifier(case_id, "case_id")
        self._validate_identifier(kind, "kind")

        if filename:
            target_id = filename.removesuffix(".enc")
        elif artifact_id:
            target_id = artifact_id.removesuffix(".enc")
        else:
            target_id = str(uuid.uuid4())

        self._validate_identifier(target_id, "artifact_id")

        nonce = os.urandom(12)
        aad = f"{case_id}:{kind}".encode()

        aesgcm = AESGCM(self.master_key)
        ciphertext = aesgcm.encrypt(nonce, data, aad)

        payload = pack_envelope(case_id=case_id, kind=kind, nonce=nonce, ciphertext=ciphertext)

        case_dir = self.root / case_id
        try:
            resolved_case = case_dir.resolve()
            if not resolved_case.is_relative_to(self.root):
                raise DomainError("PATH_TRAVERSAL", "Case directory points outside storage root")
        except OSError as e:
            raise DomainError("PATH_TRAVERSAL", "Invalid case directory") from e

        case_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(case_dir, 0o700)

        target_file = case_dir / f"{target_id}.enc"
        temp_file = case_dir / f".{target_id}.tmp"

        temp_file.write_bytes(payload)
        os.chmod(temp_file, 0o600)
        temp_file.replace(target_file)
        os.chmod(target_file, 0o600)

        return target_id

    def get(self, case_id: str, artifact_id: str) -> bytes:
        """讀取並解密 artifact，拒絕跨案存取、篡改與路徑穿越。"""
        self._validate_identifier(case_id, "case_id")
        self._validate_identifier(artifact_id, "artifact_id")

        pure_id = artifact_id.removesuffix(".enc")
        case_dir = self.root / case_id
        target_file = case_dir / f"{pure_id}.enc"

        # 檢驗 symlink 與目標路徑是否跳出 storage root（防止 case_dir 或檔案為跳出根目錄之 symlink）
        try:
            resolved = target_file.resolve()
            if not resolved.is_relative_to(self.root):
                raise DomainError("PATH_TRAVERSAL", "Symlink points outside storage root")
        except OSError as e:
            raise DomainError("PATH_TRAVERSAL", "Invalid symlink") from e

        if not target_file.exists():
            # 檢查是否屬於其他案件（跨案存取防護）
            escaped_id = glob.escape(pure_id)
            other_matches = list(self.root.glob(f"*/{escaped_id}.enc"))
            if other_matches:
                raise DomainError(
                    "ARTIFACT_CROSS_CASE_ACCESS",
                    f"Artifact {artifact_id} belongs to another case",
                )
            raise DomainError(
                "ARTIFACT_NOT_FOUND",
                f"Artifact {artifact_id} not found in case {case_id}",
            )

        payload = target_file.read_bytes()
        stored_cid, kind, nonce, ciphertext = unpack_envelope(payload)

        if stored_cid != case_id:
            raise DomainError(
                "ARTIFACT_CROSS_CASE_ACCESS",
                f"Artifact belongs to {stored_cid}, not {case_id}",
            )

        aad = f"{case_id}:{kind}".encode()
        aesgcm = AESGCM(self.master_key)
        try:
            return aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as e:
            raise DomainError(
                "ARTIFACT_TAMPERED",
                "Artifact ciphertext has been tampered with or corrupted",
            ) from e
