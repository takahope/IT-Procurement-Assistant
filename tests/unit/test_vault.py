import os
from pathlib import Path

import pytest

from procurement_review.domain.errors import DomainError
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


def test_put_and_get_artifact(tmp_path: Path):
    """驗證正常寫入與讀取加密 artifact，並確認回傳 UUID 與解密內容一致。"""
    secrets = FakeSecretStore()
    store = ArtifactStore(root=tmp_path / "vault", secrets=secrets)

    case_id = "11111111-1111-4111-8111-111111111111"
    kind = "contract_original"
    data = b"Hello, confidential procurement contract content!"

    artifact_id = store.put(case_id=case_id, kind=kind, data=data)
    assert isinstance(artifact_id, str)
    assert len(artifact_id) == 36  # UUID format

    decrypted = store.get(case_id=case_id, artifact_id=artifact_id)
    assert decrypted == data


def test_cross_case_get_rejected(tmp_path: Path):
    """跨案 get 拒絕：當 artifact 屬於 case-1，以 case-2 呼叫 get 必須拋出 ARTIFACT_CROSS_CASE_ACCESS。"""
    secrets = FakeSecretStore()
    store = ArtifactStore(root=tmp_path / "vault", secrets=secrets)

    case_1 = "11111111-1111-4111-8111-111111111111"
    case_2 = "22222222-2222-4222-8222-222222222222"
    data = b"Secret data belonging only to case 1"

    artifact_id = store.put(case_id=case_1, kind="contract_draft", data=data)

    with pytest.raises(DomainError) as excinfo:
        store.get(case_id=case_2, artifact_id=artifact_id)
    assert excinfo.value.code == "ARTIFACT_CROSS_CASE_ACCESS"


def test_ciphertext_tampering_rejected(tmp_path: Path):
    """密文篡改拒絕：當實體檔案密文遭惡意篡改，AES-GCM 認證失敗並拋出 ARTIFACT_TAMPERED。"""
    secrets = FakeSecretStore()
    store = ArtifactStore(root=tmp_path / "vault", secrets=secrets)

    case_id = "11111111-1111-4111-8111-111111111111"
    data = b"Authentic payload to be tampered"
    artifact_id = store.put(case_id=case_id, kind="evidence", data=data)

    # 尋找落盤檔案並篡改位元組
    artifact_files = list((tmp_path / "vault").glob(f"**/{artifact_id}.enc"))
    assert len(artifact_files) == 1
    enc_file = artifact_files[0]

    content = bytearray(enc_file.read_bytes())
    # 翻轉最後幾個位元組（認證 tag 或密文尾段）
    content[-1] ^= 0xFF
    enc_file.write_bytes(bytes(content))

    with pytest.raises(DomainError) as excinfo:
        store.get(case_id=case_id, artifact_id=artifact_id)
    assert excinfo.value.code == "ARTIFACT_TAMPERED"


def test_storage_inside_repo_rejected():
    """資料根在 repo 拒絕：若儲存根路徑指向 git repo 內部，拒絕初始化。"""
    secrets = FakeSecretStore()
    repo_internal_path = Path(__file__).resolve().parent / "leak_vault"

    with pytest.raises(DomainError) as excinfo:
        ArtifactStore(root=repo_internal_path, secrets=secrets)
    assert excinfo.value.code == "STORAGE_INSIDE_REPO"


def test_path_traversal_rejected(tmp_path: Path):
    """路徑穿越拒絕：檔名含 `../`、斜線或跳出根目錄均拒絕。"""
    secrets = FakeSecretStore()
    store = ArtifactStore(root=tmp_path / "vault", secrets=secrets)
    valid_case = "11111111-1111-4111-8111-111111111111"

    # 1. case_id 穿越
    with pytest.raises(DomainError) as excinfo:
        store.put(case_id="../traversal_case", kind="test", data=b"data")
    assert excinfo.value.code == "PATH_TRAVERSAL"

    with pytest.raises(DomainError) as excinfo:
        store.get(case_id="../traversal_case", artifact_id="11111111-1111-4111-8111-111111111111")
    assert excinfo.value.code == "PATH_TRAVERSAL"

    # 2. artifact_id 穿越
    with pytest.raises(DomainError) as excinfo:
        store.get(case_id=valid_case, artifact_id="../../etc/passwd")
    assert excinfo.value.code == "PATH_TRAVERSAL"


def test_symlink_jumping_out_rejected(tmp_path: Path):
    """跳出 root 的 symlink 拒絕存取。"""
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    store = ArtifactStore(root=vault_root, secrets=secrets)

    case_id = "11111111-1111-4111-8111-111111111111"
    _ = store.put(case_id=case_id, kind="test", data=b"safe")

    # 在 case 目錄建立指向外部的 symlink
    outside_file = tmp_path / "outside.txt"
    outside_file.write_text("evil outside content")

    fake_artifact_id = "33333333-3333-4333-8333-333333333333"
    symlink_path = vault_root / case_id / f"{fake_artifact_id}.enc"
    try:
        os.symlink(outside_file, symlink_path)
    except OSError:
        pytest.skip("Filesystem does not support symlinks")

    with pytest.raises(DomainError) as excinfo:
        store.get(case_id=case_id, artifact_id=fake_artifact_id)
    assert excinfo.value.code == "PATH_TRAVERSAL"


def test_key_unavailable_when_existing_artifacts_lost_key(tmp_path: Path):
    """既有 artifact 對應 key 遺失時回 KEY_UNAVAILABLE，不能重新產生 key 覆蓋。"""
    vault_root = tmp_path / "vault"
    secrets_1 = FakeSecretStore()
    store_1 = ArtifactStore(root=vault_root, secrets=secrets_1)

    case_id = "11111111-1111-4111-8111-111111111111"
    _ = store_1.put(case_id=case_id, kind="contract", data=b"important")

    # 模擬金鑰庫遺失金鑰（新的空 SecretStore）
    secrets_empty = FakeSecretStore()

    # 嘗試以空的 SecretStore 重新載入既有 storage
    with pytest.raises(DomainError) as excinfo:
        ArtifactStore(root=vault_root, secrets=secrets_empty)
    assert excinfo.value.code == "KEY_UNAVAILABLE"


def test_directory_and_file_permissions(tmp_path: Path):
    """本機目錄 0700、檔案 0600。"""
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    store = ArtifactStore(root=vault_root, secrets=secrets)

    case_id = "11111111-1111-4111-8111-111111111111"
    artifact_id = store.put(case_id=case_id, kind="spec", data=b"secret spec")

    case_dir = vault_root / case_id
    assert case_dir.is_dir()
    # 檢查目錄權限為 0700 (drwx------)
    dir_stat = case_dir.stat().st_mode & 0o777
    assert dir_stat == 0o700, f"Expected 0700, got {oct(dir_stat)}"

    artifact_file = case_dir / f"{artifact_id}.enc"
    assert artifact_file.is_file()
    # 檢查檔案權限為 0600 (-rw-------)
    file_stat = artifact_file.stat().st_mode & 0o777
    assert file_stat == 0o600, f"Expected 0600, got {oct(file_stat)}"


def test_no_plaintext_in_artifact_storage_files(tmp_path: Path):
    """額外掃測試 root 確認唯一合成敏感字串不出現在密文、非加密檔案。"""
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    store = ArtifactStore(root=vault_root, secrets=secrets)

    sensitive_token = b"TOP_SECRET_RESEARCH_CONTRACT_DATA_xyz987654"
    case_id = "11111111-1111-4111-8111-111111111111"
    store.put(case_id=case_id, kind="confidential_proposal", data=sensitive_token)

    # 遞迴檢查 vault_root 底下所有檔案
    for root_dir, _, filenames in os.walk(vault_root):
        for fname in filenames:
            fpath = Path(root_dir) / fname
            raw_bytes = fpath.read_bytes()
            assert sensitive_token not in raw_bytes, (
                f"Plaintext sensitive token leaked into {fpath}"
            )


def test_secret_store_interface():
    """驗證 SecretStore / FakeSecretStore / OSKeychainSecretStore 基本介面。"""
    fake = FakeSecretStore()
    k1 = fake.get_or_create_key("test_key")
    assert isinstance(k1, bytes)
    assert len(k1) == 32
    k2 = fake.get_or_create_key("test_key")
    assert k1 == k2

    # allow_create=False 時找不到 key 拋出 KEY_UNAVAILABLE
    with pytest.raises(DomainError) as excinfo:
        fake.get_or_create_key("nonexistent_key", allow_create=False)
    assert excinfo.value.code == "KEY_UNAVAILABLE"


def test_symlink_prefix_collision_rejected(tmp_path: Path):
    """驗證指向與 root 具相同字串前綴 (如 /tmp/vault_attacker) 的 symlink 必須被拒絕。"""
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    store = ArtifactStore(root=vault_root, secrets=secrets)

    case_id = "11111111-1111-4111-8111-111111111111"
    _ = store.put(case_id=case_id, kind="test", data=b"safe")

    # 建立具有相同前綴的攻擊者目錄，例如 vault_attacker
    attacker_dir = tmp_path / "vault_attacker"
    attacker_dir.mkdir(parents=True, exist_ok=True)
    attacker_file = attacker_dir / "evil.enc"
    attacker_file.write_bytes(b"evil outside data")

    fake_artifact_id = "44444444-4444-4444-8444-444444444444"
    symlink_path = vault_root / case_id / f"{fake_artifact_id}.enc"
    try:
        os.symlink(attacker_file, symlink_path)
    except OSError:
        pytest.skip("Filesystem does not support symlinks")

    # 即使 attacker_file 的字串開頭為 str(vault_root)，is_relative_to 也必須精確判定為外部並拋出 PATH_TRAVERSAL
    with pytest.raises(DomainError) as excinfo:
        store.get(case_id=case_id, artifact_id=fake_artifact_id)
    assert excinfo.value.code == "PATH_TRAVERSAL"

    # 測試 case_dir 本身為 symlink 跳出根目錄的情境
    evil_case_id = "55555555-5555-4555-8555-555555555555"
    evil_case_symlink = vault_root / evil_case_id
    try:
        os.symlink(attacker_dir, evil_case_symlink)
    except OSError:
        pytest.skip("Filesystem does not support symlinks")

    with pytest.raises(DomainError) as excinfo_dir:
        store.get(case_id=evil_case_id, artifact_id="evil")
    assert excinfo_dir.value.code == "PATH_TRAVERSAL"

    with pytest.raises(DomainError) as excinfo_put:
        store.put(case_id=evil_case_id, kind="test", data=b"leak")
    assert excinfo_put.value.code == "PATH_TRAVERSAL"


def test_wildcard_artifact_id_not_triggering_cross_case_error(tmp_path: Path):
    """驗證 artifact_id 含 * 或 ? 等 glob 通配符時，不會誤比對其他案件檔案或誤觸跨案存取例外。"""
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    store = ArtifactStore(root=vault_root, secrets=secrets)

    case_1 = "11111111-1111-4111-8111-111111111111"
    case_2 = "22222222-2222-4222-8222-222222222222"
    data = b"Case 1 payload"
    _ = store.put(case_id=case_1, kind="contract", data=data)

    # 在 case_2 嘗試以通配符查詢，若未逃逸 glob，將比對到 case_1 導致誤拋 ARTIFACT_CROSS_CASE_ACCESS
    for wildcard in ["*", "*.*", "?", "[0-9]*"]:
        with pytest.raises(DomainError) as excinfo:
            store.get(case_id=case_2, artifact_id=wildcard)
        assert excinfo.value.code == "ARTIFACT_NOT_FOUND"

