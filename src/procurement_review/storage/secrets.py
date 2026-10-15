import contextlib
import os
from abc import ABC, abstractmethod

import keyring
import keyring.errors

from procurement_review.domain.errors import DomainError


class SecretStore(ABC):
    """機密與加密金鑰管理介面"""

    @abstractmethod
    def get_or_create_key(self, name: str, allow_create: bool = True) -> bytes:
        """取得或建立 256 位元 (32 bytes) 金鑰。

        若金鑰不存在且 allow_create 為 False，必須拋出 DomainError("KEY_UNAVAILABLE", ...)。
        """
        ...

    @abstractmethod
    def get_key(self, name: str) -> bytes | None:
        """取得金鑰，若不存在回傳 None。"""
        ...

    @abstractmethod
    def set_key(self, name: str, key: bytes) -> None:
        """儲存金鑰。"""
        ...

    @abstractmethod
    def delete_key(self, name: str) -> None:
        """刪除金鑰。"""
        ...


class FakeSecretStore(SecretStore):
    """記憶體內的假金鑰庫，用於單元測試與安全模擬。"""

    def __init__(self, initial_keys: dict[str, bytes] | None = None) -> None:
        self._keys: dict[str, bytes] = dict(initial_keys) if initial_keys else {}

    def get_key(self, name: str) -> bytes | None:
        return self._keys.get(name)

    def set_key(self, name: str, key: bytes) -> None:
        self._keys[name] = key

    def delete_key(self, name: str) -> None:
        self._keys.pop(name, None)

    def get_or_create_key(self, name: str, allow_create: bool = True) -> bytes:
        existing = self.get_key(name)
        if existing is not None:
            return existing
        if not allow_create:
            raise DomainError("KEY_UNAVAILABLE", f"Key '{name}' is unavailable in secret store")
        new_key = os.urandom(32)
        self.set_key(name, new_key)
        return new_key


class OSKeychainSecretStore(SecretStore):
    """基於作業系統原生 Keychain (如 macOS Keychain、Windows Credential Manager) 的金鑰庫。"""

    def __init__(self, service_name: str = "procurement_review") -> None:
        self.service_name = service_name

    def get_key(self, name: str) -> bytes | None:
        val = keyring.get_password(self.service_name, name)
        if val is None:
            return None
        try:
            return bytes.fromhex(val)
        except ValueError:
            return None

    def set_key(self, name: str, key: bytes) -> None:
        keyring.set_password(self.service_name, name, key.hex())

    def delete_key(self, name: str) -> None:
        with contextlib.suppress(keyring.errors.KeyringError, OSError):
            keyring.delete_password(self.service_name, name)

    def get_or_create_key(self, name: str, allow_create: bool = True) -> bytes:
        existing = self.get_key(name)
        if existing is not None:
            return existing
        if not allow_create:
            raise DomainError("KEY_UNAVAILABLE", f"Key '{name}' is unavailable in OS keychain")
        new_key = os.urandom(32)
        self.set_key(name, new_key)
        return new_key
