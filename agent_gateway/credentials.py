"""Upstream credentials: storage and outbound scrubbing.

Storage is one Fernet-encrypted JSON file (`cryptography`'s Fernet: AES-CBC +
HMAC, no crypto written here). The key lives in a separate file so the
encrypted store can be backed up anywhere while the key goes into a password
manager.

What this does and does not buy: it keeps secrets out of the config file, out
of backups and out of reach of anything that can read the data volume but not
the key. It is NOT a defence against whoever controls the gateway host: root
there, or anything running as the gateway's user, reads the key and decrypts.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path
from typing import Any, Protocol

from cryptography.fernet import Fernet, InvalidToken

REDACTED = "[REDACTED]"


class SecretStoreError(Exception):
    """Raised with messages that never include secret values."""


class SecretStore(Protocol):
    def get(self, name: str) -> str: ...
    def set(self, name: str, value: str) -> None: ...
    def delete(self, name: str) -> None: ...
    def names(self) -> list[str]: ...


class EncryptedFileStore:
    def __init__(self, path: Path, key_file: Path) -> None:
        self._path = Path(path)
        self._fernet = key_cipher(Path(key_file))

    @staticmethod
    def create_key(key_file: Path) -> None:
        key_file = Path(key_file)
        key_file.parent.mkdir(parents=True, exist_ok=True)
        # O_EXCL: never overwrite a key, losing it makes the store unreadable.
        fd = os.open(key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(Fernet.generate_key() + b"\n")

    def _load(self) -> dict[str, str]:
        try:
            blob = self._path.read_bytes()
        except FileNotFoundError:
            return {}
        try:
            return json.loads(self._fernet.decrypt(blob))
        except InvalidToken:
            raise SecretStoreError("cannot decrypt the secret store: wrong key or corrupted file") from None

    def _save(self, data: dict[str, str]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        blob = self._fernet.encrypt(json.dumps(data, sort_keys=True).encode("utf-8"))
        tmp = self._path.with_name(self._path.name + ".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, self._path)

    def get(self, name: str) -> str:
        try:
            return self._load()[name]
        except KeyError:
            raise SecretStoreError(f"secret {name!r} is not in the store") from None

    def set(self, name: str, value: str) -> None:
        if not value:
            raise SecretStoreError("refusing to store an empty secret")
        data = self._load()
        data[name] = value
        self._save(data)

    def delete(self, name: str) -> None:
        data = self._load()
        if name not in data:
            raise SecretStoreError(f"secret {name!r} is not in the store")
        del data[name]
        self._save(data)

    def names(self) -> list[str]:
        return sorted(self._load())


def key_cipher(key_file: Path) -> Fernet:
    try:
        mode = key_file.stat().st_mode
        key = key_file.read_bytes().strip()
    except OSError as exc:
        raise SecretStoreError(f"cannot read the key file: {exc.strerror}") from None
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise SecretStoreError("the key file is readable by group or others; chmod 600 it")
    try:
        return Fernet(key)
    except ValueError:
        raise SecretStoreError("the key file does not contain a valid key") from None


class Scrubber:
    """Replaces known secret values in anything the gateway sends to an agent.

    A backstop for accidents (an upstream echoing its password in an error),
    not a control: an upstream that wants to leak a secret can encode it.
    """

    def __init__(self, values: list[str], dynamic=None) -> None:
        # Longest first so a secret containing another is replaced whole.
        self._values = sorted({v for v in values if len(v) >= 6}, key=len, reverse=True)
        self._dynamic = dynamic

    def text(self, text: str) -> str:
        values = self._values
        if self._dynamic:
            values = sorted(set(values) | {v for v in self._dynamic() if len(v) >= 6}, key=len, reverse=True)
        for value in values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text

    def data(self, obj: Any) -> Any:
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.data(item) for item in obj]
        if isinstance(obj, dict):
            return {self.text(k) if isinstance(k, str) else k: self.data(v) for k, v in obj.items()}
        return obj
