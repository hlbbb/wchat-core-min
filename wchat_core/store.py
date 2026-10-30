"""Account discovery, key lookup, and decrypted-DB cache management."""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .wechat_decrypt import WeChatDatabaseDecryptor


SOURCE_FILE_NAME = "_source.json"
KEY_STORE_NAME = "account_keys.json"
CACHE_META_NAME = "_wchat_cache.json"


@dataclass(frozen=True)
class CacheInfo:
    account: str
    cache_dir: Path
    contact_db: Path | None
    session_db: Path | None
    message_dbs: list[Path]
    source_storage: Path | None
    source: str


def resolve_data_dir(value: str | None = None) -> Path:
    """Resolve the directory that contains ``account_keys.json``/``databases``."""

    candidates: list[Path] = []
    raw = str(value or os.environ.get("WCHAT_DATA_DIR", "") or "").strip()
    if raw:
        candidates.append(Path(raw).expanduser())
    else:
        candidates.extend([Path.cwd() / "output", Path.cwd() / "data"])

    for candidate in candidates:
        if (candidate / KEY_STORE_NAME).is_file():
            return candidate.resolve()
        if (candidate / "output" / KEY_STORE_NAME).is_file():
            return (candidate / "output").resolve()
    if candidates:
        return candidates[0].resolve()
    return (Path.cwd() / "output").resolve()


def load_key_store(data_dir: Path) -> dict[str, Any]:
    path = Path(data_dir) / KEY_STORE_NAME
    if not path.is_file():
        return {}
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _canonical_account(value: str) -> str:
    text = str(value or "").strip()
    return re.sub(r"_[0-9a-fA-F]{4}$", "", text)


def list_accounts(data_dir: Path) -> list[str]:
    names: set[str] = set()
    for name in load_key_store(data_dir):
        if str(name or "").strip():
            names.add(str(name).strip())
    databases = Path(data_dir) / "databases"
    if databases.is_dir():
        for child in databases.iterdir():
            if child.is_dir():
                names.add(child.name)
    return sorted(names)


def resolve_account(data_dir: Path, requested: str | None = None) -> str:
    accounts = list_accounts(data_dir)
    value = str(requested or "").strip()
    if value:
        if value in accounts:
            return value
        canonical = _canonical_account(value)
        matches = [name for name in accounts if _canonical_account(name) == canonical]
        if len(matches) == 1:
            return matches[0]
        raise SystemExit(
            f"Account not found: {value}. Available: {', '.join(accounts) or '(none)'}"
        )
    if not accounts:
        raise SystemExit(
            f"No accounts found under {data_dir}. Pass --data-dir to the directory "
            f"containing {KEY_STORE_NAME}."
        )
    if len(accounts) == 1:
        return accounts[0]
    canonical = {_canonical_account(name) for name in accounts}
    if len(canonical) == 1:
        # Prefer the shorter canonical name.
        return sorted(accounts, key=len)[0]
    raise SystemExit(
        f"Multiple accounts found: {', '.join(accounts)}. Pass --account."
    )


def account_key(data_dir: Path, account: str, override: str | None = None) -> str:
    raw = str(override or os.environ.get("WCHAT_DB_KEY", "") or "").strip()
    if raw:
        raw = raw.lower().removeprefix("0x")
        if not re.fullmatch(r"[0-9a-f]{64}", raw):
            raise SystemExit("--key/WCHAT_DB_KEY must be 64 hex characters.")
        return raw
    store = load_key_store(data_dir)
    candidates = [account]
    canonical = _canonical_account(account)
    candidates.extend(name for name in store if _canonical_account(name) == canonical)
    for name in candidates:
        item = store.get(name)
        if isinstance(item, dict):
            key = str(item.get("db_key") or "").strip().lower()
            if re.fullmatch(r"[0-9a-f]{64}", key):
                return key
    raise SystemExit(
        f"No database key for {account} in {Path(data_dir) / KEY_STORE_NAME}. "
        "Pass --key or WCHAT_DB_KEY."
    )


def account_dir(data_dir: Path, account: str) -> Path:
    return Path(data_dir) / "databases" / account


def source_storage(data_dir: Path, account: str) -> Path | None:
    source_path = account_dir(data_dir, account) / SOURCE_FILE_NAME
    if not source_path.is_file():
        return None
    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    raw = str(payload.get("db_storage_path") or "").strip()
    return Path(raw).expanduser() if raw else None


def _source_database(storage: Path, category: str, name: str) -> Path | None:
    path = Path(storage) / category / name
    return path if path.is_file() else None


def _source_message_dbs(storage: Path) -> list[Path]:
    folder = Path(storage) / "message"
    if not folder.is_dir():
        return []
    result: list[Path] = []
    for path in sorted(folder.glob("message_*.db")):
        lower = path.name.lower()
        if lower.endswith("_fts.db") or lower.endswith("_resource.db"):
            continue
        if path.is_file():
            result.append(path)
    return result


def _source_media_support_dbs(storage: Path) -> list[Path]:
    """Return media metadata databases needed to resolve original attachments."""

    candidates = [
        Path(storage) / "hardlink" / "hardlink.db",
        Path(storage) / "message" / "message_resource.db",
        Path(storage) / "message" / "media_0.db",
    ]
    return [path for path in candidates if path.is_file()]


def _decrypted_message_dbs(folder: Path) -> list[Path]:
    if not Path(folder).is_dir():
        return []
    result: list[Path] = []
    for path in sorted(Path(folder).glob("message_*.db")):
        lower = path.name.lower()
        if lower.endswith("_fts.db") or lower.endswith("_resource.db"):
            continue
        if path.is_file():
            result.append(path)
    return result


def _file_stamp(path: Path) -> dict[str, Any]:
    try:
        stat = path.stat()
    except FileNotFoundError:
        return {"exists": False}
    wal = Path(str(path) + "-wal")
    try:
        wal_stat = wal.stat()
    except FileNotFoundError:
        wal_stat = None
    return {
        "exists": True,
        "size": stat.st_size,
        "mtime_ns": stat.st_mtime_ns,
        "wal_size": wal_stat.st_size if wal_stat else 0,
        "wal_mtime_ns": wal_stat.st_mtime_ns if wal_stat else 0,
    }


def _load_meta(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _save_meta(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _decrypt_with_retry(
    key: str,
    source: Path,
    destination: Path,
    *,
    attempts: int = 3,
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    last_error: Exception | None = None
    for attempt in range(max(1, attempts)):
        try:
            decryptor = WeChatDatabaseDecryptor(key)
            if decryptor.decrypt_database(str(source), str(destination)):
                return
            last_error = RuntimeError(
                str((decryptor.last_result or {}).get("error") or "decrypt failed")
            )
        except Exception as exc:  # source may be changing while WeChat writes
            last_error = exc
        if attempt + 1 < attempts:
            time.sleep(0.35)
    raise SystemExit(f"Failed to decrypt {source}: {last_error}")


def ensure_cache(
    data_dir: Path,
    account: str,
    *,
    cache_root: str | Path | None = None,
    refresh: bool = False,
    key_override: str | None = None,
) -> CacheInfo:
    """Ensure contact/session/message DBs are available as plain SQLite."""

    data_dir = Path(data_dir).resolve()
    storage = source_storage(data_dir, account)
    if storage is None or not Path(storage).is_dir():
        # Fall back to the app's already-decrypted snapshot.
        folder = account_dir(data_dir, account)
        contact_db = folder / "contact.db"
        session_db = folder / "session.db"
        message_dbs = _decrypted_message_dbs(folder)
        if not (contact_db.is_file() or session_db.is_file() or message_dbs):
            raise SystemExit(
                f"No source storage or decrypted databases for {account}. "
                "Check _source.json or run the main app once."
            )
        return CacheInfo(
            account=account,
            cache_dir=folder,
            contact_db=contact_db if contact_db.is_file() else None,
            session_db=session_db if session_db.is_file() else None,
            message_dbs=message_dbs,
            source_storage=None,
            source="decrypted-snapshot",
        )

    root = (
        Path(cache_root).expanduser()
        if cache_root
        else Path(tempfile.gettempdir()) / "wchat-core-cache"
    )
    cache_dir = (root / account).resolve()
    cache_dir.mkdir(parents=True, exist_ok=True)
    key = account_key(data_dir, account, key_override)

    sources: dict[str, Path] = {}
    contact = _source_database(storage, "contact", "contact.db")
    session = _source_database(storage, "session", "session.db")
    if contact:
        sources["contact.db"] = contact
    if session:
        sources["session.db"] = session
    for path in _source_media_support_dbs(storage):
        sources[path.name] = path
    for path in _source_message_dbs(storage):
        sources[path.name] = path
    if not sources:
        raise SystemExit(f"No supported .db files found under {storage}")

    meta_path = cache_dir / CACHE_META_NAME
    meta = _load_meta(meta_path)
    meta.setdefault("files", {})
    meta["account"] = account
    meta["source_storage"] = str(storage)

    for name, source in sources.items():
        destination = cache_dir / name
        stamp = _file_stamp(source)
        cached_stamp = meta["files"].get(name)
        needs_decrypt = (
            refresh
            or not destination.is_file()
            or cached_stamp != stamp
        )
        if needs_decrypt:
            _decrypt_with_retry(key, source, destination)
            meta["files"][name] = stamp
            _save_meta(meta_path, meta)

    message_dbs = sorted(
        path
        for path in cache_dir.glob("message_*.db")
        if path.name.lower() not in {"message_resource.db", "message_fts.db"}
        and not path.name.lower().endswith("_fts.db")
    )
    return CacheInfo(
        account=account,
        cache_dir=cache_dir,
        contact_db=(cache_dir / "contact.db") if (cache_dir / "contact.db").is_file() else None,
        session_db=(cache_dir / "session.db") if (cache_dir / "session.db").is_file() else None,
        message_dbs=message_dbs,
        source_storage=Path(storage),
        source="live-decrypted-cache",
    )
