"""Locate and export original chat attachments from a local WeChat data tree."""

from __future__ import annotations

import hashlib
import json
import mimetypes
import os
import re
import shutil
import sqlite3
import struct
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .image_keys import resolve_image_keys


_WECHAT_DAT_V1 = b"\x07\x08V1\x08\x07"
_WECHAT_DAT_V2 = b"\x07\x08V2\x08\x07"
_FIXED_DAT_AES_KEY = b"cfcd208495d565ef"
_MD5_RE = re.compile(r"[0-9a-f]{32}")
_WINDOWS_RESERVED_NAMES = {
    "con",
    "prn",
    "aux",
    "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}
_WXGF_PARTITION_START = b"\x00\x00\x00\x01\x40\x01"
_WXGF_TIMEOUT_SECONDS = 20
_WXGF_MAX_PIXELS = 50_000_000


class MediaUnavailable(RuntimeError):
    """Raised when a message is valid but its attachment cannot be recovered."""


@dataclass(slots=True, repr=False)
class MediaKeys:
    xor_key: int | None = None
    aes_key: bytes = b""


@dataclass(slots=True)
class HardlinkEntry:
    md5: str
    file_name: str
    file_size: int
    modify_time: int
    dir1: int
    dir2: int
    dir1_name: str = ""
    dir2_name: str = ""


@dataclass(slots=True)
class SourceResolution:
    kind: str
    source_path: Path
    source: str


@dataclass(slots=True)
class ExportResult:
    kind: str
    status: str
    output_path: Path | None = None
    source_path: Path | None = None
    source: str = ""
    error: str = ""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _parse_xor_key(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 0xFF else None
    text = str(value).strip()
    if not text:
        return None
    try:
        parsed = int(text, 16) if text.lower().startswith("0x") else int(text)
    except ValueError:
        try:
            parsed = int(text, 16)
        except ValueError:
            return None
    return parsed if 0 <= parsed <= 0xFF else None


def load_media_keys(
    account_dir: Path,
    *,
    data_dir: Path | None = None,
    account: str = "",
    fallback_account_dir: Path | None = None,
) -> MediaKeys:
    """Load optional image/media keys without logging or returning them publicly."""

    payload = _read_json(Path(account_dir) / "_media_keys.json")
    if not payload and fallback_account_dir is not None:
        payload = _read_json(Path(fallback_account_dir) / "_media_keys.json")
    xor_raw = payload.get("xor", payload.get("image_xor_key"))
    aes_raw = payload.get("aes", payload.get("image_aes_key", ""))

    if data_dir and account:
        key_store = _read_json(Path(data_dir) / "account_keys.json")
        item = key_store.get(account)
        if not isinstance(item, dict):
            for name, candidate in key_store.items():
                if re.sub(r"_[0-9a-fA-F]{4}$", "", str(name)) == re.sub(
                    r"_[0-9a-fA-F]{4}$", "", account
                ):
                    item = candidate
                    break
        if isinstance(item, dict):
            if xor_raw is None:
                xor_raw = item.get("image_xor_key") or item.get("xor_key")
            if not str(aes_raw or "").strip():
                aes_raw = item.get("image_aes_key") or item.get("aes_key")

    aes_text = str(aes_raw or "").strip()
    aes_key = aes_text.encode("ascii", errors="ignore")[:16]
    if len(aes_key) != 16:
        aes_key = b""
    return MediaKeys(xor_key=_parse_xor_key(xor_raw), aes_key=aes_key)


def resolve_media_keys(
    account_dir: Path,
    source_root: Path | None,
    *,
    data_dir: Path | None = None,
    account: str = "",
    auto_resolve_image: bool = True,
    fallback_account_dir: Path | None = None,
) -> MediaKeys:
    keys = load_media_keys(
        account_dir,
        data_dir=data_dir,
        account=account,
        fallback_account_dir=fallback_account_dir,
    )
    if keys.xor_key is not None and keys.aes_key:
        return keys
    if not auto_resolve_image:
        return keys

    resolution = resolve_image_keys(
        account_dir=source_root or account_dir,
        source_root=source_root,
        account=account,
        target_wxid=account,
    )
    if resolution is None:
        return keys
    return MediaKeys(
        xor_key=resolution.xor_key,
        aes_key=resolution.aes_key.encode("ascii"),
    )


def _detect_dat_version(data: bytes) -> int:
    if data.startswith(_WECHAT_DAT_V1):
        return 1
    if data.startswith(_WECHAT_DAT_V2):
        return 2
    return 0


def _xor_bytes(data: bytes, key: int) -> bytes:
    return bytes(value ^ key for value in data)


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise MediaUnavailable("Decrypted attachment is empty.")
    padding = data[-1]
    if padding < 1 or padding > 16 or data[-padding:] != bytes([padding]) * padding:
        raise MediaUnavailable("Attachment key is missing or does not match this file.")
    return data[:-padding]


def decrypt_wechat_dat(data: bytes, keys: MediaKeys) -> bytes | None:
    """Decrypt a WeChat V1/V2 DAT payload; return None for plain files."""

    version = _detect_dat_version(data)
    if version == 0:
        return None
    if keys.xor_key is None:
        raise MediaUnavailable(
            "Encrypted attachment requires an image XOR key in _media_keys.json."
        )

    try:
        signature, aes_size, xor_size = struct.unpack("<6sLLx", data[:15])
    except struct.error as exc:
        raise MediaUnavailable("Encrypted attachment header is invalid.") from exc
    if signature not in {_WECHAT_DAT_V1, _WECHAT_DAT_V2}:
        raise MediaUnavailable("Encrypted attachment version is unsupported.")

    aes_size += 16 - (aes_size % 16)
    body = data[15:]
    encrypted = body[:aes_size]
    if len(encrypted) != aes_size:
        raise MediaUnavailable("Encrypted attachment is truncated.")

    aes_key = _FIXED_DAT_AES_KEY if version == 1 else keys.aes_key
    if len(aes_key) != 16:
        raise MediaUnavailable(
            "Encrypted attachment requires a 16-byte AES key in _media_keys.json."
        )

    decryptor = Cipher(algorithms.AES(aes_key), modes.ECB()).decryptor()
    decrypted_aes = _pkcs7_unpad(
        decryptor.update(encrypted) + decryptor.finalize()
    )

    if xor_size:
        if xor_size > len(body) - aes_size:
            raise MediaUnavailable("Encrypted attachment XOR segment is invalid.")
        raw = body[aes_size:-xor_size]
        xored = _xor_bytes(body[-xor_size:], keys.xor_key)
    else:
        raw = body[aes_size:]
        xored = b""
    return decrypted_aes + raw + xored


def _detect_image_media_type(data: bytes) -> str:
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "image/gif"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return "image/webp"
    return "application/octet-stream"


def _extension_for_media(data: bytes, title: str = "") -> str:
    media_type = _detect_image_media_type(data)
    by_type = {
        "image/png": "png",
        "image/jpeg": "jpg",
        "image/gif": "gif",
        "image/webp": "webp",
    }.get(media_type)
    if by_type:
        return by_type
    suffix = Path(str(title or "")).suffix.lstrip(".").lower()
    return suffix or "bin"


def _find_ffmpeg() -> str:
    for name in ("WCHAT_FFMPEG", "FFMPEG_PATH", "WECHAT_TOOL_FFMPEG"):
        value = str(os.environ.get(name) or "").strip()
        if value:
            path = Path(value).expanduser()
            if path.is_file():
                return str(path)
    return shutil.which("ffmpeg") or ""


def _wxgf_partitions(data: bytes) -> list[bytes]:
    starts: list[int] = []
    position = data.find(_WXGF_PARTITION_START, 4)
    while position >= 0:
        if len(starts) >= 2:
            return []
        starts.append(position)
        position = data.find(
            _WXGF_PARTITION_START,
            position + len(_WXGF_PARTITION_START),
        )
    partitions: list[bytes] = []
    for start, limit in zip(starts, starts[1:] + [len(data)]):
        if start < 4:
            return []
        size = int.from_bytes(data[start - 4 : start], "big")
        if not 0 < size <= limit - start:
            return []
        partitions.append(data[start : start + size])
    return partitions


def _hevc_picture_count(stream: bytes) -> int:
    count = 0
    position = stream.find(b"\x00\x00\x01")
    while 0 <= position < len(stream) - 5:
        nal_type = (stream[position + 3] >> 1) & 0x3F
        if nal_type < 32 and stream[position + 5] & 0x80:
            count += 1
        position = stream.find(b"\x00\x00\x01", position + 3)
    return count


def _ffmpeg_first_frame(
    ffmpeg_exe: str,
    stream: bytes,
    output_args: list[str],
    deadline: float,
) -> bytes:
    timeout = deadline - time.monotonic()
    if timeout <= 0:
        return b""
    try:
        completed = subprocess.run(
            [
                ffmpeg_exe,
                "-hide_banner",
                "-loglevel",
                "error",
                "-xerror",
                "-err_detect",
                "explode",
                "-max_pixels",
                str(_WXGF_MAX_PIXELS),
                "-f",
                "hevc",
                "-i",
                "pipe:0",
                "-frames:v",
                "1",
                *output_args,
                "pipe:1",
            ],
            input=stream,
            check=False,
            capture_output=True,
            timeout=timeout,
            creationflags=(
                getattr(subprocess, "CREATE_NO_WINDOW", 0)
                if os.name == "nt"
                else 0
            ),
        )
    except (OSError, subprocess.SubprocessError):
        return b""
    return completed.stdout if completed.returncode == 0 else b""


def _wxgf_to_jpeg(data: bytes) -> bytes | None:
    if not data.startswith(b"wxgf"):
        return None
    ffmpeg_exe = _find_ffmpeg()
    if not ffmpeg_exe:
        return None
    partitions = _wxgf_partitions(data)
    if not partitions or _hevc_picture_count(partitions[-1]) != 1:
        return None
    deadline = time.monotonic() + _WXGF_TIMEOUT_SECONDS
    for alpha in partitions[:-1]:
        plane = _ffmpeg_first_frame(
            ffmpeg_exe,
            alpha,
            ["-f", "rawvideo", "-pix_fmt", "gray"],
            deadline,
        )
        if not plane or plane.count(b"\xff") != len(plane):
            return None
    output = _ffmpeg_first_frame(
        ffmpeg_exe,
        partitions[-1],
        ["-f", "image2pipe", "-codec:v", "mjpeg", "-q:v", "3"],
        deadline,
    )
    return output if _detect_image_media_type(output) == "image/jpeg" else None


def _safe_name(value: str, fallback: str = "attachment") -> str:
    text = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", str(value or "")).strip(" .")
    text = text or fallback
    if text.casefold() in _WINDOWS_RESERVED_NAMES:
        text = "_" + text
    return text[:180]


def _connect_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)


def _find_table(conn: sqlite3.Connection, prefix: str) -> str | None:
    names = [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        if row and row[0]
    ]
    wanted = str(prefix or "").casefold()
    exact = next((name for name in names if name.casefold() == wanted), None)
    if exact:
        return exact
    return next(
        (name for name in names if name.casefold().startswith(wanted + "_")),
        None,
    )


def _load_dir_map(conn: sqlite3.Connection) -> dict[int, str]:
    table = _find_table(conn, "dir2id")
    if not table:
        return {}
    quoted = '"' + table.replace('"', '""') + '"'
    try:
        rows = conn.execute(f"SELECT rowid, username FROM {quoted}").fetchall()
    except sqlite3.Error:
        return {}
    return {
        int(rowid): str(username or "").strip()
        for rowid, username in rows
        if username is not None
    }


def _read_hardlink_entry(
    account_dir: Path,
    kind: str,
    md5: str,
) -> HardlinkEntry | None:
    if not md5 or not _MD5_RE.fullmatch(md5):
        return None
    hardlink_db = Path(account_dir) / "hardlink.db"
    if not hardlink_db.is_file():
        return None
    prefix = "image_hardlink_info" if kind == "image" else "file_hardlink_info"
    conn = _connect_readonly(hardlink_db)
    try:
        table = _find_table(conn, prefix)
        if not table:
            return None
        dir_map = _load_dir_map(conn)
        quoted = '"' + table.replace('"', '""') + '"'
        try:
            row = conn.execute(
                "SELECT md5, file_name, file_size, modify_time, dir1, dir2 "
                f"FROM {quoted} WHERE lower(md5) = ? "
                "ORDER BY modify_time DESC, rowid DESC LIMIT 1",
                (md5.lower(),),
            ).fetchone()
        except sqlite3.Error:
            return None
        if not row:
            return None
        dir1 = int(row[4] or 0)
        dir2 = int(row[5] or 0)
        return HardlinkEntry(
            md5=str(row[0] or "").strip().lower(),
            file_name=str(row[1] or "").strip(),
            file_size=int(row[2] or 0),
            modify_time=int(row[3] or 0),
            dir1=dir1,
            dir2=dir2,
            dir1_name=dir_map.get(dir1, ""),
            dir2_name=dir_map.get(dir2, ""),
        )
    finally:
        conn.close()


def _cached_resources(
    account_dir: Path,
    source_root: Path | None,
    md5: str,
) -> list[Path]:
    if not md5 or not _MD5_RE.fullmatch(md5):
        return []
    prefix = md5[:2]
    roots = [Path(account_dir) / "resource"]
    if source_root:
        roots.append(Path(source_root) / "resource")
    hits: list[Path] = []
    for root in roots:
        for directory in (root / prefix, root):
            try:
                if not directory.is_dir():
                    continue
                hits.extend(
                    path
                    for path in directory.glob(f"{md5}*")
                    if path.is_file()
                )
            except OSError:
                continue
    return sorted(
        dict.fromkeys(hits),
        key=lambda path: path.stat().st_size,
        reverse=True,
    )


def _month_name(entry: HardlinkEntry, timestamp: int = 0) -> str:
    if re.fullmatch(r"\d{4}-\d{2}", entry.dir2_name or ""):
        return entry.dir2_name
    candidate = int(entry.modify_time or timestamp or 0)
    if candidate > 0:
        try:
            return datetime.fromtimestamp(candidate).strftime("%Y-%m")
        except (OSError, OverflowError, ValueError):
            pass
    return ""


def _pick_best_path(paths: list[Path], expected_size: int = 0) -> Path | None:
    existing = [path for path in paths if path.is_file()]
    if not existing:
        return None
    if expected_size > 0:
        exact = [path for path in existing if path.stat().st_size == expected_size]
        if exact:
            return exact[0]
    return existing[0]


def _resolve_image_from_entry(
    source_root: Path,
    username: str,
    entry: HardlinkEntry,
    timestamp: int,
) -> Path | None:
    if not entry.file_name:
        return None
    month = _month_name(entry, timestamp)
    stem = Path(entry.file_name).stem
    variants = list(
        dict.fromkeys(
            [
                entry.file_name,
                f"{stem}_h.dat",
                f"{stem}_t.dat",
                f"{stem}.dat",
            ]
        )
    )
    chat_hashes = []
    if entry.dir1_name and re.fullmatch(r"[0-9a-fA-F]{32}", entry.dir1_name):
        chat_hashes.append(entry.dir1_name.lower())
    if username:
        chat_hashes.append(hashlib.md5(username.encode("utf-8")).hexdigest())

    directories: list[Path] = []
    attach_root = source_root / "msg" / "attach"
    for chat_hash in dict.fromkeys(chat_hashes):
        if month:
            directories.append(attach_root / chat_hash / month / "Img")
        directories.append(attach_root / chat_hash)
    if month:
        directories.append(attach_root / month / "Img")

    for directory in directories:
        for variant in variants:
            path = directory / variant
            if path.is_file():
                return path
    return None


def _resolve_file_from_entry(
    source_root: Path,
    entry: HardlinkEntry,
    title: str,
    timestamp: int,
) -> Path | None:
    base = source_root / "msg" / "file"
    if not base.is_dir():
        return None
    names = list(
        dict.fromkeys(
            name
            for name in (
                _safe_name(title, "") if title else "",
                entry.file_name,
            )
            if name
        )
    )
    month = _month_name(entry, timestamp)
    directories = [base / month] if month else []
    try:
        directories.extend(
            child
            for child in sorted(base.iterdir())
            if child.is_dir() and re.fullmatch(r"\d{4}-\d{2}", child.name)
        )
    except OSError:
        pass

    candidates: list[Path] = []
    for directory in dict.fromkeys(directories or [base]):
        for name in names:
            candidates.append(directory / name)
            candidates.append(directory / Path(name).stem / name)
    picked = _pick_best_path(candidates, entry.file_size)
    if picked:
        return picked

    for name in names:
        try:
            candidates = [path for path in base.rglob(name) if path.is_file()]
        except OSError:
            candidates = []
        picked = _pick_best_path(candidates, entry.file_size)
        if picked:
            return picked
    return None


def _fallback_search(
    source_root: Path,
    kind: str,
    md5: str,
    title: str,
) -> Path | None:
    if kind == "file":
        base = source_root / "msg" / "file"
        if not base.is_dir() or not title:
            return None
        try:
            return _pick_best_path(
                [path for path in base.rglob(_safe_name(title, "")) if path.is_file()]
            )
        except OSError:
            return None

    base = source_root / "msg" / "attach"
    if not base.is_dir() or not md5:
        return None
    patterns = (
        f"{md5}_h.dat",
        f"{md5}_t.dat",
        f"{md5}.dat",
        f"{md5}*.jpg",
        f"{md5}*.jpeg",
        f"{md5}*.png",
        f"{md5}*.gif",
        f"{md5}*.webp",
    )
    for pattern in patterns:
        try:
            hit = next((path for path in base.rglob(pattern) if path.is_file()), None)
        except OSError:
            hit = None
        if hit:
            return hit
    return None


def resolve_media_source(
    account_dir: Path,
    source_root: Path | None,
    *,
    kind: str,
    username: str,
    md5: str = "",
    title: str = "",
    timestamp: int = 0,
) -> SourceResolution | None:
    kind_key = str(kind or "").strip().lower()
    if kind_key not in {"image", "file"}:
        return None

    cached = _cached_resources(account_dir, source_root, md5)
    if cached:
        return SourceResolution(kind_key, cached[0], "decrypted-cache")
    if not source_root or not source_root.is_dir():
        return None

    entry = _read_hardlink_entry(account_dir, kind_key, md5)
    path: Path | None = None
    if entry:
        if kind_key == "image":
            path = _resolve_image_from_entry(
                source_root, username, entry, timestamp
            )
        else:
            path = _resolve_file_from_entry(
                source_root, entry, title, timestamp
            )
    if not path:
        path = _fallback_search(source_root, kind_key, md5, title)
    if not path:
        return None
    return SourceResolution(kind_key, path, "wechat-data")


def _unique_destination(path: Path, *, overwrite: bool) -> Path:
    if overwrite or not path.exists():
        return path
    index = 2
    while True:
        candidate = path.with_name(f"{path.stem} ({index}){path.suffix}")
        if not candidate.exists():
            return candidate
        index += 1


def _image_source_variants(path: Path) -> list[Path]:
    stem = Path(path).stem
    base = stem
    for suffix in ("_h", "_t", "_b"):
        if base.endswith(suffix):
            base = base[: -len(suffix)]
            break
    candidates = [
        Path(path),
        path.with_name(f"{base}_h.dat"),
        path.with_name(f"{base}.dat"),
        path.with_name(f"{base}_t.dat"),
    ]
    return list(dict.fromkeys(candidate for candidate in candidates if candidate.is_file()))


def export_media_source(
    account_dir: Path,
    source_root: Path | None,
    *,
    kind: str,
    username: str,
    md5: str = "",
    title: str = "",
    timestamp: int = 0,
    output_dir: Path,
    keys: MediaKeys | None = None,
    overwrite: bool = False,
) -> ExportResult:
    kind_key = str(kind or "").strip().lower()
    resolution: SourceResolution | None = None
    try:
        resolution = resolve_media_source(
            account_dir,
            source_root,
            kind=kind_key,
            username=username,
            md5=md5,
            title=title,
            timestamp=timestamp,
        )
        if resolution is None:
            return ExportResult(
                kind=kind_key,
                status="missing",
                error="Attachment is not present in the local WeChat data tree.",
            )

        source_path = resolution.source_path
        raw = source_path.read_bytes()
        decrypted = decrypt_wechat_dat(raw, keys or MediaKeys())
        payload = decrypted if decrypted is not None else raw

        if kind_key == "image":
            media_type = _detect_image_media_type(payload)
            if media_type == "application/octet-stream":
                converted = _wxgf_to_jpeg(payload)
                if converted:
                    payload = converted
                    media_type = _detect_image_media_type(payload)
            if media_type == "application/octet-stream":
                for candidate_path in _image_source_variants(source_path):
                    if candidate_path == source_path:
                        continue
                    candidate_raw = candidate_path.read_bytes()
                    candidate_decrypted = decrypt_wechat_dat(
                        candidate_raw,
                        keys or MediaKeys(),
                    )
                    candidate_payload = (
                        candidate_decrypted
                        if candidate_decrypted is not None
                        else candidate_raw
                    )
                    if _detect_image_media_type(candidate_payload) == (
                        "application/octet-stream"
                    ):
                        converted = _wxgf_to_jpeg(candidate_payload)
                        if converted:
                            candidate_payload = converted
                    if _detect_image_media_type(candidate_payload) != (
                        "application/octet-stream"
                    ):
                        source_path = candidate_path
                        payload = candidate_payload
                        decrypted = candidate_decrypted
                        media_type = _detect_image_media_type(payload)
                        break
            if media_type == "application/octet-stream":
                raise MediaUnavailable(
                    "Attachment was found but could not be decoded as an image."
                )
            ext = _extension_for_media(payload)
            name = f"{md5 or resolution.source_path.stem}.{ext}"
        else:
            ext = _extension_for_media(payload, title or resolution.source_path.name)
            base_name = _safe_name(title or resolution.source_path.name)
            if not Path(base_name).suffix and ext:
                base_name = f"{base_name}.{ext}"
            name = base_name

        target_dir = Path(output_dir) / ("images" if kind_key == "image" else "files")
        target_dir.mkdir(parents=True, exist_ok=True)
        destination = _unique_destination(
            target_dir / _safe_name(name), overwrite=overwrite
        )
        if decrypted is None and kind_key == "file":
            shutil.copyfile(source_path, destination)
        else:
            destination.write_bytes(payload)
        return ExportResult(
            kind=kind_key,
            status="exported",
            output_path=destination.resolve(),
            source_path=source_path.resolve(),
            source=resolution.source,
        )
    except MediaUnavailable as exc:
        return ExportResult(
            kind=kind_key,
            status="missing-key",
            source_path=(
                resolution.source_path.resolve()
                if resolution is not None
                else None
            ),
            source=resolution.source if resolution is not None else "",
            error=str(exc),
        )
    except OSError as exc:
        return ExportResult(
            kind=kind_key,
            status="error",
            error=str(exc),
        )
