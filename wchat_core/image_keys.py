"""Derive WeChat 4.x V2 image keys from local kvcomm cache and image templates."""

from __future__ import annotations

import hashlib
import heapq
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


V2_MAGIC = b"\x07\x08V2\x08\x07"
V2_CIPHERTEXT_START = 0x0F
AES_BLOCK_SIZE = 16
_KVCOMM_FILE_RE = re.compile(r"^key_(\d+)_.+\.statistic$", re.IGNORECASE)
_SUFFIXED_WXID_RE = re.compile(r"^(wxid_[^_]+)(?:_.+)$", re.IGNORECASE)
_MONTH_DIR_RE = re.compile(r"^\d{4}-\d{2}$")
_MAX_CODE = 0xFFFFFFFF


@dataclass(frozen=True, slots=True)
class DerivedImageKeys:
    xor_key: int
    aes_key: str


@dataclass(frozen=True, slots=True)
class V2Template:
    path: Path
    ciphertext: bytes
    mtime_ns: int
    tail_xor_key: int | None
    tail_bytes: bytes = b""


@dataclass(frozen=True, slots=True)
class TemplateScanResult:
    templates: tuple[V2Template, ...]
    inferred_xor_key: int | None
    xor_support: int = 0


@dataclass(frozen=True, slots=True)
class ImageKeyResolution:
    code: int
    wxid: str
    xor_key: int
    aes_key: str
    template_path: Path


def clean_wxid(value: str | None) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return ""
    match = _SUFFIXED_WXID_RE.fullmatch(candidate)
    return match.group(1) if match else candidate


def enumerate_kvcomm_codes(kvcomm_dir: Path) -> tuple[int, ...]:
    codes: set[int] = set()
    try:
        entries = os.scandir(kvcomm_dir)
    except OSError:
        return ()
    with entries:
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
            except OSError:
                continue
            match = _KVCOMM_FILE_RE.fullmatch(entry.name)
            if not match:
                continue
            try:
                code = int(match.group(1))
            except ValueError:
                continue
            if 0 < code <= _MAX_CODE:
                codes.add(code)
    return tuple(sorted(codes))


def derive_image_keys(code: int, wxid: str) -> DerivedImageKeys:
    cleaned = clean_wxid(wxid)
    if not cleaned or code <= 0:
        raise ValueError("A positive code and wxid are required.")
    digest = hashlib.md5(f"{code}{cleaned}".encode("utf-8")).hexdigest()
    return DerivedImageKeys(xor_key=code & 0xFF, aes_key=digest[:16])


def _detect_image_format(plaintext: bytes) -> str | None:
    if plaintext.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if plaintext.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if plaintext.startswith(b"RIFF") and plaintext[8:12] == b"WEBP":
        return "webp"
    if plaintext.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if plaintext.startswith((b"wxgf", b"WXGF")):
        return "wxgf"
    return None


def _decrypt_first_block(aes_key: str | bytes, ciphertext: bytes) -> bytes | None:
    try:
        key = aes_key.encode("ascii") if isinstance(aes_key, str) else bytes(aes_key)
    except (UnicodeEncodeError, TypeError, ValueError):
        return None
    if len(key) != AES_BLOCK_SIZE or len(ciphertext) != AES_BLOCK_SIZE:
        return None
    try:
        decryptor = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except (TypeError, ValueError):
        return None


def _verify_aes_key(aes_key: str | bytes, ciphertext: bytes) -> bool:
    return _detect_image_format(_decrypt_first_block(aes_key, ciphertext) or b"") is not None


def _xor_from_tail(tail: bytes) -> int | None:
    if len(tail) != 2:
        return None
    first = tail[0] ^ 0xFF
    second = tail[1] ^ 0xD9
    return first if first == second else None


def _infer_xor(tails: Iterable[bytes]) -> tuple[int | None, int]:
    counts: Counter[int] = Counter(
        key for key in (_xor_from_tail(tail) for tail in tails) if key is not None
    )
    if not counts:
        return None, 0
    key, support = counts.most_common(1)[0]
    return key, support


def _path_mtime_ns(path: Path) -> int:
    try:
        return path.stat().st_mtime_ns
    except OSError:
        return 0


def _collect_template_paths(
    account_dir: Path,
    *,
    limit: int,
    max_dirs: int,
) -> list[Path]:
    roots = [
        root
        for root in (
            account_dir / "msg" / "attach",
            account_dir / "cache",
            account_dir / "resource",
        )
        if root.is_dir()
    ]
    heap: list[tuple[int, str, Path]] = []
    visited = 0
    for root in roots:
        for current, directories, filenames in os.walk(root):
            visited += 1
            if visited > max_dirs:
                break
            directories.sort()
            for filename in filenames:
                if not filename.casefold().endswith("_t.dat"):
                    continue
                path = Path(current) / filename
                mtime_ns = _path_mtime_ns(path)
                item = (mtime_ns, str(path).casefold(), path)
                if len(heap) < limit:
                    heapq.heappush(heap, item)
                elif item > heap[0]:
                    heapq.heapreplace(heap, item)
        if visited > max_dirs:
            break
    return [item[2] for item in sorted(heap, reverse=True)]


def scan_v2_templates(
    account_dir: Path,
    *,
    limit: int = 128,
    max_dirs: int = 1500,
) -> TemplateScanResult:
    templates: list[V2Template] = []
    for path in _collect_template_paths(
        Path(account_dir), limit=limit, max_dirs=max_dirs
    ):
        try:
            with path.open("rb") as stream:
                header = stream.read(V2_CIPHERTEXT_START + AES_BLOCK_SIZE)
                if (
                    len(header) < V2_CIPHERTEXT_START + AES_BLOCK_SIZE
                    or not header.startswith(V2_MAGIC)
                ):
                    continue
                stream.seek(-2, os.SEEK_END)
                tail = stream.read(2)
        except OSError:
            continue
        templates.append(
            V2Template(
                path=path,
                ciphertext=header[
                    V2_CIPHERTEXT_START : V2_CIPHERTEXT_START + AES_BLOCK_SIZE
                ],
                mtime_ns=_path_mtime_ns(path),
                tail_xor_key=_xor_from_tail(tail),
                tail_bytes=tail,
            )
        )
    inferred, support = _infer_xor(template.tail_bytes for template in templates)
    return TemplateScanResult(
        templates=tuple(templates),
        inferred_xor_key=inferred,
        xor_support=support,
    )


def _trusted_xor(aes_key: str, scan: TemplateScanResult) -> int | None:
    current = scan.templates[0] if scan.templates else None
    if current is None:
        return None
    current_plain = _decrypt_first_block(aes_key, current.ciphertext) or b""
    if _detect_image_format(current_plain) is None:
        return None

    matching: list[int] = []
    for template in scan.templates:
        plain = _decrypt_first_block(aes_key, template.ciphertext) or b""
        if (
            _detect_image_format(plain) == "jpeg"
            and template.tail_xor_key is not None
        ):
            matching.append(template.tail_xor_key)
    if matching:
        return Counter(matching).most_common(1)[0][0]
    if _detect_image_format(current_plain) == "jpeg":
        return current.tail_xor_key
    return None


def find_kvcomm_dirs(source_root: Path | None = None) -> tuple[Path, ...]:
    override = str(os.environ.get("WECHAT_IMAGE_KVCOMM_DIR") or "").strip()
    if override:
        return (Path(override).expanduser(),)

    candidates: list[Path] = []
    if sys.platform == "darwin":
        container = (
            Path.home()
            / "Library"
            / "Containers"
            / "com.tencent.xinWeChat"
            / "Data"
        )
        candidates.extend(
            [
                container / "Documents" / "app_data" / "net" / "kvcomm",
                container / "Documents" / "xwechat" / "net" / "kvcomm",
            ]
        )
        if source_root is not None:
            candidates.append(source_root.parent / "app_data" / "net" / "kvcomm")
    else:
        appdata = str(os.environ.get("APPDATA") or "").strip()
        root = Path(appdata) if appdata else Path.home() / "AppData" / "Roaming"
        candidates.append(root / "Tencent" / "xwechat" / "net" / "kvcomm")
    return tuple(dict.fromkeys(path for path in candidates if path.is_dir()))


def _wxid_candidates(
    *,
    target_wxid: str,
    account: str,
    account_dir_name: str,
) -> tuple[str, ...]:
    values = [target_wxid, account, account_dir_name, "unknown"]
    result: list[str] = []
    for value in values:
        cleaned = clean_wxid(value)
        if cleaned and cleaned not in result:
            result.append(cleaned)
    return tuple(result)


def resolve_image_keys(
    *,
    account_dir: Path,
    source_root: Path | None,
    account: str,
    target_wxid: str = "",
) -> ImageKeyResolution | None:
    """Return a verified key pair, or None when no local proof is available."""

    scan = scan_v2_templates(Path(account_dir))
    if not scan.templates:
        return None
    current = scan.templates[0]
    wxids = _wxid_candidates(
        target_wxid=target_wxid,
        account=account,
        account_dir_name=Path(account_dir).name,
    )
    for kvcomm_dir in find_kvcomm_dirs(source_root):
        codes = list(enumerate_kvcomm_codes(kvcomm_dir))
        if scan.inferred_xor_key is not None and scan.xor_support >= 2:
            codes.sort(
                key=lambda code: (
                    (code & 0xFF) != scan.inferred_xor_key,
                    code,
                )
            )
        for wxid in wxids:
            for code in codes:
                derived = derive_image_keys(code, wxid)
                if not _verify_aes_key(derived.aes_key, current.ciphertext):
                    continue
                xor_key = _trusted_xor(derived.aes_key, scan)
                if xor_key is None:
                    continue
                return ImageKeyResolution(
                    code=code,
                    wxid=wxid,
                    xor_key=xor_key,
                    aes_key=derived.aes_key,
                    template_path=current.path,
                )
    return None
