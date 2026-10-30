"""Message payload decoding.

WeChat 4.x stores most text and app messages as zstd frames.  Group messages
also carry a ``sender:\\n`` prefix in the payload.  This module keeps only the
read-only decoding rules needed by the standalone core.
"""

from __future__ import annotations

import base64
import html
import re
import xml.etree.ElementTree as ET
from typing import Any, Optional

import zstandard as zstd


_ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"
_XML_START_RE = re.compile(r"<\s*(?:\?xml|msg|appmsg|sysmsg)\b", re.IGNORECASE)

APP_TYPE_KINDS = {
    4: "video",
    5: "link",
    6: "file",
    19: "chat_history",
    33: "mini_program",
    36: "mini_program",
    51: "video_channel",
    57: "quote",
    63: "live",
    2000: "transfer",
    2001: "red_packet",
}

LOCAL_TYPE_KINDS = {
    1: "text",
    3: "image",
    34: "voice",
    43: "video",
    47: "sticker",
    48: "location",
    49: "app",
    10000: "system",
    10002: "system",
}


def decode_sqlite_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, memoryview):
        value = bytes(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="ignore")
    return str(value)


def is_mostly_printable_text(value: str) -> bool:
    sample = (value or "")[:600]
    if not sample:
        return False
    printable = sum(
        1 for ch in sample if ch.isprintable() or ch in {"\n", "\r", "\t"}
    )
    return (printable / len(sample)) >= 0.85


def looks_like_xml(value: str) -> bool:
    text = (value or "").lstrip()
    if text.startswith('"') and text.endswith('"'):
        text = text.strip('"').lstrip()
    return bool(_XML_START_RE.match(text))


def _try_decode_text_blob(text: str) -> Optional[str]:
    raw_text = (text or "").strip()
    if not raw_text:
        return None

    if (
        len(raw_text) >= 16
        and len(raw_text) % 2 == 0
        and re.fullmatch(r"[0-9a-fA-F]+", raw_text)
    ):
        try:
            raw = bytes.fromhex(raw_text)
            if raw.startswith(_ZSTD_MAGIC):
                decoded = zstd.decompress(raw).decode("utf-8", errors="ignore")
                decoded = html.unescape(decoded.strip())
                if looks_like_xml(decoded) or is_mostly_printable_text(decoded):
                    return decoded
            decoded = raw.decode("utf-8", errors="ignore")
            decoded = html.unescape(decoded.strip())
            lower = decoded.lower()
            if looks_like_xml(decoded) or ("<msg" in lower and "</msg>" in lower):
                return decoded
        except Exception:
            return None

    if (
        len(raw_text) >= 24
        and len(raw_text) % 4 == 0
        and re.fullmatch(r"[A-Za-z0-9+/=]+", raw_text)
    ):
        try:
            raw = base64.b64decode(raw_text)
            if raw.startswith(_ZSTD_MAGIC):
                decoded = zstd.decompress(raw).decode("utf-8", errors="ignore")
                decoded = html.unescape(decoded.strip())
                if looks_like_xml(decoded) or is_mostly_printable_text(decoded):
                    return decoded
            decoded = raw.decode("utf-8", errors="ignore")
            decoded = html.unescape(decoded.strip())
            lower = decoded.lower()
            if looks_like_xml(decoded) or ("<msg" in lower and "</msg>" in lower):
                return decoded
        except Exception:
            return None

    return None


def decode_message_content(compress_value: Any, message_value: Any) -> str:
    """Decode ``compress_content`` / ``message_content`` into text."""

    msg_text = decode_sqlite_text(message_value)

    decoded = _try_decode_text_blob(html.unescape(msg_text.strip()))
    if decoded:
        msg_text = decoded

    if isinstance(message_value, (bytes, bytearray, memoryview)):
        raw = bytes(message_value)
        if raw.startswith(_ZSTD_MAGIC):
            try:
                decoded = zstd.decompress(raw).decode("utf-8", errors="ignore")
                decoded = html.unescape(decoded.strip())
                if looks_like_xml(decoded) or is_mostly_printable_text(decoded):
                    msg_text = decoded
            except Exception:
                pass

    if compress_value is None:
        return msg_text

    if isinstance(compress_value, str):
        text = html.unescape(compress_value.strip())
        decoded = _try_decode_text_blob(text)
        if decoded:
            return decoded
        if looks_like_xml(text) or is_mostly_printable_text(text):
            return text
        return msg_text

    data = bytes(compress_value) if isinstance(compress_value, memoryview) else compress_value
    if not isinstance(data, (bytes, bytearray)) or not data:
        return msg_text

    try:
        decoded = zstd.decompress(bytes(data)).decode("utf-8", errors="ignore")
        decoded = html.unescape(decoded.strip())
        if looks_like_xml(decoded) or is_mostly_printable_text(decoded):
            return decoded
    except Exception:
        pass

    try:
        text = bytes(data).decode("utf-8", errors="ignore")
        text = html.unescape(text.strip())
        decoded = _try_decode_text_blob(text)
        if decoded:
            return decoded
        if looks_like_xml(text) or is_mostly_printable_text(text):
            return text
    except Exception:
        pass

    return msg_text


def strip_sender_prefix(text: str, sender_username: str = "") -> str:
    """Remove the ``wxid_xxx:\\n`` prefix stored at the start of group payloads."""

    value = text or ""
    match = re.match(r"^\s*([^\s:：<>]{1,128})\s*[:：]\s*\r?\n", value)
    if not match:
        return value
    prefix = match.group(1)
    if (
        prefix == sender_username
        or prefix.startswith("wxid_")
        or prefix.endswith("@chatroom")
        or re.fullmatch(r"[A-Za-z0-9_.@-]+", prefix)
    ):
        return value[match.end() :]
    return value


def base_local_type(local_type: Any) -> int:
    try:
        return int(local_type) & 0xFFFFFFFF
    except Exception:
        return 0


def local_type_kind(local_type: Any) -> str:
    return LOCAL_TYPE_KINDS.get(base_local_type(local_type), "unknown")


def _find_text(root: ET.Element, path: str) -> str:
    node = root.find(path)
    if node is None or node.text is None:
        return ""
    return str(node.text).strip()


def _find_text_any(root: ET.Element, *paths: str) -> str:
    for path in paths:
        value = _find_text(root, path)
        if value:
            return value
    return ""


def parse_app_message(text: str) -> dict[str, Any]:
    """Parse an ``<appmsg>`` payload into stable, AI-friendly fields."""

    result: dict[str, Any] = {
        "kind": "app",
        "title": "",
        "description": "",
        "url": "",
        "app_type": 0,
        "file_ext": "",
        "file_size": 0,
        "app_name": "",
        "publisher": "",
        "duration_seconds": 0,
        "object_id": "",
    }
    value = (text or "").strip()
    if not value:
        return result
    start = value.find("<")
    if start < 0:
        return result
    value = value[start:]
    try:
        root = ET.fromstring(value)
    except Exception:
        # Best-effort fallback for malformed XML.
        title = re.search(r"<title>(.*?)</title>", value, re.S)
        url = re.search(r"<url>(.*?)</url>", value, re.S)
        if title:
            result["title"] = html.unescape(title.group(1).strip())
        if url:
            result["url"] = html.unescape(url.group(1).strip())
        return result

    appmsg = root if root.tag == "appmsg" else root.find(".//appmsg")
    if appmsg is None:
        return result

    app_type_text = _find_text(appmsg, "type")
    try:
        app_type = int(app_type_text or 0)
    except Exception:
        app_type = 0
    result["app_type"] = app_type
    result["kind"] = APP_TYPE_KINDS.get(app_type, "app")
    result["title"] = html.unescape(_find_text(appmsg, "title"))
    result["description"] = html.unescape(_find_text(appmsg, "des"))
    result["url"] = html.unescape(_find_text(appmsg, "url"))
    result["app_name"] = html.unescape(_find_text(appmsg, "appname"))
    result["file_ext"] = _find_text(appmsg, ".//appattach/fileext")
    try:
        result["file_size"] = int(_find_text(appmsg, ".//appattach/totallen") or 0)
    except Exception:
        result["file_size"] = 0

    finder = appmsg.find("finderFeed")
    if finder is not None:
        result["kind"] = "video_channel"
        result["publisher"] = html.unescape(_find_text(finder, "nickname"))
        result["description"] = html.unescape(_find_text(finder, "desc"))
        result["object_id"] = _find_text(finder, "objectId")
        duration = _find_text(finder, ".//media/videoPlayDuration")
        try:
            result["duration_seconds"] = int(duration or 0)
        except Exception:
            result["duration_seconds"] = 0
        if not result["title"] or result["title"].startswith("当前微信版本"):
            result["title"] = result["publisher"] or "视频号内容"
        if result["url"].startswith("https://support.weixin.qq.com/update"):
            result["url"] = ""

    if result["kind"] == "link" and not result["description"]:
        result["description"] = html.unescape(
            _find_text_any(appmsg, "des", "messageext")
        )
    return result


def _xml_tag_value(text: str, tag: str) -> str:
    match = re.search(
        rf"<{re.escape(tag)}(?:\s[^>]*)?>(.*?)</{re.escape(tag)}>",
        text or "",
        re.IGNORECASE | re.DOTALL,
    )
    if not match:
        return ""
    return html.unescape(re.sub(r"<!\[CDATA\[(.*?)\]\]>", r"\1", match.group(1), flags=re.DOTALL)).strip()


def _xml_attr_value(text: str, attr: str) -> str:
    match = re.search(
        rf"\b{re.escape(attr)}\s*=\s*(['\"])(.*?)\1",
        text or "",
        re.IGNORECASE | re.DOTALL,
    )
    return html.unescape(match.group(2).strip()) if match else ""


def parse_media_refs(text: str, kind: str) -> dict[str, str]:
    """Extract stable attachment identifiers from an image/file payload."""

    value = text or ""
    kind_key = str(kind or "").strip().lower()
    md5 = ""
    file_id = ""

    if kind_key == "file":
        md5 = _xml_tag_value(value, "md5") or _xml_tag_value(value, "filemd5")
        file_id = _xml_tag_value(value, "attachid") or _xml_tag_value(
            value, "cdnattachurl"
        )
    elif kind_key == "image":
        md5 = (
            _xml_attr_value(value, "md5")
            or _xml_attr_value(value, "fullmd5")
            or _xml_tag_value(value, "md5")
        )
        file_id = (
            _xml_attr_value(value, "cdnbigimgurl")
            or _xml_attr_value(value, "cdnmidimgurl")
            or _xml_attr_value(value, "cdnthumburl")
        )

    md5 = md5.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{32}", md5):
        md5 = ""
    file_id = file_id.strip()
    result: dict[str, str] = {}
    if md5:
        result["md5"] = md5
    if file_id:
        result["file_id"] = file_id
    return result


def decode_message_row(
    row: dict[str, Any],
    *,
    sender_username: str = "",
    include_raw: bool = False,
) -> dict[str, Any]:
    """Convert a raw message row into a stable read-only message object."""

    text = decode_message_content(
        row.get("compress_content"), row.get("message_content")
    )
    text = strip_sender_prefix(text, sender_username)
    local_type = row.get("local_type")
    kind = local_type_kind(local_type)
    result: dict[str, Any] = {
        "local_id": row.get("local_id"),
        "timestamp": row.get("create_time"),
        "type": base_local_type(local_type),
        "kind": kind,
        "text": text,
    }

    if kind == "app":
        app = parse_app_message(text)
        result.update(
            {
                "kind": app["kind"],
                "title": app["title"],
                "description": app["description"],
                "url": app["url"],
                "app_type": app["app_type"],
                "publisher": app["publisher"],
                "duration_seconds": app["duration_seconds"],
            }
        )
        if app["file_ext"]:
            result["file_ext"] = app["file_ext"]
        if app["file_size"]:
            result["file_size"] = app["file_size"]
        if app["kind"] == "file":
            result["text"] = app["title"]
        elif app["kind"] == "link":
            result["text"] = "\n".join(
                part for part in (app["title"], app["url"]) if part
            )
        elif app["kind"] == "video_channel":
            result["text"] = app["description"] or app["title"]
    elif kind in {"image", "voice", "video", "sticker", "location"}:
        # Media payloads are XML/plain metadata; return a readable placeholder.
        result["text"] = {
            "image": "[图片]",
            "voice": "[语音]",
            "video": "[视频]",
            "sticker": "[表情]",
            "location": "[位置]",
        }[kind]

    media_refs = parse_media_refs(text, kind)
    if not media_refs and kind == "app":
        media_refs = parse_media_refs(text, str(result.get("kind") or ""))
    if media_refs:
        result["media"] = media_refs

    if include_raw:
        result["raw"] = text
    return result
