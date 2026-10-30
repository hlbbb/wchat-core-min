"""Contact and group-member parsing for the read-only core."""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path
from typing import Any, Optional


def _connect_readonly(path: str | Path) -> sqlite3.Connection:
    return sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)


def contact_display_name(item: dict[str, Any]) -> str:
    for key in ("remark", "nick_name", "alias", "username"):
        value = str(item.get(key) or "").strip()
        if value:
            return value
    return ""


def load_contact_map(contact_db_path: str | Path) -> dict[str, dict[str, Any]]:
    result: dict[str, dict[str, Any]] = {}
    conn = _connect_readonly(contact_db_path)
    try:
        rows = conn.execute(
            """
            SELECT username, remark, nick_name, alias, local_type
            FROM contact
            WHERE username IS NOT NULL AND username <> ''
            """
        ).fetchall()
        for username, remark, nick_name, alias, local_type in rows:
            name = str(username or "").strip()
            if not name:
                continue
            item = {
                "username": name,
                "remark": str(remark or "").strip(),
                "nick_name": str(nick_name or "").strip(),
                "alias": str(alias or "").strip(),
                "local_type": int(local_type or 0),
            }
            item["display_name"] = contact_display_name(item)
            result[name] = item
    finally:
        conn.close()
    return result


def _decode_varint(raw: bytes, offset: int) -> tuple[Optional[int], int]:
    value = 0
    shift = 0
    pos = int(offset)
    while pos < len(raw):
        byte = raw[pos]
        pos += 1
        value |= (byte & 0x7F) << shift
        if (byte & 0x80) == 0:
            return value, pos
        shift += 7
        if shift > 63:
            return None, len(raw)
    return None, len(raw)


def _iter_fields(raw: bytes):
    idx = 0
    while idx < len(raw):
        tag, next_idx = _decode_varint(raw, idx)
        if tag is None or next_idx <= idx:
            break
        idx = next_idx
        field_no = int(tag) >> 3
        wire_type = int(tag) & 0x7

        if wire_type == 0:
            _, next_idx = _decode_varint(raw, idx)
            if next_idx <= idx:
                break
            idx = next_idx
            continue
        if wire_type == 2:
            size, next_idx = _decode_varint(raw, idx)
            if size is None or next_idx <= idx:
                break
            idx = next_idx
            end = idx + int(size)
            if end > len(raw):
                break
            chunk = raw[idx:end]
            idx = end
            yield field_no, wire_type, chunk
            continue
        if wire_type == 1:
            idx += 8
            continue
        if wire_type == 5:
            idx += 4
            continue
        break


def _looks_like_username(value: str) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    if (
        text.startswith("wxid_")
        or text.endswith("@chatroom")
        or text.startswith("gh_")
        or "@" in text
    ):
        return True
    if len(text) < 6 or len(text) > 32:
        return False
    if re.search(r"\s", text):
        return False
    if not re.match(r"^[A-Za-z][A-Za-z0-9_-]+$", text):
        return False
    return not text.isdigit()


def _pick_display(
    strings: list[tuple[int, str]],
    target: str,
    *,
    allowed_fields: set[int],
) -> str:
    best_score = -1
    best = ""
    for index, (field_no, value) in enumerate(strings):
        if int(field_no) not in allowed_fields:
            continue
        text = str(value or "").strip()
        if not text or text == target or _looks_like_username(text):
            continue
        if "\n" in text or "\r" in text or len(text) > 64:
            continue
        score = 0
        if int(field_no) == 2:
            score += 100
        if not _looks_like_username(text):
            score += 20
        score += max(0, 32 - len(text))
        score = score * 1000 - index
        if score > best_score:
            best_score = score
            best = text
    return best


def load_group_nickname_map(
    contact_db_path: str | Path,
    chatroom_id: str,
    sender_usernames: list[str],
) -> dict[str, str]:
    """Return per-chatroom group nicknames for the requested senders."""

    chatroom = str(chatroom_id or "").strip()
    if not chatroom.endswith("@chatroom"):
        return {}
    targets = list(
        dict.fromkeys(
            str(value or "").strip()
            for value in sender_usernames
            if str(value or "").strip()
        )
    )
    if not targets:
        return {}
    target_set = set(targets)

    try:
        conn = _connect_readonly(contact_db_path)
    except Exception:
        return {}
    try:
        row = conn.execute(
            "SELECT ext_buffer FROM chat_room WHERE username = ? LIMIT 1",
            (chatroom,),
        ).fetchone()
        if row is None or row[0] is None:
            return {}
        ext = row[0]
        if isinstance(ext, memoryview):
            ext_buffer = ext.tobytes()
        elif isinstance(ext, (bytes, bytearray)):
            ext_buffer = bytes(ext)
        else:
            return {}
        if not ext_buffer:
            return {}

        member_records: list[list[tuple[int, str]]] = []
        for _, wire_type, chunk in _iter_fields(ext_buffer):
            if wire_type != 2 or not chunk:
                continue
            strings: list[tuple[int, str]] = []
            for field_no, sub_wire, value in _iter_fields(chunk):
                if sub_wire != 2 or not value or len(value) > 256:
                    continue
                try:
                    text = bytes(value).decode("utf-8", errors="strict").strip()
                except Exception:
                    continue
                if text:
                    strings.append((int(field_no), text))
            if strings:
                member_records.append(strings)

        uses_current_layout = any(
            field_no == 2 or (field_no == 1 and value in target_set)
            for strings in member_records
            for field_no, value in strings
        )

        output: dict[str, str] = {}
        if uses_current_layout:
            for strings in member_records:
                for field_no, value in strings:
                    if field_no != 1 or value not in target_set or value in output:
                        continue
                    display = _pick_display(strings, value, allowed_fields={2})
                    if display:
                        output[value] = display
                if len(output) >= len(target_set):
                    break
            return output

        legacy_records = [
            strings
            for strings in member_records
            if any(field_no == 4 and value in target_set for field_no, value in strings)
        ]
        if not legacy_records:
            return {}
        for strings in legacy_records:
            field1_values = [
                value for field_no, value in strings if field_no == 1 and value
            ]
            if not field1_values or any(
                _looks_like_username(value) for value in field1_values
            ):
                return {}
        for strings in legacy_records:
            for field_no, value in strings:
                if field_no != 4 or value not in target_set or value in output:
                    continue
                display = _pick_display(strings, value, allowed_fields={1})
                if display:
                    output[value] = display
            if len(output) >= len(target_set):
                break
        return output
    except Exception:
        return {}
    finally:
        try:
            conn.close()
        except Exception:
            pass


def load_group_members(
    contact_db_path: str | Path,
    chatroom_id: str,
) -> list[dict[str, Any]]:
    """Return group members with contact and group-nickname display names."""

    room = str(chatroom_id or "").strip()
    if not room.endswith("@chatroom"):
        return []
    contact_map = load_contact_map(contact_db_path)
    conn = _connect_readonly(contact_db_path)
    try:
        owner_row = conn.execute(
            "SELECT owner FROM chat_room WHERE username = ? LIMIT 1", (room,)
        ).fetchone()
        owner = str(owner_row[0] or "").strip() if owner_row else ""
        rows = conn.execute(
            """
            SELECT c.username
            FROM chatroom_member m
            JOIN contact c ON c.id = m.member_id
            JOIN chat_room r ON r.id = m.room_id
            WHERE r.username = ?
            ORDER BY c.username
            """,
            (room,),
        ).fetchall()
    finally:
        conn.close()

    usernames = [str(row[0] or "").strip() for row in rows if row and row[0]]
    if not usernames:
        return []
    nickname_map = load_group_nickname_map(contact_db_path, room, usernames)
    members: list[dict[str, Any]] = []
    for username in usernames:
        contact = contact_map.get(username, {})
        members.append(
            {
                "username": username,
                "group_nickname": nickname_map.get(username, ""),
                "display_name": nickname_map.get(username)
                or contact.get("display_name")
                or username,
                "remark": contact.get("remark", ""),
                "nick_name": contact.get("nick_name", ""),
                "is_owner": username == owner,
            }
        )
    return members
