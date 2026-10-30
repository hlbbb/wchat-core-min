"""AI-friendly command line interface for the read-only WeChat core."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from pathlib import Path
from typing import Any

from .contacts import (
    contact_display_name,
    load_contact_map,
    load_group_members,
    load_group_nickname_map,
)
from .content import decode_message_row, decode_message_content
from .media import export_media_source, resolve_media_keys
from .store import (
    CacheInfo,
    account_dir,
    ensure_cache,
    list_accounts,
    load_key_store,
    resolve_account,
    resolve_data_dir,
    source_storage,
)


def _connect_readonly(path: Path) -> sqlite3.Connection:
    return sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)


def _canonical(value: str) -> str:
    return re.sub(r"_[0-9a-fA-F]{4}$", "", str(value or "").strip())


def _local_tz() -> timezone:
    now = datetime.now().astimezone()
    offset = now.utcoffset() or timedelta(0)
    return timezone(offset, "local")


def _iso(ts: Any, tz: timezone) -> str:
    try:
        return datetime.fromtimestamp(int(ts), tz).isoformat(timespec="seconds")
    except Exception:
        return ""


def _date_bounds(args: argparse.Namespace) -> tuple[int | None, int | None]:
    tz = _local_tz()
    if getattr(args, "date", None) == "all":
        return None, None
    if getattr(args, "start", None) or getattr(args, "end", None):
        start = _parse_datetime(args.start, tz, end_of_day=False) if args.start else None
        end = _parse_datetime(args.end, tz, end_of_day=True) if args.end else None
        return (
            int(start.timestamp()) if start else None,
            int(end.timestamp()) + 1 if end else None,
        )
    if getattr(args, "days", None):
        end_day = datetime.now(tz).date()
        start_day = end_day - timedelta(days=max(1, int(args.days)) - 1)
        return (
            int(datetime.combine(start_day, datetime_time.min, tzinfo=tz).timestamp()),
            int(datetime.combine(end_day + timedelta(days=1), datetime_time.min, tzinfo=tz).timestamp()),
        )
    raw = str(getattr(args, "date", None) or "today").strip()
    if raw.lower() == "today":
        day = datetime.now(tz).date()
    else:
        try:
            day = date.fromisoformat(raw)
        except ValueError as exc:
            raise SystemExit(f"Invalid --date: {raw}") from exc
    start = datetime.combine(day, datetime_time.min, tzinfo=tz)
    return int(start.timestamp()), int((start + timedelta(days=1)).timestamp())


def _parse_datetime(value: str, tz: timezone, *, end_of_day: bool) -> datetime:
    text = str(value or "").strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        try:
            day = date.fromisoformat(text)
        except ValueError as exc:
            raise SystemExit(f"Invalid date/time: {value}") from exc
        return datetime.combine(
            day, datetime_time.max if end_of_day else datetime_time.min, tzinfo=tz
        )
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed


def _load_sessions(cache: CacheInfo, contacts: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    if not cache.session_db or not cache.session_db.is_file():
        return []
    conn = _connect_readonly(cache.session_db)
    try:
        rows = conn.execute(
            """
            SELECT username, type, last_timestamp, sort_timestamp, summary, last_msg_type
            FROM SessionTable
            WHERE username IS NOT NULL AND username <> ''
            ORDER BY sort_timestamp DESC
            """
        ).fetchall()
    finally:
        conn.close()
    tz = _local_tz()
    sessions: list[dict[str, Any]] = []
    for username, session_type, last_ts, sort_ts, summary, last_type in rows:
        name = str(username or "").strip()
        contact = contacts.get(name, {})
        sessions.append(
            {
                "username": name,
                "name": contact.get("display_name") or name,
                "remark": contact.get("remark", ""),
                "nick_name": contact.get("nick_name", ""),
                "is_group": name.endswith("@chatroom"),
                "type": int(session_type or 0),
                "last_timestamp": int(last_ts or 0),
                "last_time": _iso(last_ts, tz),
                "sort_timestamp": int(sort_ts or 0),
                "summary": _decode_summary(summary),
                "last_msg_type": int(last_type or 0),
            }
        )
    return sessions


def _decode_summary(value: Any) -> str:
    if value is None:
        return ""
    text = decode_message_content(None, value)
    return text.strip()[:500]


def _match_session(
    sessions: list[dict[str, Any]], query: str
) -> dict[str, Any]:
    wanted = str(query or "").strip()
    if not wanted:
        raise SystemExit("--chat is required")
    exact = [
        item
        for item in sessions
        if item["username"] == wanted or item["name"] == wanted
    ]
    if len(exact) == 1:
        return exact[0]
    lowered = wanted.casefold()
    partial = [
        item
        for item in sessions
        if lowered in str(item["name"]).casefold()
        or lowered in str(item["username"]).casefold()
        or lowered in str(item.get("remark") or "").casefold()
    ]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise SystemExit(f"Chat not found: {wanted}")
    candidates = [
        {"username": item["username"], "name": item["name"]} for item in partial[:20]
    ]
    raise SystemExit(
        "Chat name is ambiguous. Candidates: "
        + json.dumps(candidates, ensure_ascii=False)
    )


def _match_chat(
    sessions: list[dict[str, Any]],
    contacts: dict[str, dict[str, Any]],
    query: str,
) -> dict[str, Any]:
    try:
        return _match_session(sessions, query)
    except SystemExit as session_error:
        wanted = str(query or "").strip()
        if not wanted:
            raise
        exact = [
            item
            for item in contacts.values()
            if item.get("username") == wanted or item.get("display_name") == wanted
        ]
        matches = exact
        if not matches:
            lowered = wanted.casefold()
            matches = [
                item
                for item in contacts.values()
                if lowered in str(item.get("display_name") or "").casefold()
                or lowered in str(item.get("username") or "").casefold()
                or lowered in str(item.get("remark") or "").casefold()
                or lowered in str(item.get("nick_name") or "").casefold()
            ]
        if len(matches) == 1:
            item = matches[0]
            username = str(item.get("username") or "")
            return {
                "username": username,
                "name": item.get("display_name") or username,
                "remark": item.get("remark", ""),
                "nick_name": item.get("nick_name", ""),
                "is_group": username.endswith("@chatroom"),
                "type": 0,
                "last_timestamp": 0,
                "last_time": "",
                "sort_timestamp": 0,
                "summary": "",
                "last_msg_type": 0,
            }
        raise session_error


def _table_name(username: str) -> str:
    return "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()


def _table_names(conn: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        if row and row[0]
    }


def _resolve_table(conn: sqlite3.Connection, username: str) -> str | None:
    names = _table_names(conn)
    expected = _table_name(username)
    lower = {name.lower(): name for name in names}
    if expected.lower() in lower:
        return lower[expected.lower()]
    md5_hex = expected[4:].lower()
    for name in names:
        if md5_hex in name.lower():
            return name
    return None


def _name2id(conn: sqlite3.Connection) -> dict[int, str]:
    try:
        rows = conn.execute("SELECT rowid, user_name FROM Name2Id").fetchall()
    except Exception:
        return {}
    return {int(row[0]): str(row[1] or "") for row in rows if row and row[0] is not None}


def _self_username(cache: CacheInfo, account: str) -> str:
    candidates: list[str] = []
    if cache.source_storage:
        candidates.append(Path(cache.source_storage).parent.name)
    candidates.append(account)
    for value in candidates:
        name = _canonical(value)
        if name:
            return name
    return account


def _read_messages(
    cache: CacheInfo,
    chat_username: str,
    *,
    start: int | None,
    end: int | None,
    include_raw: bool,
) -> list[dict[str, Any]]:
    contact_map = load_contact_map(cache.contact_db) if cache.contact_db else {}
    is_group = chat_username.endswith("@chatroom")
    nickname_map: dict[str, str] = {}
    self_name = _self_username(cache, cache.account)
    tz = _local_tz()

    collected: list[dict[str, Any]] = []
    for db in cache.message_dbs:
        conn = _connect_readonly(db)
        try:
            table = _resolve_table(conn, chat_username)
            if not table:
                continue
            quoted = '"' + table.replace('"', '""') + '"'
            where: list[str] = []
            params: list[Any] = []
            if start is not None:
                where.append("create_time >= ?")
                params.append(start)
            if end is not None:
                where.append("create_time < ?")
                params.append(end)
            sql = (
                "SELECT local_id, local_type, create_time, real_sender_id, "
                "message_content, compress_content "
                f"FROM {quoted}"
            )
            if where:
                sql += " WHERE " + " AND ".join(where)
            sql += " ORDER BY create_time, local_id"
            rows = conn.execute(sql, params).fetchall()
            id_map = _name2id(conn)
        finally:
            conn.close()

        if is_group and rows and not nickname_map:
            senders = [
                id_map.get(int(row[3]), "") for row in rows if row and row[3] is not None
            ]
            if cache.contact_db:
                nickname_map = load_group_nickname_map(
                    cache.contact_db, chat_username, senders
                )

        for row in rows:
            local_id, local_type, create_time, sender_id, content, compressed = row
            sender_username = id_map.get(int(sender_id), "") if sender_id is not None else ""
            contact = contact_map.get(sender_username, {})
            if _canonical(sender_username) == self_name:
                sender = "我"
            elif is_group:
                sender = (
                    nickname_map.get(sender_username)
                    or contact.get("display_name")
                    or sender_username
                )
            else:
                sender = contact.get("display_name") or sender_username
            item = decode_message_row(
                {
                    "local_id": local_id,
                    "local_type": local_type,
                    "create_time": create_time,
                    "message_content": content,
                    "compress_content": compressed,
                },
                sender_username=sender_username,
                include_raw=include_raw,
            )
            item["time"] = _iso(create_time, tz)
            item["sender"] = sender
            item["sender_username"] = sender_username
            collected.append(item)

    collected.sort(key=lambda item: (item.get("timestamp") or 0, item.get("local_id") or 0))
    return collected


def _format_messages(messages: list[dict[str, Any]], fmt: str, chat: dict[str, Any]) -> str:
    if fmt == "json":
        return json.dumps(messages, ensure_ascii=False, indent=2)
    lines: list[str] = []
    if chat:
        lines.append(f"# {chat.get('name')} ({chat.get('username')})")
        lines.append("")
    for item in messages:
        kind = item.get("kind")
        text = item.get("text") or ""
        if kind == "file":
            text = f"[文件] {item.get('title') or text}"
            if item.get("file_ext") and not text.lower().endswith(
                f".{str(item['file_ext']).lower()}"
            ):
                text += f" (.{item['file_ext']})"
            if item.get("file_size"):
                text += f" {item['file_size']} bytes"
        elif kind == "video_channel":
            text = f"[视频号] {item.get('publisher') or ''} {text}".strip()
        elif kind in {"image", "voice", "video", "sticker", "location"}:
            text = text or f"[{kind}]"
        if fmt == "md":
            lines.append(f"- **{item.get('time')} · {item.get('sender')}**：{text}")
        else:
            lines.append(f"[{item.get('time')}] {item.get('sender')}: {text}")
    return "\n".join(lines).strip() + "\n"


def _format_media_export(payload: dict[str, Any], fmt: str) -> str:
    if fmt == "json":
        return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    lines = [
        f"# {payload['chat']['name']} ({payload['chat']['username']})",
        "",
        (
            f"Matched: {payload['total']} | Exported: {payload['exported']} | "
            f"Missing: {payload['missing']}"
        ),
        "",
    ]
    for item in payload["items"]:
        title = item.get("title") or item.get("md5") or "(untitled)"
        if item["status"] == "exported":
            lines.append(
                f"- {item['time']} · {item['sender']} · {item['kind']} · "
                f"{title} -> {item['output_path']}"
            )
        else:
            error = item.get("error") or item["status"]
            lines.append(
                f"- {item['time']} · {item['sender']} · {item['kind']} · "
                f"{title} [FAILED: {error}]"
            )
            if item.get("source_path"):
                lines.append(f"  Source: {item['source_path']}")
    return "\n".join(lines).strip() + "\n"


def _output(payload: Any, *, compact: bool = False) -> None:
    sys.stdout.reconfigure(encoding="utf-8")
    if isinstance(payload, str):
        sys.stdout.write(payload)
        return
    sys.stdout.write(
        json.dumps(
            payload,
            ensure_ascii=False,
            indent=None if compact else 2,
            separators=(",", ":") if compact else None,
        )
        + "\n"
    )


def _common_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument(
        "--data-dir",
        help="Directory containing account_keys.json and databases/ (default: ./output or WCHAT_DATA_DIR)",
    )
    parser.add_argument("--account", help="Account directory name / wxid")
    parser.add_argument("--cache-dir", help="Decrypted DB cache root")
    parser.add_argument("--key", help="64-hex database key (overrides account_keys.json)")
    parser.add_argument("--refresh", action="store_true", help="Force re-decryption")
    parser.add_argument("--compact", action="store_true", help="Compact JSON output")
    return parser


def build_parser() -> argparse.ArgumentParser:
    common = _common_parser()
    parser = argparse.ArgumentParser(
        prog="wchat-core",
        description="Read-only WeChat 4.x local database decryption and chat reader.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    accounts = sub.add_parser("accounts", parents=[common], help="List accounts")
    accounts.set_defaults(handler=_cmd_accounts)

    decrypt = sub.add_parser("decrypt", parents=[common], help="Decrypt contact/session/message DBs")
    decrypt.set_defaults(handler=_cmd_decrypt)

    sessions = sub.add_parser("sessions", parents=[common], help="List / search sessions")
    sessions.add_argument("--query", default="", help="Filter by display name or username")
    sessions.add_argument("--limit", type=int, default=200)
    sessions.set_defaults(handler=_cmd_sessions)

    messages = sub.add_parser("messages", parents=[common], help="Read messages")
    messages.add_argument("--chat", required=True, help="Chat display name or username")
    messages.add_argument("--date", default="today", help="today | YYYY-MM-DD | all")
    messages.add_argument("--start", help="Start date/time (ISO)")
    messages.add_argument("--end", help="End date/time (ISO)")
    messages.add_argument("--days", type=int, help="Include the last N days")
    messages.add_argument("--limit", type=int, default=200)
    messages.add_argument("--offset", type=int, default=0)
    messages.add_argument("--format", choices=("json", "md", "txt"), default="json")
    messages.add_argument("--include-raw", action="store_true")
    messages.set_defaults(handler=_cmd_messages)

    media = sub.add_parser(
        "media",
        parents=[common],
        help="Export original image and file attachments",
    )
    media.add_argument("--chat", required=True, help="Chat display name or username")
    media.add_argument("--date", default="today", help="today | YYYY-MM-DD | all")
    media.add_argument("--start", help="Start date/time (ISO)")
    media.add_argument("--end", help="End date/time (ISO)")
    media.add_argument("--days", type=int, help="Include the last N days")
    media.add_argument(
        "--kind",
        choices=("all", "image", "file"),
        default="all",
        help="Attachment type to export",
    )
    media.add_argument(
        "--output-dir",
        required=True,
        help="Destination directory for images/ and files/",
    )
    media.add_argument(
        "--overwrite",
        action="store_true",
        help="Replace an existing destination file instead of creating a numbered copy",
    )
    media.add_argument(
        "--include-source-paths",
        action="store_true",
        help="Include local source paths in JSON/text output",
    )
    media.add_argument(
        "--no-auto-image-key",
        action="store_true",
        help="Do not derive a verified image key from the local kvcomm cache",
    )
    media.add_argument("--format", choices=("json", "md", "txt"), default="json")
    media.set_defaults(handler=_cmd_media)

    contacts = sub.add_parser("contacts", parents=[common], help="List / search contacts")
    contacts.add_argument("--query", default="")
    contacts.add_argument("--limit", type=int, default=200)
    contacts.set_defaults(handler=_cmd_contacts)

    members = sub.add_parser("group-members", parents=[common], help="List group members")
    members.add_argument("--chat", required=True, help="Group display name or username")
    members.set_defaults(handler=_cmd_group_members)
    return parser


def _prepare(args: argparse.Namespace) -> tuple[Path, str, CacheInfo]:
    data_dir = resolve_data_dir(args.data_dir)
    account = resolve_account(data_dir, args.account)
    cache = ensure_cache(
        data_dir,
        account,
        cache_root=args.cache_dir,
        refresh=args.refresh,
        key_override=args.key,
    )
    return data_dir, account, cache


def _cmd_accounts(args: argparse.Namespace) -> None:
    data_dir = resolve_data_dir(args.data_dir)
    keys = load_key_store(data_dir)
    result = []
    for account in list_accounts(data_dir):
        key_item = keys.get(account) if isinstance(keys.get(account), dict) else {}
        storage = source_storage(data_dir, account)
        folder = account_dir(data_dir, account)
        result.append(
            {
                "account": account,
                "has_key": bool(str((key_item or {}).get("db_key") or "").strip()),
                "source_storage": str(storage) if storage else "",
                "decrypted_databases": len(list(folder.glob("*.db"))) if folder.is_dir() else 0,
            }
        )
    _output({"data_dir": str(data_dir), "accounts": result}, compact=args.compact)


def _cmd_decrypt(args: argparse.Namespace) -> None:
    data_dir, account, cache = _prepare(args)
    _output(
        {
            "account": account,
            "source": cache.source,
            "source_storage": str(cache.source_storage or ""),
            "cache_dir": str(cache.cache_dir),
            "contact_db": str(cache.contact_db or ""),
            "session_db": str(cache.session_db or ""),
            "message_dbs": [str(path) for path in cache.message_dbs],
        },
        compact=args.compact,
    )


def _cmd_sessions(args: argparse.Namespace) -> None:
    _, account, cache = _prepare(args)
    contacts = load_contact_map(cache.contact_db) if cache.contact_db else {}
    sessions = _load_sessions(cache, contacts)
    query = str(args.query or "").strip().casefold()
    if query:
        sessions = [
            item
            for item in sessions
            if query in str(item["name"]).casefold()
            or query in str(item["username"]).casefold()
            or query in str(item.get("remark") or "").casefold()
        ]
    total = len(sessions)
    sessions = sessions[: max(0, int(args.limit))]
    _output(
        {"account": account, "total": total, "sessions": sessions},
        compact=args.compact,
    )


def _cmd_messages(args: argparse.Namespace) -> None:
    _, account, cache = _prepare(args)
    contacts = load_contact_map(cache.contact_db) if cache.contact_db else {}
    sessions = _load_sessions(cache, contacts)
    chat = _match_chat(sessions, contacts, args.chat)
    start, end = _date_bounds(args)
    messages = _read_messages(
        cache,
        chat["username"],
        start=start,
        end=end,
        include_raw=args.include_raw,
    )
    total = len(messages)
    offset = max(0, int(args.offset))
    limit = max(0, int(args.limit))
    page = messages[offset : offset + limit] if limit else messages[offset:]
    if args.format != "json":
        _output(_format_messages(page, args.format, chat))
        return
    _output(
        {
            "account": account,
            "chat": chat,
            "start": _iso(start, _local_tz()) if start is not None else "",
            "end": _iso(end - 1, _local_tz()) if end is not None else "",
            "total": total,
            "offset": offset,
            "messages": page,
        },
        compact=args.compact,
    )


def _cmd_media(args: argparse.Namespace) -> None:
    data_dir, account, cache = _prepare(args)
    contacts = load_contact_map(cache.contact_db) if cache.contact_db else {}
    sessions = _load_sessions(cache, contacts)
    chat = _match_chat(sessions, contacts, args.chat)
    start, end = _date_bounds(args)
    messages = _read_messages(
        cache,
        chat["username"],
        start=start,
        end=end,
        include_raw=False,
    )
    wanted = {"image", "file"} if args.kind == "all" else {str(args.kind)}
    matched = [
        item
        for item in messages
        if str(item.get("kind") or "") in wanted
    ]

    snapshot_account_dir = account_dir(data_dir, account)
    account_metadata_dir = cache.cache_dir
    source_root = (
        cache.source_storage.parent if cache.source_storage is not None else None
    )
    keys = resolve_media_keys(
        account_metadata_dir,
        source_root,
        data_dir=data_dir,
        account=account,
        auto_resolve_image=(
            "image" in wanted and not bool(args.no_auto_image_key)
        ),
        fallback_account_dir=snapshot_account_dir,
    )
    output_dir = Path(args.output_dir).expanduser()
    exported = 0
    missing = 0
    results: list[dict[str, Any]] = []
    for item in matched:
        refs = item.get("media")
        media_ref = refs if isinstance(refs, dict) else {}
        result = export_media_source(
            account_metadata_dir,
            source_root,
            kind=str(item.get("kind") or ""),
            username=chat["username"],
            md5=str(media_ref.get("md5") or ""),
            title=str(item.get("title") or item.get("text") or ""),
            timestamp=int(item.get("timestamp") or 0),
            output_dir=output_dir,
            keys=keys,
            overwrite=bool(args.overwrite),
        )
        if result.status == "exported":
            exported += 1
        else:
            missing += 1
        entry = {
            "message_id": item.get("local_id"),
            "timestamp": item.get("timestamp"),
            "time": item.get("time"),
            "sender": item.get("sender"),
            "kind": item.get("kind"),
            "title": item.get("title") or "",
            "md5": media_ref.get("md5") or "",
            "file_id": media_ref.get("file_id") or "",
            "status": result.status,
            "error": result.error,
            "output_path": str(result.output_path or ""),
            "source_path": (
                str(result.source_path or "")
                if args.include_source_paths
                else ""
            ),
        }
        results.append(entry)

    payload = {
        "account": account,
        "chat": chat,
        "start": _iso(start, _local_tz()) if start is not None else "",
        "end": _iso(end - 1, _local_tz()) if end is not None else "",
        "output_dir": str(output_dir.resolve()),
        "total": len(matched),
        "exported": exported,
        "missing": missing,
        "items": results,
    }
    if args.format == "json":
        _output(payload, compact=args.compact)
    else:
        _output(_format_media_export(payload, args.format))


def _cmd_contacts(args: argparse.Namespace) -> None:
    _, account, cache = _prepare(args)
    contacts = list(load_contact_map(cache.contact_db).values()) if cache.contact_db else []
    query = str(args.query or "").strip().casefold()
    if query:
        contacts = [
            item
            for item in contacts
            if query in str(item.get("display_name") or "").casefold()
            or query in str(item.get("username") or "").casefold()
            or query in str(item.get("remark") or "").casefold()
            or query in str(item.get("nick_name") or "").casefold()
            or query in str(item.get("alias") or "").casefold()
        ]
    contacts.sort(key=lambda item: str(item.get("display_name") or ""))
    total = len(contacts)
    _output(
        {
            "account": account,
            "total": total,
            "contacts": contacts[: max(0, int(args.limit))],
        },
        compact=args.compact,
    )


def _cmd_group_members(args: argparse.Namespace) -> None:
    _, account, cache = _prepare(args)
    contacts = load_contact_map(cache.contact_db) if cache.contact_db else {}
    sessions = _load_sessions(cache, contacts)
    chat = _match_chat(sessions, contacts, args.chat)
    if not chat["username"].endswith("@chatroom"):
        raise SystemExit(f"Not a group chat: {chat['name']}")
    members = load_group_members(cache.contact_db, chat["username"]) if cache.contact_db else []
    _output(
        {"account": account, "chat": chat, "total": len(members), "members": members},
        compact=args.compact,
    )


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args: argparse.Namespace | None = None
    try:
        args = parser.parse_args(argv)
        args.handler(args)
        return 0
    except SystemExit as exc:
        code = exc.code
        if code in (0, None):
            return 0
        _output(
            {"error": str(code)},
            compact=bool(getattr(args, "compact", False)),
        )
        return 1
    except Exception as exc:
        _output(
            {"error": str(exc)},
            compact=bool(getattr(args, "compact", False)),
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
