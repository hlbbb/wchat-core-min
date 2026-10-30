---
name: wchat-core
description: Read-only WeChat 4.x local database CLI for AI agents. Use when the user asks to read WeChat chat history, search chats/contacts/group members, or export original image and file attachments from locally synced WeChat data. Triggers include 微信聊天记录, 读取微信消息, 查聊天记录, 微信群成员, 导出微信图片, 导出微信文件, wechat-core, wchat-core. Runs fully offline against the user's own WeChat data directory; never sends chat content anywhere.
---

# wchat-core

Read-only CLI over locally synced WeChat 4.x databases. It decrypts SQLCipher
databases into a cache, then answers queries as JSON. It never writes to WeChat
itself and never touches the network.

## Hard rules

- Only operate on the user's own WeChat data, on their machine, at their request.
- Never upload, paste, or forward chat content, exported attachments, keys, or
  cache paths to any external service, repo, or report. Summarize locally.
- Treat `account_keys.json`, `_media_keys.json`, `--key`, and `WCHAT_DB_KEY` as
  secrets. Never print their values.
- The decrypted cache contains plaintext chat data. Prefer `--cache-dir` to keep
  it in a user-chosen folder instead of the shared temp directory.

## Setup

Requires Python 3.11+.

```powershell
pip install wchat-core-min            # from the release wheel or zip
python -m wchat_core accounts --data-dir "C:\...\output"
```

`--data-dir` must contain `account_keys.json` and `databases/<wxid>/`. The CLI
falls back to `./output`, `./data`, or the `WCHAT_DATA_DIR` environment variable
when the flag is omitted.

## Commands

All commands print JSON by default (`--compact` for one-line JSON) and print
`{"error": "..."}` on failure. Shared flags: `--data-dir`, `--account`,
`--cache-dir`, `--key`, `--refresh`, `--compact`.

- `accounts` — list accounts and whether a key exists.
- `sessions --query TEXT --limit N` — search chats by name/username/remark.
  Returns `username` (stable ID), `name`, `is_group`, `last_time`.
- `messages --chat NAME_OR_ID [--date today|YYYY-MM-DD|all] [--days N]
  [--start ISO --end ISO] [--limit N --offset M] [--format json|md|txt]
  [--include-raw]` — read one chat's messages.
- `media --chat NAME_OR_ID --output-dir DIR [--kind all|image|file]`
  (same date flags) — export original attachments into `<DIR>/images/` and
  `<DIR>/files/`. Add `--include-source-paths` only when the user needs them.
- `contacts --query TEXT` and `group-members --chat GROUP` — contact lookup.
- `decrypt` — force-refresh the decrypted cache, then print cache paths.

Chat matching: exact name/username first, then substring. Ambiguous matches fail
with a candidate list — retry with the exact `username` (e.g. `wxid_...` or
`12345678@chatroom`) from `sessions`.

## Typical flow

```powershell
# 1. Which account?
python -m wchat_core accounts --data-dir "C:\...\output"

# 2. Find the chat (use the returned username if the name is ambiguous)
python -m wchat_core sessions --data-dir "C:\...\output" --query 关键词 --compact

# 3. Read today's messages (page with --limit/--offset for long chats)
python -m wchat_core messages --data-dir "C:\...\output" --chat NAME --date today --limit 200

# 4. Export today's images and files
python -m wchat_core media --data-dir "C:\...\output" --chat NAME --date today --output-dir "D:\exports\chat"
```

WeChat writes new data continuously. If results look stale, rerun with
`--refresh` to re-decrypt the latest databases and WAL.

## Media export results

Each item in the JSON has a `status`:

- `exported` — done; `output_path` is the exported file.
- `missing` — attachment was cleaned up by WeChat; not recoverable.
- `missing-key` — encrypted image found but no verified key; the CLI derives a
  key from the local `kvcomm` cache automatically. Disable with
  `--no-auto-image-key`. `wxgf` images convert to JPEG when `ffmpeg` is found
  (set `WCHAT_FFMPEG` to point at a specific binary).

## Known limits

- Reads only what desktop WeChat has synced locally; cloud-only or deleted
  messages are unavailable.
- Voice/video/sticker messages are metadata placeholders, not exported media.
- Group name matching can be ambiguous; prefer the `username`.
- Timestamps use the local timezone of the machine running the CLI.
