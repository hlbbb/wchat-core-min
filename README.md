# wchat-core-min

微信 4.x 本地数据库的**只读核心**，面向 AI / 脚本调用：

- 数据库解密（SQLCipher 4，包含 WAL 增量合并）
- 单聊 / 群聊会话与消息读取
- 联系人解析、群成员与群昵称解析
- 文本、文件卡片、链接、视频号、引用等常见消息解析

不包含：Electron UI、前端、年度总结、朋友圈、收藏、语音转文字、AI 助手、MCP、遥测、任何聊天记录或密钥。

## 安装

```powershell
cd C:\Users\Zyz\Documents\projects\wechat-core-min
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
```

只需要 Python 3.11+ 和两个依赖：`cryptography`、`zstandard`。

## 数据目录

`--data-dir` 指向主程序输出的目录，结构如下：

```text
output/
  account_keys.json
  databases/
    wxid_xxx/
      _source.json          # 含 db_storage_path，指向微信原始加密数据库
      contact.db            # 可选：已有的解密快照
      session.db
      message_0.db
```

也可以不传 `--data-dir`，程序会依次尝试 `./output`、`./data`，或读取环境变量 `WCHAT_DATA_DIR`。

## 常用命令

所有命令默认输出 JSON，适合 AI 直接解析。

```powershell
# 1. 查看账号
python -m wchat_core accounts --data-dir "C:\...\output"

# 2. 搜索会话
python -m wchat_core sessions --data-dir "C:\...\output" --query 示例联系人

# 3. 读取今天某个群/联系人的消息
python -m wchat_core messages --data-dir "C:\...\output" --chat "示例群" --date today

# 4. 读取指定日期
python -m wchat_core messages --data-dir "C:\...\output" --chat "示例联系人" --date 2026-10-30

# 5. 搜索联系人
python -m wchat_core contacts --data-dir "C:\...\output" --query 示例联系人

# 6. 查看群成员和群昵称
python -m wchat_core group-members --data-dir "C:\...\output" --chat "示例群"

# 7. 强制重新解密（微信有新消息 / WAL 更新后）
python -m wchat_core messages --data-dir "C:\...\output" --chat "示例群" --date today --refresh

# 8. 导出某个会话的图片和文件原件
python -m wchat_core media --data-dir "C:\...\output" --chat "示例联系人" --date all --output-dir ".\exports\attachments"

# 只导出文件原件
python -m wchat_core media --data-dir "C:\...\output" --chat "示例联系人" --date all --kind file --output-dir ".\exports\attachments"
```

### 日期范围

```powershell
--date today
--date 2026-10-30
--days 7
--start 2026-10-01 --end 2026-10-30
--date all
```

### 图片和文件原件

`media` 命令会从微信本地数据目录定位消息对应的附件：

- 图片：优先使用已解密资源，其次通过 `hardlink.db` 和 `msg/attach` 定位 `.dat` 文件。
- 文件：通过 `hardlink.db` 和 `msg/file` 定位原始文件，未加密文件直接复制。
- 微信 V1/V2 加密 `.dat` 会优先读取账号目录中的 `_media_keys.json`。
- 图片密钥缺失时，会从本机微信 `kvcomm` 缓存和 V2 图片模板推导并验证密钥；不会输出未验证的猜测。
- `wxgf` 原图会在找到 `ffmpeg` 时转为 JPEG；可通过 `WCHAT_FFMPEG` 指定可执行文件，缺少时回退到本地 JPEG 缩略图。
- 输出分别写入 `<output-dir>/images/` 和 `<output-dir>/files/`。

如果本机没有可验证的图片密钥，图片仍能定位到源文件，但会返回 `missing-key`；不会输出未解密的伪图片。可使用 `--no-auto-image-key` 关闭自动推导。附件已被微信清理时返回 `missing`。

### 输出格式

```powershell
--format json   # 默认，AI 推荐
--format md
--format txt
--compact       # 单行 JSON
--limit 500 --offset 0
```

## JSON 示例

`messages` 的主要字段：

```json
{
  "account": "wxid_xxx",
  "chat": {
    "username": "12345678@chatroom",
    "name": "示例群",
    "is_group": true
  },
  "start": "2026-10-30T00:00:00+08:00",
  "end": "2026-10-30T23:59:59+08:00",
  "total": 2,
  "messages": [
    {
      "time": "2026-10-30T17:49:45+08:00",
      "timestamp": 1793346585,
      "sender": "好名字",
      "sender_username": "wxid_xxx",
      "kind": "text",
      "text": "..."
    }
  ]
}
```

文件卡片会带 `title`、`file_ext`、`file_size`；视频号会带 `publisher`、`duration_seconds`、`description`；链接会带 `url`。

## 解密与缓存

- 源数据库始终只读，解密结果写入缓存目录。
- 默认缓存：`%TEMP%\wchat-core-cache\<account>`。
- 可指定：`--cache-dir "D:\wchat-cache"`。
- 默认按源 DB/WAL 的修改时间自动判断是否需要重新解密；`--refresh` 强制刷新。
- 如果 `_source.json` 不存在，会退回到 `databases/<account>/` 中已有的解密快照。

## 密钥

- 默认从 `account_keys.json` 读取 `db_key`。
- 也可以用 `--key` 或环境变量 `WCHAT_DB_KEY` 传入 64 位十六进制密钥。
- 密钥不要写进代码、README 或聊天记录。

## 作为库调用

```python
from pathlib import Path
from wchat_core.store import resolve_data_dir, resolve_account, ensure_cache

data_dir = resolve_data_dir(r"C:\...\output")
account = resolve_account(data_dir)
cache = ensure_cache(data_dir, account)
print(cache.cache_dir)
```

## Agent skill

`skills/wchat-core/SKILL.md` 是面向 AI agent 的调用说明（Codex/Claude 等技能格式）。
把它复制到你的技能目录即可让 agent 自动发现并正确调用本 CLI：

```powershell
Copy-Item -Recurse skills\wchat-core "$env:USERPROFILE\.codex\skills\wchat-core"
```

技能文档包含触发条件、命令参考、典型流程、密钥与隐私规则，不包含任何聊天数据。

## 边界

当前版本只做只读解析：

- 图片和文件原件通过 `media` 命令显式导出；语音、视频只返回类型和元数据。
- 不支持朋友圈、收藏、小程序、视频号直播、服务号、转账红包等扩展导出。
- 不发送消息、不修改微信数据，不访问网络。
