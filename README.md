# Kiln IDA — an MCP server inside IDA Pro 9.1

`kiln_ida.py` is a native IDA Pro plugin that exposes the open database to AI over the
[Model Context Protocol](https://modelcontextprotocol.io) (Streamable HTTP). It was written for
[Kiln](https://github.com/TechMecca/kiln-releases), where `/ida` attaches one or more running IDA
sessions to a chat and the model works on the real database: functions, pseudocode, assembly,
cross-references, imports, exports, strings, segments, names, types, stack frames, memory, the
debugger, navigation — and, with your permission per call, renames, comments, types, new functions,
patches and IDAPython.

Any MCP client that speaks Streamable HTTP can use it; the session file (below) has the URL and key.

- IDA Pro **9.1** (SDK 910) with IDAPython on Python 3.10+. Hex-Rays is optional (`decompile` and
  `rename_local_variable` need it).
- Standard library only — nothing to `pip install`.
- Windows is what it is tested on. The code has no Windows-only parts except the process-liveness
  check, which falls back to `os.kill(pid, 0)` elsewhere.

## Install

1. Copy `kiln_ida.py` into your IDA user plugin folder:
   - Windows: `%APPDATA%\Hex-Rays\IDA Pro\plugins\`
   - Linux / macOS: `~/.idapro/plugins/`

   Kiln can do this for you: **Settings → Capabilities → IDA Pro → Install plugin into IDA** (the
   `/ida` dialog has the same button). Updating is the same copy; restart IDA after either.
2. Start IDA and open a database. The server starts on its own (autostart is on by default) and
   the Output window shows:

   ```
   [Kiln IDA] server ON — session 50a47088 at http://127.0.0.1:24137/mcp (33 tools, Hex-Rays yes)
   ```

3. In Kiln, type `/ida` in any chat, tick the session, Done. The chip above the composer shows
   what is attached.

## Controls in IDA

| Where | What |
|---|---|
| **Edit → Plugins → Kiln IDA → Start / Stop server** | Enable / disable. Also **Ctrl-Alt-K**. |
| **… → Status…** | Session id, URL, uptime, calls served, errors, whether Hex-Rays is available. |
| **… → Copy session id** | Puts the id on the clipboard (handy with `/ida <id>`). |
| **… → Start automatically when a database opens** | Toggle autostart (saved in `%APPDATA%\Kiln\ida\plugin.json`). |

The Output window logs every start/stop, each modifying call, and errors. The same lines go to
`%APPDATA%\Kiln\ida\plugin.log` (2 MB, one rotation).

Every IDA instance gets its **own session**: a random 8-hex-digit id, its own port (24137 upward,
first free of 100) and its own secret key. Closing the database or IDA stops the server and removes
the session file. Opening another database in the same IDA starts a fresh session.

## How Kiln finds it — the session file

While the server is on, the plugin keeps `%APPDATA%\Kiln\ida\sessions\<id>.json`:

```json
{
  "id": "50a47088", "plugin": "kiln-ida", "version": "0.1.0",
  "name": "whoami.exe", "binary": "whoami.exe",
  "input_path": "C:\\dumps\\whoami.exe", "idb_path": "C:\\dumps\\whoami.exe.i64",
  "pid": 10216, "host": "127.0.0.1", "port": 24137, "url": "http://127.0.0.1:24137/mcp",
  "token": "…secret…", "ida_version": "9.1", "sdk": 910, "python": "3.10.5",
  "hexrays": true, "processor": "metapc", "bits": 64, "gui": true,
  "started_at": "2026-10-13T10:00:00Z", "tools": 33
}
```

Kiln watches that folder, drops files whose `pid` is gone, pings `/health` every 15 s, and shows
each session's name, id, database, pid, IDA version, Hex-Rays and status (connected / not answering
/ gone). A chat remembers its sessions by id **and** database path, so an IDA you restart (new id,
new port) is picked up again without re-attaching.

## Security

- Binds **127.0.0.1 only**. Never reachable from the network.
- Every request must carry the session's key: `Authorization: Bearer <token>`. Requests without it
  get **401**, including `/health`.
- Requests with an `Origin` header (a browser page) are refused with **403**, as are non-local
  `Host` values. This blocks DNS-rebinding and drive-by pages.
- The key lives only in the session file (your user profile) and is rotated every start.
- `GET /mcp` is **405** — no server-initiated streams, so nothing can be pushed to a client.

## Transport

MCP **Streamable HTTP**, JSON-RPC 2.0 over `POST /mcp`:

| Method | Behaviour |
|---|---|
| `initialize` | Protocol versions `2025-06-18`, `2025-03-26`, `2024-11-05`; returns a `Mcp-Session-Id` header. Capabilities: `tools` only. |
| `ping`, `tools/list`, `tools/call` | As specified. `resources/list` and `prompts/list` return empty lists. |
| notifications | `202 Accepted`, no body. Batches (JSON arrays) are accepted. |
| `GET /mcp` | `405` (no SSE stream). `DELETE /mcp` → `204`. |
| `GET /health` | `{ ok, session, binary, pid, calls, busy }` — needs the key. |

Tool results are `content: [{ type: "text", text: <JSON> }]`; failures are `isError: true` with a
one-line message (`No function at 0x401000`, `Hex-Rays decompiler is not available in this IDA`,
`Couldn't parse the pattern`, …). Every tool carries MCP annotations: `readOnlyHint`,
`destructiveHint`, `title`.

## Execution model

- The HTTP server runs on a **daemon thread**; every IDA API call is marshalled to IDA's main thread
  with `execute_sync` (`MFF_READ` for read-only tools, `MFF_WRITE` for modifying ones). The UI never
  runs IDA calls concurrently with you or with another tool.
- One tool runs at a time (a lock); parallel requests queue. `/health` reports `busy` with the name
  of the running tool.
- Lists are **paged** (`offset`, `limit`, `total`, `next_offset`). `list_strings` caches the string
  list for 5 minutes (`refresh=true` rebuilds it). `search_text` stops after `limit` hits or 20 s.
- Addresses accept an int, hex (`0x401000` / `401000h`), or a name (mangled or demangled).

## Tools

Read-only (21) — Kiln runs these without asking, except in Manual mode:

| Tool | Arguments | What it returns |
|---|---|---|
| `get_database_info` | — | binary, database file, processor, bitness, image base, entry point, range, function/segment counts, Hex-Rays, analysis done, debugger on |
| `list_segments` | — | name, class, start, end, size, permissions, bitness |
| `list_functions` | `filter?`, `regex?`, `offset?`, `limit?` | address, name, size — paged |
| `get_function` | `address` | bounds, size, name, prototype, comments, chunks, callers count, frame size, library / thunk / no-return |
| `decompile` | `address` | Hex-Rays pseudocode of the function |
| `disassemble` | `address`, `count?`, `max_lines?` | the whole function, or `count` instructions from an address |
| `get_xrefs_to` | `address`, `offset?`, `limit?` | who calls / jumps to / reads / writes it |
| `get_xrefs_from` | `address`, `whole_function?`, `offset?`, `limit?` | what it calls, jumps to, reads, writes |
| `list_imports` | `filter?`, `offset?`, `limit?` | module, name, address, ordinal |
| `list_exports` | `offset?`, `limit?` | name, address, ordinal |
| `list_strings` | `filter?`, `min_length?`, `refresh?`, `offset?`, `limit?` | address, length, type, text |
| `search_names` | `query`, `regex?`, `offset?`, `limit?` | names containing text / matching a regex, with demangled form |
| `read_bytes` | `address`, `size?`, `debugger?` | hex + printable ASCII, up to 64 KB, from the database or the live process |
| `search_bytes` | `pattern`, `start?`, `end?`, `limit?` | addresses of a hex pattern (`??` wildcards) and their functions |
| `search_text` | `text`, `case_sensitive?`, `start?`, `limit?` | disassembly lines containing text |
| `list_types` | `filter?`, `offset?`, `limit?` | local types: ordinal, name, kind, size |
| `get_type` | `name?`, `ordinal?` | a type's full C definition |
| `get_stack_frame` | `address` | a function's frame: variables / arguments with offset, size, type |
| `get_cursor` | — | the address under the user's cursor and its function |
| `get_debugger_state` | — | debugging?, state, threads, current registers |
| `jump_to` | `address` | moves IDA's view (changes nothing) |

Modifying (12) — Kiln asks you before each one (except in Bypass mode); Plan mode never offers them:

| Tool | Arguments | Effect |
|---|---|---|
| `set_name` | `address`, `name` | rename a function / label / global (empty = remove) |
| `set_comment` | `address`, `comment`, `repeatable?` | instruction / data comment |
| `set_function_comment` | `address`, `comment`, `repeatable?` | the comment at the top of a function |
| `set_type` | `address`, `declaration` | apply a prototype or a variable type |
| `declare_types` | `declarations` | add / replace structs, unions, enums, typedefs |
| `rename_local_variable` | `function`, `old_name`, `new_name` | rename a pseudocode local (Hex-Rays) |
| `create_function` | `address` | like pressing **P** |
| `undefine` ⚠ | `address`, `size?` | like pressing **U** — destructive |
| `patch_bytes` ⚠ | `address`, `hex` | patch the database (IDA keeps the originals for *Apply patches*) — destructive |
| `wait_for_analysis` | — | block until auto-analysis finishes |
| `save_database` | — | save the IDB |
| `run_python` ⚠ | `code` | run IDAPython in IDA and return stdout / the result — anything the API can do |

⚠ = `destructiveHint`; Kiln's approval card says so.

## Testing

`tests/live_test.py` is a plain-Python MCP client (urllib, no dependencies). With IDA open and the
server on:

```bash
set PYTHONIOENCODING=utf-8
python tests/live_test.py
```

It reads the newest session file and runs 50 checks: security (401 / 403 / 405), `/health`,
`initialize`, notifications → 202, `tools/list`, every read-only tool, each modifying tool followed
by its undo, and 6 concurrent calls. Last run against IDA 9.1 + Hex-Rays on `whoami.exe`:
**50 passed, 0 failed**.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Nothing in `Edit → Plugins` | The file isn't in the plugin folder, or IDAPython failed to load it: check the Output window at startup for a traceback. |
| `server OFF` / `/ida` shows **not answering** | The server was stopped (toggle it back on, Ctrl-Alt-K) or IDA is modal (a dialog is open) and can't service calls. |
| `/ida` shows **gone** | That IDA process has exited; the chat keeps the attachment and reconnects when the same database is opened again. |
| Port in use | The plugin scans 24137…24236. To start elsewhere set `"port"` in `%APPDATA%\Kiln\ida\plugin.json`. |
| `Hex-Rays decompiler is not available` | No decompiler licence for this processor; `disassemble` still works. |
| A call takes long and IDA's UI freezes | Big `list_strings` / `search_text` on a large database run on IDA's main thread — that is required by the IDA API. They are bounded (cache, 20 s limit) but not interruptible. |
| `401` from a script | Send `Authorization: Bearer <token>` from the session file — every endpoint needs it. |
| Headless `idat -S` | Cross-thread `execute_sync` is only serviced by the GUI event loop; the server needs the IDA GUI (`ida.exe`). |

## Limitations

- IDA 9.x API only (no 7.x / 8.x compatibility layer).
- No plugin-side per-call timeout: a tool runs to completion on the main thread. Kiln times a call
  out after 10 minutes on its side.
- `read_bytes` with `debugger=true` needs a suspended debuggee.
- One session per IDA instance — one database at a time, as in IDA itself.
