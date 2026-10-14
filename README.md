# Kiln IDA — an MCP server inside IDA Pro 9.1

`kiln_ida.py` is a native IDA Pro plugin that exposes the open database to AI over the
[Model Context Protocol](https://modelcontextprotocol.io) (Streamable HTTP). It was written for
[Kiln](https://github.com/TechMecca/kiln-releases), where `/ida` attaches one or more running IDA
sessions to a chat and the model works on the real database: functions, pseudocode, assembly,
cross-references, callers and callees, imports, exports, strings, segments, names, types, data,
stack frames, memory, bookmarks, the debugger, navigation — and, with your permission per call,
renames, comments, types, local variables, calling conventions, new functions, patches, breakpoints,
running / stepping the program, and IDAPython. It can also **push debugger events** so a client watches a
session and reviews each stop (Kiln's `/ida` → *review stops*).

Any MCP client that speaks Streamable HTTP can use it; the session file (below) has the URL and key.

- IDA Pro **9.1** (SDK 910) with IDAPython on Python 3.10+. Hex-Rays is optional (`decompile`,
  `decompile_many`, `get_pseudocode_lines`, `rename_local_variable`, `set_lvar_type`,
  `set_lvar_comment` need it).
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
   [Kiln IDA] server ON — session 50a47088 at http://127.0.0.1:24137/mcp (65 tools, Hex-Rays yes)
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
  "id": "50a47088", "plugin": "kiln-ida", "version": "0.5.1",
  "name": "whoami.exe", "binary": "whoami.exe",
  "input_path": "C:\\dumps\\whoami.exe", "idb_path": "C:\\dumps\\whoami.exe.i64",
  "pid": 10216, "host": "127.0.0.1", "port": 24137, "url": "http://127.0.0.1:24137/mcp",
  "token": "…secret…", "ida_version": "9.1", "sdk": 910, "python": "3.10.5",
  "hexrays": true, "processor": "metapc", "bits": 64, "gui": true,
  "started_at": "2026-10-13T10:00:00Z", "tools": 65
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
| `GET /health` | `{ ok, session, binary, pid, calls, busy, events_seq }` — needs the key. |

Tool results are `content: [{ type: "text", text: <JSON> }]` (and the same object as
`structuredContent`); failures are `isError: true` with a one-line message (`No function at
0x401000`, `Hex-Rays decompiler is not available in this IDA`, `Couldn't parse the pattern`, …).
Every tool carries MCP annotations: `readOnlyHint`, `destructiveHint`, `title`. Schemas are strict
(`additionalProperties: false`); an argument a model invents (`"action": "search_names"` is a
favourite) is dropped, the call still runs, and the result lists it under `ignored_arguments`.

## Execution model

- The HTTP server runs on a **daemon thread**; every IDA API call is marshalled to IDA's main thread
  with `execute_sync` (`MFF_READ` for read-only tools, `MFF_WRITE` for modifying ones). The UI never
  runs IDA calls concurrently with you or with another tool.
- One tool runs at a time (a lock); parallel requests queue. `/health` reports `busy` with the name
  of the running tool.
- **Chunked tools** (`search_text`, `search_bytes`, `decompile_many`, `find_similar_functions`) run on
  the server thread and send *windows* of work to the main thread (3000 items, 4 MB, one function,
  300 functions), so IDA's UI breathes between windows and you can keep working. They take
  `budget_ms` (default 20 s; 60 s for `decompile_many`): when it runs out they return what they
  have with `truncated: true` and `resume_from` / `remaining` so the next call continues.
- Lists are **paged** (`offset`, `limit`, `total`, `next_offset`). `list_strings` caches the string
  list for 5 minutes (`refresh=true` rebuilds it).
- Addresses accept an int, hex (`0x401000` / `401000h`), or a name (mangled or demangled).

## Breakpoints are hardware only

`set_breakpoint` uses the CPU's debug registers (`kind=exec` by default, or `write` / `read` / `access` to watch
data). Not one byte of the program is modified, so code that checksums itself sees nothing. Software `0xCC`
breakpoints are deliberately **not** offered: they patch the instruction and any self-check can spot them. The
trade-off is that x86 has only four debug registers, so delete breakpoints you have finished with.

A breakpoint stops the whole process when it is hit — every thread. To watch a hot function without freezing the
target, give the breakpoint an IDC `condition` that does its logging and then evaluates false: IDA resumes on its
own. Note that such a breakpoint produces no stop, so nothing appears in the live card or the review.

## Tracing: getting information without stopping

A breakpoint stops the program. To watch something busy without freezing it, make the breakpoint **non-suspending**
with `set_breakpoint(..., suspend=false)`: IDA records each hit in the trace and lets the program run straight on.
Call `trace_start` first, then read the hits back whenever you like with `read_trace`. This is the way to watch a hot
function on an interactive target — the client never pauses, so it cannot time out or disconnect while you think.

`trace_start` also offers two heavier modes. `function` records every call and return, so a short burst tells you
what a function actually does at runtime; `instruction` records every instruction. Both work by single-stepping the
process, which is hundreds of times slower — fine for a few seconds of a specific path, hopeless as a background
setting. Measured on a small console program, a two second burst of function tracing recorded about 2,500 events
with callee names resolved.

`read_trace` returns the newest events by default and is paged, so a long recording can be read in chunks.

## Watching the debugger

While the server is on the plugin hooks IDA's debugger. Every stop — a breakpoint, an exception, a pause,
a step, the process starting or exiting — is snapshotted (instruction, function, registers, top of the
stack, the breakpoint that fired) and queued with a sequence number. `wait_for_debugger_event` is a
**long-poll**: give it the last `seq` you saw and it returns as soon as there is a newer event, or after
`timeout_s` with an empty list. It runs off IDA's main thread, so stepping and reading still work while a
client waits.

A stop inside a function also carries that function's **arguments**, read out of the live process: each one's name
and type from the prototype, its value, `text` for a `char *` / `wchar_t *` (the string itself), and `points_to` for
a pointer into something named. They are only read at the function's first instruction, where a breakpoint on the
function's address stops — once the prologue has run the incoming values are no longer where the ABI says, so the
event says so rather than guessing. A function with no prototype falls back to the raw stack slots a caller pushed.

Each event carries a `source`: the Kiln tool that was running when it happened (`debugger_start`,
`debugger_step`, …), or `null` when nothing was — i.e. the user drove IDA, or a running process stopped on
its own. A client watches by looping `wait_for_debugger_event` and reviewing the `null`-source stops (the
tool-driven ones are already in that tool's own result). In Kiln this is `/ida` → **review stops**: the chat
posts each stop and the model looks at what is going on, then drives on with `debugger_step`.

## Tools

65 tools. Read-only ones Kiln runs without asking (except in Manual mode); modifying ones ask before
each call (except in Bypass mode) and Plan mode never offers them; ⚠ = `destructiveHint`, which the
approval card says.

### Understanding the code (read-only)

| Tool | Arguments | What it returns |
|---|---|---|
| `get_database_info` | — | binary, database file, processor, bitness, image base, entry point, range, function/segment counts, Hex-Rays, analysis done, debugger on |
| `list_segments` | — | name, class, start, end, size, permissions, bitness |
| `list_functions` | `filter?`, `regex?`, `offset?`, `limit?` | address, name, size — paged |
| `get_function` | `address` | bounds, size, name, prototype, comments, chunks, callers count, frame size, library / thunk / no-return |
| `get_functions` | `addresses[]` | the same for up to 50 functions in one call (`error` per bad address) |
| `get_callers` | `address`, paging | who calls it: one row per calling function with call count and sites |
| `get_callees` | `address`, paging | what it calls: one row per target with kind (function / import / thunk / data), call count, sites |
| `decompile` | `address` | Hex-Rays pseudocode of the function |
| `decompile_many` | `addresses[]`, `max_chars_each?`, `budget_ms?` | pseudocode of up to 20 functions; `remaining` when the budget ran out |
| `get_pseudocode_lines` | `address` | pseudocode as numbered lines, each with the address it came from |
| `disassemble` | `address`, `count?`, `max_lines?` | the whole function, or `count` instructions from an address |
| `get_xrefs_to` | `address`, paging | who calls / jumps to / reads / writes it |
| `get_xrefs_from` | `address`, `whole_function?`, paging | what it calls, jumps to, reads, writes |
| `list_imports` | `filter?`, paging | module, name, address, ordinal |
| `list_exports` | paging | name, address, ordinal |
| `list_strings` | `filter?`, `min_length?`, `refresh?`, paging | address, length, type, text |
| `search_names` | `query`, `regex?`, paging | names containing text / matching a regex, with demangled form |
| `search_text` | `text`, `case_sensitive?`, `start?`, `end?`, `limit?`, `budget_ms?` | disassembly lines (and comments) containing text; `resume_from` |
| `search_bytes` | `pattern`, `start?`, `end?`, `limit?`, `budget_ms?` | addresses of a hex pattern (`??` wildcards) and their functions; `resume_from` |
| `find_similar_functions` | `address`, `limit?`, `min_similarity?`, `budget_ms?` | functions with the same instruction shapes (inlined / duplicated / templated copies), scored 0..1 |
| `suggest_struct_from_accesses` | `address`, `register?`, `name?` | a draft C struct from the `[reg+off]` accesses in a function, with the access list |
| `read_bytes` | `address`, `size?`, `debugger?` | hex + printable ASCII, up to 64 KB, from the database or the live process |
| `get_data_item` | `address`, `max_elements?` | a data item decoded: string, number / array, pointer (and target), struct instance (member values), or code |
| `list_types` | `filter?`, paging | local types: ordinal, name, kind, size |
| `get_type` | `name?`, `ordinal?` | a type's full C definition |
| `get_stack_frame` | `address` | a function's frame: variables / arguments with offset, size, type |
| `list_signatures` | — | FLIRT signatures applied: name, library, matches |
| `list_bookmarks` | — | IDA bookmarks: slot, address, name, description, function |
| `list_breakpoints` | — | address, enabled, type, size, condition, pass count |
| `get_cursor` | — | the address under the user's cursor and its function |
| `get_debugger_state` | — | debugging?, state, threads, registers; when suspended: `ip`, the instruction, the function |
| `get_arguments` | `address?` | the stopped function's arguments read out of the live process: name, type and value, strings followed, pointers named |
| `wait_for_debugger_event` | `since?`, `timeout_s?` | long-poll: the debugger stops after `since` (instruction, registers, stack, breakpoint, `source`). Kiln uses it for the live debugger card and for reviewing stops |
| `jump_to` | `address` | moves IDA's view (changes nothing) |

### Changing the database (modifying)

| Tool | Arguments | Effect |
|---|---|---|
| `set_name` | `address`, `name` | rename a function / label / global (empty = remove) |
| `set_comment` | `address`, `comment`, `repeatable?` | instruction / data comment |
| `set_function_comment` | `address`, `comment`, `repeatable?` | the comment at the top of a function |
| `set_type` | `address`, `declaration` | apply a prototype or a variable type |
| `set_calling_convention` | `address`, `convention` | cdecl / stdcall / fastcall / thiscall / pascal / usercall / userpurge, keeping the rest of the prototype |
| `mark_as_noreturn` | `address`, `noreturn?` | mark a function as never returning (callers re-analysed), or clear it |
| `declare_types` | `declarations` | add / replace structs, unions, enums, typedefs |
| `rename_local_variable` | `function`, `old_name`, `new_name` | rename a pseudocode local (Hex-Rays) |
| `set_lvar_type` | `function`, `name`, `type` | type a pseudocode local / argument (Hex-Rays) |
| `set_lvar_comment` | `function`, `name`, `comment` | comment on a pseudocode local (Hex-Rays) |
| `create_function` | `address` | like pressing **P** |
| `undefine` ⚠ | `address`, `size?` | like pressing **U** — destructive |
| `patch_bytes` ⚠ | `address`, `hex` | patch the database (IDA keeps the originals for *Apply patches*) — destructive |
| `apply_signature` | `name` | queue a FLIRT signature (then `wait_for_analysis`, `list_signatures`) |
| `add_bookmark` | `address`, `description` | an IDA bookmark (Ctrl-M) — a trail the user can walk |
| `delete_bookmark` | `slot` | remove one (higher slots move down, as IDA does) |
| `wait_for_analysis` | — | block until auto-analysis finishes |
| `save_database` | — | save the IDB |
| `run_python` ⚠ | `code` | run IDAPython in IDA and return stdout / the result — anything the API can do |

### Driving the debugger (modifying)

The debugger selected in IDA is used (win32 is loaded on Windows if none is). IDA may show its own
confirmation the first time a process is started; the call waits for it.

| Tool | Arguments | Effect |
|---|---|---|
| `set_breakpoint` | `address`, `kind?` (exec / write / read / access), `size?`, `suspend?`, `condition?`, `enabled?` | add or update a **hardware** breakpoint — debug registers, no byte of the program is changed, so self-checks see nothing. Software (`0xCC`) breakpoints are deliberately not offered. Only 4 debug registers exist. A condition that evaluates false logs without stopping the process |
| `delete_breakpoint` | `address` | remove it |
| `trace_start` | `kind?`, `size?`, `clear?` | start recording: `breakpoints` (logging breakpoints only, full speed), `function` (every call and return) or `instruction` (every instruction) |
| `trace_stop` | — | stop recording; what was recorded stays readable |
| `trace_clear` | — | throw the recording away |
| `read_trace` | `offset?`, `limit?`, `newest?`, `kind?` | the recorded events: index, kind (bpt / call / ret / insn), thread, function + offset, and what a call called |
| `debugger_start` ⚠ | `path?`, `args?`, `directory?`, `break_at?`, `timeout_s?` | **runs the program** under IDA and waits until it is suspended (at `break_at`, a breakpoint, or the entry); returns the stop event, instruction, registers |
| `debugger_attach` ⚠ | `pid`, `timeout_s?` | attach to a running process and suspend it |
| `debugger_step` | `action` (step_over / step_into / step_out / continue / run_to), `address?`, `timeout_s?` | drive the process and wait for the next stop; `event: timeout` means it is still running |
| `set_register` | `name`, `value` | set a register of the suspended process |
| `write_memory` ⚠ | `address`, `hex` | write the live process's memory (the database is untouched) |
| `debugger_stop` ⚠ | `detach?` | kill the process (or detach) and end the session |

## Testing

`tests/live_test.py` is a plain-Python MCP client (urllib, no dependencies). With IDA open and the
server on:

```bash
set PYTHONIOENCODING=utf-8
python tests/live_test.py
```

It reads the newest session file and runs 80 checks: security (401 / 403 / 405), `/health`,
`initialize`, notifications → 202, `tools/list`, every read-only tool, each modifying tool followed
by its undo, the searches with limits and budgets, unknown-argument handling, bookmarks, breakpoints,
a real debugger run (start at the target, read the pushed debugger events, step, set a register, write
memory back, continue, stop — set `KILN_LIVE_DEBUGGER=0` to skip it) and 6 concurrent calls. Last run
against IDA 9.1 + Hex-Rays on `whoami.exe`: **80 passed, 0 failed**.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Nothing in `Edit → Plugins` | The file isn't in the plugin folder, or IDAPython failed to load it: check the Output window at startup for a traceback. |
| `server OFF` / `/ida` shows **not answering** | The server was stopped (toggle it back on, Ctrl-Alt-K) or IDA is modal (a dialog is open) and can't service calls. |
| `/ida` shows **gone** | That IDA process has exited; the chat keeps the attachment and reconnects when the same database is opened again. |
| Port in use | The plugin scans 24137…24236. To start elsewhere set `"port"` in `%APPDATA%\Kiln\ida\plugin.json`. |
| `Hex-Rays decompiler is not available` | No decompiler licence for this processor; `disassemble` still works. |
| A call takes long and IDA's UI freezes | A single IDA call (one `decompile`, building `list_strings`) runs on IDA's main thread — the IDA API requires it. The searches, batch decompiles and similarity scans are chunked with a `budget_ms`, so the UI breathes between windows. |
| `debugger_start` fails or hangs | Pick a debugger in IDA (Debugger → Select debugger) and check Debugger → Process options; the input file must exist. A confirmation dialog in IDA blocks the call until answered. |
| `401` from a script | Send `Authorization: Bearer <token>` from the session file — every endpoint needs it. |
| `ConnectionAbortedError` / `ConnectionResetError` traceback in the Output window | Fixed in **0.3.1**. An HTTP/1.1 client (Kiln included) keeps sockets open between calls and closes them when idle; older builds let Python print a traceback for that. It never affected a call — the one before it still says `ok`. Update the plugin and restart IDA. |
| Headless `idat -S` | Cross-thread `execute_sync` is only serviced by the GUI event loop; the server needs the IDA GUI (`ida.exe`). |

## Limitations

- IDA 9.x API only (no 7.x / 8.x compatibility layer).
- A non-chunked tool runs to completion on the main thread (no per-call timeout there). Kiln times a
  call out after 10 minutes on its side; the chunked tools honour `budget_ms`.
- `suggest_struct_from_accesses` reads operands as text (`[rcx+18h]`), which is right for x86 / x64
  and ARM-style `[x0,#0x18]` is not handled yet.
- `find_similar_functions` compares instruction shapes, not semantics: it finds copies and near
  copies, not reimplementations.
- `read_bytes` with `debugger=true` needs a suspended debuggee.
- One session per IDA instance — one database at a time, as in IDA itself.
