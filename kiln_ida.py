"""Kiln IDA — an MCP server inside IDA Pro 9.x.

Lets Kiln (and any MCP client) read and work with the open database: functions, pseudocode, assembly,
cross-references, imports, exports, strings, segments, names, types, the stack frame, memory, the debugger — and,
when you allow it, change the database (names, comments, types, functions, patches) or run Python.

How it works
- An HTTP server on 127.0.0.1 (one port per IDA instance) speaks MCP (JSON-RPC 2.0, Streamable HTTP, POST /mcp).
- Every IDA call runs on IDA's main thread, one at a time (execute_sync), so the database is never touched
  concurrently; the server thread only does I/O, so IDA stays responsive.
- While the server is on, the session is registered as a small JSON file in %APPDATA%\\Kiln\\ida\\sessions\\<id>.json
  (id, binary, database, port, key, IDA version, Hex-Rays…). Kiln reads these to list sessions for /ida.
- Every request needs the session's key (Authorization: Bearer …); browsers (requests with an Origin header) are
  refused. Nothing is reachable from other computers.
- Tools are marked read-only or modifying (MCP annotations); a client can ask before the modifying ones.

Install: copy this file to %APPDATA%\\Hex-Rays\\IDA Pro\\plugins\\ (or IDA's plugins folder) and restart IDA.
Menu: Edit → Plugins → Kiln IDA (start/stop, status, autostart). Hotkey Ctrl-Alt-K toggles the server.
Standard library only — nothing to pip-install into IDA's Python.
"""

import collections
import contextlib
import ctypes
import datetime
import io
import json
import os
import re
import secrets
import socket
import struct
import sys
import threading
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import idaapi
import ida_auto
import ida_bytes
import ida_dbg
import ida_entry
import ida_frame
import ida_funcs
import ida_ida
import ida_idc
import ida_idd
import ida_idp
import ida_kernwin
import ida_lines
import ida_loader
import ida_nalt
import ida_name
import ida_search
import ida_segment
import ida_typeinf
import ida_ua
import ida_xref
import idautils
import idc

try:
    import ida_hexrays
except ImportError:  # no decompiler in this installation
    ida_hexrays = None

PLUGIN_VERSION = "0.4.0"
PLUGIN_NAME = "Kiln IDA"
DEFAULT_PORT = 24137
PORT_RANGE = 100
BADADDR = idaapi.BADADDR
PROTOCOL_VERSIONS = ("2025-06-18", "2025-03-26", "2024-11-05")
MAX_BODY = 4 * 1024 * 1024
LOG_MAX_BYTES = 2 * 1024 * 1024


# ───────────────────────── files: sessions, preferences, log ─────────────────────────

def kiln_dir() -> str:
    base = os.environ.get("APPDATA") if sys.platform == "win32" else os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base or os.path.expanduser("~"), "Kiln", "ida")


def sessions_dir() -> str:
    return os.path.join(kiln_dir(), "sessions")


def prefs_file() -> str:
    return os.path.join(kiln_dir(), "plugin.json")


def load_prefs() -> dict:
    try:
        with open(prefs_file(), "r", encoding="utf-8") as f:
            p = json.load(f)
        return p if isinstance(p, dict) else {}
    except (OSError, ValueError):
        return {}


def save_prefs(p: dict) -> None:
    os.makedirs(kiln_dir(), exist_ok=True)
    _atomic_write(prefs_file(), json.dumps(p, indent=2))


def _atomic_write(path: str, text: str) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    os.replace(tmp, path)


_log_lock = threading.Lock()


def log(text: str) -> None:
    """To IDA's Output window (from any thread) and to %APPDATA%\\Kiln\\ida\\plugin.log."""
    line = f"[{PLUGIN_NAME}] {text}"
    try:
        if _executor and _executor.on_main_thread():
            ida_kernwin.msg(line + "\n")
        else:
            ida_kernwin.execute_sync(lambda: ida_kernwin.msg(line + "\n") or 0, ida_kernwin.MFF_NOWAIT | ida_kernwin.MFF_FAST)
    except Exception:
        pass
    try:
        with _log_lock:
            os.makedirs(kiln_dir(), exist_ok=True)
            path = os.path.join(kiln_dir(), "plugin.log")
            if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
                os.replace(path, path + ".old")
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"{datetime.datetime.now().isoformat(timespec='seconds')} pid={os.getpid()} {text}\n")
    except OSError:
        pass


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        # Never os.kill(pid, 0) on Windows: it terminates the process.
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            code = ctypes.c_ulong()
            ok = ctypes.windll.kernel32.GetExitCodeProcess(h, ctypes.byref(code))
            return bool(ok) and code.value == 259  # STILL_ACTIVE
        finally:
            ctypes.windll.kernel32.CloseHandle(h)
    try:
        os.kill(int(pid), 0)
        return True
    except OSError:
        return False


# ───────────────────────── running on IDA's main thread ─────────────────────────

class ToolError(Exception):
    """A tool couldn't do what was asked: the message goes back to the client as the result (isError)."""


class _Executor:
    """Runs a callable on IDA's main thread (execute_sync), one at a time. Created on the main thread at plugin init."""

    def __init__(self):
        self.main_tid = threading.get_ident()
        self.lock = threading.Lock()
        self.busy_with = None
        self.busy_since = 0.0

    def on_main_thread(self) -> bool:
        return threading.get_ident() == self.main_tid

    def run(self, fn, write: bool, label: str = ""):
        if self.on_main_thread():
            return fn()
        box = {}

        def job():
            try:
                box["r"] = fn()
            except BaseException as e:  # handed to the waiting thread
                box["e"] = e
                box["tb"] = traceback.format_exc()
            return 1

        with self.lock:
            self.busy_with, self.busy_since = label, time.monotonic()
            try:
                ida_kernwin.execute_sync(job, ida_kernwin.MFF_WRITE if write else ida_kernwin.MFF_READ)
            finally:
                self.busy_with = None
        if "e" in box:
            e = box["e"]
            if not isinstance(e, ToolError):
                log(f"tool {label} failed:\n{box.get('tb', '')}")
            raise e
        return box.get("r")


_executor: "_Executor | None" = None


# ───────────────────────── helpers ─────────────────────────

def hexa(ea: int) -> str:
    return f"0x{ea:X}"


def parse_ea(value, what: str = "address") -> int:
    """An address: a number, "0x401000" / "401000" (hex), or a name (sub_401000, main, …)."""
    if isinstance(value, bool) or value is None:
        raise ToolError(f"Give the {what} (hex like 0x401000, or a name).")
    if isinstance(value, (int, float)):
        ea = int(value)
    else:
        s = str(value).strip()
        if not s:
            raise ToolError(f"Give the {what} (hex like 0x401000, or a name).")
        if re.fullmatch(r"(0[xX])?[0-9a-fA-F]+[hH]?", s):
            ea = int(s.rstrip("hH"), 16)
        else:
            ea = ida_name.get_name_ea(BADADDR, s)
            if ea == BADADDR:
                # Demangled / display names: search the name list once.
                for cand_ea, cand in idautils.Names():
                    if cand == s or ida_name.demangle_name(cand, 0) == s:
                        ea = cand_ea
                        break
            if ea == BADADDR:
                raise ToolError(f"No such name: {s} (search_names finds names; addresses are hex like 0x401000).")
    if ea < 0:
        raise ToolError(f"{value} isn't a valid address.")
    return ea


def check_in_db(ea: int) -> int:
    if ida_segment.getseg(ea) is None and not (ida_dbg.is_debugger_on() and ida_bytes.is_loaded(ea)):
        raise ToolError(f"{hexa(ea)} is not inside any segment of this database.")
    return ea


def int_arg(args: dict, key: str, default: int, lo: int, hi: int) -> int:
    v = args.get(key, default)
    try:
        n = int(v) if v is not None else default
    except (TypeError, ValueError):
        raise ToolError(f"{key} must be a number.")
    return max(lo, min(hi, n))


def page(items: list, args: dict, default_limit: int = 100, max_limit: int = 1000) -> dict:
    offset = int_arg(args, "offset", 0, 0, 10_000_000)
    limit = int_arg(args, "limit", default_limit, 1, max_limit)
    chunk = items[offset: offset + limit]
    out = {"total": len(items), "offset": offset, "count": len(chunk), "items": chunk}
    if offset + limit < len(items):
        out["next_offset"] = offset + limit
    return out


def name_at(ea: int) -> str:
    return ida_name.get_name(ea) or ""


def func_of(ea: int):
    return ida_funcs.get_func(ea)


def func_summary(pfn) -> dict:
    return {
        "address": hexa(pfn.start_ea), "end": hexa(pfn.end_ea), "size": pfn.end_ea - pfn.start_ea,
        "name": ida_funcs.get_func_name(pfn.start_ea) or "",
    }


def xref_dict(x) -> dict:
    return {"from": hexa(x.frm), "to": hexa(x.to), "type": idautils.XrefTypeName(x.type), "code": bool(x.iscode)}


def hexrays_ok() -> bool:
    return bool(ida_hexrays) and bool(_state.hexrays)


_strings_cache = {"at": 0.0, "minlen": 0, "items": None}


def strings_list(min_length: int, refresh: bool) -> list:
    now = time.monotonic()
    c = _strings_cache
    if refresh or c["items"] is None or c["minlen"] != min_length or now - c["at"] > 300:
        s = idautils.Strings(default_setup=False)
        s.setup(strtypes=[ida_nalt.STRTYPE_C, ida_nalt.STRTYPE_C_16], minlen=min_length, only_7bit=False, ignore_instructions=True)
        items = []
        for it in s:
            try:
                if ida_bytes.is_code(ida_bytes.get_flags(ida_bytes.get_item_head(it.ea))):
                    continue  # instruction bytes that happen to look like text (often starting mid-instruction)
                items.append({"address": hexa(it.ea), "length": it.length, "type": "utf16" if it.strtype == ida_nalt.STRTYPE_C_16 else "c", "text": str(it)})
            except Exception:
                continue
        c.update(at=now, minlen=min_length, items=items)
    return c["items"]


# ───────────────────────── tools ─────────────────────────

TOOLS: "dict[str, dict]" = {}


def tool(name: str, description: str, params: dict | None = None, required: list | None = None, *, write: bool = False, destructive: bool = False, title: str | None = None, chunked: bool = False):
    """Registers a tool. `write`: runs under MFF_WRITE and is marked as modifying the database. `chunked`: the function
    runs on the server thread and sends its own windows of work to IDA's main thread (on_main) so the UI breathes
    between them and a budget_ms can stop it."""
    def deco(fn):
        TOOLS[name] = {
            "fn": fn, "write": write, "chunked": chunked,
            "def": {
                "name": name, "description": description,
                "inputSchema": {"type": "object", "properties": params or {}, **({"required": required} if required else {}), "additionalProperties": False},
                "annotations": {"title": title or name.replace("_", " "), "readOnlyHint": not write, "destructiveHint": destructive, "idempotentHint": not write, "openWorldHint": False},
            },
        }
        return fn
    return deco


ADDR = {"type": "string", "description": "An address (hex, e.g. 0x401000) or a name (e.g. sub_401000, main)."}
BUDGET = {"type": "integer", "description": "Time budget in milliseconds: stop after this long and return what was found so far, with resume_from (default 20000, max 180000)."}


def budget_deadline(args: dict, default_ms: int = 20000, max_ms: int = 180000) -> float:
    return time.monotonic() + int_arg(args, "budget_ms", default_ms, 100, max_ms) / 1000


def on_main(fn, write: bool = False, label: str = ""):
    """From a chunked tool (server thread): run one window of work on IDA's main thread."""
    return _executor.run(fn, write, label)
PAGING = {"offset": {"type": "integer", "description": "Skip this many (paging)."}, "limit": {"type": "integer", "description": "At most this many (default 100, max 1000)."}}


@tool("get_database_info", "What is open in this IDA session: the binary, the database file, processor and bitness, image base, entry point, address range, function and segment counts, whether the Hex-Rays decompiler is available, whether auto-analysis has finished, and whether the debugger is running.")
def t_db_info(args):
    return {
        "session": _state.session_id, "binary": ida_nalt.get_root_filename() or "", "input_path": ida_nalt.get_input_file_path() or "",
        "database": idc.get_idb_path() or "", "ida_version": ida_kernwin.get_kernel_version(), "sdk": idaapi.IDA_SDK_VERSION,
        "processor": ida_ida.inf_get_procname(), "bits": 64 if ida_ida.inf_is_64bit() else (32 if ida_ida.inf_is_32bit_exactly() else 16),
        "image_base": hexa(ida_nalt.get_imagebase()), "entry_point": hexa(ida_ida.inf_get_start_ea()),
        "min_address": hexa(ida_ida.inf_get_min_ea()), "max_address": hexa(ida_ida.inf_get_max_ea()),
        "functions": ida_funcs.get_func_qty(), "segments": ida_segment.get_segm_qty(), "hexrays": hexrays_ok(),
        "analysis_done": bool(ida_auto.auto_is_ok()), "debugger_on": bool(ida_dbg.is_debugger_on()),
        "plugin_version": PLUGIN_VERSION,
    }


@tool("list_segments", "The database's segments: name, class, start, end, size, permissions and bitness.")
def t_segments(args):
    out = []
    for i in range(ida_segment.get_segm_qty()):
        s = ida_segment.getnseg(i)
        if not s:
            continue
        perm = "".join(c for c, bit in (("r", ida_segment.SEGPERM_READ), ("w", ida_segment.SEGPERM_WRITE), ("x", ida_segment.SEGPERM_EXEC)) if s.perm & bit)
        out.append({"name": ida_segment.get_segm_name(s), "class": ida_segment.get_segm_class(s), "start": hexa(s.start_ea), "end": hexa(s.end_ea), "size": s.end_ea - s.start_ea, "permissions": perm, "bits": 64 if s.bitness == 2 else (32 if s.bitness == 1 else 16)})
    return {"segments": out}


@tool("list_functions", "Functions in the database (address, name, size), with an optional name filter (substring, or a regular expression with regex=true). Paged.", {"filter": {"type": "string", "description": "Only names containing this (case-insensitive)."}, "regex": {"type": "boolean"}, **PAGING})
def t_functions(args):
    q = str(args.get("filter") or "")
    rx = re.compile(q, re.I) if q and args.get("regex") else None
    out = []
    for ea in idautils.Functions():
        name = ida_funcs.get_func_name(ea) or ""
        if q and (not rx.search(name) if rx else q.lower() not in name.lower()):
            continue
        pfn = ida_funcs.get_func(ea)
        out.append({"address": hexa(ea), "name": name, "size": (pfn.end_ea - pfn.start_ea) if pfn else 0})
    return page(out, args)


@tool("get_function", "Details of one function: bounds, size, name, prototype, comments, chunks, how many places call it, the stack frame size, and whether it is a library / thunk / no-return function.", {"address": ADDR}, ["address"])
def t_function(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function (create_function can make one).")
    return _function_info(pfn)


@tool("decompile", "Hex-Rays pseudocode of the function containing the address (needs the decompiler). Returns the C code with the function's name and bounds.", {"address": ADDR}, ["address"])
def t_decompile(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available in this IDA installation (or not for this processor). Use disassemble.")
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    try:
        cfunc = ida_hexrays.decompile(pfn.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise ToolError(f"Decompilation failed: {e}")
    if cfunc is None:
        raise ToolError("Decompilation failed (no result).")
    return {**func_summary(pfn), "code": str(cfunc)}


@tool("disassemble", "Assembly listing. Give a function (any address inside it) for the whole function, or address + count for that many instructions from there. Each line: address, the instruction, and any comment / label.", {"address": ADDR, "count": {"type": "integer", "description": "Instructions to list from the address (when not a whole function). Max 2000."}, "max_lines": {"type": "integer", "description": "Cap for a whole function (default 2000)."}}, ["address"])
def t_disasm(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    count = args.get("count")
    pfn = func_of(ea)
    lines = []
    cap = int_arg(args, "max_lines", 2000, 1, 5000)
    if count is None and pfn:
        heads = list(idautils.FuncItems(pfn.start_ea))
        truncated = len(heads) > cap
        heads = heads[:cap]
        where = func_summary(pfn)
    else:
        n = int_arg(args, "count", 50, 1, 2000)
        heads, cur = [], ida_bytes.get_item_head(ea) if ida_bytes.is_loaded(ea) else ea
        end = ida_ida.inf_get_max_ea()
        while len(heads) < n and cur != BADADDR and cur < end:
            heads.append(cur)
            cur = ida_bytes.next_head(cur, end)
        truncated = False
        where = {"address": hexa(ea), "count": len(heads)}
    for h in heads:
        text = ida_lines.generate_disasm_line(h, ida_lines.GENDSM_REMOVE_TAGS) or ""
        row = {"address": hexa(h), "text": text.strip()}
        label = name_at(h)
        if label:
            row["label"] = label
        cmt = ida_bytes.get_cmt(h, False) or ida_bytes.get_cmt(h, True)
        if cmt:
            row["comment"] = cmt
        lines.append(row)
    return {**where, "lines": lines, **({"truncated": True} if truncated else {})}


@tool("get_xrefs_to", "Cross-references TO an address: who calls / jumps to / reads / writes it. Each: from, type, and the function it is in.", {"address": ADDR, **PAGING}, ["address"])
def t_xrefs_to(args):
    ea = parse_ea(args.get("address"))
    out = []
    for x in idautils.XrefsTo(ea):
        d = xref_dict(x)
        pf = func_of(x.frm)
        if pf:
            d["function"] = ida_funcs.get_func_name(pf.start_ea)
            d["function_address"] = hexa(pf.start_ea)
        out.append(d)
    return {"address": hexa(ea), "name": name_at(ea), **page(out, args)}


@tool("get_xrefs_from", "Cross-references FROM an address or a whole function: what it calls, jumps to, reads and writes.", {"address": ADDR, "whole_function": {"type": "boolean", "description": "true (default when the address is in a function): every reference from the function; false: only from that instruction."}, **PAGING}, ["address"])
def t_xrefs_from(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    whole = args.get("whole_function", pfn is not None)
    heads = list(idautils.FuncItems(pfn.start_ea)) if (whole and pfn) else [ea]
    out = []
    for h in heads:
        for x in idautils.XrefsFrom(h):
            if x.type == ida_xref.fl_F:  # ordinary flow to the next instruction
                continue
            d = xref_dict(x)
            d["target_name"] = name_at(x.to)
            out.append(d)
    return {"address": hexa(ea), **({"function": func_summary(pfn)} if pfn and whole else {}), **page(out, args, 200)}


@tool("list_imports", "Imported functions, by module (DLL): module, name, address, ordinal. Optional name filter. Paged.", {"filter": {"type": "string"}, **PAGING})
def t_imports(args):
    q = str(args.get("filter") or "").lower()
    out = []
    for i in range(ida_nalt.get_import_module_qty()):
        mod = ida_nalt.get_import_module_name(i) or ""

        def cb(ea, name, ordinal, _mod=mod):
            n = name or ""
            if not q or q in n.lower() or q in _mod.lower():
                out.append({"module": _mod, "name": n, "address": hexa(ea), **({"ordinal": ordinal} if ordinal else {})})
            return True
        ida_nalt.enum_import_names(i, cb)
    return page(out, args, 200)


@tool("list_exports", "Exported symbols and entry points: name, address, ordinal.", PAGING)
def t_exports(args):
    out = [{"ordinal": ordinal, "address": hexa(ea), "name": name or ""} for _i, ordinal, ea, name in idautils.Entries()]
    return page(out, args, 200)


@tool("list_strings", "Strings found in the binary (address, length, type, text). Filter by a substring (case-insensitive). Paged. Building the list the first time can take a few seconds on a big database.", {"filter": {"type": "string"}, "min_length": {"type": "integer", "description": "Default 5."}, "refresh": {"type": "boolean", "description": "Rebuild the string list (after analysis changed)."}, **PAGING})
def t_strings(args):
    q = str(args.get("filter") or "").lower()
    items = strings_list(int_arg(args, "min_length", 5, 1, 1000), bool(args.get("refresh")))
    out = [s for s in items if not q or q in s["text"].lower()]
    return page(out, args)


@tool("search_names", "Find names (functions, labels, globals) containing text, or matching a regular expression with regex=true. Returns address, name, demangled name, and whether it is a function.", {"query": {"type": "string"}, "regex": {"type": "boolean"}, **PAGING}, ["query"])
def t_search_names(args):
    q = str(args.get("query") or "")
    if not q:
        raise ToolError("Give the query.")
    rx = re.compile(q, re.I) if args.get("regex") else None
    out, seen = [], set()
    # The names list, then functions with automatic names (sub_401000 …), which the list leaves out.
    entries = [(ea, name) for ea, name in idautils.Names()]
    entries += [(ea, ida_funcs.get_func_name(ea) or "") for ea in idautils.Functions()]
    for ea, name in entries:
        if not name or (ea, name) in seen:
            continue
        seen.add((ea, name))
        dem = ida_name.demangle_name(name, 0) or ""
        hay = f"{name} {dem}"
        if (rx.search(hay) if rx else q.lower() in hay.lower()):
            pf = ida_funcs.get_func(ea)
            out.append({"address": hexa(ea), "name": name, **({"demangled": dem} if dem else {}), "function": pf is not None and pf.start_ea == ea})
    out.sort(key=lambda x: int(x["address"], 16))
    return page(out, args)


@tool("read_bytes", "Raw bytes at an address (from the database, or from the live process when the debugger is running and debugger=true): hex, and the printable ASCII. Up to 65536 bytes.", {"address": ADDR, "size": {"type": "integer", "description": "Default 64."}, "debugger": {"type": "boolean", "description": "Read the debugged process's memory instead of the database."}}, ["address"])
def t_read_bytes(args):
    ea = parse_ea(args.get("address"))
    size = int_arg(args, "size", 64, 1, 65536)
    if args.get("debugger"):
        if not ida_dbg.is_debugger_on():
            raise ToolError("The debugger isn't running.")
        data = ida_idd.dbg_read_memory(ea, size)
        if not data:
            raise ToolError(f"Couldn't read {size} bytes at {hexa(ea)} from the process.")
    else:
        check_in_db(ea)
        data = ida_bytes.get_bytes(ea, size)
        if data is None:
            raise ToolError(f"No bytes at {hexa(ea)} (not loaded).")
    return {"address": hexa(ea), "size": len(data), "hex": data.hex(" "), "ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in data)}


@tool("search_bytes", "Find a byte pattern (hex, ? for a wildcard byte, e.g. \"48 8B 05 ?? ?? ?? ??\"). Returns the addresses found and the function each is in. Scans in windows so IDA stays responsive; stops at `limit` hits or when budget_ms runs out (then `resume_from` says where to continue).", {"pattern": {"type": "string"}, "start": ADDR, "end": ADDR, "limit": {"type": "integer", "description": "Default 100."}, "budget_ms": BUDGET}, ["pattern"], chunked=True)
def t_search_bytes(args):
    pat = str(args.get("pattern") or "").strip()
    if not pat:
        raise ToolError("Give the pattern.")
    limit = int_arg(args, "limit", 100, 1, 1000)
    deadline = budget_deadline(args)

    def setup():
        start = parse_ea(args["start"]) if args.get("start") else ida_ida.inf_get_min_ea()
        end = parse_ea(args["end"]) if args.get("end") else ida_ida.inf_get_max_ea()
        vec = ida_bytes.compiled_binpat_vec_t()
        # IDA 9: returns an error message, '' on success (older versions: a bool).
        r = ida_bytes.parse_binpat_str(vec, start, pat, 16)
        if (isinstance(r, str) and r) or r is False or len(vec) == 0:
            raise ToolError(f"Couldn't parse the pattern “{pat}” — hex bytes separated by spaces, ? or ?? for any byte.{(' ' + r) if isinstance(r, str) and r else ''}")
        return start, end, vec, max(len(vec[0].bytes), 1)
    ea, end, vec, patlen = on_main(setup, label="search_bytes")
    flags = getattr(ida_bytes, "BIN_SEARCH_FORWARD", 0) | getattr(ida_bytes, "BIN_SEARCH_NOBREAK", 0)
    hits, WINDOW, truncated = [], 4 * 1024 * 1024, False
    while ea < end and len(hits) < limit:
        wend = min(end, ea + WINDOW + patlen)

        def window():
            found, cur = [], ea
            while cur < wend and len(hits) + len(found) < limit:
                r = ida_bytes.bin_search(cur, wend, vec, flags)
                at = r[0] if isinstance(r, tuple) else r
                if at is None or at == BADADDR:
                    break
                pf = func_of(at)
                found.append({"address": hexa(at), **({"function": ida_funcs.get_func_name(pf.start_ea), "function_address": hexa(pf.start_ea)} if pf else {})})
                cur = at + 1
            return found
        hits.extend(on_main(window, label="search_bytes"))
        ea = wend - patlen + 1 if wend < end else end
        if time.monotonic() > deadline and ea < end:
            truncated = True
            break
    out = {"pattern": pat, "count": len(hits), "hits": hits}
    if len(hits) >= limit:
        out.update(truncated=True, resume_from=hexa(int(hits[-1]["address"], 16) + 1))
    elif truncated:
        out.update(truncated=True, resume_from=hexa(ea), reason="budget_ms")
    return out


@tool("search_text", "Search the disassembly text (instructions, operands, names, comments) for a string. Returns matching lines with their addresses. Scans in windows so IDA stays responsive; stops at `limit` hits or when budget_ms runs out (then `resume_from` says where to continue).", {"text": {"type": "string"}, "case_sensitive": {"type": "boolean"}, "start": ADDR, "end": ADDR, "limit": {"type": "integer", "description": "Default 50."}, "budget_ms": BUDGET}, ["text"], chunked=True)
def t_search_text(args):
    text = str(args.get("text") or "")
    if not text:
        raise ToolError("Give the text.")
    cs = bool(args.get("case_sensitive"))
    needle = text if cs else text.lower()
    limit = int_arg(args, "limit", 50, 1, 500)
    deadline = budget_deadline(args)

    def setup():
        a = parse_ea(args["start"]) if args.get("start") else ida_ida.inf_get_min_ea()
        b = parse_ea(args["end"]) if args.get("end") else ida_ida.inf_get_max_ea()
        return a, b
    ea, end = on_main(setup, label="search_text")
    hits, WINDOW, truncated = [], 3000, False
    while ea < end and ea != BADADDR and len(hits) < limit:
        def window():
            cur, n, found = ea, 0, []
            while n < WINDOW and cur < end and cur != BADADDR and len(hits) + len(found) < limit:
                flags = ida_bytes.get_flags(cur)
                if ida_bytes.is_unknown(flags):
                    # Skip the unexplored run in one go (every byte of it would be an item otherwise).
                    try:
                        nxt = ida_bytes.next_that(cur, end, lambda f, *_: not ida_bytes.is_unknown(f))
                    except Exception:
                        nxt = BADADDR
                    cur = nxt if nxt != BADADDR and nxt > cur else ida_bytes.next_head(cur, end)
                    n += 1
                    continue
                line = ida_lines.generate_disasm_line(cur, ida_lines.GENDSM_REMOVE_TAGS) or ""
                hay = line if cs else line.lower()
                if needle not in hay:
                    for rep_ in (False, True):
                        cmt = ida_bytes.get_cmt(cur, rep_) or ""
                        if cmt and needle in (cmt if cs else cmt.lower()):
                            line = line.rstrip() + "  ; " + cmt
                            hay = needle
                            break
                if needle in hay:
                    pf = func_of(cur)
                    found.append({"address": hexa(cur), "text": line.strip(), **({"function": ida_funcs.get_func_name(pf.start_ea)} if pf else {})})
                cur = ida_bytes.next_head(cur, end)
                n += 1
            return cur, found
        ea, found = on_main(window, label="search_text")
        hits.extend(found)
        if time.monotonic() > deadline and ea < end and len(hits) < limit:
            truncated = True
            break
    out = {"text": text, "count": len(hits), "hits": hits}
    if len(hits) >= limit and ea < end:
        out.update(truncated=True, resume_from=hexa(ea))
    elif truncated:
        out.update(truncated=True, resume_from=hexa(ea), reason="budget_ms")
    return out


def _tif_kind(tif) -> str:
    for k in ("struct", "union", "enum", "typedef", "func", "ptr", "array"):
        if getattr(tif, f"is_{k}")():
            return k
    return "other"


@tool("list_types", "Local types (structs, unions, enums, typedefs) in the database: ordinal, name, kind, size. Optional name filter. Paged.", {"filter": {"type": "string"}, **PAGING})
def t_list_types(args):
    q = str(args.get("filter") or "").lower()
    out = []
    for ordinal in range(1, ida_typeinf.get_ordinal_limit(None)):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(None, ordinal):
            continue
        name = tif.get_type_name() or ""
        if q and q not in name.lower():
            continue
        out.append({"ordinal": ordinal, "name": name, "kind": _tif_kind(tif), "size": tif.get_size() if tif.get_size() != BADADDR else None})
    return page(out, args, 200)


@tool("get_type", "A local type's full C definition (struct members with offsets, enum values, typedef), by name or ordinal.", {"name": {"type": "string"}, "ordinal": {"type": "integer"}})
def t_get_type(args):
    tif = ida_typeinf.tinfo_t()
    if args.get("name"):
        if not tif.get_named_type(None, str(args["name"])):
            raise ToolError(f"No local type called {args['name']} (list_types lists them).")
    elif args.get("ordinal") is not None:
        if not tif.get_numbered_type(None, int(args["ordinal"])):
            raise ToolError(f"No local type with ordinal {args['ordinal']}.")
    else:
        raise ToolError("Give name or ordinal.")
    name = tif.get_type_name() or str(args.get("name") or "")
    text = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_MULTI | ida_typeinf.PRTYPE_TYPE | ida_typeinf.PRTYPE_SEMI | ida_typeinf.PRTYPE_DEF, tif, name, "")
    out = {"name": name, "kind": _tif_kind(tif), "size": tif.get_size() if tif.get_size() != BADADDR else None, "definition": text or str(tif)}
    if tif.is_struct() or tif.is_union():
        udt = ida_typeinf.udt_type_data_t()
        if tif.get_udt_details(udt):
            out["members"] = [{"name": m.name, "offset": m.offset // 8, "size": m.size // 8, "type": str(m.type)} for m in udt]
    return out


@tool("get_stack_frame", "A function's stack frame: each variable / argument with its offset, size and type (offsets are from the frame's start; the return address and saved registers show as such).", {"address": ADDR}, ["address"])
def t_frame(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    tif = ida_typeinf.tinfo_t()
    if not ida_frame.get_func_frame(tif, pfn):
        raise ToolError("This function has no stack frame.")
    udt = ida_typeinf.udt_type_data_t()
    members = []
    if tif.get_udt_details(udt):
        members = [{"name": m.name, "offset": m.offset // 8, "size": m.size // 8, "type": str(m.type)} for m in udt]
    return {**func_summary(pfn), "frame_size": ida_frame.get_frame_size(pfn), "local_size": pfn.frsize, "saved_registers": pfn.frregs, "argument_size": pfn.argsize, "members": members}


@tool("get_cursor", "Where the user is in IDA right now: the address under the cursor, its name, and the function it is in.")
def t_cursor(args):
    ea = ida_kernwin.get_screen_ea()
    pfn = func_of(ea) if ea != BADADDR else None
    return {"address": hexa(ea) if ea != BADADDR else None, "name": name_at(ea) if ea != BADADDR else "", **({"function": func_summary(pfn)} if pfn else {})}


def _reg_names() -> list:
    """Registers worth showing: the full-width ones on x86 / x64 (IDA's own list starts with ax, bx, …), else the processor's."""
    proc = (ida_ida.inf_get_procname() or "").lower()
    if proc == "metapc":
        if ida_ida.inf_is_64bit():
            return ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "rip", "efl", "cs", "ds", "es", "fs", "gs", "ss"]
        return ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "efl", "cs", "ds", "es", "fs", "gs", "ss"]
    return list(ida_idp.ph_get_regnames())[:64]


@tool("get_arguments", "The arguments of the function the debugged process is stopped in, read out of the live process: each argument's name, type and value, with strings followed and pointers named. Accurate at the function's first instruction (before its prologue runs), which is exactly where a breakpoint on the function's address stops.", {"address": {**ADDR, "description": "Which function (default: where the process is stopped)."}})
def t_get_args(args):
    if not ida_dbg.is_debugger_on():
        raise ToolError("The debugger isn't running.")
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise ToolError("The process is running — it has to be stopped to read its arguments.")
    ip = int(ida_dbg.get_ip_val() or BADADDR)
    ea = parse_ea(args["address"]) if args.get("address") else ip
    pfn = func_of(ea)
    if not pfn:
        raise ToolError("%s is not inside a function." % hexa(ea))
    out = {"function": func_summary(pfn), "ip": hexa(ip) if ip != BADADDR else None}
    out.update(_read_args(pfn, ip))
    if "arguments" not in out and "arguments_note" not in out:
        out["arguments_note"] = "no arguments could be read here"
    return out


@tool("get_debugger_state", "The debugger: whether a process is being debugged, its state, threads, and the current thread's registers.")
def t_dbg(args):
    if not ida_dbg.is_debugger_on():
        return {"debugger_on": False}
    st = ida_dbg.get_process_state()
    state = {ida_dbg.DSTATE_SUSP: "suspended", ida_dbg.DSTATE_RUN: "running", ida_dbg.DSTATE_NOTASK: "no process"}.get(st, str(st))
    threads = [{"id": ida_dbg.getn_thread(i), "name": ida_dbg.getn_thread_name(i) or ""} for i in range(ida_dbg.get_thread_qty())]
    regs = {}
    if st == ida_dbg.DSTATE_SUSP:
        for r in _reg_names():
            try:
                v = ida_dbg.get_reg_val(r)
                regs[r] = hexa(int(v)) if isinstance(v, int) else v
            except Exception:
                continue
    out = {"debugger_on": True, "state": state, "current_thread": ida_dbg.get_current_thread(), "threads": threads, "registers": regs}
    if st == ida_dbg.DSTATE_SUSP:
        try:
            ip = int(ida_dbg.get_ip_val() or BADADDR)
            if ip != BADADDR:
                out["ip"] = hexa(ip)
                out["instruction"] = (ida_lines.generate_disasm_line(ip, ida_lines.GENDSM_REMOVE_TAGS) or "").strip()
                pf = func_of(ip)
                if pf:
                    out["function"] = func_summary(pf)
        except Exception:
            pass
    return out


@tool("jump_to", "Move IDA's view to an address (shows it to the user). Changes nothing in the database.", {"address": ADDR}, ["address"])
def t_jump(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    ok = ida_kernwin.jumpto(ea)
    return {"address": hexa(ea), "jumped": bool(ok)}


# ── modifying tools ──

@tool("set_name", "Rename an address: a function, label or global. Empty name removes the name.", {"address": ADDR, "name": {"type": "string"}}, ["address", "name"], write=True, title="rename")
def t_set_name(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    name = str(args.get("name") or "")
    old = name_at(ea)
    if not ida_name.set_name(ea, name, ida_name.SN_NOCHECK | ida_name.SN_NOWARN):
        raise ToolError(f"IDA refused the name “{name}” at {hexa(ea)} (already used, or not a valid identifier).")
    return {"address": hexa(ea), "old_name": old, "name": name_at(ea)}


@tool("set_comment", "Set (or clear with an empty string) the comment on an instruction or data item. repeatable=true for a repeatable comment (shown at every reference).", {"address": ADDR, "comment": {"type": "string"}, "repeatable": {"type": "boolean"}}, ["address", "comment"], write=True)
def t_set_comment(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    if not ida_bytes.set_cmt(ea, str(args.get("comment") or ""), bool(args.get("repeatable"))):
        raise ToolError(f"Couldn't set the comment at {hexa(ea)}.")
    return {"address": hexa(ea), "comment": str(args.get("comment") or "")}


@tool("set_function_comment", "Set (or clear) the comment shown at the top of a function.", {"address": ADDR, "comment": {"type": "string"}, "repeatable": {"type": "boolean"}}, ["address", "comment"], write=True)
def t_set_func_comment(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    ida_funcs.set_func_cmt(pfn, str(args.get("comment") or ""), bool(args.get("repeatable")))
    return {**func_summary(pfn), "comment": str(args.get("comment") or "")}


@tool("set_type", "Apply a C declaration to an address: a function prototype (e.g. \"int __fastcall sub_401000(int a, char *b)\") or a variable's type (e.g. \"struct Player *g_player\"). The name in the declaration is ignored for functions.", {"address": ADDR, "declaration": {"type": "string"}}, ["address", "declaration"], write=True)
def t_set_type(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    decl = str(args.get("declaration") or "").strip()
    if not decl:
        raise ToolError("Give the declaration.")
    if not decl.endswith(";"):
        decl += ";"
    tif = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(tif, None, decl, ida_typeinf.PT_SIL) is None:
        raise ToolError(f"IDA couldn't parse “{decl}”. Unknown types must be declared first (declare_types).")
    if not ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE):
        raise ToolError(f"IDA refused to apply the type at {hexa(ea)}.")
    return {"address": hexa(ea), "type": ida_typeinf.print_type(ea, ida_typeinf.PRTYPE_1LINE) or str(tif)}


@tool("declare_types", "Add or replace local types from C declarations: structs, unions, enums, typedefs (several at once, e.g. \"struct Vec3 { float x, y, z; }; typedef Vec3 *PVec3;\").", {"declarations": {"type": "string"}}, ["declarations"], write=True)
def t_declare_types(args):
    text = str(args.get("declarations") or "").strip()
    if not text:
        raise ToolError("Give the declarations.")
    before = ida_typeinf.get_ordinal_limit(None)
    errors = ida_typeinf.parse_decls(None, text, None, ida_typeinf.HTI_DCL)
    if errors:
        raise ToolError(f"IDA reported {errors} error(s) parsing the declarations (check the Output window for details).")
    return {"ok": True, "new_types": max(0, ida_typeinf.get_ordinal_limit(None) - before)}


@tool("rename_local_variable", "Rename a local variable or argument in a function's pseudocode (Hex-Rays).", {"function": ADDR, "old_name": {"type": "string"}, "new_name": {"type": "string"}}, ["function", "old_name", "new_name"], write=True)
def t_rename_lvar(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available.")
    ea = parse_ea(args.get("function"), "function")
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    old, new = str(args.get("old_name") or ""), str(args.get("new_name") or "")
    if not old or not new:
        raise ToolError("Give old_name and new_name.")
    if not ida_hexrays.rename_lvar(pfn.start_ea, old, new):
        raise ToolError(f"Couldn't rename {old} → {new} (is {old} a variable of this function? decompile to see them).")
    return {**func_summary(pfn), "old_name": old, "new_name": new}


@tool("create_function", "Make IDA treat the code at an address as a function (like pressing P).", {"address": ADDR}, ["address"], write=True)
def t_create_func(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    if func_of(ea):
        raise ToolError(f"{hexa(ea)} is already inside {ida_funcs.get_func_name(func_of(ea).start_ea)}.")
    if not ida_funcs.add_func(ea):
        raise ToolError(f"IDA couldn't create a function at {hexa(ea)} (is it code?).")
    return func_summary(func_of(ea))


@tool("undefine", "Undefine bytes (turn an instruction or data item back into raw bytes, like pressing U). Destructive: analysis and names there are lost.", {"address": ADDR, "size": {"type": "integer", "description": "Bytes to undefine (default: the item at the address)."}}, ["address"], write=True, destructive=True)
def t_undefine(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    size = int_arg(args, "size", ida_bytes.get_item_size(ea) or 1, 1, 1 << 20)
    if not ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, size):
        raise ToolError(f"Couldn't undefine {size} byte(s) at {hexa(ea)}.")
    return {"address": hexa(ea), "size": size}


@tool("patch_bytes", "Patch bytes in the database (hex, e.g. \"90 90\"). Destructive: the original bytes are replaced (IDA keeps the originals for Edit → Patch program → Apply patches).", {"address": ADDR, "hex": {"type": "string"}}, ["address", "hex"], write=True, destructive=True)
def t_patch(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    try:
        data = bytes.fromhex(re.sub(r"[\s,]", "", str(args.get("hex") or "")))
    except ValueError:
        raise ToolError("hex must be bytes like \"90 90\".")
    if not data:
        raise ToolError("Nothing to patch.")
    before = ida_bytes.get_bytes(ea, len(data)) or b""
    ida_bytes.patch_bytes(ea, data)
    return {"address": hexa(ea), "size": len(data), "before": before.hex(" "), "after": data.hex(" ")}


@tool("wait_for_analysis", "Wait until IDA's auto-analysis is finished (after creating functions or patching). Can take a while on a big database.", write=True)
def t_wait(args):
    ida_auto.auto_wait()
    return {"analysis_done": bool(ida_auto.auto_is_ok())}


@tool("save_database", "Save the database (.i64 / .idb) to disk.", write=True)
def t_save(args):
    ok = ida_loader.save_database(None, 0)
    if not ok:
        raise ToolError("IDA couldn't save the database.")
    return {"saved": True, "database": idc.get_idb_path()}


@tool("run_python", "Run Python inside IDA (IDAPython: idaapi, idautils, idc, ida_* are available). Returns what it prints and the value of `result` if the code sets it. Can do anything to the database — use the other tools where they fit.", {"code": {"type": "string"}}, ["code"], write=True, destructive=True)
def t_python(args):
    code = str(args.get("code") or "")
    if not code.strip():
        raise ToolError("Give the code.")
    env = {"__name__": "__kiln_ida__", "idaapi": idaapi, "idautils": idautils, "idc": idc}
    buf = io.StringIO()
    try:
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            exec(compile(code, "<kiln_ida>", "exec"), env)
    except Exception:
        return {"ok": False, "output": buf.getvalue(), "error": traceback.format_exc(limit=3)}
    out = {"ok": True, "output": buf.getvalue()[:60000]}
    if "result" in env:
        try:
            json.dumps(env["result"])
            out["result"] = env["result"]
        except (TypeError, ValueError):
            out["result"] = repr(env["result"])[:10000]
    return out


# ───────────────────────── calls graph, batches, decompiler extras ─────────────────────────

CALL_TYPES = None  # set lazily: the xref types that are calls / jumps


def _is_call_xref(x) -> bool:
    global CALL_TYPES
    if CALL_TYPES is None:
        CALL_TYPES = {ida_xref.fl_CN, ida_xref.fl_CF, ida_xref.fl_JN, ida_xref.fl_JF}
    return x.iscode and x.type in CALL_TYPES


def _callee_kind(ea: int) -> str:
    """What a call target is: a function here, an import (thunk / IAT slot), or plain data."""
    pf = func_of(ea)
    seg = ida_segment.getseg(ea)
    segname = (ida_segment.get_segm_name(seg) or "") if seg else ""
    if segname.lower() in (".idata", "idata", ".plt", ".got", "extern", "UNDEF") or (seg and seg.type == ida_segment.SEG_XTRN):
        return "import"
    if pf and (pf.flags & ida_funcs.FUNC_THUNK):
        return "thunk"
    if pf:
        return "function"
    n = name_at(ea)
    return "import" if n.startswith("__imp_") else "data"


def _call_sites_of(pfn) -> list:
    """Every call / jump out of a function: (site, target)."""
    out = []
    for h in idautils.FuncItems(pfn.start_ea):
        for x in idautils.XrefsFrom(h):
            if _is_call_xref(x) and not (pfn.start_ea <= x.to < pfn.end_ea):
                out.append((h, x.to))
    return out


def _group_calls(pairs, key_index: int, max_sites: int = 5) -> list:
    groups: "dict[int, dict]" = {}
    for site, other in pairs:
        k = (site, other)[key_index]
        g = groups.get(k)
        if g is None:
            g = groups[k] = {"calls": 0, "sites": []}
        g["calls"] += 1
        if len(g["sites"]) < max_sites:
            g["sites"].append(hexa(site))
    return sorted(groups.items(), key=lambda kv: -kv[1]["calls"])


@tool("get_callers", "Who calls a function: each calling function with its name, how many call sites it has, and where they are (grouped — one entry per caller, most calls first). Paged.", {"address": ADDR, **PAGING}, ["address"])
def t_callers(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    target = pfn.start_ea if pfn else ea
    pairs = []
    for x in idautils.XrefsTo(target):
        if _is_call_xref(x):
            pf = func_of(x.frm)
            pairs.append((x.frm, pf.start_ea if pf else BADADDR))
    items = []
    for caller_ea, g in _group_calls(pairs, 1):
        row = {"calls": g["calls"], "sites": g["sites"]}
        if caller_ea == BADADDR:
            row.update(function=None, address=None, note="call from outside any function")
        else:
            row.update(function=ida_funcs.get_func_name(caller_ea) or "", address=hexa(caller_ea))
        items.append(row)
    return {"address": hexa(target), "name": name_at(target), "total_call_sites": len(pairs), **page(items, args)}


@tool("get_callees", "What a function calls: each target with its name, kind (function / import / thunk / data), how many times it is called from here, and the call sites (grouped, most calls first). The fastest way to see a function's dependencies without reading its code. Paged.", {"address": ADDR, **PAGING}, ["address"])
def t_callees(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    pairs = _call_sites_of(pfn)
    items = []
    for target, g in _group_calls(pairs, 1):
        name = name_at(target)
        tf = func_of(target)
        items.append({"address": hexa(target), "name": ida_funcs.get_func_name(tf.start_ea) if tf else (ida_name.demangle_name(name, 0) or name), "kind": _callee_kind(target), "calls": g["calls"], "sites": g["sites"]})
    return {**func_summary(pfn), "total_call_sites": len(pairs), "distinct_targets": len(items), **page(items, args)}


ADDR_LIST = {"type": "array", "items": {"type": "string"}, "description": "Addresses or names (max 50)."}


def _addr_list(args, key: str = "addresses", max_n: int = 50) -> list:
    raw = args.get(key)
    if isinstance(raw, str):
        raw = [p for p in re.split(r"[,\s]+", raw) if p]
    if not isinstance(raw, list) or not raw:
        raise ToolError(f"Give {key}: a list of addresses or names.")
    return raw[:max_n]


def _function_info(pfn) -> dict:
    callers = sum(1 for x in idautils.XrefsTo(pfn.start_ea) if x.iscode)
    chunks = [{"start": hexa(start), "end": hexa(end)} for start, end in idautils.Chunks(pfn.start_ea)]
    f = pfn.flags
    return {
        **func_summary(pfn), "prototype": ida_typeinf.print_type(pfn.start_ea, ida_typeinf.PRTYPE_1LINE) or "",
        "comment": ida_funcs.get_func_cmt(pfn, False) or "", "repeatable_comment": ida_funcs.get_func_cmt(pfn, True) or "",
        "callers": callers, "chunks": chunks, "frame_size": ida_frame.get_frame_size(pfn),
        "library": bool(f & ida_funcs.FUNC_LIB), "thunk": bool(f & ida_funcs.FUNC_THUNK), "noreturn": bool(f & ida_funcs.FUNC_NORET),
        "decompilable": hexrays_ok(),
    }


@tool("get_functions", "Details of several functions in one call (same fields as get_function, one entry per address; an entry carries `error` when an address isn't a function). Up to 50.", {"addresses": ADDR_LIST}, ["addresses"])
def t_functions_many(args):
    out = []
    for a in _addr_list(args):
        try:
            pfn = func_of(parse_ea(a))
            if not pfn:
                raise ToolError("not inside a function")
            out.append(_function_info(pfn))
        except ToolError as e:
            out.append({"address": str(a), "error": str(e)})
    return {"count": len(out), "items": out}


def _decompile_one(ea: int, max_chars: int) -> dict:
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    try:
        cfunc = ida_hexrays.decompile(pfn.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise ToolError(f"Decompilation failed: {e}")
    if cfunc is None:
        raise ToolError("Decompilation failed (no result).")
    code = str(cfunc)
    out = {**func_summary(pfn), "code": code[:max_chars]}
    if len(code) > max_chars:
        out["truncated"] = True
        out["chars"] = len(code)
    return out


@tool("decompile_many", "Hex-Rays pseudocode of several functions in one call (one entry per address, each with `code` or `error`). Up to 20 functions; stops early when budget_ms runs out and says which addresses are left in `remaining`.", {"addresses": {**ADDR_LIST, "description": "Functions (addresses or names), max 20."}, "max_chars_each": {"type": "integer", "description": "Cut each function's code at this many characters (default 20000)."}, "budget_ms": {"type": "integer", "description": "Time budget in milliseconds (default 60000)."}}, ["addresses"], chunked=True)
def t_decompile_many(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available in this IDA installation. Use disassemble.")
    addrs = _addr_list(args, max_n=20)
    max_chars = int_arg(args, "max_chars_each", 20000, 200, 200000)
    deadline = budget_deadline(args, 60000)
    items, i = [], 0
    while i < len(addrs):
        a = addrs[i]

        def one():
            try:
                return _decompile_one(parse_ea(a), max_chars)
            except ToolError as e:
                return {"address": str(a), "error": str(e)}
        items.append(on_main(one, label="decompile_many"))
        i += 1
        if time.monotonic() > deadline and i < len(addrs):
            break
    return {"count": len(items), "items": items, **({"remaining": [str(a) for a in addrs[i:]], "truncated": True} if i < len(addrs) else {})}


@tool("get_pseudocode_lines", "Hex-Rays pseudocode as numbered lines, each with the address of the instruction it came from (when known) — so a finding can be tied back to an exact address and a comment can be placed on the right line. Needs the decompiler.", {"address": ADDR}, ["address"])
def t_pseudocode_lines(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available.")
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    try:
        cfunc = ida_hexrays.decompile(pfn.start_ea)
    except ida_hexrays.DecompilationFailure as e:
        raise ToolError(f"Decompilation failed: {e}")
    if cfunc is None:
        raise ToolError("Decompilation failed (no result).")
    pseudocode = cfunc.get_pseudocode()  # generates the text; item coordinates exist only after this
    line_ea: "dict[int, int]" = {}
    for item in cfunc.treeitems:
        iea = item.ea
        if iea == BADADDR:
            continue
        try:
            coords = cfunc.find_item_coords(item)
        except Exception:
            continue
        if not coords:
            continue
        y = coords[1]
        if y not in line_ea or iea < line_ea[y]:
            line_ea[y] = iea
    lines = []
    for n, sl in enumerate(pseudocode):
        row = {"line": n + 1, "text": ida_lines.tag_remove(sl.line)}
        if n in line_ea:
            row["address"] = hexa(line_ea[n])
        lines.append(row)
    return {**func_summary(pfn), "lines": lines}


def _find_lvar(cfunc, name: str):
    for lv in cfunc.get_lvars():
        if lv.name == name:
            return lv
    return None


def _parse_type(text: str):
    tif = ida_typeinf.tinfo_t()
    decl = text.strip().rstrip(";")
    if not decl:
        raise ToolError("Give the type (C syntax, e.g. \"struct Player *\" or \"unsigned int\").")
    if ida_typeinf.parse_decl(tif, None, decl + ";", ida_typeinf.PT_SIL | ida_typeinf.PT_TYP) is None:
        # Maybe a declaration with a name ("int x"): take its type.
        if ida_typeinf.parse_decl(tif, None, decl + ";", ida_typeinf.PT_SIL) is None:
            raise ToolError(f"Couldn't parse the type “{text}”.")
    return tif


@tool("set_lvar_type", "Set the type of a local variable or argument in a function's pseudocode (Hex-Rays), e.g. name=\"v3\", type=\"struct Player *\". The variable keeps its name.", {"function": ADDR, "name": {"type": "string"}, "type": {"type": "string", "description": "C type, e.g. \"int\", \"char *\", \"struct Foo *\"."}}, ["function", "name", "type"], write=True)
def t_set_lvar_type(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available.")
    ea = parse_ea(args.get("function"), "function")
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    name = str(args.get("name") or "")
    cfunc = ida_hexrays.decompile(pfn.start_ea)
    lv = _find_lvar(cfunc, name) if cfunc else None
    if lv is None:
        raise ToolError(f"No variable called {name} in {ida_funcs.get_func_name(pfn.start_ea)} (decompile to see them).")
    tif = _parse_type(str(args.get("type") or ""))
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lv
    lsi.type = tif
    if not ida_hexrays.modify_user_lvar_info(pfn.start_ea, ida_hexrays.MLI_TYPE, lsi):
        raise ToolError(f"IDA refused the type {tif} for {name}.")
    return {**func_summary(pfn), "name": name, "type": str(tif)}


@tool("set_lvar_comment", "Set (or clear with an empty string) the comment shown next to a local variable's declaration in the pseudocode (Hex-Rays).", {"function": ADDR, "name": {"type": "string"}, "comment": {"type": "string"}}, ["function", "name", "comment"], write=True)
def t_set_lvar_comment(args):
    if not hexrays_ok():
        raise ToolError("The Hex-Rays decompiler isn't available.")
    ea = parse_ea(args.get("function"), "function")
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    name = str(args.get("name") or "")
    cfunc = ida_hexrays.decompile(pfn.start_ea)
    lv = _find_lvar(cfunc, name) if cfunc else None
    if lv is None:
        raise ToolError(f"No variable called {name} in {ida_funcs.get_func_name(pfn.start_ea)}.")
    lsi = ida_hexrays.lvar_saved_info_t()
    lsi.ll = lv
    lsi.cmt = str(args.get("comment") or "")
    if not ida_hexrays.modify_user_lvar_info(pfn.start_ea, ida_hexrays.MLI_CMT, lsi):
        raise ToolError(f"Couldn't set the comment on {name}.")
    return {**func_summary(pfn), "name": name, "comment": lsi.cmt}


@tool("mark_as_noreturn", "Mark a function as never returning (like exit / abort / a panic handler) — or clear the mark with noreturn=false. Callers are re-analysed so code after their calls is treated correctly.", {"address": ADDR, "noreturn": {"type": "boolean", "description": "Default true."}}, ["address"], write=True)
def t_noreturn(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    flag = args.get("noreturn", True)
    flag = bool(flag) if not isinstance(flag, str) else flag.lower() not in ("false", "0", "no")
    if flag:
        pfn.flags |= ida_funcs.FUNC_NORET
    else:
        pfn.flags &= ~ida_funcs.FUNC_NORET
    ida_funcs.update_func(pfn)
    ida_auto.reanalyze_callers(pfn.start_ea, flag)
    return {**func_summary(pfn), "noreturn": flag}


CALLING_CONVENTIONS = {
    "cdecl": "CM_CC_CDECL", "stdcall": "CM_CC_STDCALL", "fastcall": "CM_CC_FASTCALL", "thiscall": "CM_CC_THISCALL",
    "pascal": "CM_CC_PASCAL", "usercall": "CM_CC_SPECIAL", "userpurge": "CM_CC_SPECIALP", "ellipsis": "CM_CC_ELLIPSIS",
    "unknown": "CM_CC_UNKNOWN",
}


@tool("set_calling_convention", "Change a function's calling convention (cdecl, stdcall, fastcall, thiscall, pascal, usercall, userpurge) keeping its return type and arguments. On x64 Windows, fastcall is the normal convention.", {"address": ADDR, "convention": {"type": "string", "enum": list(CALLING_CONVENTIONS)}}, ["address", "convention"], write=True)
def t_set_cc(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    conv = str(args.get("convention") or "").lower().lstrip("_")
    const = CALLING_CONVENTIONS.get(conv)
    if not const:
        raise ToolError(f"Unknown convention {conv!r}; one of {', '.join(CALLING_CONVENTIONS)}.")
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, pfn.start_ea):
        if ida_typeinf.guess_tinfo(tif, pfn.start_ea) != ida_typeinf.GUESS_FUNC_OK:
            raise ToolError("IDA has no prototype for this function yet — set_type one first.")
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        raise ToolError("Couldn't read the function's prototype.")
    fi.cc = (fi.cc & ~ida_typeinf.CM_CC_MASK) | getattr(ida_typeinf, const)
    new_tif = ida_typeinf.tinfo_t()
    if not new_tif.create_func(fi) or not ida_typeinf.apply_tinfo(pfn.start_ea, new_tif, ida_typeinf.TINFO_DEFINITE):
        raise ToolError("IDA refused the new prototype.")
    return {**func_summary(pfn), "convention": conv, "prototype": ida_typeinf.print_type(pfn.start_ea, ida_typeinf.PRTYPE_1LINE) or ""}


# ───────────────────────── structure recovery ─────────────────────────

_FRAME_REGS = {"rbp", "rsp", "ebp", "esp", "sp", "fp", "x29", "r11"}
_SIZE_TYPES = {1: "unsigned __int8", 2: "unsigned __int16", 4: "unsigned __int32", 8: "unsigned __int64", 16: "__m128"}


def _operand_access(ea: int, n: int, op, insn):
    """A memory operand [reg+off] → (base register, offset, size, is_write) or None."""
    if op.type not in (ida_ua.o_displ, ida_ua.o_phrase):
        return None
    text = ida_lines.tag_remove(ida_ua.print_operand(ea, n) or "")
    m = re.search(r"\[([^\]]+)\]", text)
    if not m:
        return None
    parts = [p.strip() for p in re.split(r"\+", m.group(1))]
    if not parts:
        return None
    base = parts[0].lower()
    if not re.fullmatch(r"[a-z][a-z0-9]{0,4}", base) or base in _FRAME_REGS:
        return None
    off = 0
    for p in parts[1:]:
        pl = p.lower()
        if re.fullmatch(r"[0-9a-f]+h", pl):
            off += int(pl[:-1], 16)
        elif re.fullmatch(r"\d+", pl):
            off += int(pl)
        elif re.fullmatch(r"[a-z][a-z0-9]{0,4}(\*\d)?", pl):
            continue  # an index register: still the same base object
        else:
            return None  # a stack variable, a named global, …
    size = ida_ua.get_dtype_size(op.dtype) or 0
    feature = insn.get_canon_feature()
    is_write = bool(feature & getattr(ida_idp, f"CF_CHG{n + 1}", 0))
    return base, off, size, is_write


@tool("suggest_struct_from_accesses", "Recover a structure from how a function uses a pointer: every [register+offset] memory access in the function is collected per base register, and for the busiest registers (or the one you name) a draft C struct is returned with a field per distinct offset (typed by access size), plus the access list (offset, size, read/write, where). Edit the draft and feed it to declare_types, then set_type / set_lvar_type the pointer.", {"address": ADDR, "register": {"type": "string", "description": "Only this base register (e.g. rcx). Default: the 3 most-used."}, "name": {"type": "string", "description": "Name for the draft struct (default: from the function)."}}, ["address"])
def t_suggest_struct(args):
    ea = parse_ea(args.get("address"))
    pfn = func_of(ea)
    if not pfn:
        raise ToolError(f"{hexa(ea)} is not inside a function.")
    want = str(args.get("register") or "").lower() or None
    per_reg: "dict[str, list]" = {}
    insn = ida_ua.insn_t()
    for h in idautils.FuncItems(pfn.start_ea):
        if not ida_ua.decode_insn(insn, h):
            continue
        for n in range(8):
            op = insn.ops[n]
            if op.type == ida_ua.o_void:
                break
            acc = _operand_access(h, n, op, insn)
            if not acc:
                continue
            base, off, size, is_write = acc
            if want and base != want:
                continue
            per_reg.setdefault(base, []).append({"offset": off, "size": size, "access": "write" if is_write else "read", "at": hexa(h)})
    if not per_reg:
        raise ToolError("No [register+offset] accesses in this function" + (f" through {want}" if want else "") + ".")
    fname = ida_funcs.get_func_name(pfn.start_ea) or hexa(pfn.start_ea)
    base_name = str(args.get("name") or "").strip() or re.sub(r"\W+", "_", fname) + "_obj"
    regs = sorted(per_reg.items(), key=lambda kv: -len(kv[1]))[: (1 if want else 3)]
    results = []
    for reg, accesses in regs:
        fields: "dict[int, int]" = {}
        for a in accesses:
            fields[a["offset"]] = max(fields.get(a["offset"], 0), a["size"] or 0)
        lines, last_end = [], 0
        for off in sorted(fields):
            size = fields[off] or 1
            if off > last_end:
                lines.append(f"  unsigned __int8 gap_{last_end:X}[{off - last_end}];")
            ctype = _SIZE_TYPES.get(size)
            lines.append(f"  {ctype} field_{off:X};" if ctype else f"  unsigned __int8 field_{off:X}[{size}];")
            last_end = off + size
        sname = base_name if len(regs) == 1 else f"{base_name}_{reg}"
        results.append({
            "register": reg, "accesses": len(accesses), "fields": len(fields), "size": last_end,
            "struct_c": f"struct {sname} {{\n" + "\n".join(lines) + "\n};",
            "access_list": sorted(accesses, key=lambda a: (a["offset"], a["at"]))[:400],
        })
    return {**func_summary(pfn), "registers": results}


# ───────────────────────── signatures and similar code ─────────────────────────

@tool("list_signatures", "FLIRT signatures applied to this database: name, library, how many functions each matched.")
def t_list_sigs(args):
    out = []
    for i in range(ida_funcs.get_idasgn_qty()):
        try:
            d = ida_funcs.get_idasgn_desc_with_matches(i)
            out.append({"index": i, "name": d[0], "library": d[1], "matches": d[2]})
        except Exception:
            d = ida_funcs.get_idasgn_desc(i)
            out.append({"index": i, "name": d[0], "library": d[1]})
    return {"count": len(out), "signatures": out}


@tool("apply_signature", "Apply a FLIRT signature file (from IDA's sig folder, e.g. \"vc64ucrt\" or \"vc64seh\") to recognise library functions. The matching runs in IDA's auto-analysis: call wait_for_analysis, then list_signatures to see how many matched.", {"name": {"type": "string", "description": "Signature file name without extension (e.g. vc64ucrt)."}}, ["name"], write=True)
def t_apply_sig(args):
    name = str(args.get("name") or "").strip()
    if not name:
        raise ToolError("Give the signature name.")
    r = ida_funcs.plan_to_apply_idasgn(name)
    if not r:
        raise ToolError(f"IDA couldn't find or queue the signature {name!r} (look in IDA's sig/<processor> folder for the file name).")
    return {"name": name, "queued": True, "signature_index": r}


def _func_sig(pfn) -> list:
    """Instruction shape of a function: canonical mnemonic + operand kinds, one token per instruction."""
    insn = ida_ua.insn_t()
    toks = []
    for h in idautils.FuncItems(pfn.start_ea):
        if not ida_ua.decode_insn(insn, h):
            continue
        kinds = []
        for n in range(8):
            t = insn.ops[n].type
            if t == ida_ua.o_void:
                break
            kinds.append(str(t))
        toks.append(insn.get_canon_mnem() + ":" + ",".join(kinds))
    return toks


def _ngrams(toks: list, n: int = 3) -> set:
    if len(toks) < n:
        return {tuple(toks)} if toks else set()
    return {tuple(toks[i:i + n]) for i in range(len(toks) - n + 1)}


@tool("find_similar_functions", "Functions whose code looks like a given one (same instruction shapes, ignoring addresses and register names — finds inlined / duplicated / templated copies). Compares functions of comparable size, scores by shared instruction trigrams (0..1), returns the best matches. Stops when budget_ms runs out and says how far it got.", {"address": ADDR, "limit": {"type": "integer", "description": "Best N matches (default 10)."}, "min_similarity": {"type": "number", "description": "0..1, default 0.5."}, "budget_ms": {"type": "integer", "description": "Time budget in milliseconds (default 20000)."}}, ["address"], chunked=True)
def t_similar(args):
    limit = int_arg(args, "limit", 10, 1, 100)
    try:
        min_sim = float(args.get("min_similarity", 0.5))
    except (TypeError, ValueError):
        raise ToolError("min_similarity must be a number between 0 and 1.")
    deadline = budget_deadline(args, 20000)

    def setup():
        pfn = func_of(parse_ea(args.get("address")))
        if not pfn:
            raise ToolError("Not inside a function.")
        toks = _func_sig(pfn)
        if len(toks) < 3:
            raise ToolError("The function is too small to compare (fewer than 3 instructions).")
        return func_summary(pfn), pfn.start_ea, _ngrams(toks), len(toks), list(idautils.Functions())
    me, me_ea, me_grams, me_len, all_funcs = on_main(setup, label="find_similar_functions")
    lo, hi = me_len * 0.5, me_len * 2.0
    found, i, scanned, WINDOW = [], 0, 0, 300
    while i < len(all_funcs):
        chunk = all_funcs[i:i + WINDOW]

        def window():
            res, n = [], 0
            for fea in chunk:
                if fea == me_ea:
                    continue
                pfn = ida_funcs.get_func(fea)
                if not pfn:
                    continue
                # Cheap size gate before decoding anything.
                if not (lo * 2 <= (pfn.end_ea - pfn.start_ea) <= hi * 16):
                    continue
                toks = _func_sig(pfn)
                n += 1
                if not (lo <= len(toks) <= hi):
                    continue
                g = _ngrams(toks)
                inter = len(me_grams & g)
                if not inter:
                    continue
                sim = inter / len(me_grams | g)
                if sim >= min_sim:
                    res.append({"address": hexa(pfn.start_ea), "name": ida_funcs.get_func_name(pfn.start_ea) or "", "size": pfn.end_ea - pfn.start_ea, "instructions": len(toks), "similarity": round(sim, 3)})
            return res, n
        res, n = on_main(window, label="find_similar_functions")
        found.extend(res)
        scanned += n
        i += WINDOW
        if time.monotonic() > deadline and i < len(all_funcs):
            break
    found.sort(key=lambda r: -r["similarity"])
    return {"function": me, "instructions": me_len, "compared": scanned, "functions_total": len(all_funcs), "matches": found[:limit], **({"truncated": True, "scanned_up_to": i} if i < len(all_funcs) else {})}


# ───────────────────────── data ─────────────────────────

def _int_at(ea: int, size: int) -> "int | None":
    b = ida_bytes.get_bytes(ea, size)
    return int.from_bytes(b, "little") if b and len(b) == size else None


@tool("get_data_item", "What is at a data address, decoded: a string (its text and encoding), a number / array (each element's value), a pointer (and what it points to), a structure instance (each member's value), or code (the instruction). Also the item's name, size, type and how many places reference it.", {"address": ADDR, "max_elements": {"type": "integer", "description": "For arrays, default 64."}}, ["address"])
def t_data_item(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    head = ida_bytes.get_item_head(ea)
    flags = ida_bytes.get_flags(head)
    size = ida_bytes.get_item_size(head)
    out = {"address": hexa(head), "name": name_at(head), "size": size, "references": sum(1 for _ in idautils.XrefsTo(head))}
    if head != ea:
        out["note"] = f"{hexa(ea)} is inside the item that starts at {hexa(head)}"
    tif = ida_typeinf.tinfo_t()
    if ida_nalt.get_tinfo(tif, head):
        out["type"] = str(tif)
    if ida_bytes.is_code(flags):
        out.update(kind="code", text=(ida_lines.generate_disasm_line(head, ida_lines.GENDSM_REMOVE_TAGS) or "").strip())
        pf = func_of(head)
        if pf:
            out["function"] = func_summary(pf)
        return out
    if ida_bytes.is_strlit(flags):
        st = ida_nalt.get_str_type(head)
        raw = ida_bytes.get_strlit_contents(head, size, st) or b""
        enc = "utf-16" if (st & 0xFF) in (ida_nalt.STRTYPE_C_16, ida_nalt.STRTYPE_PASCAL_16, ida_nalt.STRTYPE_LEN2_16) else ("utf-32" if (st & 0xFF) == ida_nalt.STRTYPE_C_32 else "utf-8")
        try:
            text = raw.decode(enc, errors="replace") if enc != "utf-8" else raw.decode("utf-8", errors="replace")
        except Exception:
            text = raw.decode("latin-1", errors="replace")
        out.update(kind="string", encoding=enc, text=text[:20000], length=len(text))
        return out
    if ida_bytes.is_struct(flags):
        udt = ida_typeinf.udt_type_data_t()
        members = []
        if tif.is_struct() and tif.get_udt_details(udt):
            for m in udt:
                off, msize = m.offset // 8, max(1, m.size // 8)
                row = {"name": m.name, "offset": off, "size": msize, "type": str(m.type)}
                v = _int_at(head + off, msize) if msize <= 8 else None
                if v is not None:
                    row["value"] = v
                    row["hex"] = hexa(v)
                else:
                    b = ida_bytes.get_bytes(head + off, min(msize, 64)) or b""
                    row["hex"] = b.hex(" ")
                members.append(row)
        out.update(kind="struct", members=members)
        return out
    if ida_bytes.is_data(flags):
        elsize = ida_bytes.get_data_elsize(head, flags) or 1
        count = max(1, size // elsize)
        max_el = int_arg(args, "max_elements", 64, 1, 4096)
        values = []
        is_float = ida_bytes.is_float(flags) or ida_bytes.is_double(flags)
        for i in range(min(count, max_el)):
            at = head + i * elsize
            if is_float and elsize in (4, 8):
                b = ida_bytes.get_bytes(at, elsize)
                values.append(struct.unpack("<f" if elsize == 4 else "<d", b)[0] if b else None)
            else:
                v = _int_at(at, elsize) if elsize <= 8 else None
                values.append(hexa(v) if v is not None else (ida_bytes.get_bytes(at, elsize) or b"").hex())
        out.update(kind="float" if is_float else "data", element_size=elsize, count=count, values=values)
        if count > max_el:
            out["truncated"] = True
        if ida_bytes.is_off0(flags) and elsize in (4, 8):
            targets = []
            for i in range(min(count, max_el)):
                v = _int_at(head + i * elsize, elsize)
                if v is not None:
                    targets.append({"address": hexa(v), "name": name_at(v)})
            out.update(kind="pointer", targets=targets)
        if elsize == 1 and count > 1:
            b = ida_bytes.get_bytes(head, min(size, 256)) or b""
            out["ascii"] = "".join(chr(x) if 32 <= x < 127 else "." for x in b)
        return out
    b = ida_bytes.get_bytes(head, min(max(size, 16), 64)) or b""
    out.update(kind="undefined", hex=b.hex(" "), ascii="".join(chr(x) if 32 <= x < 127 else "." for x in b))
    return out


# ───────────────────────── bookmarks ─────────────────────────

MAX_BOOKMARKS = 1024


def _bookmarks() -> list:
    out = []
    for slot in range(1, MAX_BOOKMARKS + 1):
        ea = ida_idc.get_marked_pos(slot)
        if ea == BADADDR:
            continue
        pf = func_of(ea)
        out.append({"slot": slot, "address": hexa(ea), "name": name_at(ea), "description": ida_idc.get_mark_comment(slot) or "", **({"function": ida_funcs.get_func_name(pf.start_ea)} if pf else {})})
    return out


@tool("list_bookmarks", "IDA's bookmarks (Ctrl-M marks): slot, address, name, description, function.")
def t_list_bookmarks(args):
    bm = _bookmarks()
    return {"count": len(bm), "bookmarks": bm}


@tool("add_bookmark", "Add an IDA bookmark at an address with a description — a trail the user can walk with Ctrl-M. Returns the slot.", {"address": ADDR, "description": {"type": "string"}}, ["address", "description"], write=True)
def t_add_bookmark(args):
    ea = parse_ea(args.get("address"))
    check_in_db(ea)
    desc = str(args.get("description") or "").strip() or name_at(ea) or hexa(ea)
    for slot in range(1, MAX_BOOKMARKS + 1):
        if ida_idc.get_marked_pos(slot) == BADADDR:
            ida_idc.mark_position(ea, 0, 0, 0, slot, desc)
            if ida_idc.get_marked_pos(slot) != ea:
                raise ToolError("IDA didn't keep the bookmark.")
            return {"slot": slot, "address": hexa(ea), "description": desc}
    raise ToolError("All 1024 bookmark slots are used.")


@tool("delete_bookmark", "Remove an IDA bookmark by slot (see list_bookmarks).", {"slot": {"type": "integer"}}, ["slot"], write=True)
def t_del_bookmark(args):
    slot = int_arg(args, "slot", 0, 1, MAX_BOOKMARKS)
    ea = ida_idc.get_marked_pos(slot)
    if ea == BADADDR:
        raise ToolError(f"No bookmark in slot {slot}.")
    desc = ida_idc.get_mark_comment(slot) or ""
    before = len(_bookmarks())
    ida_idc.mark_position(BADADDR, 0, 0, 0, slot, "")
    after = len(_bookmarks())
    # IDA erases the entry and shifts the ones above it down a slot.
    return {"slot": slot, "was": hexa(ea), "description": desc, "deleted": after < before, "bookmarks_left": after, "note": "bookmarks in higher slots moved down by one" if after < before and after >= slot else ""}


# ───────────────────────── debugger control ─────────────────────────

DBG_EVENTS = None


def _dbg_event_name(code: int) -> str:
    global DBG_EVENTS
    if DBG_EVENTS is None:
        DBG_EVENTS = {}
        for n in ("NO_EVENT", "PROCESS_STARTED", "PROCESS_EXITED", "THREAD_STARTED", "THREAD_EXITED", "BREAKPOINT", "STEP", "EXCEPTION", "LIB_LOADED", "LIB_UNLOADED", "INFORMATION", "PROCESS_ATTACHED", "PROCESS_DETACHED", "PROCESS_SUSPENDED", "TRACE_FULL"):
            v = getattr(ida_idd, n, None)
            if isinstance(v, int):
                DBG_EVENTS[v] = n.lower()
    if code == -1:
        return "timeout"
    return DBG_EVENTS.get(code, str(code))


def _dbg_snapshot() -> dict:
    base = t_dbg({})
    if not base.get("debugger_on"):
        return base
    if base.get("state") == "suspended":
        ip = ida_dbg.get_ip_val()
        if ip is not None and ip != BADADDR:
            base["ip"] = hexa(int(ip))
            base["instruction"] = (ida_lines.generate_disasm_line(int(ip), ida_lines.GENDSM_REMOVE_TAGS) or "").strip()
            pf = func_of(int(ip))
            if pf:
                base["function"] = func_summary(pf)
        sp = ida_dbg.get_sp_val()
        if sp is not None and sp != BADADDR:
            base["sp"] = hexa(int(sp))
    return base


def _wait_suspended(timeout_s: float) -> dict:
    code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_SUSP, int(max(1, timeout_s)))
    return {"event": _dbg_event_name(code), **_dbg_snapshot()}


def _timeout_arg(args, default: int = 15) -> int:
    return int_arg(args, "timeout_s", default, 1, 120)


@tool("debugger_start", "Start the program under IDA's debugger (the one selected in IDA, win32 by default on Windows) and run until it is suspended: at break_at (a temporary stop), at the first breakpoint, or at the process entry if IDA is set to stop there. This RUNS the binary on this PC. Returns the stop event, the current instruction and the registers.", {"path": {"type": "string", "description": "Executable to run (default: the database's input file)."}, "args": {"type": "string", "description": "Command line."}, "directory": {"type": "string", "description": "Working directory."}, "break_at": ADDR, "timeout_s": {"type": "integer", "description": "How long to wait for the stop (default 15, max 120)."}}, write=True, destructive=True)
def t_dbg_start(args):
    if ida_dbg.is_debugger_on():
        raise ToolError("A process is already being debugged (debugger_stop first).")
    if ida_idd.get_dbg() is None:
        name = "win32" if sys.platform == "win32" else ("mac" if sys.platform == "darwin" else "linux")
        if not ida_dbg.load_debugger(name, False):
            raise ToolError(f"Couldn't load the {name} debugger — pick one in IDA (Debugger → Select debugger).")
    path = str(args.get("path") or "")
    cmdline = str(args.get("args") or "")
    sdir = str(args.get("directory") or "")
    if path or cmdline or sdir:
        ida_dbg.set_process_options(path or ida_nalt.get_input_file_path(), cmdline, sdir, "", "", 0)
    if args.get("break_at"):
        ea = parse_ea(args["break_at"], "break_at")
        if not ida_dbg.run_to(ea):
            raise ToolError("IDA couldn't start the process (run_to failed) — check Debugger → Process options.")
    else:
        r = ida_dbg.start_process(path, cmdline, sdir)
        if r == 0:
            raise ToolError("Starting the process was cancelled in IDA.")
        if r != 1:
            raise ToolError("IDA couldn't start the process — check Debugger → Process options and the debugger's log.")
    return _wait_suspended(_timeout_arg(args))


@tool("debugger_attach", "Attach IDA's debugger to a running process by pid and suspend it.", {"pid": {"type": "integer"}, "timeout_s": {"type": "integer"}}, ["pid"], write=True, destructive=True)
def t_dbg_attach(args):
    if ida_dbg.is_debugger_on():
        raise ToolError("A process is already being debugged (debugger_stop first).")
    pid = int_arg(args, "pid", 0, 1, 1 << 31)
    if ida_idd.get_dbg() is None:
        name = "win32" if sys.platform == "win32" else ("mac" if sys.platform == "darwin" else "linux")
        if not ida_dbg.load_debugger(name, False):
            raise ToolError(f"Couldn't load the {name} debugger.")
    r = ida_dbg.attach_process(pid, -1)
    if r != 1:
        raise ToolError(f"Couldn't attach to pid {pid} (result {r}).")
    return _wait_suspended(_timeout_arg(args))


@tool("debugger_step", "Drive the debugged process: action = step_over, step_into, step_out (run until the current function returns), continue (run until a breakpoint / exception / exit), or run_to (run until `address`). Waits up to timeout_s for the process to stop again and returns where it is (event, instruction, registers). A `timeout` event means it is still running.", {"action": {"type": "string", "enum": ["step_over", "step_into", "step_out", "continue", "run_to"]}, "address": {**ADDR, "description": "For run_to: where to stop."}, "timeout_s": {"type": "integer", "description": "Default 15, max 120."}}, ["action"], write=True)
def t_dbg_step(args):
    if not ida_dbg.is_debugger_on():
        raise ToolError("The debugger isn't running (debugger_start or debugger_attach first).")
    action = str(args.get("action") or "")
    if ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP and action != "continue":
        raise ToolError("The process is running — it must be suspended to step (wait for a breakpoint, or debugger_stop).")
    ok = True
    if action == "step_over":
        ok = ida_dbg.step_over()
    elif action == "step_into":
        ok = ida_dbg.step_into()
    elif action == "step_out":
        ok = ida_dbg.step_until_ret()
    elif action == "continue":
        ok = ida_dbg.continue_process()
    elif action == "run_to":
        ok = ida_dbg.run_to(parse_ea(args.get("address")))
    else:
        raise ToolError("action must be step_over, step_into, step_out, continue or run_to.")
    if not ok:
        raise ToolError(f"IDA refused {action}.")
    return {"action": action, **_wait_suspended(_timeout_arg(args))}


@tool("debugger_stop", "End the debugging session: kill the process (default) or detach from it and let it run.", {"detach": {"type": "boolean", "description": "true: detach instead of killing."}}, write=True, destructive=True)
def t_dbg_stop(args):
    if not ida_dbg.is_debugger_on():
        return {"debugger_on": False, "note": "nothing was being debugged"}
    detach = bool(args.get("detach"))
    ok = ida_dbg.detach_process() if detach else ida_dbg.exit_process()
    code, deadline = -1, time.monotonic() + 15
    while ida_dbg.is_debugger_on() and time.monotonic() < deadline:
        code = ida_dbg.wait_for_next_event(ida_dbg.WFNE_ANY, 2)
        if code in (getattr(ida_idd, "PROCESS_EXITED", -2), getattr(ida_idd, "PROCESS_DETACHED", -3)):
            break
    return {"stopped": bool(ok), "detached": detach, "last_event": _dbg_event_name(code), "debugger_on": ida_dbg.is_debugger_on()}


def _bpt_row(b) -> dict:
    kinds = {ida_idd.BPT_SOFT: "software", ida_idd.BPT_EXEC: "hardware exec", ida_idd.BPT_WRITE: "hardware write", ida_idd.BPT_READ: "hardware read", ida_idd.BPT_RDWR: "hardware read/write"}
    return {"address": hexa(b.ea), "enabled": b.enabled(), "type": kinds.get(b.type, str(b.type)), "size": b.size, "condition": b.condition or "", "pass_count": b.pass_count, "name": name_at(b.ea)}


@tool("list_breakpoints", "The debugger's breakpoints: address, enabled, type, size, condition, pass count.")
def t_list_bpts(args):
    out = []
    for i in range(ida_dbg.get_bpt_qty()):
        b = ida_dbg.bpt_t()
        if ida_dbg.getn_bpt(i, b):
            out.append(_bpt_row(b))
    return {"count": len(out), "breakpoints": out}


@tool("set_breakpoint", "Add (or update) a HARDWARE breakpoint — the CPU's debug registers, so not one byte of the program changes and code that checksums itself sees nothing. kind=exec (default) breaks when the address is executed; kind=write|read|access watches DATA at the address (give size). There are only 4 debug registers, so delete breakpoints you no longer need. An IDC condition that evaluates to false lets the process carry straight on (log without freezing it). Software (0xCC) breakpoints are deliberately not available: they patch the code and any self-check can see them.", {"address": ADDR, "kind": {"type": "string", "enum": ["exec", "write", "read", "access"], "description": "Default exec (break when it runs)."}, "size": {"type": "integer", "description": "Bytes watched by a data breakpoint (1, 2, 4, 8)."}, "condition": {"type": "string"}, "enabled": {"type": "boolean"}}, ["address"], write=True)
def t_set_bpt(args):
    ea = parse_ea(args.get("address"))
    # Hardware only: a software breakpoint writes 0xCC into the code, which a self-checking target can detect.
    kind = str(args.get("kind") or "exec")
    btype = {"exec": ida_idd.BPT_EXEC, "write": ida_idd.BPT_WRITE, "read": ida_idd.BPT_READ, "access": ida_idd.BPT_RDWR}.get(kind)
    if btype is None:
        raise ToolError("kind must be exec, write, read or access (hardware only — software breakpoints patch the code and are not offered).")
    size = int_arg(args, "size", 1, 1, 8)
    existing = ida_dbg.bpt_t()
    if not ida_dbg.get_bpt(ea, existing):
        if not ida_dbg.add_bpt(ea, size, btype):
            raise ToolError(f"IDA couldn't add a hardware {kind} breakpoint at {hexa(ea)}: they need a running process and a free debug register, and x86 has only 4. Delete one (list_breakpoints / delete_breakpoint) and try again.")
    b = ida_dbg.bpt_t()
    ida_dbg.get_bpt(ea, b)
    changed = False
    if "condition" in args:
        b.condition = str(args.get("condition") or "")
        changed = True
    if changed and not ida_dbg.update_bpt(b):
        raise ToolError("Couldn't update the breakpoint.")
    if "enabled" in args:
        ida_dbg.enable_bpt(ea, bool(args.get("enabled")))
    ida_dbg.get_bpt(ea, b)
    return _bpt_row(b)


@tool("delete_breakpoint", "Remove the breakpoint at an address.", {"address": ADDR}, ["address"], write=True)
def t_del_bpt(args):
    ea = parse_ea(args.get("address"))
    if not ida_dbg.del_bpt(ea):
        raise ToolError(f"No breakpoint at {hexa(ea)}.")
    return {"address": hexa(ea), "deleted": True}


@tool("set_register", "Set a register of the suspended process (e.g. rax = 0, rip = an address).", {"name": {"type": "string"}, "value": {"type": "string", "description": "Hex (0x…) or decimal."}}, ["name", "value"], write=True)
def t_set_reg(args):
    if not ida_dbg.is_debugger_on() or ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        raise ToolError("The process must be suspended under the debugger.")
    name = str(args.get("name") or "").strip()
    v = args.get("value")
    try:
        val = int(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else int(str(v).strip(), 0)
    except (TypeError, ValueError):
        raise ToolError("value must be a number (hex 0x… or decimal).")
    if not ida_dbg.set_reg_val(name, val):
        raise ToolError(f"Couldn't set {name} (unknown register?).")
    return {"name": name, "value": hexa(val), "now": ida_dbg.get_reg_val(name)}


@tool("write_memory", "Write bytes into the debugged process's memory (hex, e.g. \"90 90\"). Only the live process changes — the database is untouched (patch_bytes changes the database).", {"address": ADDR, "hex": {"type": "string"}}, ["address", "hex"], write=True, destructive=True)
def t_write_mem(args):
    if not ida_dbg.is_debugger_on():
        raise ToolError("The debugger isn't running.")
    ea = parse_ea(args.get("address"))
    try:
        data = bytes.fromhex(re.sub(r"[^0-9a-fA-F]", "", str(args.get("hex") or "")))
    except ValueError:
        raise ToolError("hex must be hex bytes, e.g. \"90 90\".")
    if not data:
        raise ToolError("Give the bytes.")
    n = ida_idd.dbg_write_memory(ea, data)
    if n is False or n is None or (isinstance(n, int) and n <= 0 and n is not True):
        raise ToolError(f"Couldn't write {len(data)} bytes at {hexa(ea)} in the process.")
    back = ida_idd.dbg_read_memory(ea, len(data)) or b""
    return {"address": hexa(ea), "size": len(data), "now": back.hex(" ")}


# ───────────────────────── reading a function's arguments at a stop ─────────────────────────

STR_PTR_TYPES = ("char *", "char*", "CHAR *", "LPSTR", "LPCSTR", "PCSTR", "PSTR")
WSTR_PTR_TYPES = ("wchar_t *", "wchar_t*", "WCHAR *", "LPWSTR", "LPCWSTR", "PCWSTR", "PWSTR", "OLECHAR *", "BSTR")


def _dbg_bytes(ea: int, size: int) -> bytes:
    try:
        return ida_idd.dbg_read_memory(ea, size) or b""
    except Exception:
        return b""


def _dbg_int(ea: int, size: int) -> "int | None":
    b = _dbg_bytes(ea, size)
    return int.from_bytes(b, "little") if len(b) == size else None


def _dbg_cstring(ea: int, wide: bool = False, limit: int = 300) -> "str | None":
    """Read a NUL-terminated string out of the debugged process (not the database: the process may have changed it)."""
    if not ea:
        return None
    step, raw = 2 if wide else 1, b""
    term = b"\x00\x00" if wide else b"\x00"
    while len(raw) < limit * step:
        chunk = _dbg_bytes(ea + len(raw), 64)
        if not chunk:
            break
        raw += chunk
        end = raw.find(term)
        if end >= 0:
            if wide:
                end += end % 2  # the match starts on the previous character's zero high byte
            raw = raw[:end]
            break
    if not raw:
        return ""
    try:
        return raw.decode("utf-16-le" if wide else "utf-8", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")


def _reg(name: str) -> "int | None":
    try:
        v = ida_dbg.get_reg_val(name)
        return int(v) if isinstance(v, (int, float)) else None
    except Exception:
        return None


def _func_prototype(pfn):
    """The function's argument list (name + type), from its prototype or IDA's guess. [] when unknown."""
    tif = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(tif, pfn.start_ea):
        try:
            if ida_typeinf.guess_tinfo(tif, pfn.start_ea) != ida_typeinf.GUESS_FUNC_OK:
                return None, []
        except Exception:
            return None, []
    fi = ida_typeinf.func_type_data_t()
    if not tif.get_func_details(fi):
        return None, []
    return fi, [(a.name or ("arg%d" % i), str(a.type)) for i, a in enumerate(fi)]


def _arg_slots(cc, count: int, bits: int) -> list:
    """Where each argument sits at the function's FIRST instruction (none of the prologue has run yet)."""
    slots = []
    if bits == 64:
        # Windows x64: the first four integer arguments are in registers, the rest above the shadow space.
        regs = ["rcx", "rdx", "r8", "r9"]
        for i in range(count):
            slots.append(("reg", regs[i]) if i < 4 else ("stack", 8 * (i + 1)))
        return slots
    masked = (cc & ida_typeinf.CM_CC_MASK) if isinstance(cc, int) else None
    lead = []
    if masked == ida_typeinf.CM_CC_THISCALL:
        lead = ["ecx"]
    elif masked == ida_typeinf.CM_CC_FASTCALL:
        lead = ["ecx", "edx"]
    for i in range(count):
        slots.append(("reg", lead[i]) if i < len(lead) else ("stack", 4 * (i - len(lead) + 1)))
    return slots


def _format_arg(name: str, type_str: str, value, size: int) -> dict:
    out = {"name": name, "type": type_str}
    if value is None:
        out["error"] = "couldn't read it"
        return out
    out["value"] = hexa(value)
    t = type_str.replace("const ", "").strip()
    one_level = t.count("*") <= 1  # char ** is an array of pointers, not a string
    if one_level and any(t.startswith(x) or t == x for x in WSTR_PTR_TYPES):
        out["text"] = _dbg_cstring(value, wide=True)
    elif one_level and any(t.startswith(x) or t == x for x in STR_PTR_TYPES):
        out["text"] = _dbg_cstring(value)
    elif t.endswith("*"):
        nm = name_at(value)
        if nm:
            out["points_to"] = nm
    else:
        out["int"] = value - (1 << (size * 8)) if value >= (1 << (size * 8 - 1)) else value
    return out


def _read_args(pfn, ip: int) -> dict:
    """The function's arguments, read from the suspended process. Only trustworthy at its first instruction."""
    if pfn is None or ida_dbg.get_process_state() != ida_dbg.DSTATE_SUSP:
        return {}
    bits = 64 if ida_ida.inf_is_64bit() else 32
    at_entry = ip == pfn.start_ea
    fi, args = _func_prototype(pfn)
    size = bits // 8
    sp = _reg("rsp" if bits == 64 else "esp")
    if not args:
        if not at_entry or sp is None:
            return {}
        # No prototype: show the raw slots a caller would have pushed, so there is still something to go on.
        raw = []
        for i in range(6):
            v = _dbg_int(sp + size * (i + 1), size)
            raw.append({"name": "arg%d" % i, "type": "?", **({"value": hexa(v)} if v is not None else {"error": "couldn't read it"})})
        return {"arguments": raw, "arguments_note": "no prototype for this function — these are the raw stack slots at its entry"}
    if not at_entry:
        return {"arguments_note": "arguments are only read at the function's first instruction (%s); the prologue has already run here" % hexa(pfn.start_ea)}
    if sp is None:
        return {}
    out = []
    for (name, type_str), slot in zip(args, _arg_slots(getattr(fi, "cc", None), len(args), bits)):
        value = _reg(slot[1]) if slot[0] == "reg" else _dbg_int(sp + slot[1], size)
        out.append(_format_arg(name, type_str, value, size))
    return {"arguments": out}


# ───────────────────────── debugger events (pushed by IDA, long-polled by Kiln) ─────────────────────────

EVENTS_KEEP = 200
_events: "collections.deque" = collections.deque(maxlen=EVENTS_KEEP)
_events_cv = threading.Condition()
_events_seq = 0


def _stack_top(n: int = 8) -> list:
    """The top n stack slots of the suspended thread: value and, when it points into a function, its name."""
    try:
        sp = int(ida_dbg.get_sp_val() or BADADDR)
    except Exception:
        return []
    if sp == BADADDR:
        return []
    width = 8 if ida_ida.inf_is_64bit() else 4
    data = ida_idd.dbg_read_memory(sp, width * n) or b""
    out = []
    for i in range(len(data) // width):
        v = int.from_bytes(data[i * width:(i + 1) * width], "little")
        row = {"offset": i * width, "value": hexa(v)}
        pf = func_of(v)
        if pf:
            row["points_to"] = f"{ida_funcs.get_func_name(pf.start_ea)}+{v - pf.start_ea:#x}"
        else:
            nm = name_at(v)
            if nm:
                row["points_to"] = nm
        out.append(row)
    return out


def _push_event(kind: str, ea: "int | None" = None, tid: "int | None" = None, extra: "dict | None" = None) -> None:
    """Called from IDA's debugger hooks (main thread). Snapshots the stop and wakes anyone waiting."""
    global _events_seq
    ev = {"event": kind, "time": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"), "source": _executor.busy_with if _executor else None}
    if tid is not None:
        ev["thread"] = tid
    try:
        if kind not in ("process_exited",) and ida_dbg.is_debugger_on():
            ip = int(ida_dbg.get_ip_val() or BADADDR) if ea is None else int(ea)
            if ip != BADADDR:
                ev["ip"] = hexa(ip)
                ev["instruction"] = (ida_lines.generate_disasm_line(ip, ida_lines.GENDSM_REMOVE_TAGS) or "").strip()
                pf = func_of(ip)
                if pf:
                    ev["function"] = {**func_summary(pf), "offset": ip - pf.start_ea}
                nm = name_at(ip)
                if nm:
                    ev["name"] = nm
            if ida_dbg.get_process_state() == ida_dbg.DSTATE_SUSP:
                regs = {}
                for r in _reg_names():
                    try:
                        v = ida_dbg.get_reg_val(r)
                        regs[r] = hexa(int(v)) if isinstance(v, int) else v
                    except Exception:
                        continue
                ev["registers"] = regs
                ev["stack"] = _stack_top()
                try:
                    ev.update(_read_args(func_of(ip) if ip != BADADDR else None, ip))
                except Exception as e:
                    ev["arguments_note"] = "couldn't read the arguments: %s: %s" % (type(e).__name__, e)
            if kind == "breakpoint" and ea is not None:
                b = ida_dbg.bpt_t()
                if ida_dbg.get_bpt(int(ea), b):
                    ev["breakpoint"] = _bpt_row(b)
    except Exception as e:  # never let a snapshot problem break the debugger
        ev["snapshot_error"] = f"{type(e).__name__}: {e}"
    if extra:
        ev.update(extra)
    with _events_cv:
        _events_seq += 1
        ev["seq"] = _events_seq
        _events.append(ev)
        _events_cv.notify_all()
    log(f"debugger event #{ev['seq']}: {kind}{' at ' + ev['ip'] if ev.get('ip') else ''}{' (during ' + ev['source'] + ')' if ev.get('source') else ''}")


class _DbgHooks(ida_dbg.DBG_Hooks):
    """IDA's debugger notifications → the event queue. Installed while the server is on."""

    def dbg_process_start(self, *a):
        _push_event("process_started", ea=a[2] if len(a) > 2 else None, tid=a[1] if len(a) > 1 else None, extra={"pid": a[0] if a else None, "module": a[3] if len(a) > 3 else ""})
        return 0

    def dbg_process_attach(self, *a):
        _push_event("process_attached", ea=a[2] if len(a) > 2 else None, tid=a[1] if len(a) > 1 else None, extra={"pid": a[0] if a else None})
        return 0

    def dbg_process_exit(self, *a):
        _push_event("process_exited", extra={"pid": a[0] if a else None, "exit_code": a[3] if len(a) > 3 else None})
        return 0

    def dbg_process_detach(self, *a):
        _push_event("process_detached", extra={"pid": a[0] if a else None})
        return 0

    def dbg_bpt(self, tid, ea, *rest):
        _push_event("breakpoint", ea=ea, tid=tid)
        return 0

    def dbg_exception(self, *a):
        # (pid, tid, ea, exc_code, exc_can_cont, exc_ea, exc_info)
        _push_event("exception", ea=a[2] if len(a) > 2 else None, tid=a[1] if len(a) > 1 else None,
                    extra={"code": hexa(int(a[3])) if len(a) > 3 and isinstance(a[3], int) else (a[3] if len(a) > 3 else None), "can_continue": bool(a[4]) if len(a) > 4 else None,
                           "exception_address": hexa(int(a[5])) if len(a) > 5 and isinstance(a[5], int) else None, "info": a[6] if len(a) > 6 else ""})
        return 0

    def dbg_suspend_process(self, *a):
        _push_event("suspended")
        return 0

    def dbg_step_into(self, *a):
        _push_event("step")
        return 0

    def dbg_step_over(self, *a):
        _push_event("step")
        return 0

    def dbg_step_until_ret(self, *a):
        _push_event("step")
        return 0


def _hook_debugger() -> None:
    if _state.dbg_hooks is None:
        try:
            _state.dbg_hooks = _DbgHooks()
            _state.dbg_hooks.hook()
        except Exception as e:
            _state.dbg_hooks = None
            log(f"debugger hooks not installed: {e}")


def _unhook_debugger() -> None:
    if _state.dbg_hooks is not None:
        try:
            _state.dbg_hooks.unhook()
        except Exception:
            pass
        _state.dbg_hooks = None


@tool("wait_for_debugger_event", "Wait for the debugged process to stop (a breakpoint, an exception, a pause, a step, the process starting or exiting) and return the events after `since` — each with the instruction, function, registers, top of the stack and the breakpoint that fired. Returns at once when there already are newer events, or after timeout_s with an empty list. Does not touch IDA's main thread while waiting. `source` names the Kiln tool that was running when the event happened (its result already reported it); events without a source came from the user or from a running process.", {"since": {"type": "integer", "description": "The last seq you have seen (0 = from the beginning of this session; the response's `seq` is the newest)."}, "timeout_s": {"type": "integer", "description": "How long to wait for a new event (default 25, max 60)."}}, chunked=True)
def t_wait_dbg_event(args):
    since = int_arg(args, "since", 0, 0, 1 << 31)
    timeout = int_arg(args, "timeout_s", 25, 0, 60)
    deadline = time.monotonic() + timeout
    with _events_cv:
        while True:
            fresh = [e for e in _events if e["seq"] > since]
            if fresh:
                break
            left = deadline - time.monotonic()
            if left <= 0:
                break
            _events_cv.wait(min(left, 5))
        newest = _events_seq
        oldest = _events[0]["seq"] if _events else 0
    return {"since": since, "seq": newest, "events": fresh, **({"dropped": True} if since and oldest > since + 1 else {})}


# ───────────────────────── MCP (JSON-RPC 2.0 over HTTP) ─────────────────────────

class _State:
    session_id = ""
    token = ""
    port = 0
    hexrays = False
    started_at = ""
    # Read on the main thread at start: the server thread must not touch the database itself.
    binary = ""
    ida_version = ""
    calls = 0
    errors = 0
    server: "ThreadingHTTPServer | None" = None
    thread: "threading.Thread | None" = None
    dbg_hooks = None


_state = _State()


def rpc_error(id_, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}


def handle_rpc(msg: dict) -> "dict | None":
    """One JSON-RPC message → its response (None for a notification)."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0" or not isinstance(msg.get("method"), str):
        return rpc_error(msg.get("id") if isinstance(msg, dict) else None, -32600, "Not a JSON-RPC 2.0 request")
    method, id_, params = msg["method"], msg.get("id"), msg.get("params") or {}
    if id_ is None:  # notification (initialized, cancelled, …)
        return None
    if method == "initialize":
        want = str(params.get("protocolVersion") or "")
        return {"jsonrpc": "2.0", "id": id_, "result": {
            "protocolVersion": want if want in PROTOCOL_VERSIONS else PROTOCOL_VERSIONS[1],
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": "kiln-ida", "version": PLUGIN_VERSION},
            "instructions": f"IDA Pro {_state.ida_version} session for {_state.binary}. Addresses are hex (0x401000) or names. Tools marked read-only never change the database; the others do.",
        }}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": id_, "result": {}}
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": id_, "result": {"tools": [t["def"] for t in TOOLS.values()]}}
    if method in ("resources/list", "resources/templates/list", "prompts/list"):
        return {"jsonrpc": "2.0", "id": id_, "result": {method.split("/")[0]: [], **({"resourceTemplates": []} if "templates" in method else {})}}
    if method == "tools/call":
        name = str(params.get("name") or "")
        t = TOOLS.get(name)
        if not t:
            return rpc_error(id_, -32602, f"Unknown tool: {name}")
        args = params.get("arguments") or {}
        if not isinstance(args, dict):
            return rpc_error(id_, -32602, "arguments must be an object")
        known = set(t["def"]["inputSchema"]["properties"])
        ignored = sorted(k for k in args if k not in known)
        if ignored:  # a model that invents arguments (e.g. "action") still gets its call
            args = {k: v for k, v in args.items() if k in known}
        _state.calls += 1
        started = time.monotonic()
        try:
            result = t["fn"](args) if t.get("chunked") else _executor.run(lambda: t["fn"](args), t["write"], name)
            if ignored and isinstance(result, dict):
                result["ignored_arguments"] = ignored
            text = json.dumps(result, ensure_ascii=False, default=str)
            log(f"{name} ok ({(time.monotonic() - started) * 1000:.0f} ms)")
            return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": text}], "structuredContent": result if isinstance(result, dict) else {"result": result}}}
        except ToolError as e:
            _state.errors += 1
            log(f"{name}: {e}")
            return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": str(e)}], "isError": True}}
        except Exception as e:
            _state.errors += 1
            return {"jsonrpc": "2.0", "id": id_, "result": {"content": [{"type": "text", "text": f"Internal error in {name}: {type(e).__name__}: {e}"}], "isError": True}}
    return rpc_error(id_, -32601, f"Method not supported: {method}")


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = f"KilnIDA/{PLUGIN_VERSION}"

    def log_message(self, *_args):  # quiet: our own log is enough
        pass

    def handle_one_request(self):
        """As the base class, but a client hanging up on an idle keep-alive connection ends it quietly.

        Kiln (and any HTTP/1.1 client with a connection pool) keeps sockets open between calls and closes them when
        idle. The base class lets the resulting ConnectionAbortedError / ConnectionResetError escape, and socketserver
        prints a traceback for it — noise in IDA's Output window for something completely normal.
        """
        try:
            return BaseHTTPRequestHandler.handle_one_request(self)
        except (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, socket.timeout):
            self.close_connection = True

    def _send(self, code: int, body: bytes = b"", ctype: str = "application/json", extra: "dict | None" = None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body)

    def _json(self, code: int, obj, extra=None):
        self._send(code, json.dumps(obj).encode("utf-8"), extra=extra)

    def _authorized(self) -> bool:
        if self.headers.get("Origin"):  # a browser page: never
            self._json(403, {"error": "browsers are not allowed"})
            return False
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        if host not in ("127.0.0.1", "localhost", "[::1]", "::1"):
            self._json(403, {"error": "local connections only"})
            return False
        auth = self.headers.get("Authorization") or ""
        got = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        if not got or not secrets.compare_digest(got, _state.token):
            self._json(401, {"error": "missing or wrong session key"})
            return False
        return True

    def do_GET(self):
        path = self.path.split("?")[0]
        if path == "/health":
            if not self._authorized():
                return
            self._json(200, {"ok": True, "session": _state.session_id, "binary": _state.binary, "pid": os.getpid(), "calls": _state.calls, "busy": _executor.busy_with if _executor else None, "events_seq": _events_seq})
        elif path == "/mcp":
            self._json(405, {"error": "no server-to-client stream; POST JSON-RPC to /mcp"}, {"Allow": "POST, DELETE"})
        else:
            self._json(404, {"error": "not found"})

    def do_DELETE(self):
        if not self._authorized():
            return
        self._send(204)

    def do_POST(self):
        if self.path.split("?")[0] != "/mcp":
            return self._json(404, {"error": "not found"})
        if not self._authorized():
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length > MAX_BODY:
            return self._json(413, {"error": "request too large"})
        raw = self.rfile.read(length) if length else b""
        try:
            msg = json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._json(200, rpc_error(None, -32700, "Invalid JSON"))
        if isinstance(msg, list):
            responses = [r for r in (handle_rpc(m) for m in msg) if r is not None]
            if not responses:
                return self._send(202)
            return self._json(200, responses, {"Mcp-Session-Id": _state.session_id})
        resp = handle_rpc(msg)
        if resp is None:
            return self._send(202)
        self._json(200, resp, {"Mcp-Session-Id": _state.session_id})


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False  # a port in use must fail, not be shared

    def handle_error(self, request, client_address):
        """Never print a traceback to IDA's Output window: a dropped connection is normal, anything else goes to the log."""
        e = sys.exc_info()[1]
        if isinstance(e, (ConnectionAbortedError, ConnectionResetError, BrokenPipeError, socket.timeout)):
            return
        log(f"HTTP error from {client_address[0] if client_address else '?'}: {traceback.format_exc(limit=4)}")


# ───────────────────────── session registration ─────────────────────────

def session_file() -> str:
    return os.path.join(sessions_dir(), f"{_state.session_id}.json")


def register_session() -> None:
    info = {
        "id": _state.session_id, "plugin": "kiln-ida", "version": PLUGIN_VERSION,
        "name": ida_nalt.get_root_filename() or os.path.basename(idc.get_idb_path() or "") or "IDA",
        "binary": ida_nalt.get_root_filename() or "", "input_path": ida_nalt.get_input_file_path() or "", "idb_path": idc.get_idb_path() or "",
        "pid": os.getpid(), "host": "127.0.0.1", "port": _state.port, "url": f"http://127.0.0.1:{_state.port}/mcp", "token": _state.token,
        "ida_version": ida_kernwin.get_kernel_version(), "sdk": idaapi.IDA_SDK_VERSION, "python": sys.version.split()[0],
        "hexrays": _state.hexrays, "processor": ida_ida.inf_get_procname(), "bits": 64 if ida_ida.inf_is_64bit() else 32,
        "gui": bool(ida_kernwin.is_idaq()), "started_at": _state.started_at, "tools": len(TOOLS),
    }
    os.makedirs(sessions_dir(), exist_ok=True)
    _atomic_write(session_file(), json.dumps(info, indent=2))
    # Files left by IDA instances that are gone (crashed, killed) are cleaned up here.
    for fn in os.listdir(sessions_dir()):
        if not fn.endswith(".json") or fn == f"{_state.session_id}.json":
            continue
        p = os.path.join(sessions_dir(), fn)
        try:
            with open(p, "r", encoding="utf-8") as f:
                pid = int(json.load(f).get("pid") or 0)
            if not pid_alive(pid):
                os.remove(p)
        except (OSError, ValueError):
            continue


def unregister_session() -> None:
    try:
        os.remove(session_file())
    except OSError:
        pass


# ───────────────────────── start / stop ─────────────────────────

def server_on() -> bool:
    return _state.server is not None


def start_server(base_port: int) -> str:
    """Starts the server; returns the status line. Must be called on the main thread."""
    if server_on():
        return f"already running on port {_state.port}"
    if ida_hexrays:
        try:
            _state.hexrays = bool(ida_hexrays.init_hexrays_plugin())
        except Exception:
            _state.hexrays = False
    _state.binary = ida_nalt.get_root_filename() or ""
    _state.ida_version = ida_kernwin.get_kernel_version()
    last = None
    for port in range(base_port, base_port + PORT_RANGE):
        try:
            srv = _Server(("127.0.0.1", port), _Handler)
        except OSError as e:
            last = e
            continue
        _state.server, _state.port = srv, port
        _state.session_id = secrets.token_hex(4)
        _state.token = secrets.token_urlsafe(24)
        _state.started_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        _state.calls = _state.errors = 0
        _hook_debugger()
        t = threading.Thread(target=srv.serve_forever, name="kiln-ida-mcp", daemon=True)
        _state.thread = t
        t.start()
        register_session()
        log(f"server ON — session {_state.session_id}, http://127.0.0.1:{port}/mcp, {len(TOOLS)} tools, Hex-Rays {'yes' if _state.hexrays else 'no'}")
        return f"on, port {port}, session {_state.session_id}"
    raise OSError(f"no free port in {base_port}–{base_port + PORT_RANGE - 1}: {last}")


def stop_server(reason: str = "stopped") -> None:
    _unhook_debugger()
    srv = _state.server
    if not srv:
        return
    unregister_session()
    _state.server = None
    try:
        srv.shutdown()
        srv.server_close()
    except Exception:
        pass
    log(f"server OFF ({reason}) — session {_state.session_id} after {_state.calls} call(s)")
    _state.session_id = _state.token = ""
    _state.port = 0


# ───────────────────────── IDA plugin: menu, actions, lifecycle ─────────────────────────

ACT_TOGGLE, ACT_STATUS, ACT_AUTOSTART, ACT_COPY = "kilnida:toggle", "kilnida:status", "kilnida:autostart", "kilnida:copy"
MENU = "Edit/Plugins/Kiln IDA/"


class _Action(ida_kernwin.action_handler_t):
    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def activate(self, ctx):
        try:
            self.fn()
        except Exception as e:
            log(f"error: {e}")
            ida_kernwin.warning(f"{PLUGIN_NAME}: {e}")
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class _UIHooks(ida_kernwin.UI_Hooks):
    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def ready_to_run(self):
        for act in (ACT_TOGGLE, ACT_STATUS, ACT_COPY, ACT_AUTOSTART):
            ida_kernwin.attach_action_to_menu(MENU, act, ida_kernwin.SETMENU_APP)
        self.plugin.refresh_labels()
        if self.plugin.prefs.get("autostart", True):
            self.plugin.toggle(start=True)
        self.unhook()


class KilnIdaPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "Kiln IDA — MCP server for Kiln and other AI clients"
    help = "Edit → Plugins → Kiln IDA"
    wanted_name = PLUGIN_NAME
    wanted_hotkey = "Ctrl-Alt-K"

    def init(self):
        global _executor
        _executor = _Executor()
        self.prefs = load_prefs()
        ida_kernwin.register_action(ida_kernwin.action_desc_t(ACT_TOGGLE, "Start MCP server", _Action(self.toggle), None, "Start or stop the Kiln IDA MCP server for this database"))
        ida_kernwin.register_action(ida_kernwin.action_desc_t(ACT_STATUS, "Status…", _Action(self.show_status), None, "Session id, port and call counts"))
        ida_kernwin.register_action(ida_kernwin.action_desc_t(ACT_COPY, "Copy connection details", _Action(self.copy_details), None, "Copy the MCP address and session key to the clipboard"))
        ida_kernwin.register_action(ida_kernwin.action_desc_t(ACT_AUTOSTART, "Start automatically when a database opens", _Action(self.toggle_autostart), None, "Autostart on/off (for every database)"))
        self._hooks = _UIHooks(self)
        self._hooks.hook()
        log(f"plugin {PLUGIN_VERSION} loaded (IDA {ida_kernwin.get_kernel_version()}, Python {sys.version.split()[0]}); autostart {'on' if self.prefs.get('autostart', True) else 'off'}")
        return idaapi.PLUGIN_KEEP

    def run(self, arg):  # the hotkey / Edit → Plugins → Kiln IDA
        self.toggle()

    def term(self):
        try:
            self._hooks.unhook()
        except Exception:
            pass
        stop_server("database closed")
        for act in (ACT_TOGGLE, ACT_STATUS, ACT_COPY, ACT_AUTOSTART):
            ida_kernwin.unregister_action(act)

    # ── actions ──

    def toggle(self, start: "bool | None" = None):
        if server_on() and start is not True:
            stop_server("stopped by the user")
            ida_kernwin.msg(f"[{PLUGIN_NAME}] Server is OFF — this session is no longer available to Kiln.\n")
        elif not server_on():
            try:
                status = start_server(int(self.prefs.get("port") or DEFAULT_PORT))
                ida_kernwin.msg(f"[{PLUGIN_NAME}] Server is ON ({status}). In Kiln, type /ida to attach this session.\n")
            except OSError as e:
                log(f"couldn't start: {e}")
                ida_kernwin.warning(f"{PLUGIN_NAME} couldn't start its server: {e}")
        self.refresh_labels()

    def toggle_autostart(self):
        self.prefs["autostart"] = not self.prefs.get("autostart", True)
        save_prefs(self.prefs)
        log(f"autostart {'on' if self.prefs['autostart'] else 'off'}")
        self.refresh_labels()

    def refresh_labels(self):
        on = server_on()
        ida_kernwin.update_action_label(ACT_TOGGLE, f"Stop MCP server (ON — port {_state.port}, session {_state.session_id})" if on else "Start MCP server (OFF)")
        ida_kernwin.update_action_label(ACT_AUTOSTART, f"Start automatically when a database opens [{'on' if self.prefs.get('autostart', True) else 'off'}]")

    def show_status(self):
        if server_on():
            busy = _executor.busy_with if _executor else None
            text = (f"{PLUGIN_NAME} {PLUGIN_VERSION}\n\nServer: ON\nSession: {_state.session_id}\nAddress: http://127.0.0.1:{_state.port}/mcp\n"
                    f"Database: {idc.get_idb_path()}\nHex-Rays: {'available' if _state.hexrays else 'not available'}\nTools: {len(TOOLS)}\n"
                    f"Calls served: {_state.calls} ({_state.errors} failed)\nNow: {('running ' + busy) if busy else 'idle'}\n\nRegistered for Kiln in:\n{session_file()}")
        else:
            text = f"{PLUGIN_NAME} {PLUGIN_VERSION}\n\nServer: OFF — this session is offline for Kiln.\nEdit → Plugins → Kiln IDA → Start MCP server (or Ctrl-Alt-K)."
        ida_kernwin.info(text)

    def copy_details(self):
        if not server_on():
            ida_kernwin.warning(f"{PLUGIN_NAME}: the server is off.")
            return
        text = f"url=http://127.0.0.1:{_state.port}/mcp\nkey={_state.token}\nsession={_state.session_id}"
        try:
            from PyQt5 import QtWidgets
            QtWidgets.QApplication.clipboard().setText(text)
            ida_kernwin.msg(f"[{PLUGIN_NAME}] Connection details copied to the clipboard.\n")
        except Exception:
            ida_kernwin.info(text)


def PLUGIN_ENTRY():
    return KilnIdaPlugin()
