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

import contextlib
import ctypes
import datetime
import io
import json
import os
import re
import secrets
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
import ida_xref
import idautils
import idc

try:
    import ida_hexrays
except ImportError:  # no decompiler in this installation
    ida_hexrays = None

PLUGIN_VERSION = "0.1.0"
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
                items.append({"address": hexa(it.ea), "length": it.length, "type": "utf16" if it.strtype == ida_nalt.STRTYPE_C_16 else "c", "text": str(it)})
            except Exception:
                continue
        c.update(at=now, minlen=min_length, items=items)
    return c["items"]


# ───────────────────────── tools ─────────────────────────

TOOLS: "dict[str, dict]" = {}


def tool(name: str, description: str, params: dict | None = None, required: list | None = None, *, write: bool = False, destructive: bool = False, title: str | None = None):
    """Registers a tool. `write`: runs under MFF_WRITE and is marked as modifying the database."""
    def deco(fn):
        TOOLS[name] = {
            "fn": fn, "write": write,
            "def": {
                "name": name, "description": description,
                "inputSchema": {"type": "object", "properties": params or {}, **({"required": required} if required else {})},
                "annotations": {"title": title or name.replace("_", " "), "readOnlyHint": not write, "destructiveHint": destructive, "idempotentHint": not write, "openWorldHint": False},
            },
        }
        return fn
    return deco


ADDR = {"type": "string", "description": "An address (hex, e.g. 0x401000) or a name (e.g. sub_401000, main)."}
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


@tool("search_bytes", "Find a byte pattern (hex, ? for a wildcard byte, e.g. \"48 8B 05 ?? ?? ?? ??\"). Returns the addresses found and the function each is in.", {"pattern": {"type": "string"}, "start": ADDR, "end": ADDR, "limit": {"type": "integer", "description": "Default 100."}}, ["pattern"])
def t_search_bytes(args):
    pat = str(args.get("pattern") or "").strip()
    if not pat:
        raise ToolError("Give the pattern.")
    start = parse_ea(args["start"]) if args.get("start") else ida_ida.inf_get_min_ea()
    end = parse_ea(args["end"]) if args.get("end") else ida_ida.inf_get_max_ea()
    limit = int_arg(args, "limit", 100, 1, 1000)
    vec = ida_bytes.compiled_binpat_vec_t()
    # IDA 9: returns an error message, '' on success (older versions: a bool).
    r = ida_bytes.parse_binpat_str(vec, start, pat, 16)
    if (isinstance(r, str) and r) or r is False or len(vec) == 0:
        raise ToolError(f"Couldn't parse the pattern “{pat}” — hex bytes separated by spaces, ? or ?? for any byte.{(' ' + r) if isinstance(r, str) and r else ''}")
    flags = getattr(ida_bytes, "BIN_SEARCH_FORWARD", 0) | getattr(ida_bytes, "BIN_SEARCH_NOBREAK", 0)
    hits, ea = [], start
    while len(hits) < limit and ea < end:
        r = ida_bytes.bin_search(ea, end, vec, flags)
        found = r[0] if isinstance(r, tuple) else r
        if found is None or found == BADADDR:
            break
        pf = func_of(found)
        hits.append({"address": hexa(found), **({"function": ida_funcs.get_func_name(pf.start_ea), "function_address": hexa(pf.start_ea)} if pf else {})})
        ea = found + 1
    return {"pattern": pat, "count": len(hits), "hits": hits, **({"truncated": True} if len(hits) >= limit else {})}


@tool("search_text", "Search the disassembly text (instructions, operands, names, comments) for a string. Returns matching lines with their addresses. Stops after `limit` hits or 20 seconds.", {"text": {"type": "string"}, "case_sensitive": {"type": "boolean"}, "start": ADDR, "limit": {"type": "integer", "description": "Default 50."}}, ["text"])
def t_search_text(args):
    text = str(args.get("text") or "")
    if not text:
        raise ToolError("Give the text.")
    ea = parse_ea(args["start"]) if args.get("start") else ida_ida.inf_get_min_ea()
    limit = int_arg(args, "limit", 50, 1, 500)
    flags = ida_search.SEARCH_DOWN | (ida_search.SEARCH_CASE if args.get("case_sensitive") else 0)
    hits, deadline, end = [], time.monotonic() + 20, ida_ida.inf_get_max_ea()
    while len(hits) < limit and ea != BADADDR and ea < end and time.monotonic() < deadline:
        ea = ida_search.find_text(ea, 0, 0, text, flags)
        if ea == BADADDR:
            break
        pf = func_of(ea)
        hits.append({"address": hexa(ea), "text": (ida_lines.generate_disasm_line(ea, ida_lines.GENDSM_REMOVE_TAGS) or "").strip(), **({"function": ida_funcs.get_func_name(pf.start_ea)} if pf else {})})
        ea = ida_bytes.next_head(ea, end)
    return {"text": text, "count": len(hits), "hits": hits, **({"truncated": True} if len(hits) >= limit or time.monotonic() >= deadline else {})}


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


@tool("get_debugger_state", "The debugger: whether a process is being debugged, its state, threads, and the current thread's registers.")
def t_dbg(args):
    if not ida_dbg.is_debugger_on():
        return {"debugger_on": False}
    st = ida_dbg.get_process_state()
    state = {ida_dbg.DSTATE_SUSP: "suspended", ida_dbg.DSTATE_RUN: "running", ida_dbg.DSTATE_NOTASK: "no process"}.get(st, str(st))
    threads = [{"id": ida_dbg.getn_thread(i), "name": ida_dbg.getn_thread_name(i) or ""} for i in range(ida_dbg.get_thread_qty())]
    regs = {}
    if st == ida_dbg.DSTATE_SUSP:
        for r in list(ida_idp.ph_get_regnames())[:64]:
            try:
                v = ida_dbg.get_reg_val(r)
                regs[r] = hexa(int(v)) if isinstance(v, int) else v
            except Exception:
                continue
    return {"debugger_on": True, "state": state, "current_thread": ida_dbg.get_current_thread(), "threads": threads, "registers": regs}


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
        _state.calls += 1
        started = time.monotonic()
        try:
            result = _executor.run(lambda: t["fn"](args), t["write"], name)
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
            self._json(200, {"ok": True, "session": _state.session_id, "binary": _state.binary, "pid": os.getpid(), "calls": _state.calls, "busy": _executor.busy_with if _executor else None})
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
        t = threading.Thread(target=srv.serve_forever, name="kiln-ida-mcp", daemon=True)
        _state.thread = t
        t.start()
        register_session()
        log(f"server ON — session {_state.session_id}, http://127.0.0.1:{port}/mcp, {len(TOOLS)} tools, Hex-Rays {'yes' if _state.hexrays else 'no'}")
        return f"on, port {port}, session {_state.session_id}"
    raise OSError(f"no free port in {base_port}–{base_port + PORT_RANGE - 1}: {last}")


def stop_server(reason: str = "stopped") -> None:
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
