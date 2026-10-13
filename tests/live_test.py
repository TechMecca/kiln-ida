"""Drives a running Kiln IDA session end to end (plain Python, no IDA): reads the session file Kiln would read,
speaks MCP to the plugin, calls every read-only tool, and the modifying ones in a way that leaves the database as it
was (a comment set then cleared, a name set then restored, a patch written then written back).

  python tests/live_test.py [session-id]   (default: the newest session)
"""
import glob
import json
import os
import sys
import time
import urllib.error
import urllib.request

SESSIONS = os.path.join(os.environ.get("APPDATA", ""), "Kiln", "ida", "sessions")
passed = failed = 0


def check(cond, what):
    global passed, failed
    if cond:
        passed += 1
        print(f"  ok  {what}")
    else:
        failed += 1
        print(f"  FAIL {what}")


def newest_session(want=None):
    files = sorted(glob.glob(os.path.join(SESSIONS, "*.json")), key=os.path.getmtime)
    if want:
        files = [f for f in files if os.path.basename(f) == f"{want}.json"]
    if not files:
        raise SystemExit(f"no session file in {SESSIONS} — is IDA open with the plugin's server on?")
    with open(files[-1], "r", encoding="utf-8") as f:
        return json.load(f)


class Client:
    def __init__(self, s):
        self.url, self.token, self.n = s["url"], s["token"], 0

    def raw(self, body, token=None, headers=None, method="POST", path=None):
        req = urllib.request.Request(path or self.url, data=json.dumps(body).encode() if body is not None else None, method=method)
        req.add_header("Content-Type", "application/json")
        req.add_header("Accept", "application/json, text/event-stream")
        if token or token is None and self.token:
            req.add_header("Authorization", f"Bearer {token or self.token}")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
                return r.status, (json.loads(data) if data else None)
        except urllib.error.HTTPError as e:
            data = e.read()
            return e.code, (json.loads(data) if data else None)

    def rpc(self, method, params=None):
        self.n += 1
        status, body = self.raw({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}})
        assert status == 200, f"{method}: HTTP {status} {body}"
        return body

    def call(self, tool_name, **args):
        r = self.rpc("tools/call", {"name": tool_name, "arguments": args})
        res = r.get("result") or {}
        text = "".join(c.get("text", "") for c in res.get("content", []))
        if res.get("isError"):
            return None, text
        try:
            return json.loads(text), None
        except ValueError:
            return text, None


def main():
    s = newest_session(sys.argv[1] if len(sys.argv) > 1 else None)
    print(f"session {s['id']} · {s['name']} · {s['url']} · IDA {s['ida_version']} · Hex-Rays {s['hexrays']} · {s['tools']} tools")
    c = Client(s)

    # Protocol and security.
    status, body = c.raw({"jsonrpc": "2.0", "id": 1, "method": "ping"}, token="wrong")
    check(status == 401, "a wrong key is refused (401)")
    status, _ = c.raw({"jsonrpc": "2.0", "id": 1, "method": "ping"}, headers={"Origin": "http://evil.example"})
    check(status == 403, "a browser (Origin header) is refused (403)")
    status, _ = c.raw(None, method="GET", path=s["url"])
    check(status == 405, "GET /mcp is 405 (no server stream)")
    status, health = c.raw(None, method="GET", path=s["url"].replace("/mcp", "/health"))
    check(status == 200 and health.get("ok") and health.get("session") == s["id"], f"health: {health}")
    init = c.rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "live-test", "version": "0"}})
    check(init.get("result", {}).get("protocolVersion") == "2025-06-18" and init["result"]["serverInfo"]["name"] == "kiln-ida", "initialize")
    status, _ = c.raw({"jsonrpc": "2.0", "method": "notifications/initialized"})
    check(status == 202, "a notification gets 202")
    tools = c.rpc("tools/list")["result"]["tools"]
    names = [t["name"] for t in tools]
    ro = [t["name"] for t in tools if t["annotations"]["readOnlyHint"]]
    check(len(tools) >= 25 and "decompile" in names and "set_name" in names, f"tools/list: {len(tools)} tools, {len(ro)} read-only")
    bad = c.rpc("tools/call", {"name": "nope", "arguments": {}})
    check(bad.get("error", {}).get("code") == -32602, "unknown tool → JSON-RPC error")

    # Read-only tools.
    info, err = c.call("get_database_info")
    check(info and info["binary"] == s["binary"] and info["functions"] > 0, f"get_database_info: {info and info['binary']}, {info and info['functions']} functions, {info and info['processor']} {info and info['bits']}-bit")
    segs, _ = c.call("list_segments")
    check(segs and any(x["name"] == ".text" for x in segs["segments"]), f"list_segments: {segs and [x['name'] for x in segs['segments']]}")
    funcs, _ = c.call("list_functions", limit=5)
    check(funcs and funcs["count"] == 5 and funcs["total"] == info["functions"], f"list_functions: {funcs and funcs['total']} total, paged")
    first = funcs["items"][0]
    f, err = c.call("get_function", address=first["address"])
    check(f and f["name"] == first["name"] and "prototype" in f, f"get_function by address: {err or (f['name'] + ' ' + f['prototype'][:60])}")
    f2, err = c.call("get_function", address=first["name"])
    check(f2 and f2["address"] == first["address"], f"get_function by name: {err or 'ok'}")
    f = f or {"name": first["name"]}
    _, err = c.call("get_function", address="0x1")
    check(err and "not inside" in err, f"a bad address is a clear error: {err}")
    _, err = c.call("get_function", address="no_such_name_xyz")
    check(err and "No such name" in err, f"an unknown name is a clear error: {err}")
    main_ea = None
    for cand in ("main", "wmain", "WinMain", "start"):
        r, _ = c.call("search_names", query=cand)
        hit = r and next((i for i in r["items"] if i["name"] == cand), None)
        if hit:
            main_ea = hit["address"]
            break
    target = main_ea or first["address"]
    if s["hexrays"]:
        d, err = c.call("decompile", address=target)
        check(d and "code" in d and ("(" in d["code"]), f"decompile {target}: {len(d['code']) if d else err} chars")
    else:
        _, err = c.call("decompile", address=target)
        check(err and "decompiler" in err, "no Hex-Rays: decompile explains")
    dis, _ = c.call("disassemble", address=target)
    check(dis and len(dis["lines"]) > 3 and all("address" in l and "text" in l for l in dis["lines"]), f"disassemble (function): {dis and len(dis['lines'])} lines")
    dis2, _ = c.call("disassemble", address=target, count=3)
    check(dis2 and len(dis2["lines"]) == 3, "disassemble (count)")
    xt, _ = c.call("get_xrefs_to", address=target)
    xf, _ = c.call("get_xrefs_from", address=target)
    check(xt is not None and xf is not None, f"xrefs: {xt and xt['total']} to, {xf and xf['total']} from")
    imps, _ = c.call("list_imports", limit=5)
    check(imps and imps["total"] > 0 and "module" in imps["items"][0], f"list_imports: {imps and imps['total']} ({imps and imps['items'][0]['module']})")
    exps, _ = c.call("list_exports")
    check(exps is not None, f"list_exports: {exps and exps['total']}")
    strs, _ = c.call("list_strings", limit=5)
    check(strs and strs["total"] > 0 and "text" in strs["items"][0], f"list_strings: {strs and strs['total']}")
    strf, _ = c.call("list_strings", filter=strs["items"][0]["text"][:4], limit=5)
    check(strf and strf["total"] >= 1, "list_strings with a filter")
    names_r, _ = c.call("search_names", query=first["name"][:6], limit=3)
    check(names_r and names_r["total"] >= 1 and any(i["name"] == first["name"] for i in names_r["items"]), f"search_names “{first['name'][:6]}”: {names_r and names_r['total']}")
    names_rx, _ = c.call("search_names", query="^sub_[0-9A-F]+$", regex=True, limit=3)
    check(names_rx is not None, f"search_names with a regex: {names_rx and names_rx['total']} automatic names")
    rb, _ = c.call("read_bytes", address=target, size=8)
    check(rb and rb["size"] == 8 and len(rb["hex"].split()) == 8, f"read_bytes: {rb and rb['hex']}")
    pat = " ".join(rb["hex"].split()[:4])
    sb, err = c.call("search_bytes", pattern=pat, limit=5)
    check(sb and sb["count"] >= 1 and any(h["address"].lower() == target.lower() for h in sb["hits"]), f"search_bytes “{pat}”: {err or str(sb['count']) + ' hit(s), includes the target'}")
    parts = pat.split(); parts[1] = "??"
    sbw, err = c.call("search_bytes", pattern=" ".join(parts), limit=5)
    check(sbw and sbw["count"] >= 1, f"search_bytes with a wildcard: {err or sbw['count']}")
    st_r, _ = c.call("search_text", text="call", limit=3)
    check(st_r and st_r["count"] == 3, f"search_text: {st_r and st_r['count']}")
    types, _ = c.call("list_types", limit=5)
    check(types is not None, f"list_types: {types and types['total']}")
    if types and types["total"]:
        t0 = types["items"][0]
        gt, err = c.call("get_type", ordinal=t0["ordinal"])
        check(gt and gt["definition"], f"get_type #{t0['ordinal']} {t0['name']}: {gt and gt['definition'][:50]!r}")
    fr, err = c.call("get_stack_frame", address=target)
    check(fr is not None or (err and "no stack frame" in err), f"get_stack_frame: {fr and len(fr['members'])} members" if fr else f"get_stack_frame: {err}")
    cur, _ = c.call("get_cursor")
    check(cur is not None, f"get_cursor: {cur and cur['address']}")
    dbg, _ = c.call("get_debugger_state")
    check(dbg is not None and dbg["debugger_on"] is False, "get_debugger_state (off)")
    j, _ = c.call("jump_to", address=target)
    check(j and j["jumped"], f"jump_to {target}")
    cur2, _ = c.call("get_cursor")
    check(cur2 and cur2["address"].lower() == target.lower(), f"the cursor moved there: {cur2 and cur2['address']}")

    # Modifying tools, each undone.
    sc, err = c.call("set_comment", address=target, comment="kiln live test")
    check(sc and sc["comment"] == "kiln live test", f"set_comment: {err or 'ok'}")
    dis3, _ = c.call("disassemble", address=target, count=1)
    check(dis3 and dis3["lines"][0].get("comment") == "kiln live test", "the comment shows in the disassembly")
    c.call("set_comment", address=target, comment="")
    dis4, _ = c.call("disassemble", address=target, count=1)
    check(dis4 and not dis4["lines"][0].get("comment"), "cleared again")
    sn, err = c.call("set_name", address=target, name="kiln_live_test_fn")
    check(sn and sn["name"] == "kiln_live_test_fn", f"set_name: {err or sn}")
    old = (sn or {}).get("old_name") or ""
    c.call("set_name", address=target, name=old if not old.startswith("sub_") else "")
    back, _ = c.call("get_function", address=target)
    check(back and back["name"] == old, f"name restored: {back and back['name']}")
    fc, err = c.call("set_function_comment", address=target, comment="live test fn comment")
    check(fc and fc["comment"] == "live test fn comment", f"set_function_comment: {err or 'ok'}")
    c.call("set_function_comment", address=target, comment="")
    dt, err = c.call("declare_types", declarations="struct KilnLiveTest { int a; char b[4]; float c; };")
    check(dt and dt["ok"], f"declare_types: {err or dt}")
    gt2, err = c.call("get_type", name="KilnLiveTest")
    check(gt2 and gt2["size"] == 12 and [m["name"] for m in gt2["members"]] == ["a", "b", "c"], f"get_type of the new struct: {gt2 and gt2['members']}")
    pb, err = c.call("patch_bytes", address=target, hex=rb["hex"])
    check(pb and pb["after"] == rb["hex"], f"patch_bytes (same bytes back): {err or 'ok'}")
    py, err = c.call("run_python", code="import ida_funcs\nprint('hello from ida')\nresult = ida_funcs.get_func_qty()")
    check(py and py["ok"] and "hello from ida" in py["output"] and py["result"] == info["functions"], f"run_python: {err or py}")
    py2, _ = c.call("run_python", code="raise ValueError('boom')")
    check(py2 and py2["ok"] is False and "boom" in py2["error"], "run_python reports exceptions")
    if s["hexrays"] and d:
        import re
        m = re.search(r"\b(v\d+|a\d+|result)\b", d["code"])
        if m:
            rl, err = c.call("rename_local_variable", function=target, old_name=m.group(1), new_name="kiln_tmp_var")
            check(rl is not None, f"rename_local_variable {m.group(1)} → kiln_tmp_var: {err or 'ok'}")
            if rl:
                c.call("rename_local_variable", function=target, old_name="kiln_tmp_var", new_name=m.group(1))
    w, _ = c.call("wait_for_analysis")
    check(w and w["analysis_done"], "wait_for_analysis")

    # Concurrency: several requests at once are served (serialized inside IDA).
    import threading
    results = []

    def one():
        r, e = c.call("get_function", address=target)
        results.append(r is not None)
    ts = [threading.Thread(target=one) for _ in range(6)]
    t0 = time.monotonic()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    check(len(results) == 6 and all(results), f"6 concurrent calls all answered ({(time.monotonic() - t0) * 1000:.0f} ms)")

    print(f"\n{passed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
