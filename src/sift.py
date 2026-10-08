#!/usr/bin/env python3
"""sift — core deterministik untuk workflow riset kerentanan (8 tahap, ala Quarkslab).

Tahap: graph → recon → slicing → analysis → triage → poc → chain → exploit
Reproducible (deterministik) untuk 5 tahap pertama; `poc/chain/exploit` bergantung
toolchain (ASan) dan gate yang harus terbukti.

Pakai:
  python3 sift.py index   --src <dir-kloning> --db state/graph.db
  python3 sift.py recon   --db state/graph.db --out state/slices.json
  python3 sift.py slice   --db state/graph.db --entry nego_recv --out state/slice-nego.json
  python3 sift.py analyze --db state/graph.db --slice state/slice-nego.json --out state/findings-nego.json
  python3 sift.py triage  --in state/findings-nego.json --out state/clusters-nego.json
  python3 sift.py poc     --clusters state/clusters-nego.json        # gate: butuh compiler+ASan
  python3 sift.py chain   --clusters state/clusters-nego.json
  python3 sift.py exploit --chain state/chain.json
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, re, sqlite3, sys, time

EXTS = {".c": "c", ".h": "c", ".cc": "cpp", ".cpp": "cpp", ".hpp": "cpp"}

# --- kosakata serangan (bisa diperluas per-target lewat --vocab JSON) -------------
SOURCES = ["recv", "recvfrom", "read", "fread", "Stream_Read", "Stream_Read_UINT32", "Stream_Read_UINT16",
           "Stream_Read_UINT8", "Stream_Read_INT32", "Stream_Read_int", "Stream_GetRemainingLength",
           "Stream_GetRemainingCapacity", "fgets", "getc", "fgetc", "BIO_read", "SSL_read", "gzread",
           "inflate", "uncompress", "Stream_Pointer", "Stream_GetPosition",
           "rdp_redirection_read_data", "rdp_redirection_read", "rdp_read_settings"]
SINKS = ["memcpy", "memmove", "strcpy", "strncpy", "strcat", "sprintf", "snprintf", "vsnprintf", "alloca",
         "malloc", "calloc", "realloc", "Stream_Write", "Stream_Write_UINT32", "Stream_Write_UINT16",
         "Stream_EnsureRemainingCapacity", "Stream_Write_INT32", "WriteFile", "send", "write", "fwrite",
         "new", "delete", "memcmp", "strlen", "atoi", "atol", "sscanf",
         "CopyMemory", "MoveMemory", "ZeroMemory", "FillMemory", "SecureZeroMemory"]
SINK_RISKY = {"memcpy", "memmove", "strcpy", "strcat", "sprintf", "vsnprintf", "Stream_Write", "Stream_Write_UINT32",
              "Stream_Write_UINT16", "Stream_Write_INT32", "alloca", "malloc", "calloc", "realloc",
              "CopyMemory", "MoveMemory", "Stream_EnsureRemainingCapacity"}

# kosakata khusus-target: pasangan setter/getter (mis. FreeRDP: freerdp_settings_set_pointer_len / _get_pointer)
SETTER = re.compile(r"_set_(?:pointer_len|pointer|uint64|uint32|uint16|uint8|int64|int32|int16|int8|string|bool|size_t)$")
GETTER = re.compile(r"_get_(?:pointer|uint64|uint32|uint16|uint8|int64|int32|string|bool)\s*\(\s*([A-Za-z_]\w*)\s*,\s*([A-Za-z_]\w*)\s*\)")

SQL = """
CREATE TABLE IF NOT EXISTS files(path TEXT PRIMARY KEY, lang TEXT, loc INT, sha TEXT);
CREATE TABLE IF NOT EXISTS funcs(id INTEGER PRIMARY KEY, name TEXT, file TEXT, start_line INT, end_line INT, nparams INT);
CREATE TABLE IF NOT EXISTS types(name TEXT, kind TEXT, file TEXT, line INT);
CREATE TABLE IF NOT EXISTS calls(caller_id INT, callee TEXT, file TEXT, line INT, args TEXT);
CREATE TABLE IF NOT EXISTS srcs(func_id INT, name TEXT, file TEXT, line INT);
CREATE TABLE IF NOT EXISTS snks(func_id INT, name TEXT, file TEXT, line INT, risky INT, args TEXT);
CREATE TABLE IF NOT EXISTS fieldwrites(var TEXT, field TEXT, src TEXT, file TEXT, line INT, func TEXT, dari_param INT, tainted INT);
CREATE TABLE IF NOT EXISTS params(func_id INT, idx INT, name TEXT);
CREATE TABLE IF NOT EXISTS taint_calls(caller_func TEXT, callee TEXT, arg_idx INT, arg_text TEXT, file TEXT, line INT);
CREATE INDEX IF NOT EXISTS i_calls_caller ON calls(caller_id);
CREATE INDEX IF NOT EXISTS i_calls_callee ON calls(callee);
CREATE INDEX IF NOT EXISTS i_funcs_name ON funcs(name);
"""


def _parser():
    from tree_sitter import Language, Parser
    import tree_sitter_c, tree_sitter_cpp
    return {"c": Parser(Language(tree_sitter_c.language())), "cpp": Parser(Language(tree_sitter_cpp.language()))}


def txt(src: bytes, node) -> str:
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def find_all(node, kinds):
    out, stack = [], [node]
    while stack:
        n = stack.pop()
        if n.type in kinds:
            out.append(n)
        stack.extend(n.children)
    return out


def func_name(src: bytes, node) -> str:
    d = node.child_by_field_name("declarator")
    cur = d
    while cur is not None:
        if cur.type in ("identifier", "field_identifier"):
            return txt(src, cur)
        nxt = cur.child_by_field_name("declarator")
        if nxt is None:
            ids = [c for c in find_all(cur, {"identifier"})]
            if ids:
                return txt(src, ids[0])
            break
        cur = nxt
    return "?"


def index_file(conn, path: pathlib.Path, root: pathlib.Path, parsers):
    raw = path.read_bytes()
    lang = EXTS[path.suffix.lower()]
    p = parsers.get(lang)
    if p is None:
        return 0
    tree = p.parse(raw)
    rel = str(path.relative_to(root)).replace("\\", "/")
    conn.execute("INSERT OR REPLACE INTO files VALUES (?,?,?,?)",
                 (rel, lang, raw.count(b"\n") + 1, hashlib.sha1(raw).hexdigest()[:16]))
    nfun = 0
    for t in ("struct_specifier", "union_specifier", "enum_specifier", "type_definition"):
        for node in find_all(tree.root_node, {t}):
            nm = node.child_by_field_name("name")
            if nm is not None:
                conn.execute("INSERT INTO types VALUES (?,?,?,?)", (txt(raw, nm), t, rel, node.start_point[0] + 1))
    for fnode in find_all(tree.root_node, {"function_definition"}):
        name = func_name(raw, fnode)
        sl = fnode.start_point[0] + 1
        el = fnode.end_point[0] + 1
        plist = []
        d = fnode.child_by_field_name("declarator")
        if d is not None:
            for pl in find_all(d, {"parameter_list"}):
                for p in pl.children:
                    if p.type == "parameter_declaration":
                        nm = p.child_by_field_name("declarator")
                        if nm is not None:
                            ids = find_all(nm, {"identifier"})
                            if ids:
                                plist.append(txt(raw, ids[-1]))
                    elif p.type == "identifier":
                        plist.append(txt(raw, p))
        params = len(plist)
        cur = conn.execute("INSERT INTO funcs (name,file,start_line,end_line,nparams) VALUES (?,?,?,?,?)",
                           (name, rel, sl, el, params))
        fid = cur.lastrowid
        for i, pn in enumerate(plist):
            conn.execute("INSERT INTO params VALUES (?,?,?)", (fid, i, pn))
        nfun += 1
        body = fnode
        # panggilan
        for c in find_all(body, {"call_expression"}):
            fn = c.child_by_field_name("function")
            callee = txt(raw, fn) if fn is not None else "?"
            callee = callee.split("->")[-1].split(".")[-1].strip()
            conn.execute("INSERT INTO calls VALUES (?,?,?,?,?)",
                         (fid, callee, rel, c.start_point[0] + 1,
                          (" ".join(txt(raw, c.child_by_field_name("arguments")).split())[:220]
                           if c.child_by_field_name("arguments") is not None else "")))
            if callee in SOURCES:
                conn.execute("INSERT INTO srcs VALUES (?,?,?,?)", (fid, callee, rel, c.start_point[0] + 1))
            if callee in SINKS:
                a_node = c.child_by_field_name("arguments")
                argt = (txt(raw, a_node)[:220] if a_node is not None else "")
                conn.execute("INSERT INTO snks VALUES (?,?,?,?,?,?)",
                             (fid, callee, rel, c.start_point[0] + 1, 1 if callee in SINK_RISKY else 0, argt))
        # --- taint: variabel terisi SOURCE → penulisan field (pola f-007) + penghubung antar-prosedur ---
        tainted: set = set()
        paramset = set(plist)
        urut = sorted(find_all(body, {"call_expression", "assignment_expression", "init_declarator"}), key=lambda n: n.start_byte)
        for n in urut:
            if n.type == "call_expression":
                fn = n.child_by_field_name("function")
                callee = txt(raw, fn).split("->")[-1].split(".")[-1].strip() if fn is not None else "?"
                args = n.child_by_field_name("arguments")
                arglist = [a for a in (args.children if args is not None else []) if a.type not in (",", "(", ")")]
                # catat pemanggilan yang membawa nilai bertaint → callee (penghubung param→field)
                for ai, a in enumerate(arglist):
                    at = txt(raw, a).strip()
                    if len(at) > 80:
                        continue
                    if any(re.search(r"\b%s\s*\(" % re.escape(s), at) for s in SOURCES) or \
                       any(re.search(r"\b%s\b" % re.escape(v), at) for v in tainted):
                        conn.execute("INSERT INTO taint_calls VALUES (?,?,?,?,?,?)", (name, callee, ai, at, rel, n.start_point[0] + 1))
                if callee in SOURCES:
                    for a in arglist:
                        at = txt(raw, a).strip()
                        if at.startswith("&"):
                            at = at[1:].strip()
                        if re.fullmatch(r"[A-Za-z_]\w*", at):
                            tainted.add(at)          # makro Stream_Read_UINT32(s, len) mengisi 'len'
                        elif re.fullmatch(r"[A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*", at):
                            tainted.add(at)
                            # sumber mengisi lewat pointer: &obj->field → catat sebagai penulisan field bertaint
                            conn.execute("INSERT INTO fieldwrites VALUES (?,?,?,?,?,?,?,?)",
                                         (at.split("->")[-1].split(".")[-1], at, "src:" + callee, rel,
                                          n.start_point[0] + 1, name, 0, 1))
                # SETTER (kosakata khusus target):  obj_set_xxx(settings, KEY, nilai…) → penulisan field
                if SETTER.search(callee) and len(arglist) >= 2:
                    st_t = txt(raw, arglist[0]).strip()
                    key_t = txt(raw, arglist[1]).strip()
                    if re.fullmatch(r"[A-Za-z_]\w*", st_t) and re.fullmatch(r"[A-Za-z_]\w*", key_t):
                        sumber_val = None
                        for x in arglist[2:]:
                            vt = txt(raw, x).strip()
                            if any(re.search(r"\b%s\s*\(" % re.escape(s), vt) for s in SOURCES):
                                sumber_val = "src:" + next(s for s in SOURCES if re.search(r"\b%s\s*\(" % re.escape(s), vt)); break
                            tv = next((v for v in tainted if re.search(r"\b%s\b" % re.escape(v), vt)), None)
                            if tv:
                                sumber_val = tv; break
                            if vt in paramset:
                                sumber_val = "param:" + vt; break
                        field = "%s::%s" % (st_t, key_t)
                        conn.execute("INSERT INTO fieldwrites VALUES (?,?,?,?,?,?,?,?)",
                                     (key_t, field, sumber_val or "?", rel, n.start_point[0] + 1, name,
                                      1 if (sumber_val or "").startswith("param:") else 0, 1 if sumber_val else 0))
                        if sumber_val:
                            tainted.add(field)
                continue
            lhs = n.child_by_field_name("left") or n.child_by_field_name("declarator")
            rhs = n.child_by_field_name("right") or n.child_by_field_name("value")
            if lhs is None or rhs is None:
                continue
            lhst, rhst = txt(raw, lhs).strip(), txt(raw, rhs).strip()
            if len(lhst) > 80:
                continue
            src_hit = next((s for s in SOURCES if re.search(r"\b%s\s*\(" % re.escape(s), rhst)), None)
            var_hit = next((v for v in tainted if re.search(r"\b%s\b" % re.escape(v), rhst)), None)
            param_hit = rhst if rhst in paramset else None
            if not (src_hit or var_hit or param_hit):
                continue
            sumber = src_hit or var_hit or ("param:" + rhst)
            if "->" in lhst or "." in lhst:
                var = lhst.split("->")[-1].split(".")[-1].strip()
                conn.execute("INSERT INTO fieldwrites VALUES (?,?,?,?,?,?,?,?)",
                             (var, lhst, sumber, rel, n.start_point[0] + 1, name, 1 if param_hit else 0, 1))
                tainted.add(lhst)
            else:
                if re.fullmatch(r"[A-Za-z_]\w*", lhst):
                    tainted.add(lhst)
    return nfun


def propagate_taint(conn, ronde: int = 3) -> int:
    """Pasca-index: field yang tainted menular ke penulisan lain yang argumennya menyebut field itu
    (menghubungkan  redirection->LoadBalanceInfo  →  settings::FreeRDP_LoadBalanceInfo)."""
    total = 0
    for _ in range(ronde):
        segmen = set()
        for (field,) in conn.execute("SELECT field FROM fieldwrites WHERE tainted=1"):
            seg = field.split("::")[-1].split("->")[-1].split(".")[-1].strip()
            if seg and not seg.startswith("FreeRDP_"):
                segmen.add(seg)
        baru = 0
        for var, field, f, ln in conn.execute(
                "SELECT var,field,file,line FROM fieldwrites WHERE tainted=0 OR tainted IS NULL"):
            for (args,) in conn.execute("SELECT args FROM calls WHERE file=? AND line=?", (f, ln)):
                if not args:
                    continue
                if any(re.search(r"\b%s\b" % re.escape(s), args) for s in segmen):
                    conn.execute("UPDATE fieldwrites SET tainted=1, src='via:field-taint' "
                                 "WHERE file=? AND line=? AND field=?", (f, ln, field))
                    baru += 1
                    break
        conn.commit()
        total += baru
        if not baru:
            break
    return total


def cmd_index(a):
    root = pathlib.Path(a.src).resolve()
    db = pathlib.Path(a.db); db.parent.mkdir(parents=True, exist_ok=True)
    if db.exists() and not a.append:
        db.unlink()
    conn = sqlite3.connect(db); conn.executescript(SQL)
    parsers = _parser()
    files, funs, t0 = 0, 0, time.time()
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in EXTS:
            if any(x in p.parts for x in (".git", "build", "third_party", "winpr")):
                continue
            try:
                funs += index_file(conn, p, root, parsers)
                files += 1
            except Exception as e:
                print("  ! %s: %s" % (p.name, str(e)[:60]))
            if files % 200 == 0 and files:
                conn.commit()
                print("  ... %d berkas, %d fungsi (%.0fs)" % (files, funs, time.time() - t0), flush=True)
    conn.commit()
    n_prop = propagate_taint(conn)
    n = conn.execute("SELECT COUNT(*) FROM funcs").fetchone()[0]
    e = conn.execute("SELECT COUNT(*) FROM calls").fetchone()[0]
    ty = conn.execute("SELECT COUNT(*) FROM types").fetchone()[0]
    unresolved = conn.execute("SELECT COUNT(*) FROM calls c WHERE NOT EXISTS (SELECT 1 FROM funcs f WHERE f.name=c.callee)").fetchone()[0]
    print("  [+] index: %d berkas · %d fungsi · %d tipe · %d call edge (%d sintetis/tak-teresolusi)"
          % (files, n, ty, e, unresolved))
    print("      sumber potensial: %d · sink: %d · penulisan-field-dari-sumber: %d (propagasi +%d)"
          % (*[conn.execute("SELECT COUNT(*) FROM " + t).fetchone()[0] for t in ("srcs", "snks", "fieldwrites")], n_prop))
    print("      graf: %s (%.1fs)" % (db, time.time() - t0))
    return 0


def load_graph(db):
    import networkx as nx
    conn = sqlite3.connect(db)
    funcs = {r[0]: r[1] for r in conn.execute("SELECT id,name FROM funcs")}
    byname = {}
    for fid, nm in funcs.items():
        byname.setdefault(nm, []).append(fid)
    g = nx.DiGraph()
    g.add_nodes_from(funcs)
    for cid, callee in conn.execute("SELECT caller_id,callee FROM calls"):
        tgt = byname.get(callee)
        if tgt:
            for t in tgt:                      # edge terealisasi (definisi ada di pohon)
                g.add_edge(cid, t)
        else:
            g.add_edge(cid, "N:" + callee)      # edge sintetis (fungsi eksternal/tak teresolusi)
    return conn, funcs, g


def cmd_recon(a):
    conn, funcs, g = load_graph(a.db)
    src_funcs = {r[0] for r in conn.execute("SELECT DISTINCT func_id FROM srcs")}
    # komponen = direktori tingkat-2 (libfreerdp/core, channels/urbdrc/...)
    rows = conn.execute("SELECT id, file FROM funcs").fetchall()
    comp = {}
    for fid, f in rows:
        parts = f.split("/")
        key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        d = comp.setdefault(key, {"funcs": 0, "files": set(), "sources": 0, "sinks": 0, "fieldwrites": 0})
        d["funcs"] += 1; d["files"].add(f)
        if fid in src_funcs:
            d["sources"] += 1
    for nm, f, _ in conn.execute("SELECT name,file,line FROM snks"):
        parts = f.split("/"); key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        if key in comp:
            comp[key]["sinks"] += 1
    for var, field, src, f, ln, fn in conn.execute("SELECT var,field,src,file,line,func FROM fieldwrites"):
        parts = f.split("/"); key = "/".join(parts[:2]) if len(parts) > 1 else parts[0]
        if key in comp:
            comp[key]["fieldwrites"] += 1
    slices = []
    for key, d in comp.items():
        skor = d["sources"] * 3 + d["fieldwrites"] * 2 + d["sinks"] * 0.1
        slices.append({"slice": key, "score": round(skor, 2), "files": len(d["files"]), "funcs": d["funcs"],
                       "sources": d["sources"], "sinks": d["sinks"], "fieldwrites": d["fieldwrites"]})
    slices.sort(key=lambda x: -x["score"])
    for i, s in enumerate(slices, 1):
        s["rank"] = i
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(slices, indent=1), encoding="utf-8")
    print("  [+] recon: %d slice (peringkat = peta, bukan vonis)" % len(slices))
    for s in slices[:10]:
        print("      #%-3d %-34s skor=%-7s berkas=%-4d sumber=%-3d field=%d" %
              (s["rank"], s["slice"][:34], s["score"], s["files"], s["sources"], s["fieldwrites"]))
    print("      → %s" % out)
    return 0


def cmd_slice(a):
    import networkx as nx
    conn, funcs, g = load_graph(a.db)
    # mode 1: komponen (tingkat-direktori) — seperti "slice 166 libfreerdp/core/nego" di artikel
    if getattr(a, "dir", None):
        pref = a.dir.replace("\\", "/").rstrip("/")
        fids = {fid for fid, f in conn.execute("SELECT id,file FROM funcs") if f.startswith(pref)}
        files = sorted({f for fid, f in conn.execute("SELECT id,file FROM funcs") if fid in fids})
        for fid in list(fids):
            if fid in g:
                fids |= {n for n in nx.descendants(g, fid) if isinstance(n, int)}
        nama = pref
    else:
        seeds = [fid for fid, nm in funcs.items() if nm == a.entry]
        if not seeds:
            seeds = [fid for fid, nm in funcs.items() if a.entry.lower() in nm.lower()][:5]
        if not seeds:
            print("  [x] fungsi '%s' tidak ada di graf" % a.entry); return 1
        reach = set()
        for s in seeds:
            reach |= nx.descendants(g, s)
        fids = {n for n in reach if isinstance(n, int)} | set(seeds)
        files = sorted({f for fid, f in conn.execute("SELECT id,file FROM funcs") if fid in fids})
        nama = a.entry
    fset = set(files)
    data = {"entry": nama, "dir": getattr(a, "dir", None), "funcs": len(fids), "files": files,
            "srcs": [[n, f, l] for n, f, l in conn.execute("SELECT name,file,line FROM srcs") if f in fset],
            "snks": [[n, f, l, ar] for n, f, l, ar in conn.execute("SELECT name,file,line,args FROM snks") if f in fset],
            "fieldwrites": [[v, fi, s, f, l, fu] for v, fi, s, f, l, fu in
                            conn.execute("SELECT var,field,src,file,line,func FROM fieldwrites") if f in fset]}
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1), encoding="utf-8")
    print("  [+] slice '%s': %d fungsi · %d berkas · %d sumber · %d sink · %d penulisan-field"
          % (nama, len(fids), len(files), len(data["srcs"]), len(data["snks"]), len(data["fieldwrites"])))
    for f in files[:14]:
        print("      %s" % f)
    if len(files) > 14:
        print("      … %d berkas lagi" % (len(files) - 14))
    print("      → %s" % out)
    return 0


def cmd_analyze(a):
    sl = json.loads(pathlib.Path(a.slice).read_text(encoding="utf-8"))
    temuan = []
    # (1) taint same-function: variabel diisi dari SOURCE → field, lalu sink memakai field itu
    for var, field, src, f, ln, fn in sl.get("fieldwrites", []):
        temuan.append({"kind": "field_taint_write", "key": field, "var": var, "src": src,
                       "file": f, "line": ln, "func": fn, "status": "candidate",
                       "why": "%s (dari %s) mengalir ke %s" % (src, fn, field)})
    # (2) penghubung antar-prosedur: field diisi dari PARAMETER fungsi → cari pemanggil yang
    #     mengirim nilai bertaint ke parameter itu (inilah yang menghubungkan f-007 ↔ f-005)
    conn = sqlite3.connect(a.db)
    fset = set(sl.get("files", []))
    tfields = {}
    for var, field, src, tf, tln, tfn, t in conn.execute(
            "SELECT var,field,src,file,line,func,tainted FROM fieldwrites"):
        if t:
            tfields[field] = (src, tf, tln, tfn)

    def pisah_args(t: str):
        out, buf, depth = [], "", 0
        for ch in t:
            if ch in "([":
                depth += 1
            elif ch in ")]":
                depth -= 1
            if ch == "," and depth == 0:
                out.append(buf); buf = ""
            else:
                buf += ch
        if buf.strip():
            out.append(buf)
        return out

    for field, var, f, ln, fn, dp in conn.execute(
            "SELECT field,var,file,line,func,dari_param FROM fieldwrites WHERE dari_param=1"):
        if fset and f not in fset:
            continue
        idx = conn.execute("SELECT p.idx FROM params p JOIN funcs u ON u.id=p.func_id "
                           "WHERE u.name=? AND p.name=? LIMIT 1", (fn, var)).fetchone()
        if not idx:
            continue
        for caller, argt, cf, cl in conn.execute(
                "SELECT caller_func,arg_text,file,line FROM taint_calls WHERE callee=? AND arg_idx=?", (fn, idx[0])):
            temuan.append({"kind": "param_taint_write", "key": field, "var": var,
                           "src": "%s@%s:%d" % (caller, cf, cl), "arg": argt,
                           "file": f, "line": ln, "func": fn, "status": "candidate",
                           "why": "%s memanggil %s dengan argumen bertaint '%s' → disimpan ke %s" % (caller, fn, argt, field)})
        # setter/getter: pemanggil mengirim hasil GETTER dari field yang sudah ter-taint
        for caller, args, cf, cl in conn.execute(
                "SELECT f.name, c.args, c.file, c.line FROM calls c JOIN funcs f ON f.id=c.caller_id WHERE c.callee=?", (fn,)):
            if not args:
                continue
            bersih = args.strip()
            if bersih.startswith("(") and bersih.endswith(")"):
                bersih = bersih[1:-1]
            parts = pisah_args(bersih)
            if idx[0] >= len(parts):
                continue
            g = GETTER.search(parts[idx[0]])
            key = None
            if g:
                key = "%s::%s" % (g.group(1), g.group(2))
            else:
                # argumen berbentuk ekspresi field: settings->LoadBalanceInfo / redirection->X
                mt = re.search(r"\b([A-Za-z_]\w*(?:->|\.)[A-Za-z_]\w*)", parts[idx[0]])
                if mt:
                    seg = mt.group(1).split("->")[-1].split(".")[-1]
                    for k in tfields:
                        if k.split("::")[-1].split("->")[-1].split(".")[-1].replace("FreeRDP_", "") == seg:
                            key = k
                            break
            if not key:
                continue
            info = tfields.get(key)
            if not info:
                continue
            temuan.append({"kind": "param_taint_write", "key": field, "var": var,
                           "src": "%s@%s:%d" % (caller, cf, cl), "arg": parts[idx[0]].strip(),
                           "file": f, "line": ln, "func": fn, "status": "candidate",
                           "why": "%s mengirim '%s' (field %s diisi %s pada %s:%d) → %s menyimpannya ke %s"
                                  % (caller, parts[idx[0]].strip(), key, info[0], info[1], info[2], fn, field)})
    # (3) sink berbahaya yang memakai field hasil taint — presisi: nama field harus ADA di argumen sink
    sink_of_file = {}
    for row in sl.get("snks", []):
        sname, f, l = row[0], row[1], row[2]
        args = row[3] if len(row) > 3 else ""
        sink_of_file.setdefault(f, []).append((sname, l, args))
    for t in list(temuan):
        var = (t.get("var") or t["key"].split("->")[-1].split(".")[-1]).strip()
        for sname, l, args in sink_of_file.get(t["file"], []):
            if sname not in SINK_RISKY:
                continue
            kuat = bool(re.search(r"\b%s\b" % re.escape(var), args or ""))
            if kuat:
                kind, alasan = "field_taint_sink", "%s BENAR-BENAR muncul di argumen %s" % (var, sname)
            elif abs(l - t["line"]) < 400:
                kind, alasan = "sink_nearby", "%s dipanggil dekat (%d baris); field belum terlihat di argumen" % (sname, abs(l - t["line"]))
            else:
                continue
            temuan.append({"kind": kind, "key": t["key"], "sink": sname, "sink_args": (args or "")[:200],
                           "file": t["file"], "line": l, "func": t["func"], "status": "candidate",
                           "why": alasan})
    # (4) sink di fungsi yang sama dengan sumber (kasar, tapi recall)
    for row in sl.get("snks", []):
        sname, f, l = row[0], row[1], row[2]
        if sname in SINK_RISKY and any(sf == f for _, sf, _ in sl.get("srcs", [])):
            temuan.append({"kind": "same_function_src_sink", "key": "%s@%d" % (f, l), "sink": sname,
                           "file": f, "line": l, "status": "candidate",
                           "why": "fungsi ini membaca data serangan dan memanggil %s" % sname})
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"slice": sl.get("entry"), "findings": temuan}, indent=1), encoding="utf-8")
    print("  [+] analysis: %d temuan (recall dulu; triage yang menyaring)" % len(temuan))
    for t in temuan[:12]:
        print("      [%-20s] %-32s %s:%s" % (t["kind"][:20], t.get("key", "")[:32], t["file"], t["line"]))
    print("      → %s" % out)
    return 0


def cmd_triage(a):
    d = json.loads(pathlib.Path(a.infile).read_text(encoding="utf-8"))
    temuan = d.get("findings", [])
    klaster = {}
    for t in temuan:
        key = t.get("key", "?")
        c = klaster.setdefault(key, {"key": key, "findings": [], "files": set()})
        c["findings"].append(t)
        c["files"].add(t.get("file"))
    keluar = []
    for key, c in klaster.items():
        punya_write = any(x["kind"].startswith(("field_taint_write", "param_taint_write")) for x in c["findings"])
        sink_kuat = any(x["kind"] == "field_taint_sink" for x in c["findings"])
        sink_lemah = any(x["kind"] in ("sink_nearby", "same_function_src_sink") for x in c["findings"])
        if punya_write and sink_kuat:
            cls, alasan = "real", "nilai bertaint tersimpan ke field DAN field itu muncul di argumen sink → jalur utuh"
        elif punya_write and sink_lemah:
            cls, alasan = "mixed", "field bertaint + sink di dekatnya, tapi field tidak terlihat di argumen sink"
        elif punya_write:
            cls, alasan = "latent", "data serangan tersimpan, belum terlihat dipakai sink bahaya"
        elif sink_kuat or sink_lemah:
            cls, alasan = "mixed", "sink bahaya dipanggil di jalur ber-sumber; aliran belum dibuktikan"
        else:
            cls, alasan = "noise", "tidak ada sumber maupun sink bermakna"
        keluar.append({"key": key, "class": cls, "reason": alasan, "n": len(c["findings"]),
                       "files": sorted(x for x in c["files"] if x), "findings": c["findings"]})
    urut = {"real": 0, "mixed": 1, "latent": 2, "noise": 3}
    keluar.sort(key=lambda x: (urut[x["class"]], -x["n"]))
    out = pathlib.Path(a.out); out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps({"slice": d.get("slice"), "clusters": keluar}, indent=1), encoding="utf-8")
    c = {k: sum(1 for x in keluar if x["class"] == k) for k in urut}
    print("  [+] triage: %d temuan → %d klaster (real=%d mixed=%d latent=%d noise=%d)"
          % (len(temuan), len(keluar), c["real"], c["mixed"], c["latent"], c["noise"]))
    for k in keluar[:8]:
        print("      [%-6s] %-40s %s" % (k["class"], k["key"][:40], k["reason"][:60]))
    print("      → %s" % out)
    return 0


GATES = {
    "poc": ("butuh compiler + AddressSanitizer",
            ["pasang toolchain: clang (winget install LLVM.LLVM) atau WSL2 + build-essential",
             "bangun target: cmake -DCMAKE_C_FLAGS='-fsanitize=address -g' && make",
             "harness per klaster real: panggil jalur input (server jahat untuk klien RDP)",
             "jalankan: ASAN_OPTIONS=detect_leaks=0 ./harness → butuh trace (WRITE of size N ke region M)",
             "uji kebocoran heap: ASAN_OPTIONS=fill_byte=0xcd → hitung pola 0xcd di PDU keluaran"]),
    "chain": ("hanya menerima klaster ber-bukti",
              ["≥1 primitif tulis (blind write) terukur", "≥1 primitif baca/bocor terukur",
               "urutan yang membuat keduanya hidup dalam satu sesi (mis. redirection → reconnect)"]),
    "exploit": ("harness eksploitasi + gate terukur",
                ["lab siap: VM klien + server jahat", "primitif tulis terukur",
                 "control-flow hijack terbukti", "libc base dari bocoran", "ASLR dilewati",
                 "payload utuh → shell"]),
}


def cmd_gated(a, nama):
    judul, langkah = GATES[nama]
    print("  [!] tahap '%s' — %s" % (nama, judul))
    for i, l in enumerate(langkah, 1):
        print("      [%s] %s" % (" " if i > 1 else "✓", l))
    print("      gate: tiap langkah wajib punya KELUARAN TERUKUR (angka/trace), bukan asumsi.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("index"); s.add_argument("--src", required=True); s.add_argument("--db", default="state/graph.db"); s.add_argument("--append", action="store_true"); s.set_defaults(f=cmd_index)
    s = sub.add_parser("recon"); s.add_argument("--db", default="state/graph.db"); s.add_argument("--out", default="state/slices.json"); s.set_defaults(f=cmd_recon)
    s = sub.add_parser("slice"); s.add_argument("--db", default="state/graph.db"); s.add_argument("--entry"); s.add_argument("--dir"); s.add_argument("--out", default="state/slice.json"); s.set_defaults(f=cmd_slice)
    s = sub.add_parser("analyze"); s.add_argument("--db", default="state/graph.db"); s.add_argument("--slice", required=True); s.add_argument("--out", default="state/findings.json"); s.set_defaults(f=cmd_analyze)
    s = sub.add_parser("triage"); s.add_argument("--in", dest="infile", required=True); s.add_argument("--out", default="state/clusters.json"); s.set_defaults(f=cmd_triage)
    for n in ("poc", "chain", "exploit"):
        s = sub.add_parser(n); s.add_argument("--clusters", default=None); s.add_argument("--chain", default=None); s.set_defaults(f=lambda a, n=n: cmd_gated(a, n))
    a = ap.parse_args()
    return a.f(a)


if __name__ == "__main__":
    sys.exit(main())
