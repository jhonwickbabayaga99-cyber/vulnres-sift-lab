#!/usr/bin/env python3
"""Ambil flag -I dari compile_commands.json milik build FreeRDP.

Dipakai CI: header generated (freerdp/config.h, winpr/config.h) hanya ada di direktori build
atau prefix install. Daripada menebak kombinasi -I, kita pakai set flag yang FreeRDP sendiri
pakai untuk mengompilasi libfreerdp/core/nego.c.

Keluaran: sederet flag -I (tanpa duplikat) ke stdout; exit 1 bila tak ada yang bisa dipakai.
"""
import json
import pathlib
import shlex
import sys


def extract(path: pathlib.Path):
    if not path.exists():
        return []
    entries = json.loads(path.read_text(encoding="utf-8"))
    pick = next(
        (e for e in entries if e["file"].replace("\\", "/").endswith("libfreerdp/core/nego.c")), None
    )
    if pick is None:
        pick = next(
            (e for e in entries if "libfreerdp/core/" in e["file"].replace("\\", "/")), None
        )
    if pick is None:
        return []

    cmd = pick.get("command")
    args = shlex.split(cmd) if isinstance(cmd, str) else list(pick.get("arguments", []))

    out, seen = [], set()
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-I" and i + 1 < len(args):
            out.append("-I" + args[i + 1])
            i += 2
            continue
        if a.startswith("-I"):
            out.append(a)
        i += 1

    uniq = [x for x in out if not (x in seen or seen.add(x))]
    return uniq


def main(argv):
    path = pathlib.Path(argv[1] if len(argv) > 1 else "build-freerdp/compile_commands.json")
    flags = extract(path)
    if not flags:
        print("(tak ada flag yang terekstraksi: %s tidak ada / tanpa entri nego.c)" % path, file=sys.stderr)
        return 1
    print(" ".join(flags))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
