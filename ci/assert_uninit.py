#!/usr/bin/env python3
"""Gate: mesin HARUS menemukan kandidat 'reserve tanpa tulis' (CWE-457/908) di jalur urbdrc.

Dipakai CI (job static-core). Titik acuan = dua jalur yang disebut advisory
GHSA-hw7p-5h2r-83gq pada revisi rentan (commit terpin):
  channels/urbdrc/client/data_transfer.c:134  (urb_write_completion)
  channels/urbdrc/client/data_transfer.c:893  (urb_isoch_transfer_cb)

Exit 0 bila keduanya muncul sebagai klaster `real`; exit 1 bila tidak — supaya regresi
presisi/recall pada kelas CWE-457/908 ketahuan, bukan diam-diam hilang.
"""
import json
import pathlib
import sys

EXPECT = {
    ("channels/urbdrc/client/data_transfer.c", 134),
    ("channels/urbdrc/client/data_transfer.c", 893),
}


def main(argv) -> int:
    p = pathlib.Path(argv[1] if len(argv) > 1 else "state/clusters-urbdrc.json")
    if not p.exists():
        print("  [x] %s tidak ada" % p)
        return 1
    d = json.loads(p.read_text(encoding="utf-8"))
    titik = set()
    for c in d.get("clusters", []):
        if c.get("class") != "real":
            continue
        for x in c.get("findings", []):
            if x.get("kind") == "uninit_reserve":
                titik.add((x.get("file"), int(x.get("line") or 0)))
    print("  [+] klaster uninit 'real': %d titik" % len(titik))
    for f, l in sorted(titik):
        print("      %s:%d" % (f, l))
    hilang = sorted(e for e in EXPECT if e not in titik)
    if hilang:
        print("  [x] gate GAGAL — tak ditemukan:")
        for f, l in hilang:
            print("      %s:%d" % (f, l))
        return 1
    print("  [+] gate lulus: kedua jalur kebocoran ditemukan mesin sendiri")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
