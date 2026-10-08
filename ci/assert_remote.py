#!/usr/bin/env python3
"""Gate BLOK 5 — reachability remote.

Membaca log harness_remote dan menuntut LIMA syarat sekaligus. Kalau salah satu hilang, gate
GAGAL (exit 1) dan menyebut syarat mana yang hilang — supaya "lulus" tidak pernah jadi hijau palsu.

Jalankan `--selftest` untuk membuktikan gate-nya benar-benar menolak: ia diuji pada log sintetis
yang sengaja menghilangkan tiap syarat satu per satu.
"""
import re
import sys


def write_sizes(text: str):
    return [int(m) for m in re.findall(r"WRITE of size (\d+)", text)]


def check(text: str):
    sizes = write_sizes(text)
    syarat = [
        ("laporan ASan ada", "AddressSanitizer" in text),
        ("klasifikasi heap-buffer-overflow", "heap-buffer-overflow" in text),
        ("tulisan melebihi buffer 512 (token dari server; 600 byte kita + bingkai FreeRDP)",
         any(s >= 600 for s in sizes)),
        ("jejak fungsi nego (situs overflow)", "nego" in text),
        ("jejak jalur redirection (pengurai PDU / penerap redirect)",
         any(k in text for k in ("redirection.c", "rdp_client_redirect"))),
    ]
    return syarat


def evaluate(text: str, verbose=True):
    syarat = check(text)
    lulus = [n for n, ok in syarat if ok]
    gagal = [n for n, ok in syarat if not ok]
    if verbose:
        for n, ok in syarat:
            print("    [%s] %s" % ("v" if ok else "x", n))
    return (not gagal), gagal


def selftest():
    basis = (
        "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000003200\n"
        "WRITE of size 600 at 0x515000003200 thread T0\n"
        "    #0 __asan_memcpy\n"
        "    #1 Stream_Write winpr/include/winpr/stream.h:1193:4\n"
        "    #2 nego_send_negotiation_request libfreerdp/core/nego.c:1098:3\n"
        "    #3 freerdp_connect libfreerdp/core/freerdp.c:100:9\n"
        "    #4 rdp_client_redirect libfreerdp/core/connection.c:449:5\n"
        "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
    )
    kasus = [("log lengkap (harus LULUS)", basis, True)]
    potong = [
        ("AddressSanitizer", "AddressSanitizer"),
        ("heap-buffer-overflow", "heap-buffer-overflow"),
        ("nego", "nego"),
    ]
    for nama, token in potong:
        kasus.append(("tanpa '%s' (harus GAGAL)" % nama, basis.replace(token, "XXX"), False))
    # ambang ukuran tulisan harus TERUKUR: 615 (kenyataan run) & 600 lulus, 599 gagal
    kasus.append(("WRITE of size 615 (harus LULUS)", basis.replace("WRITE of size 600", "WRITE of size 615"), True))
    kasus.append(("WRITE of size 600 (harus LULUS)", basis, True))
    kasus.append(("WRITE of size 599 (harus GAGAL)", basis.replace("WRITE of size 600", "WRITE of size 599"), False))
    # jalur redirection = syarat "atau": salah satu saja hilang masih boleh lulus, dua-duanya tidak
    kasus.append(("tanpa 'redirection.c' saja (harus LULUS)", basis.replace("redirection.c", "X.c"), True))
    both = basis.replace("redirection.c", "X.c").replace("rdp_client_redirect", "rdp_client_XXX")
    kasus.append(("tanpa kedua jejak redirection (harus GAGAL)", both, False))

    ok_semua = True
    for nama, teks, harap in kasus:
        lulus, _ = evaluate(teks, verbose=False)
        benar = lulus == harap
        ok_semua = ok_semua and benar
        print("    [%s] %s → %s (harap %s)" % ("v" if benar else "x", nama,
                                              "LULUS" if lulus else "GAGAL",
                                              "LULUS" if harap else "GAGAL"))
    print("  selftest: %s" % ("OK — gate mengukur, bukan mengasumsikan" if ok_semua else "RUSAK"))
    return 0 if ok_semua else 1


def main():
    if len(sys.argv) >= 2 and sys.argv[1] == "--selftest":
        return selftest()
    if len(sys.argv) < 2:
        print("pakai: assert_remote.py <log> | --selftest")
        return 2
    try:
        text = open(sys.argv[1], encoding="utf-8", errors="replace").read()
    except OSError as exc:
        print("::error::tak bisa membaca %s: %s" % (sys.argv[1], exc))
        return 2
    print("  --- selftest gate ---")
    if selftest() != 0:
        print("::error::selftest gate gagal — perbaiki gate dulu")
        return 2
    print("  --- penilaian log: %s ---" % sys.argv[1])
    lulus, gagal = evaluate(text)
    if not lulus:
        print("::error::syarat belum terpenuhi: %s" % "; ".join(gagal))
        return 1
    print("  semua syarat terpenuhi")
    return 0


if __name__ == "__main__":
    sys.exit(main())
