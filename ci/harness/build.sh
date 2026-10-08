#!/usr/bin/env bash
# Bangun harness_nego (PoC ASan) untuk FreeRDP.
#
# Latar: header generated (freerdp/config.h, winpr/config.h) hanya ada di direktori build/prefix,
# dan `nego_*`/`transport_new()` ditandai FREERDP_LOCAL (tak diekspor dari .so) → wajib link statis.
# Karena detail build FreeRDP bergeser antar rilis, skrip ini MENGUKUR alih-alih menebak:
# mencoba daftar kombinasi include+library, berhenti di yang pertama bisa dikompilasi+dilink,
# dan mencetak diagnosa artefak supaya kegagalan berikutnya menjelaskan dirinya sendiri.
set -e

OUT=build-harness
HARNESS=ci/harness/harness_nego.c
mkdir -p "$OUT"
export PKG_CONFIG_PATH="$HOME/frdp/lib/pkgconfig:$HOME/frdp/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"

CFLAGS_PC=$(pkg-config --cflags freerdp3 winpr3 2>/dev/null || echo "")
LIBS_PC=$(pkg-config --static --libs freerdp3 winpr3 2>/dev/null \
          || pkg-config --libs freerdp3 winpr3 2>/dev/null || echo "")

INC_SRC="-I$PWD/freerdp-src/libfreerdp/core -I$PWD/freerdp-src/libfreerdp -I$PWD/freerdp-src/winpr/include -I$PWD/freerdp-src/include"
INC_GEN="-I$PWD/build-freerdp/winpr/include -I$PWD/build-freerdp/include"
INC_CC=$(python3 ci/harness/extract_flags.py build-freerdp/compile_commands.json 2>/dev/null || true)

A_BUILD_FRDP=$(ls build-freerdp/libfreerdp/libfreerdp*.a 2>/dev/null | head -1 || true)
A_BUILD_WINPR=$(ls build-freerdp/winpr/libwinpr*.a 2>/dev/null | head -1 || true)
A_INST_FRDP=$(ls "$HOME/frdp"/lib/libfreerdp*.a 2>/dev/null | head -1 || true)
A_INST_WINPR=$(ls "$HOME/frdp"/lib/libwinpr*.a 2>/dev/null | head -1 || true)
SYS="-lssl -lcrypto -lz -lpthread -lm -ldl -lrt"

echo "--- artefak terdeteksi"
printf '  build-freerdp: %s | %s\n' "${A_BUILD_FRDP:-tidak ada}" "${A_BUILD_WINPR:-tidak ada}"
printf '  install      : %s | %s\n' "${A_INST_FRDP:-tidak ada}" "${A_INST_WINPR:-tidak ada}"
printf '  pkg-config   : %s\n' "${LIBS_PC:0:120}"

diagnosa() {
  echo "--- diagnosa berkas library"
  for f in "$A_INST_FRDP" "$A_BUILD_FRDP"; do
    [ -n "$f" ] && [ -f "$f" ] || continue
    echo "  berkas: $f"
    ls -la "$f" 2>&1 | sed 's/^/    /'
    file "$f" 2>&1 | head -1 | sed 's/^/    /'
    head -c 8 "$f" 2>/dev/null | od -c 2>/dev/null | head -2 | sed 's/^/    /'
    (ar t "$f" 2>&1 | head -3 | sed 's/^/    anggota: /') || true
    (llvm-ar t "$f" 2>&1 | head -3 | sed 's/^/    llvm-anggota: /') || true
  done
}

LABELS=(); INCS=(); LIBS=()
add() { LABELS+=("$1"); INCS+=("$2"); LIBS+=("$3"); }
add "1-pc-install"        "$CFLAGS_PC $INC_SRC"           "$LIBS_PC $SYS"
add "2-pc-buildtree"      "$CFLAGS_PC $INC_GEN $INC_SRC"  "$LIBS_PC $SYS"
[ -n "$A_BUILD_FRDP" ] && add "3-arsip-build" "$CFLAGS_PC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR $SYS"
[ -n "$A_INST_FRDP" ]  && add "4-arsip-install" "$CFLAGS_PC $INC_SRC"        "$A_INST_FRDP $A_INST_WINPR $SYS"
[ -n "$INC_CC" ]       && add "5-flagresmi" "$INC_CC $INC_SRC"               "$LIBS_PC $SYS"
[ -n "$INC_CC" ] && [ -n "$A_BUILD_FRDP" ] && add "6-flagresmi-arsip" "$INC_CC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR $SYS"

W=""
for i in "${!LABELS[@]}"; do
  echo "::: kandidat ${LABELS[$i]}"
  if clang -fsanitize=address -fno-omit-frame-pointer -g -O1 \
       ${INCS[$i]} "$HARNESS" -o "$OUT/harness_nego" ${LIBS[$i]} \
       2>"$OUT/try-${LABELS[$i]}.log"; then
    echo "  BERHASIL: ${LABELS[$i]}"
    W="${LABELS[$i]}"
    break
  fi
  echo "  gagal: ${LABELS[$i]}"
  sed -n '1,5p' "$OUT/try-${LABELS[$i]}.log" | sed 's/^/    /'
done

if [ -z "$W" ]; then
  echo "::error::semua kombinasi gagal — diagnosa di bawah"
  diagnosa
  for f in "$OUT"/try-*.log; do echo "--- $f"; head -15 "$f"; done
  exit 1
fi

echo "KANDIDAT_BERHASIL=$W" >> "${GITHUB_ENV:-/dev/null}" || true
ls -l "$OUT/harness_nego"
