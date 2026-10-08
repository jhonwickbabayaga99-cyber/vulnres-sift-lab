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

# nama TEPAT — glob "libfreerdp*.a" pernah salah pilih libfreerdp-client3.a
pick_lib() { # $1 = nama berkas, $2... = direktori pencarian (maks 3 level)
  local want="$1"; shift
  local d hit
  for d in "$@"; do
    [ -d "$d" ] || continue
    hit=$(find "$d" -maxdepth 3 -name "$want" 2>/dev/null | head -1)
    [ -n "$hit" ] && { echo "$hit"; return 0; }
  done
  return 1
}
A_BUILD_FRDP=$(pick_lib libfreerdp3.a build-freerdp || true)
A_BUILD_WINPR=$(pick_lib libwinpr3.a build-freerdp || true)
A_BUILD_CLI=$(pick_lib libfreerdp-client3.a build-freerdp || true)
A_INST_FRDP=$(pick_lib libfreerdp3.a "$HOME/frdp" || true)
A_INST_WINPR=$(pick_lib libwinpr3.a "$HOME/frdp" || true)
SYS="-lssl -lcrypto -lz -lpthread -lm -ldl -lrt"

echo "--- artefak terdeteksi"
printf '  build-freerdp: %s | %s\n' "${A_BUILD_FRDP:-tidak ada}" "${A_BUILD_WINPR:-tidak ada}"
printf '  install      : %s | %s\n' "${A_INST_FRDP:-tidak ada}" "${A_INST_WINPR:-tidak ada}"
printf '  pkg-config   : %s\n' "${LIBS_PC:0:120}"

# laporkan baris galat DI MANA PUN posisinya (warning deprecation mengubur error di awal log)
report_log() {
  local f="$1"
  [ -f "$f" ] || return 0
  echo "    --- baris galat:"
  grep -iE "error|undefined reference|cannot find|ld:" "$f" 2>/dev/null | grep -viE "deprecated|\-Wdep" | head -8 | sed 's/^/      /' || true
  echo "    --- 4 baris terakhir:"
  tail -4 "$f" | sed 's/^/      /'
}

LABELS=(); INCS=(); LIBS=(); EXTRA=()
add() { LABELS+=("$1"); INCS+=("$2"); LIBS+=("$3"); EXTRA+=("${4:-}"); }
add "1-pc-install"        "$CFLAGS_PC $INC_SRC"           "$LIBS_PC $SYS"
add "2-pc-buildtree"      "$CFLAGS_PC $INC_GEN $INC_SRC"  "$LIBS_PC $SYS"
if [ -n "$A_BUILD_FRDP" ] && [ -n "$A_BUILD_WINPR" ]; then
  add "3-arsip-build"      "$CFLAGS_PC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR $SYS"
  add "4-arsip-build-icu"  "$CFLAGS_PC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR -licuuc -licui18n -licudata $SYS"
fi
if [ -n "$A_BUILD_FRDP" ] && [ -n "$A_BUILD_CLI" ]; then
  add "5-arsip-build+client" "$CFLAGS_PC $INC_GEN $INC_SRC" "$A_BUILD_CLI $A_BUILD_FRDP $A_BUILD_WINPR $SYS"
fi
if [ -n "$A_INST_FRDP" ] && [ -n "$A_INST_WINPR" ]; then
  add "6-arsip-install"    "$CFLAGS_PC $INC_SRC"          "$A_INST_FRDP $A_INST_WINPR $SYS"
fi
if [ -n "$INC_CC" ] && [ -n "$A_BUILD_FRDP" ] && [ -n "$A_BUILD_WINPR" ]; then
  add "7-flagresmi-arsip"  "$INC_CC $INC_GEN $INC_SRC"    "$A_BUILD_FRDP $A_BUILD_WINPR -licuuc -licui18n -licudata $SYS"
fi
[ -n "$INC_CC" ] && add "8-flagresmi-pc" "$INC_CC $INC_SRC" "$LIBS_PC $SYS"
# LTO: bila arsip berisi LLVM bitcode (CMAKE_INTERPROCEDURAL_OPTIMIZATION=ON), GNU ld butuh lld
if [ -n "$A_BUILD_FRDP" ] && [ -n "$A_BUILD_WINPR" ]; then
  add "9-lld-lto-arsip"   "$CFLAGS_PC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR -licuuc -licui18n -licudata $SYS" "-fuse-ld=lld -flto"
fi
[ -n "$INC_CC" ] && [ -n "$A_BUILD_FRDP" ] && [ -n "$A_BUILD_WINPR" ] && \
  add "10-lld-lto-flagresmi" "$INC_CC $INC_GEN $INC_SRC" "$A_BUILD_FRDP $A_BUILD_WINPR -licuuc -licui18n -licudata $SYS" "-fuse-ld=lld -flto"

W=""
for i in "${!LABELS[@]}"; do
  echo "::: kandidat ${LABELS[$i]}"
  if clang -fsanitize=address -fno-omit-frame-pointer -g -O1 ${EXTRA[$i]} \
       ${INCS[$i]} "$HARNESS" -o "$OUT/harness_nego" ${LIBS[$i]} \
       2>"$OUT/try-${LABELS[$i]}.log"; then
    echo "  BERHASIL: ${LABELS[$i]}"
    W="${LABELS[$i]}"
    break
  fi
  echo "  gagal: ${LABELS[$i]}"
  report_log "$OUT/try-${LABELS[$i]}.log"
done

if [ -z "$W" ]; then
  echo "::error::semua kombinasi gagal"
  # bukti format arsip: kalau anggotanya LLVM bitcode, GNU ld memang tak bisa (butuh lld/-flto)
  ARCH=$(find build-freerdp -name 'libfreerdp3.a' 2>/dev/null | head -1)
  if [ -n "$ARCH" ]; then
    echo "  arsip: $ARCH → $(file -b "$ARCH" 2>/dev/null)"
    MEMBER=$(ar t "$ARCH" 2>/dev/null | head -1)
    if [ -n "$MEMBER" ]; then
      TMPD=$(mktemp -d)
      (cd "$TMPD" && ar x "$ARCH" "$MEMBER" 2>/dev/null) || true
      echo "  anggota: $MEMBER → $(file -b "$TMPD/$MEMBER" 2>/dev/null)"
      rm -rf "$TMPD"
    fi
  fi
  for f in "$OUT"/try-*.log; do echo "=== $f"; head -40 "$f"; done
  echo "=== resep link milik FreeRDP sendiri (dari build.ninja) ==="
  grep -m2 -A3 "C_EXECUTABLE_LINKER" build-freerdp/build.ninja 2>/dev/null | cut -c1-300 | sed 's/^/  /' || true
  exit 1
fi

echo "KANDIDAT_BERHASIL=$W" >> "${GITHUB_ENV:-/dev/null}" || true
ls -l "$OUT/harness_nego"
