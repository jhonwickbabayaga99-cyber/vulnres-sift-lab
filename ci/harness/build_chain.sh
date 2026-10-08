#!/usr/bin/env bash
# Bangun + jalankan harness rantai (overflow nego → control-flow hijack).
#
# Memakai build FreeRDP TANPA ASan yang sama dengan job leak (build-leak-frdp) — justru wajib:
# ASan memasang redzone antar chunk sehingga penulisan tidak akan pernah mencapai tetangga.
set -e

SRC=freerdp-src
BUILD=build-leak-frdp
OUT=build-chain
mkdir -p "$OUT"
export PKG_CONFIG_PATH="$HOME/frdp/lib/pkgconfig:$HOME/frdp/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"

A_FRDP=$(find "$BUILD" -name 'libfreerdp3.a' 2>/dev/null | head -1 || true)
A_WINPR=$(find "$BUILD" -name 'libwinpr3.a' 2>/dev/null | head -1 || true)
echo "--- arsip: freerdp=${A_FRDP:-tidak ada} winpr=${A_WINPR:-tidak ada}"
if [ -z "$A_FRDP" ] || [ -z "$A_WINPR" ]; then
  echo "::error::arsip inti FreeRDP/WinPR tak ditemukan di $BUILD"
  exit 1
fi

CFLAGS_PC=$(pkg-config --cflags freerdp3 winpr3 2>/dev/null || true)
LIBS_PC=$(pkg-config --static --libs freerdp3 winpr3 2>/dev/null \
          || pkg-config --libs freerdp3 winpr3 2>/dev/null || true)
INC="-I$PWD/$SRC/libfreerdp/core -I$PWD/$SRC/libfreerdp -I$PWD/$SRC/winpr/include -I$PWD/$SRC/include"

echo "::: kompilasi harness_chain (tanpa ASan)"
set +e
clang -O1 -g -DNDEBUG $CFLAGS_PC $INC ci/harness/harness_chain.c -o "$OUT/harness_chain" \
  $A_FRDP $A_WINPR $LIBS_PC -lssl -lcrypto -lz -lpthread -lm -ldl -lrt > "$OUT/cc.log" 2>&1
CC_RC=$?
set -e
if [ $CC_RC -ne 0 ]; then
  echo "::error::kompilasi/link harness_chain gagal (exit $CC_RC)"
  grep -iE "error:|undefined reference|cannot find|fatal error" "$OUT/cc.log" | head -20 || true
  tail -10 "$OUT/cc.log"
  exit 1
fi
ls -l "$OUT/harness_chain"

echo "::: jalankan (harness menilai sendiri; exit 0 = hijack terbukti)"
set +e
"$OUT/harness_chain" > "$OUT/chain.log" 2>&1
RC=$?
set -e
cat "$OUT/chain.log"
if [ $RC -ne 0 ]; then
  echo "::error::harness rantai melaporkan BELUM TERBUKTI (exit $RC)"
  exit 1
fi
echo "::: GATE LULUS — overflow menjadi kendali alur eksekusi"
