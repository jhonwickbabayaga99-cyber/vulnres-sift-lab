#!/usr/bin/env bash
# Bangun + jalankan harness kebocoran urbdrc (Blok 2/3).
#
# Harness mengompilasi `channels/urbdrc/client/data_transfer.c` ke dalam TU-nya sendiri supaya
# fungsi `static` (titik bocor) bisa dipanggil lewat pintu masuk non-static
# `urbdrc_process_udev_data_transfer`. Karena itu JANGAN menautkan urbdrc_main.o —
# `stream_write_and_free` sengaja didefinisikan harness sebagai penangkap PDU.
set -e

SRC=freerdp-src
BUILD=build-leak-frdp
OUT=build-leak
mkdir -p "$OUT"
export PKG_CONFIG_PATH="$HOME/frdp/lib/pkgconfig:$HOME/frdp/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"

A_COMMON=$(find "$BUILD" -name 'liburbdrc-common.a' 2>/dev/null | head -1 || true)
A_FRDP=$(find "$BUILD" -name 'libfreerdp3.a' 2>/dev/null | head -1 || true)
A_WINPR=$(find "$BUILD" -name 'libwinpr3.a' 2>/dev/null | head -1 || true)
echo "--- arsip: common=${A_COMMON:-tidak ada} freerdp=${A_FRDP:-tidak ada} winpr=${A_WINPR:-tidak ada}"
if [ -z "$A_FRDP" ] || [ -z "$A_WINPR" ]; then
  echo "::error::arsip inti FreeRDP/WinPR tak ditemukan di $BUILD"
  exit 1
fi

CFLAGS_PC=$(pkg-config --cflags freerdp3 winpr3 2>/dev/null || true)
LIBS_PC=$(pkg-config --static --libs freerdp3 winpr3 2>/dev/null \
          || pkg-config --libs freerdp3 winpr3 2>/dev/null || true)
INC="-I$PWD/$SRC/channels/urbdrc/client -I$PWD/$SRC/channels/urbdrc/common -I$PWD/$SRC/include -I$PWD/$SRC/libfreerdp/core -I$PWD/$SRC/libfreerdp -I$PWD/$SRC/winpr/include"

echo "::: kompilasi harness_urbdrc"
set +e
clang -O1 -g -DNDEBUG $CFLAGS_PC $INC ci/harness/harness_urbdrc.c -o "$OUT/harness_urbdrc" \
  $A_COMMON $A_FRDP $A_WINPR $LIBS_PC -lssl -lcrypto -lz -lpthread -lm -ldl -lrt \
  > "$OUT/cc.log" 2>&1
CC_RC=$?
set -e
if [ $CC_RC -ne 0 ]; then
  echo "::error::kompilasi/link harness gagal (exit $CC_RC)"
  echo "--- baris galat:"
  grep -iE "error:|undefined reference|cannot find|fatal error" "$OUT/cc.log" | head -25 || true
  echo "--- 12 baris terakhir:"
  tail -12 "$OUT/cc.log"
  exit 1
fi
ls -l "$OUT/harness_urbdrc"

echo "::: jalankan (MALLOC_PERTURB_=0xcd — glibc mengisi memori baru dengan pola)"
set +e
MALLOC_PERTURB_=0xcd "$OUT/harness_urbdrc" > "$OUT/leak.log" 2>&1
RC=$?
set -e
cat "$OUT/leak.log"
if [ $RC -ne 0 ]; then
  echo "::error::harness melaporkan BELUM TERBUKTI (exit $RC)"
  exit 1
fi
echo "::: GATE LULUS — kebocoran memori tak-terinisialisasi terbukti terukur"
