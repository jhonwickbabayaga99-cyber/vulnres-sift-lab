#!/usr/bin/env bash
# Bangun + jalankan harness REMOTE (Blok 5): klien FreeRDP ASLI ↔ server RDP jahat di loopback.
#
# Berbeda dari harness rantai (yang sengaja TANPA ASan), di sini ASan justru bagian dari bukti:
# laporan overflow + jejak tumpukan harus membuktikan tulisan 600 byte itu terjadi di jalur
# redirection yang dipicu DATA DARI SOCKET, bukan oleh panggilan API internal.
set -e

SRC=freerdp-src
BUILD=build-remote-frdp
OUT=build-remote
mkdir -p "$OUT"
export PKG_CONFIG_PATH="$HOME/frdp/lib/pkgconfig:$HOME/frdp/lib64/pkgconfig:${PKG_CONFIG_PATH:-}"

A_FRDP=$(find "$BUILD" -name 'libfreerdp3.a' 2>/dev/null | head -1 || true)
A_WINPR=$(find "$BUILD" -name 'libwinpr3.a' 2>/dev/null | head -1 || true)
A_CLI=$(find "$BUILD" -name 'libfreerdp-client3.a' 2>/dev/null | head -1 || true)
A_SRV=$(find "$BUILD" -name '*server*.a' 2>/dev/null | head -1 || true)
echo "--- arsip: freerdp=${A_FRDP:-tidak ada} winpr=${A_WINPR:-tidak ada} client=${A_CLI:-tidak ada} server=${A_SRV:-tidak ada}"
if [ -z "$A_FRDP" ] || [ -z "$A_WINPR" ]; then
  echo "::error::arsip inti FreeRDP/WinPR tak ditemukan di $BUILD"
  exit 1
fi

CFLAGS_PC=$(pkg-config --cflags freerdp3 winpr3 2>/dev/null || true)
LIBS_PC=$(pkg-config --static --libs freerdp3 winpr3 2>/dev/null \
          || pkg-config --libs freerdp3 winpr3 2>/dev/null || true)
INC="-I$PWD/$SRC/libfreerdp/core -I$PWD/$SRC/libfreerdp -I$PWD/$SRC/winpr/include -I$PWD/$SRC/include"

echo "::: siapkan sertifikat uji (TLS) untuk server peer"
CERT="$OUT/cert.pem"
KEY="$OUT/key.pem"
if [ ! -f "$CERT" ] || [ ! -f "$KEY" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$KEY" -out "$CERT" -days 1 \
    -subj "/CN=127.0.0.1" >/dev/null 2>&1 || echo "    (openssl gagal, lanjut tanpa sertifikat)"
fi
ls -l "$CERT" "$KEY" 2>/dev/null || true

echo "::: kompilasi harness_remote (peer server + klien + ASan)"
set +e
clang -O1 -g -fsanitize=address -fno-omit-frame-pointer $CFLAGS_PC $INC \
  ci/harness/harness_remote.c -o "$OUT/harness_remote" \
  $A_FRDP ${A_SRV:-} $A_WINPR ${A_CLI:-} $LIBS_PC -lssl -lcrypto -lz -lpthread -lm -ldl -lrt > "$OUT/cc.log" 2>&1
CC_RC=$?
set -e
if [ $CC_RC -ne 0 ]; then
  echo "::error::kompilasi/link harness_remote gagal (exit $CC_RC)"
  grep -iE "error:|undefined reference|cannot find|fatal error" "$OUT/cc.log" | head -20 || true
  tail -10 "$OUT/cc.log"
  exit 1
fi
ls -l "$OUT/harness_remote"

echo "::: jalankan: server peer asli mengirim redirection (600 byte) ke klien asli"
set +e
ASAN_OPTIONS=detect_leaks=0:abort_on_error=0:fill_byte=0xcd \
  "./$OUT/harness_remote" "$CERT" "$KEY" > "$OUT/remote.log" 2>&1
RC=$?
set -e
echo "    exit=$RC"
cat "$OUT/remote.log"

echo "::: gate — bukti harus menyebut overflow 600 byte di jalur redirection/nego"
python3 ci/assert_remote.py "$OUT/remote.log"
echo "::: GATE LULUS — reachability remote + overflow terkonfirmasi ASan"
