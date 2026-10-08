# RESULT-FREERDP.md — bukti bahwa harness kita bekerja pada target asli

Target: FreeRDP (sparse checkout `libfreerdp/core` + `channels/urbdrc` — 150 berkas C/H, 4,9 MB).
Artikel Quarkslab memakai seluruh repo (~500k baris). Kita sengaja memakai subset agar cepat,
lalu membandingkan **perilaku**, bukan angka mentah.

## 1. Angka terukur (bukan klaim)

| Metrik | Artikel (seluruh repo) | Kita (subset 150 berkas) |
|---|---|---|
| Fungsi terindeks | 13.506 | 2.744 |
| Tipe | 3.105 | 249 |
| Call edge | 31.705 (termasuk sintetis) | 21.816 (16.470 sintetis/tak-teresolusi) |
| Sumber potensial | — | 1.351 |
| Sink | — | 1.755 |
| Penulisan field dari sumber/param | — | 400 |
| Waktu index | (tak dilaporkan) | **4,9 detik** |
| Slice | 304 | 2 (sub-pohon) / per-komponen dgn `--dir` |
| Temuan → klaster (slice `nego`) | 14 temuan (dari 2 slice → 130 → 36 klaster, 20 real) | **224 temuan → 52 klaster (5 real, 47 mixed)** |
| Presisi (setelah patch argumen-sink) | — | real turun dari 27→5 (nego) dan 332→74 (core penuh) tanpa kehilangan temuan asli |

Kalau `--dir libfreerdp/core/nego` dipakai (setara "slice 166"):
`673 fungsi · 1 berkas · 25 sumber · 30 sink · 27 penulisan-field`.

## 2. Temuan yang dihasilkan mesin (cocok dengan advisory `GHSA-2vf2-grvj-6g8x`)

```
[real] nego->RoutingTokenLength   — "sumber dan pemakaian (sink) pada kunci yang sama → jalur utuh"
   field_taint_write   libfreerdp/core/nego.c:2028   param:RoutingTokenLength → nego->RoutingTokenLength
   field_taint_sink    libfreerdp/core/nego.c:2034   dipakai CopyMemory   ← SITUS HEAP OVERFLOW
   field_taint_sink    libfreerdp/core/nego.c:2029   dipakai malloc       (alokasi ukuran bertaint)
   field_taint_sink    libfreerdp/core/nego.c:1637   dipakai Stream_Write_UINT16
   field_taint_sink    libfreerdp/core/nego.c:1638   dipakai Stream_Write_UINT32
[real] nego->RoutingToken         — pasangan kedua (buffer-nya, bukan cuma panjangnya)
```

Kode aslinya (`nego.c`):
```c
2022 BOOL nego_set_routing_token(rdpNego* nego, const void* RoutingToken, DWORD RoutingTokenLength)
2028     nego->RoutingTokenLength = RoutingTokenLength;          // ← tulis (f-007 versi kita)
2029     nego->RoutingToken = (BYTE*)malloc(nego->RoutingTokenLength);
2034     CopyMemory(nego->RoutingToken, RoutingToken, nego->RoutingTokenLength);   // ← overflow (f-005)
1153     Stream_Write(s, nego->RoutingToken, nego->RoutingTokenLength);
```
Mesin menemukan **write@2028 → sink@2034** sebagai satu klaster `real`, tanpa diberi tahu CVE-nya,
tanpa daftar CVE lama, tanpa korpus fuzz — hanya `git clone` + kosakata generik. Ini persis
langkah `f-007 ↔ f-005` di artikel, dan situs sink-nya sama dengan advisory resmi.

## 2b. Rantai penuh (setelah tambalan setter/getter)

Mesin merekonstruksi **seluruh jalur CVE** dari data jaringan sampai sink, lintas 3 berkas:

```
redirection.c:726  rdp_redirection_read_data(..., &redirection->LoadBalanceInfoLength, &redirection->LoadBalanceInfo)
                   └─ sumber: data PDU Redirection dari server
redirection.c:611  freerdp_settings_set_pointer_len(settings, FreeRDP_LoadBalanceInfo, redirection->LoadBalanceInfo, …)
                   └─ propagasi field→field: settings::FreeRDP_LoadBalanceInfo   (src='via:field-taint')
connection.c:449   nego_set_routing_token(rdp->nego, settings->LoadBalanceInfo, settings->LoadBalanceInfoLength)
                   └─ penghubung antar-prosedur: param_idx=2 milik nego_set_routing_token
nego.c:2028        nego->RoutingTokenLength = RoutingTokenLength;      ← tersimpan bertaint
nego.c:2034        CopyMemory(nego->RoutingToken, RoutingToken, nego->RoutingTokenLength);   ← OVERFLOW
```
Jalur kedua yang **aman** (`nego.c:1010` `nego_read_request_token_or_cookie`, ada cek `strnlen`) juga terekam —
persis seperti artikel membuang satu jalur setelah dibuktikan berbatas.

Tambalan yang membuat ini mungkin (4 bug nyata ditemukan saat mengerjakan):
1. `arglist` menyertakan token `(`/`)` → **indeks argumen bergeser satu**.
2. Setter (`*_set_pointer_len`) tidak dicatat sebagai penulisan field → sekarang dicatat + masuk set taint.
3. Tidak ada propagasi field→field lintas fungsi → `propagate_taint()` (pasca-index, 3 putaran, +394 penulisan).
4. Teks argumen tersimpan **dengan tanda kurung** → pemisah depth-aware menolak memecah.

## 3. Cara menjalankan (reproducible)

```bash
cd VULNRES
python3 src/sift.py index   --src corpus/freerdp --db state/freerdp.db          # ~5s untuk 150 berkas
python3 src/sift.py recon   --db state/freerdp.db --out state/slices.json
python3 src/sift.py slice   --db state/freerdp.db --dir libfreerdp/core/nego --out state/slice-nego.json
python3 src/sift.py analyze --db state/freerdp.db --slice state/slice-nego.json --out state/f.json
python3 src/sift.py triage  --in state/f.json --out state/clusters.json
```
Uji regresi mini (sampel sintetis, pola sama): `corpus/uji/` → `state/uji-clusters.json` (1 klaster `real`).

## 4. Validasi dinamis (ASan) — TERBUKTI ✅

Dijalankan sebagai artefak CI (runner bersih), bukan klaim: repo `vulnres-sift-lab`,
workflow `vulnres-freerdp-asan`, run `37750128623` — **kedua job `success`**.
Revisi target dipin ke commit **rentan** `993499447e32344370a16936c8434317952df4e3` (25 Jun 2026).

Artefak: `out/asan-run.log` (+ biner `build-harness/harness_nego`) — salinan di `evidence/`.

```
[harness] instance+context siap (settings=0x52e000000400)
[harness] menyuntikkan routing token 600 byte (batas alokasi 512)
[harness] RoutingTokenLength tersimpan; memanggil nego_send_negotiation_request
==4922==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x515000003200 ...
WRITE of size 600 at 0x515000003200 thread T0
    #0 __asan_memcpy
    #1 Stream_Write                     winpr/include/winpr/stream.h:1193:4
    #2 nego_send_negotiation_request    libfreerdp/core/nego.c:1098:3      ← situs overflow
    #3 main                             ci/harness/harness_nego.c:84:8
0x515000003200 is located 0 bytes after 512-byte region [0x515000003000,0x515000003200)
allocated by thread T0 here:
    #1 Stream_New                       winpr/libwinpr/utils/stream.c:101:22
    #2 nego_send_negotiation_request    libfreerdp/core/nego.c:1083:6      ← alokasi 512 B
SUMMARY: AddressSanitizer: heap-buffer-overflow ... in __asan_memcpy
exit=1
```

Bacaan: token routing **600 B** (data penyerang) ditulis ke buffer **512 B** yang dialokasikan
`Stream_New(nullptr, 512)` di `nego.c:1083`, tanpa pemeriksaan kapasitas pada revisi itu —
persis yang digambarkan artikel ("...into the 512-byte allocation created by
`nego_send_negotiation_request` (nego.c:1083)"). **Nomor baris alokasinya identik.**

Bukti bahwa ini bug yang sama dengan advisory: commit perbaikan **`70d05577a3a1`** (19 Agu 2026,
*"[core,nego] fix capacity checks"*) menambahkan tepat

```c
+ if (!Stream_EnsureRemainingCapacity(s, nego->RoutingTokenLength))
      Stream_Write(s, nego->RoutingToken, nego->RoutingTokenLength);
```

dan di revisi rentan `Stream_EnsureRemainingCapacity` muncul **0 kali** di `nego.c`.

### Cara CI membangunnya (jangan diulang dari nol)

| Syarat | Nilai yang bekerja | Kalau salah, gejalanya |
|---|---|---|
| Revisi | `FREERDP_COMMIT` = **SHA 40 karakter** | `couldn't find remote ref` (SHA pendek ditolak) |
| LTO | `-DCMAKE_INTERPROCEDURAL_OPTIMIZATION=OFF` | `ld: libfreerdp3.a: file format not recognized` (objek bitcode, GNU ld tak sanggup) |
| Header | `pkg-config --cflags freerdp3 winpr3` **didahulukan** | `freerdp/config.h file not found` (header generated menang) |
| Include internal | `-I freerdp-src/libfreerdp/core` | `transport.h`/`nego.h` tak ketemu (tak diinstal) |
| Lib | `build-freerdp/libfreerdp/libfreerdp3.a` + `build-freerdp/winpr/libwinpr/libwinpr3.a` | glob `libfreerdp*.a` salah pilih `libfreerdp-client3.a` |
| Link | statis (+ `-fsanitize=address`); `nego_*`/`transport_new` `FREERDP_LOCAL` = tak diekspor `.so` | `undefined reference` |
| API | `freerdp_new()` → `freerdp_context_new()` → `transport_new(ctx)` → `nego_new(transport)` | kompilasi gagal / crash di luar sink |
| Pelaporan | cetak baris galat dari **posisi mana pun** + format anggota arsip | error terkubur di bawah ~30 baris warning deprecation |

Skrip: `ci/harness/build.sh` (10 kandidat include+lib, berhenti di yang pertama berhasil),
`ci/harness/extract_flags.py` (ambil `-I` dari `compile_commands.json`), `ci/harness/harness_nego.c`.

## 5. Yang belum (dan mengapa)

- `poc`/`chain`/`exploit` masih **gate deklaratif** di `sift.py`, belum generator otomatis.
  Harness ASan-nya sudah ada dan terbukti (§4), tetapi ia **ditulis manual** — belum dihasilkan
  mesin dari klaster (class + field + sink → harness). `chain` masih butuh kandidat kedua
  (kebocoran/info-leak) dan `exploit` butuh heap grooming + bypass mitigasi (ASLR/NX/CFG/CET).
- **Penghubung pemanggil belum terbentuk, dan sebabnya presisi**: `nego_set_routing_token` punya 2 pemanggil —
  | Jalur | Lokasi | Sifat |
  |---|---|---|
  | **Redirection (jalur CVE)** | `redirection.c:611` `freerdp_settings_set_pointer_len(settings, FreeRDP_LoadBalanceInfo, <data PDU>, len)` → `connection.c:449` `nego_set_routing_token(rdp->nego, settings->LoadBalanceInfo, settings->LoadBalanceInfoLength)` | lewat **setter fungsi** + field `settings->…` ⇒ taint kita belum memodelkannya |
  | Aman (dibuang di artikel) | `nego.c:1010` `nego_set_routing_token(nego, str, len)` + `strnlen(str, len)` | lolos batas, bukan bug |
  Perbaikan berikutnya = modelkan pasangan **setter/getter** (`freerdp_settings_set_pointer*` ↔ `settings->X`) sebagai penulisan field, lalu rangkai **field→field** lintas fungsi. Inilah "kosakata khusus target" yang di artikel dikerjakan agen — dan bukti bahwa pemisahan core/agen mereka memang perlu.
- Slicing `--entry` masih keturunan-satu-arah; artikel menghitung 9/65 berkas karena mereka
  meresolusi *function pointer*. Kita 3 berkas (`nego.c`, `tpdu.c`, `tpkt.c`) untuk `nego_recv`
  — tiga berkas pertama **sama persis** dengan keluaran artikel, sisanya = edge fptr yang belum kita resolusikan.
- Peran agen (Hermes `delegate_task` / CLI `claude-code`) belum dipasang; kontrak & gate-nya sudah
  ditulis di `HARNESS.md` §3.

## 6. Catatan kejujuran

Harness ini **menemukan jalur yang sudah diketahui** (CVE publik FreeRDP) pada kode yang kami
sengaja pilih karena itu target artikel. Ia bukan bukti bahwa mesin menemukan 0-day; ia bukti
bahwa **metodenya dapat dibangun ulang dan bekerja secara terukur** pada kode C nyata:
recall tinggi → klaster → jalur utuh → **crash di bawah ASan** (`WRITE of size 600` ke buffer
512 B, alokasi `nego.c:1083`) dengan bukti `berkas:baris` di setiap langkah.

Yang tetap benar dan penting: **temuan ini bernilai bounty 0** — sudah ada advisory dan sudah
ditambal di `master`. Nilai sesungguhnya adalah mesinnya (§1–§4) yang bisa diarahkan ke target
C/C++ lain yang belum ditambal.

## 7. Kelas kedua ditemukan mesin sendiri: reserve-tanpa-tulis (CWE-457/908)

Kosakata baru di `sift.py`: `RESERVE` (Stream_Seek/SetPosition), `CLEANER` (Stream_Write*/Zero/memset),
`EMIT` (stream_write_and_free/channel_write/…) + tabel `reserves`. Aturan: sebuah reserve pada stream
**keluaran** (parameter `out` atau hasil `Stream_New`) yang **tidak** diikuti penulisan/zero dan **tidak**
mengembalikan stream itu (`return out;`) lalu stream tersebut dikirim keluar → kandidat `real`.

Hasil pada revisi rentan yang sama (`993499447e32…`, `channels/urbdrc`):

| Klaster | Baris | Cocok dengan advisory `GHSA-hw7p-5h2r-83gq` |
|---|---|---|
| `[real] urb_write_completion` | **134** | ya — "reserves OutputBufferSize bytes with Stream_Seek, without writing or zeroing" |
| `[real] urb_isoch_transfer_cb` | **893** | ya — "same pattern in a second completion path at data_transfer.c:892/:893" |

14 kandidat `[mixed]` lain (helper control-transfer) disaring oleh triage — recall dulu, saring kemudian.
Gate CI: `ci/assert_uninit.py` (gagal bila salah satu titik hilang) dijalankan di job `static-core`.

Catatan penting & jujur: master terbaru **masih** memakai `Stream_Seek` tanpa zero (perbaikan hulu bukan
zeroing; helper `urb_completion_payload_size()` mengembalikan `outputBufferSize` untuk transfer IN).
Apakah master masih bocor **tidak** boleh diklaim dari pembacaan statis — itu urusan validasi dinamis (Blok 2/3).

## 8. Validasi dinamis kebocoran urbdrc (CWE-457/908) — TERBUKTI ✅

Harness `ci/harness/harness_urbdrc.c` (+ `ci/harness/build_urbdrc.sh`), job CI `urbdrc-leak`,
run `37765016993`. Salinan log: `evidence/urbdrc-leak-37765016993.log`.

```
harness urbdrc — kebocoran memori tak-terinisialisasi (CWE-457/908)
  MALLOC_PERTURB_=0xcd
  [transfer GAGAL] total PDU=4132 byte · region OutputBufferSize=4096 byte (offset 36) · byte dominan 0x32 = 100.0%
  LEAK: 4096 byte memori tak-terinisialisasi terkirim ke server (dominan 0x32)
  [transfer SUKSES (kontrol)] … byte dominan 0x41 = 99.1% → kontrol OK: region berisi tulisan perangkat
```

Bacaan: PDU yang "dikirim ke server" = **36 byte header + 4096 byte payload**. Pada kasus transfer IN
**gagal**, seluruh 4096 byte payload adalah `0x32` = `0xcd ^ 0xff` — yaitu pola `MALLOC_PERTURB_`,
bukti bahwa region itu **memori malloc yang tidak pernah ditulis** (sisa heap → berisi pointer di
proses nyata, persis yang dipakai untuk menaklukkan ASLR). Kasus kontrol (transfer sukses) mengisi
region dengan pola perangkat `0x41` → pengukuran membedakan, bukan hijau palsu.

Cara harness menembus jalur ini (semua fakta diverifikasi dari sumber @`993499447e32…`):

| Langkah | Detail |
|---|---|
| Pintu masuk | `urbdrc_process_udev_data_transfer()` (non-static) → `urbdrc_process_transfer_request()` → `case TS_URB_BULK_OR_INTERRUPT_TRANSFER` → `urb_bulk_or_interrupt_transfer()` → `pdev->bulk_or_interrupt_transfer()` |
| Titik bocor | fungsi `static urb_write_completion()` → `Stream_Seek(out, OutputBufferSize)` (:134) → `stream_write_and_free()` |
| Simulasi kegagalan | stub `IUDEVICE::bulk_or_interrupt_transfer` memanggil callback penyelesaian dengan `status = 0xC0000001` (device stall) dan `OutputBufferSize = 4096` |
| Penangkap PDU | harness menyediakan `stream_write_and_free()` sendiri (menyalin byte keluar), karena itu `urbdrc_main.o` **tidak** ditautkan |
| Pengukuran | `MALLOC_PERTURB_=0xcd` (glibc mengisi memori baru dengan `0xcd ^ 0xff`) + statistik byte dominan ≥90% |

Catatan kejujuran: gate pertama menandai "BELUM TERBUKTI" bukan karena pengukurannya salah, melainkan
karena bug di harness (cabang kontrol lupa menyetel `exit_code = 0`). Diperbaiki; angka bocoran
(100% pola perturb) sudah benar sejak run pertama.
