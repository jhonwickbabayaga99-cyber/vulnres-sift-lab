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

## 4. Yang belum (dan mengapa)

- `poc`/`chain`/`exploit` **sengaja bergantung toolchain**: mesin ini tidak punya compiler C.
  Untuk membuktikan `WRITE of size N` seperti artikel dibutuhkan `clang`/WSL + `-fsanitize=address`
  dan harness server-jahat (redirection PDU memuat `LoadBalanceInfo` >512 B).
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

## 5. Catatan kejujuran

Harness ini **menemukan jalur yang sudah diketahui** (CVE publik FreeRDP) pada kode yang kami
sengaja pilih karena itu target artikel. Ia bukan bukti bahwa mesin menemukan 0-day; ia bukti
bahwa **metodenya dapat dibangun ulang dan bekerja secara terukur** pada kode C nyata:
recall tinggi → klaster → jalur utuh dengan bukti `berkas:baris`.
Tahap dinamis (ASan) tetap wajib untuk mengubah "kandidat" menjadi "kerentanan terbukti".
