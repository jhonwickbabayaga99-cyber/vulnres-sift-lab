# HARNESS.md — Memetakan "Quarkslab agentic vuln-research workflow" ke implementasi kita

Sumber: *From AI Agents to RCE: building a vulnerability research workflow* (Quarkslab, 2026-09-29).
Target artikel: FreeRDP `993499447` → 2 kerentanan → klien RCE. Waktu: 4 hari dari `git clone` ke laporan.

Inti pelajaran artikel (yang harus kita tiru, bukan sekadar "pakai LLM"):
1. **Dua lapis**: *deterministic core* (reproducible) + *agent layer* (non-deterministic tapi **auditable**).
2. Core di-*tune* untuk **recall** (sengaja over-produce); agent dipakai untuk **menyerap noise**, bukan untuk "menemukan bug dari nol".
3. Pipeline **8 tahap**: `graph → recon → slicing → analysis → triage → poc → chain → exploit`.
4. Peneliti bekerja **di antara** tahap, bukan di dalam; tiap tahap bisa dimasuki sendiri.
5. **Setiap artefak harus murah diperiksa** (path, lokasi, trace ASan, angka pengukuran) — bukan "model merasa masuk akal".
6. Tahap `exploit` diberi **harness sendiri + gate** yang harus terbukti terukur sebelum lanjut.

---

## 1) Pemetaan tahap → komponen kita

| Tahap artikel | Keluaran artikel | Implementasi kita | Status |
|---|---|---|---|
| `graph` | 13.506 fungsi · 3.105 tipe · 31.705 call edge (termasuk edge sintetis utk function pointer) | `sift index` — tree-sitter → SQLite (`files/funcs/types/calls/sources/sinks`) + graf `networkx` di memori | **B1 dibuat** |
| `recon` | komponen + exposure, threat model, barrier map, **304 slice** | `sift recon` — komponen = direktori/modul; skor exposure = jumlah panggilan source yang *reachable*; urutkan slice | **B1 dibuat** |
| `slicing` | `nego_recv` → 9 berkas; `rdp_recv_pdu` → 65 berkas | `sift slice --entry <fn>` — BFS call-graph dua arah → berkas kerja terbatas | **B1 dibuat** |
| `analysis` | taint 2 lintasan + lensa (CVE/CWE + khusus target) | `sift analyze` — taint intra-prosedural + 1-hop; lensa: (a) pola sink/source bawaan, (b) CWE, (c) **khusus target**: makro baca stream & wrapper alokasi | **B1 (versi 1)** |
| `triage` | 130 temuan → **36 klaster** (20 nyata, 3 laten, 3 campur, 10 FP) | `sift triage` — klaster per (field/variabel, fungsi, tipe); label `real/latent/mixed/noise`; keluaran JSON | **B1 dibuat** |
| `poc` | harness + ASan; `WRITE of size 615` ke region 512 B; pola `0xcd` 64/64 | `sift poc` — **butuh toolchain** (lihat §4). Template harness + ASan `ASAN_OPTIONS=...` fill byte | **B2 (butuh clang/WSL)** |
| `chain` | tulis-butut + bocor → primitif kuat | `sift chain` — hanya menerima klaster **tervalidasi**; kandidat kombinasi (write+leak, use-after-free+alloc, dll) | **B3 (butuh B2)** |
| `exploit` | harness eksploitasi + **gate**: lab → primitif terukur → control-flow → libc base → ASLR → payload | `sift exploit` — tangga gate yang harus terbukti; agen hanya untuk tugas terbatas (interpretasi bocoran, enumerasi objek, uji asumsi layout) | **B3** |

## 2) Model data (SQLite, `state/graph.db`)

```
files(path, lang, loc, sha)
funcs(id, name, file, start_line, end_line, is_static, params)
types(name, kind, file, line)                  -- struct/union/enum/typedef
calls(caller_id, callee_name, callee_id NULL, file, line, synthetic)
sources(func_id, name, file, line)             -- recv/read/fread/Stream_Read/... (dapat dikonfigurasi)
sinks(func_id, name, file, line, arg_expr)     -- strcpy/memcpy/sprintf/Stream_Write/...
findings(id, slice, kind, source_ref, sink_ref, var, evidence_json, status)
clusters(id, findings, class, reason)
```
Prinsip: **relasi disimpan sebagai edge**, bukan kesimpulan. Kalau mesin tak bisa membuktikan hubungan antar-temuan (kasus `f-005` ↔ `f-007`), ia **melaporkan keduanya terpisah** dan menyerahkannya ke triage — persis yang dilakukan Quarkslab.

## 3) Kontrak antar-tahap (yang membuat sistem bisa diaudit)

Tiap tahap menulis satu berkas JSON + bukti, lalu **gate deterministik** memutuskan boleh lanjut:

| Gate | Syarat terbukti |
|---|---|
| G1 `recon→slicing` | slice list punya ≥1 entri dengan `sources>0` |
| G2 `slicing→analysis` | berkas kerja ≤ N (default 80) — menjaga konteks agen tetap terbatas |
| G3 `analysis→triage` | tiap temuan punya `file:line` untuk source **dan** sink |
| G4 `triage→poc` | hanya klaster `real` yang boleh masuk |
| G5 `poc→chain` | ada ≥1 klaster dengan **bukti pengukuran** (ASan/angka), bukan asumsi |
| G6 `chain→exploit` | ≥2 primitif tervalidasi yang saling melengkapi (mis. write + leak) |
| G7 `exploit→laporan` | tiap langkah tangga punya keluaran yang terukur |

Agen (Hermes `delegate_task`, atau CLI `claude-code`/`codex`) hanya bekerja **di dalam** tahap, dengan masukan terbatas (slice), dan keluarannya **divalidasi gate**, bukan dipercaya.

## 4) Kendala lingkungan kita (fakta, bukan asumsi)

| Kebutuhan | Status di mesin ini | Rencana |
|---|---|---|
| Parser kode | ✅ `tree-sitter` + `tree-sitter-c/cpp` (terpasang, teruji) | inti `graph` |
| Graf | ✅ `networkx` | `slicing`/`chain` |
| DB | ✅ sqlite3 (stdlib) | `state/graph.db` |
| **Compiler C + ASan** | ❌ **tidak ada gcc/clang/cl/cc/tcc** | B2: pasang LLVM (`winget install LLVM.LLVM`) atau MSYS2-mingw; alternatif terbersih: **WSL2 + build-essential**. Cek `wsl --status` lebih dulu |
| Docker / r2 / ghidra | ❌ | tidak wajib di B1; r2/ghidra opsional untuk target biner |
| RAM | ⚠️ 7.4 GB, sering <0.5 GB bebas | indeks **streaming per berkas** + SQLite (jangan muat seluruh repo ke RAM); graf hanya untuk slice aktif |
| Disk | ✅ 61 GB bebas | corpus + build ASan |

## 5) Urutan pembangunan (milestone terukur)

- **B1 — Core deterministik (tanpa compiler)** ← *dibuat di sesi ini*
  - `sift index` (tree-sitter → SQLite + call graph), `sift recon`, `sift slice`, `sift analyze`, `sift triage`.
  - Uji terima: pada FreeRDP, `index` selesai; `slice --entry nego_recv` menghasilkan **≈9 berkas** (angka artikel) dan `slice --entry rdp_recv_pdu` **≈65**.
- **B2 — Validasi dinamis** (`sift poc`)
  - Pasang toolchain; bangun target `-fsanitize=address -g`; harness per klaster; `ASAN_OPTIONS=fill_...=0xcd` untuk uji kebocoran heap.
  - Uji terima: minimal satu klaster `real` menghasilkan **trace ASan** atau angka pengukuran (0xcd count).
- **B3 — Chain + exploit**
  - `sift chain` (kombinasi primitif) + `sift exploit` (tangga gate, tiap langkah harus terukur, ada titik campur tangan manusia).
- **B4 — Lapisan agen yang auditabel**
  - Orkestrator memanggil agen dengan kontrak JSON per tahap (`{stage, slice, artifacts, questions}` → `{hypotheses, evidence, next}`), menulis transkrip ke `eviden/`, dan **menolak** keluaran yang tak memenuhi gate.
  - Peran agen yang sudah terbukti berguna di artikel: (i) membangun **kosakata khusus target** untuk taint (makro baca, wrapper alokasi) — ini yang membuka temuan `f-005/f-007`; (ii) menafsirkan byte bocoran; (iii) menguji asumsi heap.

## 6) Yang tidak kita tiru

- **Bukan** push-button: tiap gate punya campur tangan manusia (artikel pun butuh 2 intervensi peneliti di tahap eksploit).
- **Bukan** auto-report: temuannya dinilai manusia sebelum dikirim (pelajaran `curl`: laporan plausible tanpa validasi menghabiskan waktu maintainer).
- Tanpa target/izin: harness ini alat lab/CTF/engagements; tak diarahkan ke sistem orang lain tanpa izin.
