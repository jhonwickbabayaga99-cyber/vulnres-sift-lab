# ci/ — menjalankan tahap `poc` di GitHub Actions (tanpa beban mesin lokal)

## Kenapa di CI
Mesin lokal: 7,4 GB RAM (sering cuma ~0,5 GB bebas) dan **tidak ada compiler C**.
Runner GitHub **publik: 4 vCPU / 16 GB RAM, gratis & tak terbatas** → build FreeRDP + ASan
dan menjalankan harness di sana. Lokal = 0 GB, 0 RAM.

> Repo harus **publik** agar menit tak terbatas. Repo privat: 2 vCPU / 8 GB, kuota 2.000 menit/bulan
> (cukup untuk ~40 build penuh; biaya lanjutan $0,006/menit Linux).

## Isi
| Berkas | Fungsi |
|---|---|
| `../.github/workflows/vulnres.yml` | 2 job: **static-core** (sift: index→...→triage) dan **dynamic-asan** (build FreeRDP + harness ASan) |
| `harness/harness_nego.c` | PoC: suntik routing token 600 B → panggil jalur pengiriman → harap ASan `heap-buffer-overflow` |
| `harness/CMakeLists.txt` | Build harness terhadap FreeRDP hasil install; header internal diambil dari pohon sumber |

## Cara menerbitkan (sekali saja)
```bash
# 1) di folder VULNRES/ (root repo)
git init -b main
git config user.name  "<nama-kamu>"      # lokal repo saja, tidak mengubah config global
git config user.email "<email-kamu>"
git add -A && git commit -m "vulnres: sift core + ASan harness + workflow"

# 2) buat repo PUBLIK lalu push
#    opsi A (browser): buat repo kosong di github.com, lalu:
git remote add origin https://github.com/<user>/<repo>.git
git push -u origin main

#    opsi B (gh CLI portable, sudah diunduh di tools/):
#    ./tools/gh_*/bin/gh.exe auth login          # device flow, kamu yang menyelesaikan
#    ./tools/gh_*/bin/gh.exe repo create <repo> --public --source . --push
```

## Menjalankan
- Otomatis saat `push` ke `main`, atau manual: **Actions → vulnres-freerdp-asan → Run workflow**.
- Hasil: tab **Summary** job (ringkas klaster + jejak ASan) dan **Artifacts**:
  - `sift-static-results` → `clusters-nego.json`, `clusters-core.json`, `graph.db`
  - `asan-run-artifacts` → `out/asan-run.log`, binary harness

## Yang diharapkan dari run pertama
- `static-core` hampir pasti hijau; artefaknya memuat klaster `nego->RoutingTokenLength` berlabel **real**.
- `dynamic-asan` bisa **gagal sengaja** (step di-`continue-on-error`): `nego_send_negotiation_request`
  butuh transport/pengaturan yang lebih lengkap. Log akan menunjukkan sejauh mana jalur tercapai,
  lalu harness diiterasi sampai muncul `WRITE of size`. Ini memang alur artikel: kandidat statis →
  harness berulang → bukti terukur.

## Catatan etika/ruang lingkup
Harness ini menyerang **instance FreeRDP yang kita bangun sendiri** di runner (lab), bukan sistem
orang lain. Untuk target bounty: hanya yang sudah memberi izin dan sesuai aturan program.

## Cara harness dibangun (diperbarui)

Harness **tidak** lagi dibangun lewat proyek CMake terpisah: `find_package(FreeRDP)` tidak mengekspor
target yang bisa dipakai untuk build minimal (`WITH_CLIENT=OFF`), dan cabang fallback menghasilkan
`-lfreerdp2` yang tidak ada. Sekarang workflow memanggil clang langsung:

- header internal dari pohon sumber (`libfreerdp/core`, `libfreerdp`, `winpr/include`) + prefix install;
- lib dari `pkg-config --static --libs freerdp3 winpr3` (dengan `PKG_CONFIG_PATH` ke prefix install);
- `-fsanitize=address` di compile **dan** link.

Alasan teknis: `nego_*` dan `transport_new()` ditandai `FREERDP_LOCAL` (tidak diekspor dari .so),
jadi wajib link statis. Revisi target dipin lewat env `FREERDP_COMMIT` — saat ini revisi **rentan**
(`993499447e32…`, 2026-06-25); perbaikannya ada di `70d05577a3a1` (2026-08-19, "fix capacity checks").
