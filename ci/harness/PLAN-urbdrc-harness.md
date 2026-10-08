# Build sheet — harness kebocoran urbdrc (Blok 2/3)

Status: **rencana eksekusi**, fakta di bawah sudah diverifikasi dari sumber pada commit terpin
`993499447e32344370a16936c8434317952df4e3` (revisi rentan). Belum ada kode harness yang lolos CI.

## Sasaran

Membuktikan dinamis bahwa `urb_write_completion` **mengirim memori tak-terinisialisasi** ke server
(CWE-457/908, advisory `GHSA-hw7p-5h2r-83gq`) — pasangan leak untuk overflow `nego` (Blok 1, sudah terbukti).

## Fakta yang sudah dipastikan (jangan diambil dari ingatan lagi)

| Hal | Nilai |
|---|---|
| Titik bocor | `channels/urbdrc/client/data_transfer.c:134` (`Stream_Seek(out, OutputBufferSize)`) dan `:893` (`urb_isoch_transfer_cb`) |
| Sifat | reserve tanpa tulis; byte stale berisi pointer heap+libc |
| Syarat bocor | transfer IN **gagal** (device stall `LIBUSB_ERROR_PIPE`) atau mengembalikan byte < yang dideklarasikan |
| Fungsi target | `static UINT urb_write_completion(...)` — **static**, tak bisa dipanggil langsung |
| Pintu masuk yang dipakai harness | `UINT urbdrc_process_udev_data_transfer(GENERIC_CHANNEL_CALLBACK* callback, URBDRC_PLUGIN* urbdrc, IUDEVMAN* udevman, wStream* data)` (`data_transfer.c:1957`, non-static) |
| Alur di dalamnya | `Stream_Rewind_UINT32(data)` → baca `InterfaceId, MessageId, FunctionId` → `udevman->get_udevice_by_UsbDevice(udevman, InterfaceId)` → cek `pdev->isChannelClosed(pdev)` dan `pdev->detach_kernel_driver(pdev)` → `switch (FunctionId)` |
| Header yang dibutuhkan | `channels/urbdrc/client/urbdrc_main.h` (definisi `S_IUDEVICE` di baris 97+, `get_udevice_by_UsbDevice` baris 192) dan `data_transfer.h` |
| Callback yang berakhir di titik bocor | `urb_bulk_transfer_cb` → `urb_write_completion(...)` (dipanggil di `data_transfer.c:851` dan `:863`) |
| Dependensi build channel | `libusb-1.0-0-dev`, `libudev-dev`, `libfuse3-dev` (channel lain), `-DWITH_CHANNELS=ON -DWITH_CLIENT=ON` |

## Rancangan harness (`ci/harness/harness_urbdrc.c`)

1. **Fake `IUDEVMAN`** dengan satu metode `get_udevice_by_UsbDevice()` → mengembalikan `IUDEVICE*` palsu.
2. **Fake `IUDEVICE`** (vtable dari `urbdrc_main.h`), minimal:
   - `isChannelClosed` → `FALSE`
   - `detach_kernel_driver` → `TRUE`
   - `bulk_or_interrupt_transfer` (dan/atau `control_transfer`) → **stub yang memanggil balik callback
     penyelesaian dengan status gagal** dan `OutputBufferSize` tetap >0. Inilah yang mereproduksi
     kondisi "transfer IN gagal" tanpa perangkat USB nyata.
3. **Fake `GENERIC_CHANNEL_CALLBACK`** dengan `plugin->channel` yang metode `Write`-nya **menyalin byte**
   ke buffer pengamatan (jadi seluruh PDU yang "dikirim ke server" tertangkap).
4. Susun `wStream* data` berisi `[InterfaceId][MessageId][FunctionId=URB_*]` + field URB
   (`EndpointAddress`, `TransferFlags` dengan bit arah IN, `OutputBufferSize` besar, `RequestId`).
   Posisi stream di-set supaya `Stream_Rewind_UINT32` mendarat di awal `InterfaceId`.
5. Panggil `urbdrc_process_udev_data_transfer(&cb, &urbdrc, &udevman, data)` dan **periksa byte hasil**.
6. Ulangi dengan `MsgId`/`FunctionId` untuk jalur isoch (`:893`) agar **kedua** jalur tertutup.

## Pengukuran kebocoran (Blok 2)

ASan **tidak** mendeteksi baca memori tak-terinisialisasi. Dua opsi:

- **Opsi A (murah, jalur utama):** build **tanpa ASan** + `MALLOC_PERTURB_=0xcd` (glibc mengisi memori
  baru dengan pola). Bukti = byte yang tertangkap di langkah 3 **mengandung pola tersebut**.
  Terukur, tanpa toolchain baru.
- **Opsi B (lebih kuat, lebih berat):** build seluruh FreeRDP + harness dengan `-fsanitize=memory`
  (MSan) → laporan `use-of-uninitialized-value` langsung. Perlu semua dependensi terinstrumentasi
  (OpenSSL tidak) sehingga biasanya mahal.

Selaras dengan advisory, leak ini yang memberi **basis heap (connect_base) dan libc** → mematikan ASLR
bagi overflow `nego` (Blok 4).

## Perubahan CI yang dibutuhkan

1. Job baru (sudah dicoba terpisah): bangun channel `urbdrc` dengan `libusb`/`libudev` — memastikan
   dependensi ini bisa dipenuhi runner sebelum harness ditulis.
2. Job **non-ASan** untuk harness leak (`MALLOC_PERTURB_`) — terpisah dari `dynamic-asan` yang sudah hijau.
3. Gate: harness harus mencetak `LEAK: <n> byte tak-terinisialisasi terkirim` + exit 0; jika tidak,
   gate gagal (tidak boleh hijau palsu).

## Batas kejujuran

Kedua advisory ini **sudah publik dan sudah ditambal** → nilai bounty 0. Hasil akhir blok-blok ini
adalah **bukti metodologi** (dua bug dirangkai jadi RCE, ala artikel Quarkslab), bukan uang.

## Kemajuan verifikasi (sesi ini, dari sumber @993499447)

| Yang dipastikan | Nilai |
|---|---|
| Dispatch dari `urbdrc_process_udev_data_transfer` | `case TRANSFER_IN_REQUEST → urbdrc_process_transfer_request(pdev, callback, data, MessageId, udevman, transferDir=USBD_TRANSFER_DIRECTION_IN)` |
| Layout parse di dalamnya (`data_transfer.c:1651+`) | `UINT32 CbTsUrb` → cek panjang `4 + CbTsUrb` → `UINT16 Size` (**wajib == CbTsUrb**) → `UINT16 URB_Function` → `UINT32 RequestId` → `switch(URB_Function)` |
| Handler yang sampai ke titik bocor | `URB_Function` = bulk/interrupt → handler memanggil `pdev->bulk_or_interrupt_transfer(...)` → callback `urb_bulk_transfer_cb` → **`urb_write_completion`** (`data_transfer.c:851`/`863`) |
| Simbol yang perlu di-link | `create_shared_message_header_with_functionid`, `write_shared_message_header_with_functionid` → **`urbdrc_helpers.c` (liburbdrc-common.a)**; `write_urb_result_header` → **sama TU** dengan data_transfer.c |
| Header internal | `channels/urbdrc/client/data_transfer.h` (prototipe `urbdrc_process_udev_data_transfer`), `channels/urbdrc/client/urbdrc_main.h` (`S_IUDEVICE` baris 97+, `IUDEVMAN::get_udevice_by_UsbDevice` baris 192) |
| Artefak build channel (terbukti di CI run #15) | `urbdrc_main.c.o`, `urbdrc-client-libusb.dir`, `channels/urbdrc/common/liburbdrc-common.a` |

### Sisa satu langkah sebelum menulis kode

1. Baca parse lanjutan handler bulk/interrupt (field: `EndpointAddress`, `TransferFlags`, `OutputBufferSize`, `RequestId`, ukuran paket) untuk menyusun stream yang tepat.
2. Ambil **nilai konstanta**: `TRANSFER_IN_REQUEST`, `TS_URB_BULK_OR_INTERRUPT_TRANSFER`, `USBD_TRANSFER_DIRECTION_IN` (ada di header common/urbdrc, bukan di `data_transfer.c`).
3. Baru tulis `harness_urbdrc.c` + job non-ASan (`MALLOC_PERTURB_=0xcd`) + gate.

Semua di atas sudah diverifikasi dari berkas pada revisi rentan — bukan dari ingatan.
