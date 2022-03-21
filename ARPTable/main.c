// ARPTable.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <assert.h>

#include <kernel.h>
#include <queue.h>
#include <t_stdlib.h>
#include <tinet_defs.h>
#include <tinet_config.h>
#include <net/if.h>
#include <net/if_ppp.h>
#include <net/if_loop.h>
#include <net/ethernet.h>
#include <net/net_buf.h>
#include <sil.h>
#include <net/net_endian.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in4.h>
#include <netinet/in4_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet6/in6.h>
#include <netinet6/in6_var.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/if_ether.h>
#include <netinet/in_itron.h>

#include <netapp/dns.h>
#include <netapp/dhcp4_cli.h>
#include <netapp/dhcp4_cli_var.h>

#include "task.h"
#include "main.h"
#include "kernel_cfg.h"
#include "tinet_cfg.h"

// 192.168.137.201
#define IFADDR_LLADDR_0 0x12
#define IFADDR_LLADDR_1 0x34
#define IFADDR_LLADDR_2 0x56
#define IFADDR_LLADDR_3 0x78
#define IFADDR_LLADDR_4 0x9a
#define IFADDR_LLADDR_5 0xbc

// 192.168.137.202
uint8_t remote1_mac_addr[6] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbd };

// 192.168.137.203
uint8_t remote2_mac_addr[6] = { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbe };

T_IF_SOFTC g_ic;

T_IF_SOFTC *rx62n_get_softc(void)
{
	return &g_ic;
}

void rx62n_probe(T_IF_SOFTC *ic)
{
	//__builtin_trap();
}

void rx62n_init(T_IF_SOFTC *ic)
{
	//__builtin_trap();
}

void rx62n_reset(T_IF_SOFTC *ic)
{
	//__builtin_trap();
}

void rx62n_watchdog(T_IF_SOFTC *ic)
{
	__builtin_trap();
}

QUEUE output1_packets;
QUEUE output2_packets;

struct ether_packet_t {
	QUEUE queue;
	uint16_t len;
};

void rx62n_write(T_IF_SOFTC *ic, uint8_t *buf, int len, QUEUE *output_packets)
{
	struct ether_packet_t *node;

	node = (struct ether_packet_t *)malloc(sizeof(struct ether_packet_t) + len);
	if (node == NULL) {
		assert(false);
		return;
	}
	node->len = len;
	memcpy(&node[1], buf, len);

	queue_initialize(&node->queue);
	queue_insert_next(output_packets, &node->queue);
}

QUEUE input_packets;

void reply(QUEUE *output_packets)
{
	T_IF_SOFTC *ic = rx62n_get_softc();
	QUEUE *packet;
	ER ercd;

	if (queue_empty(output_packets))
		return;

	packet = queue_delete_next(output_packets);
	queue_initialize(packet);
	queue_insert_next(&input_packets, packet);

	ercd = sig_sem(ic->semid_rxb_ready);
	assert(ercd == E_OK);
}

uint16_t
calc_chksum(uint8_t proto, T_IN4_ADDR *src, T_IN4_ADDR *dst, uint8_t *buf, uint_t len)
{
	uint32_t	sum;
	uint_t		align;

	/* 4 オクテット境界のデータ長 */
	align = (len + 3) >> 2 << 2;

	/* 4 オクテット境界までパディングで埋める。*/
	if (align > len)
		memset(buf + len, 0, (size_t)(align - len));

	sum = in_cksum_sum(buf, align)
		+ in_cksum_sum(src, sizeof(T_IN4_ADDR))
		+ in_cksum_sum(dst, sizeof(T_IN4_ADDR))
		+ len + proto;
	sum = in_cksum_carry(sum);

	return (uint16_t)(~((uint16_t)sum));
}

void rx62n_start(T_IF_SOFTC *ic, T_NET_BUF *output)
{
	ER ret;
	uint8_t *data = (uint8_t *)output->buf;

	// IPv6
	if (((data[12] << 8) | data[13]) == 0x86DD)
		return;

	// 宛先MACアドレス
	if ((data[0] == 0xFF)
		&& (data[1] == 0xFF)
		&& (data[2] == 0xFF)
		&& (data[3] == 0xFF)
		&& (data[4] == 0xFF)
		&& (data[5] == 0xFF))
	{
		// ARP
		// 送信元MACアドレス
		assert((data[6] == IFADDR_LLADDR_0)
			&& (data[7] == IFADDR_LLADDR_1)
			&& (data[8] == IFADDR_LLADDR_2)
			&& (data[9] == IFADDR_LLADDR_3)
			&& (data[10] == IFADDR_LLADDR_4)
			&& (data[11] == IFADDR_LLADDR_5));
		// タイプ（ARP）
		assert(((data[12] << 8) | data[13]) == 0x0806);
		// ARP-ハードウェアタイプ（イーサネット）
		assert(((data[14] << 8) | data[15]) == 0x0001);
		// ARP-プロトコルタイプ（IPv4）
		assert(((data[16] << 8) | data[17]) == 0x0800);
		// ARP-ハードウェアアドレス長
		assert(data[18] == 6);
		// ARP-プロトコルアドレス長
		assert(data[19] == 4);
		// ARP-オペレーション-リクエスト
		assert(((data[20] << 8) | data[21]) == 0x0001);
		// ARP-送信元のMACアドレス
		assert((data[22] == IFADDR_LLADDR_0)
			&& (data[23] == IFADDR_LLADDR_1)
			&& (data[24] == IFADDR_LLADDR_2)
			&& (data[25] == IFADDR_LLADDR_3)
			&& (data[26] == IFADDR_LLADDR_4)
			&& (data[27] == IFADDR_LLADDR_5));
		// ARP-送信元のIPアドレス
		assert((data[28] == 192) && (data[29] == 168) && (data[30] == 137) && (data[31] == 201));
		// ARP-探索するMACアドレス
		assert((data[32] == 0x00) && (data[33] == 0x00) && (data[34] == 0x00) && (data[35] == 0x00) && (data[36] == 0x00) && (data[37] == 0x00));
		// ARP-探索するIPアドレス
		assert((data[38] == 192) && (data[39] == 168) && (data[40] == 137) && ((data[41] == 202) || (data[41] == 203)));

		ret = sig_sem(ic->semid_txb_ready);
		assert(ret == E_OK);

		uint8_t ipaddr = data[41];
		uint8_t *remote_mac_addr = (ipaddr == 202) ? remote1_mac_addr : remote2_mac_addr;
		QUEUE *output_packets = (ipaddr == 202) ? &output1_packets : &output2_packets;
		uint8_t arp_reply[42];
		memcpy(arp_reply, data, sizeof(arp_reply));
		// 宛先MACアドレス
		memcpy(&arp_reply[0], &arp_reply[6], 6);
		// 送信元MACアドレス
		arp_reply[6] = remote_mac_addr[0];
		arp_reply[7] = remote_mac_addr[1];
		arp_reply[8] = remote_mac_addr[2];
		arp_reply[9] = remote_mac_addr[3];
		arp_reply[10] = remote_mac_addr[4];
		arp_reply[11] = remote_mac_addr[5];
		// ARP-オペレーション-リプライ
		arp_reply[20] = 0x00;  arp_reply[21] == 0x02;
		// ARP-送信元のMACアドレス
		arp_reply[22] = remote_mac_addr[0];
		arp_reply[23] = remote_mac_addr[1];
		arp_reply[24] = remote_mac_addr[2];
		arp_reply[25] = remote_mac_addr[3];
		arp_reply[26] = remote_mac_addr[4];
		arp_reply[27] = remote_mac_addr[5];
		// ARP-送信元のIPアドレス
		arp_reply[28] = 192; arp_reply[29] = 168; arp_reply[30] = 137;  arp_reply[31] = ipaddr;
		// ARP-探索するMACアドレス
		arp_reply[32] = remote_mac_addr[0];
		arp_reply[33] = remote_mac_addr[1];
		arp_reply[34] = remote_mac_addr[2];
		arp_reply[35] = remote_mac_addr[3];
		arp_reply[36] = remote_mac_addr[4];
		arp_reply[37] = remote_mac_addr[5];
		// ARP-探索するIPアドレス
		arp_reply[38] = 192; arp_reply[39] = 168; arp_reply[40] = 137;  arp_reply[41] = 201;

		rx62n_write(ic, arp_reply, sizeof(arp_reply), output_packets);
	}
	else {
		uint8_t *remote_mac_addr = NULL;
		QUEUE *output_packets = NULL;
		uint8_t ipaddr = 0;
		// 宛先MACアドレス
		if ((data[0] == remote1_mac_addr[0])
			&& (data[1] == remote1_mac_addr[1])
			&& (data[2] == remote1_mac_addr[2])
			&& (data[3] == remote1_mac_addr[3])
			&& (data[4] == remote1_mac_addr[4])
			&& (data[5] == remote1_mac_addr[5])) {
			remote_mac_addr = remote1_mac_addr;
			output_packets = &output1_packets;
			ipaddr = 202;

		}
		else if ((data[0] == remote2_mac_addr[0])
			&& (data[1] == remote2_mac_addr[1])
			&& (data[2] == remote2_mac_addr[2])
			&& (data[3] == remote2_mac_addr[3])
			&& (data[4] == remote2_mac_addr[4])
			&& (data[5] == remote2_mac_addr[5])) {
			remote_mac_addr = remote2_mac_addr;
			output_packets = &output2_packets;
			ipaddr = 203;
		}
		assert(remote_mac_addr != NULL);
		// 送信元MACアドレス
		assert((data[6] == IFADDR_LLADDR_0)
			&& (data[7] == IFADDR_LLADDR_1)
			&& (data[8] == IFADDR_LLADDR_2)
			&& (data[9] == IFADDR_LLADDR_3)
			&& (data[10] == IFADDR_LLADDR_4)
			&& (data[11] == IFADDR_LLADDR_5));
		// タイプ（IPv4）
		assert((data[12] == 0x08) && (data[13] == 0x00));
		// 送信元IPアドレス
		assert((data[26] == 192) && (data[27] == 168) && (data[28] == 137) && (data[29] == 201));
		// 宛先IPアドレス
		assert((data[30] == 192) && (data[31] == 168) && (data[32] == 137) && (data[33] == ipaddr));

		int align = (output->len + 3) >> 2 << 2;
		uint8_t *udp_reply = (uint8_t *)malloc(align);
		memcpy(udp_reply, output->buf, output->len);

		// 宛先MACアドレス
		memcpy(&udp_reply[0], &udp_reply[6], 6);
		// 送信元MACアドレス
		udp_reply[6] = remote_mac_addr[0];
		udp_reply[7] = remote_mac_addr[1];
		udp_reply[8] = remote_mac_addr[2];
		udp_reply[9] = remote_mac_addr[3];
		udp_reply[10] = remote_mac_addr[4];
		udp_reply[11] = remote_mac_addr[5];
		// 宛先IPアドレス
		udp_reply[30] = udp_reply[26];
		udp_reply[31] = udp_reply[27];
		udp_reply[32] = udp_reply[28];
		udp_reply[33] = udp_reply[29];
		// 送信元IPアドレス
		udp_reply[26] = 192;
		udp_reply[27] = 168;
		udp_reply[28] = 137;
		udp_reply[29] = ipaddr;
		// 宛先ポート
		udp_reply[36] = udp_reply[34];
		udp_reply[37] = udp_reply[35];
		// 送信元ポート（2222）
		udp_reply[34] = 0x08;
		udp_reply[35] = 0xAE;
		// チェックサムは0
		udp_reply[40] = 0;
		udp_reply[41] = 0;

		uint16_t	len, sum;
		len = (((uint16_t)udp_reply[38]) << 8) | udp_reply[39];
		sum = calc_chksum(IPPROTO_UDP, (T_IN4_ADDR *)&udp_reply[26], (T_IN4_ADDR *)&udp_reply[30],
			&udp_reply[34], (uint_t)len);
		if (sum == 0)
			sum = UINT_C(0xffff);

		udp_reply[40] = (sum >> 8) & 0xFF;
		udp_reply[41] = sum & 0xFF;

		rx62n_write(ic, udp_reply, output->len, output_packets);

		free(udp_reply);
	}
}

ER rx62n_addmulti(T_IF_SOFTC *ic)
{
	return E_OK;
}

T_NET_BUF *rx62n_read(T_IF_SOFTC *ic)
{
	T_NET_BUF *input = NULL;
	uint16_t align;
	ER ercd;
	struct ether_packet_t *node;

	if (queue_empty(&input_packets)) {
		ext_ker();
		return NULL;
	}

	node = (struct ether_packet_t *)queue_delete_next(&input_packets);

	align = ((((node->len - sizeof(T_IF_HDR)) + 3) >> 2) << 2) + sizeof(T_IF_HDR);
	if ((ercd = tget_net_buf(&input, align, TMO_IF_RX62N_GET_NET_BUF)) == E_OK && input != NULL) {
		uint8_t *dst = input->buf + IF_ETHER_NIC_HDR_ALIGN;
		memcpy((void *)dst, (void *)&node[1], node->len);
	}
	else {
		assert((ercd == E_OK) && (input != NULL));
	}

	free(node);

	return input;
}

#define UDP_SOCKET_BUF_SIZE 256
uint8_t udp_buf1[2 * UDP_SOCKET_BUF_SIZE];
T_IPV4EP dstaddr1 = { MAKE_IPV4_ADDR(192, 168, 137, 202), 2222 };
uint8_t udp_buf2[2 * UDP_SOCKET_BUF_SIZE];
T_IPV4EP dstaddr2 = { MAKE_IPV4_ADDR(192, 168, 137, 203), 2222 };
volatile int termine_task1;
volatile int termine_task2;
volatile int snd_dat_task1;
volatile int rcv_dat_task1;
volatile int snd_dat_task2;
volatile int rcv_dat_task2;

ER socket_udp_callback(ID cepid, FN fncd, void *p_parblk)
{
	ER ret;
	uint8_t *p_snd_bef;
	uint8_t *p_rcv_bef;
	int len = UDP_SOCKET_BUF_SIZE;
	ID tskid;

	if (cepid == USR_UDP_CEP1) {
		p_snd_bef = udp_buf1;
		p_rcv_bef = &udp_buf1[UDP_SOCKET_BUF_SIZE];
		tskid = TASK1;
	}
	else if (cepid == USR_UDP_CEP2) {
		p_snd_bef = udp_buf2;
		p_rcv_bef = &udp_buf2[UDP_SOCKET_BUF_SIZE];
		tskid = TASK2;
	}
	else {
		assert((cepid == USR_UDP_CEP1) || (cepid == USR_UDP_CEP2));
	}

	if (fncd == TEV_UDP_RCV_DAT) {
		memset(p_rcv_bef, 0, len);
		ret = udp_rcv_dat(cepid, &dstaddr1, p_rcv_bef, len, TMO_FEVR);
		assert(ret == len);

		assert(memcmp(p_snd_bef, p_rcv_bef, len) == 0);

		if (cepid == USR_UDP_CEP1) {
			rcv_dat_task1++;
			assert(rcv_dat_task1 <= snd_dat_task1);
		}
		else {
			rcv_dat_task2++;
			assert(rcv_dat_task2 <= snd_dat_task2);
		}
		wup_tsk(tskid);
	}

	return E_OK;
}

void task1(void *arg)
{
	ER ret;
	T_UDP_CCEP ccep = { 0, { MAKE_IPV4_ADDR(0, 0, 0, 0), 2222 }, (FP)socket_udp_callback };
	uint8_t *p_snd_bef = udp_buf1;
	int len = UDP_SOCKET_BUF_SIZE;

	slp_tsk();

	ret = udp_cre_cep(USR_UDP_CEP1, &ccep);
	assert(ret == E_OK);

	termine_task1 = 0;
	snd_dat_task1 = 0;
	rcv_dat_task1 = 0;

	while (!termine_task1) {
		slp_tsk();

		snd_dat_task1++;
		memset(p_snd_bef, 0x22, len);
		ret = udp_snd_dat(USR_UDP_CEP1, &dstaddr1, p_snd_bef, len, TMO_FEVR);
		assert(ret == len);

		while (snd_dat_task1 != rcv_dat_task1)
			slp_tsk();
	}

	ret = udp_del_cep(USR_UDP_CEP1);
	assert(ret == E_OK);
}

void task2(void *arg)
{
	ER ret;
	T_UDP_CCEP ccep = { 0, { MAKE_IPV4_ADDR(0, 0, 0, 0), 3333 }, (FP)socket_udp_callback };
	uint8_t *p_snd_bef = udp_buf2;
	int len = UDP_SOCKET_BUF_SIZE;

	slp_tsk();

	ret = udp_cre_cep(USR_UDP_CEP2, &ccep);
	assert(ret == E_OK);

	termine_task2 = 0;
	snd_dat_task2 = 0;
	rcv_dat_task2 = 0;

	while (!termine_task2) {
		slp_tsk();

		snd_dat_task2++;
		memset(p_snd_bef, 0x33, len);
		ret = udp_snd_dat(USR_UDP_CEP2, &dstaddr2, p_snd_bef, len, TMO_FEVR);
		assert(ret == len);

		while (snd_dat_task2 != rcv_dat_task2)
			slp_tsk();
	}

	ret = udp_del_cep(USR_UDP_CEP2);
	assert(ret == E_OK);
}

const char *g_script;
const char *g_script_end;
#define countof(array)	(sizeof(array) / sizeof(array[0]))

void task3(void *arg)
{
	const char *commands[] = {
		"wup_tsk TASK1\n",
		"wup_tsk TASK2\n",
		"reply TASK1\n",
		"reply TASK2\n",
		"terminate TASK1\n",
		"terminate TASK2\n",
	};

	while (g_script < g_script_end) {
		int c = -1;
		for (int i = 0; i < countof(commands); i++) {
			int clen = strlen(commands[i]);
			int ilen = g_script_end - g_script;
			if (ilen < clen)
				continue;

			if (strncmp(g_script, commands[i], clen) != 0)
				continue;

			c = i;
			g_script += clen;
			break;
		}

		if (c == -1)
			break;

		switch (c) {
		case 0:
			wup_tsk(TASK1);
			break;
		case 1:
			wup_tsk(TASK2);
			break;
		case 2:
			reply(&output1_packets);
			break;
		case 3:
			reply(&output2_packets);
			break;
		case 4:
			termine_task1 = 1;
			break;
		case 5:
			termine_task2 = 1;
			break;
		}
	}
}

ER callback_nblk_dhcp4_cli(ID cepid, FN fncd, void *p_parblk)
{
	ER_UINT		len;

	len = *(ER_UINT *)p_parblk;
	if (len < 0 && len != E_RLWAI) {
		/* E_RLWAI 以外で、0 以下の場合は、エラーを意味している。*/
		syslog(LOG_NOTICE, "[DHCPC(CBR)] error: %s, fncd: %s", itron_strerror(len), in_strtfn(fncd));
	}
	else {
		if (fncd == TEV_UDP_RCV_DAT) {
		}
	}
	return E_OK;
}

ER callback_nblk_ntp_cli(ID cepid, FN fncd, void *p_parblk)
{
	ER_UINT		len;

	len = *(ER_UINT *)p_parblk;
	if (len < 0 && len != E_RLWAI) {
		/* E_RLWAI 以外で、0 以下の場合は、エラーを意味している。*/
		syslog(LOG_NOTICE, "[DHCPC(CBR)] error: %s, fncd: %s", itron_strerror(len), in_strtfn(fncd));
	}
	else {
		if (fncd == TEV_UDP_RCV_DAT) {
		}
	}
	return E_OK;
}

QUEUE alloc_mem;

void init_alloc_mem()
{
	queue_initialize(&alloc_mem);
}

int mpf_net_buf_cseg;
int mpf_net_buf_64;
int mpf_net_buf_256;
int mpf_net_buf_if_pdu;
int mpf_net_buf_ipv6_mmtu;
int mpf_net_buf_ip_mss;
int mpf_net_buf_reassm;
int mpf_rslv_srbuf;
int mpf_dhcp4_cli_msg;

ER tget_mpf(ID mpfid, void **p_blk, TMO tmout)
{
	size_t len;

	switch (mpfid) {
	case MPF_NET_BUF_CSEG:
		mpf_net_buf_cseg++;
		len = sizeof(T_NET_BUF_CSEG);
		break;
	case MPF_NET_BUF_64:
		mpf_net_buf_64++;
		len = sizeof(T_NET_BUF_64);
		break;
	case MPF_NET_BUF_256:
		mpf_net_buf_256++;
		len = sizeof(T_NET_BUF_256);
		break;
#if defined(NUM_MPF_NET_BUF_IF_PDU) && NUM_MPF_NET_BUF_IF_PDU > 0
	case MPF_NET_BUF_IF_PDU:
		mpf_net_buf_if_pdu++;
		len = sizeof(T_NET_BUF_IF_PDU);
		break;
#endif
#if defined(NUM_MPF_NET_BUF_IPV6_MMTU) && NUM_MPF_NET_BUF_IPV6_MMTU > 0
	case MPF_NET_BUF_IPV6_MMTU:
		mpf_net_buf_ipv6_mmtu++;
		len = sizeof(T_NET_BUF_IPV6_MMTU);
		break;
#endif
#if defined(NUM_MPF_NET_BUF_IP_MSS) && NUM_MPF_NET_BUF_IP_MSS > 0
	case MPF_NET_BUF_IP_MSS:
		mpf_net_buf_ip_mss++;
		len = sizeof(T_NET_BUF_IP_MSS);
		break;
#endif
#if (defined(NUM_MPF_NET_BUF6_REASSM) && NUM_MPF_NET_BUF6_REASSM > 0) || (defined(NUM_MPF_NET_BUF4_REASSM) && NUM_MPF_NET_BUF4_REASSM > 0)
	case MPF_NET_BUF_REASSM:
		mpf_net_buf_reassm++;
		len = sizeof(T_NET_BUF6_REASSM);
		break;
#endif
	case MPF_RSLV_SRBUF:
		mpf_rslv_srbuf++;
		len = DNS_UDP_MSG_LENGTH;
		break;
	case MPF_DHCP4_CLI_MSG:
		mpf_dhcp4_cli_msg++;
		len = sizeof(T_DHCP4_CLI_MSG);
		break;
	default:
		assert(mpfid == MPF_NET_BUF_CSEG);
		return E_OBJ;
	}

	QUEUE *node = (QUEUE *)malloc(sizeof(QUEUE) + sizeof(ID) + len);
	if (node == NULL) {
		*p_blk = NULL;
		return E_NOMEM;
	}

	queue_initialize(node);
	queue_insert_next(&alloc_mem, node);

	*(ID *)((intptr_t)node + sizeof(QUEUE)) = mpfid;
	*p_blk = (void *)((intptr_t)node + sizeof(QUEUE) + sizeof(ID));

	return E_OK;
}

ER pget_mpf(ID mpfid, void **p_blk)
{
	return tget_mpf(mpfid, p_blk, TMO_POL);
}

ER get_mpf(ID mpfid, void **p_blk)
{
	return tget_mpf(mpfid, p_blk, TMO_FEVR);
}

ER rel_mpf(ID mpfid, void *blk)
{
	if (mpfid != *(ID *)((intptr_t)blk - sizeof(ID))) {
		__builtin_trap();
		return E_OBJ;
	}

	switch (mpfid) {
	case MPF_NET_BUF_CSEG:
		mpf_net_buf_cseg--;
		assert(mpf_net_buf_cseg >= 0);
		break;
	case MPF_NET_BUF_64:
		mpf_net_buf_64--;
		assert(mpf_net_buf_64 >= 0);
		break;
	case MPF_NET_BUF_256:
		mpf_net_buf_256--;
		assert(mpf_net_buf_256 >= 0);
		break;
#if defined(NUM_MPF_NET_BUF_IF_PDU) && NUM_MPF_NET_BUF_IF_PDU > 0
	case MPF_NET_BUF_IF_PDU:
		mpf_net_buf_if_pdu--;
		assert(mpf_net_buf_if_pdu >= 0);
		break;
#endif
#if defined(NUM_MPF_NET_BUF_IPV6_MMTU) && NUM_MPF_NET_BUF_IPV6_MMTU > 0
	case MPF_NET_BUF_IPV6_MMTU:
		mpf_net_buf_ipv6_mmtu--;
		assert(mpf_net_buf_ipv6_mmtu >= 0);
		break;
#endif
#if defined(NUM_MPF_NET_BUF_IP_MSS) && NUM_MPF_NET_BUF_IP_MSS > 0
	case MPF_NET_BUF_IP_MSS:
		mpf_net_buf_ip_mss--;
		assert(mpf_net_buf_ip_mss >= 0);
		break;
#endif
#if (defined(NUM_MPF_NET_BUF6_REASSM) && NUM_MPF_NET_BUF6_REASSM > 0) || (defined(NUM_MPF_NET_BUF4_REASSM) && NUM_MPF_NET_BUF4_REASSM > 0)
	case MPF_NET_BUF_REASSM:
		mpf_net_buf_reassm--;
		assert(mpf_net_buf_reassm >= 0);
		break;
#endif
	case MPF_RSLV_SRBUF:
		mpf_rslv_srbuf--;
		assert(mpf_rslv_srbuf >= 0);
		break;
	case MPF_DHCP4_CLI_MSG:
		mpf_dhcp4_cli_msg--;
		assert(mpf_dhcp4_cli_msg >= 0);
		break;
	default:
		assert(mpfid == MPF_NET_BUF_CSEG);
		return E_OBJ;
	}

	QUEUE *node = (QUEUE *)((intptr_t)blk - sizeof(QUEUE) - sizeof(ID));

	queue_delete(node);

	free(node);

	return E_OK;
}

void clear_fixedblocks()
{
	QUEUE temp;
	int remain = 0;

	queue_initialize(&temp);

#ifdef SUPPORT_ETHER
	{
		/* ARPテーブルに残っているパケットは解放しない */
		T_ARP_ENTRY *pos = (T_ARP_ENTRY *)arp_get_cache(), *end = &pos[NUM_ARP_ENTRY];
		for (; pos < end; pos++) {
			memset(pos, 0, sizeof(T_ARP_ENTRY));
		}
	}
	for (;;) {
		bool_t empty = true;
		const T_NET_BUF **pos = ip6_get_frag_queue(), **end = &pos[NUM_IP6_FRAG_QUEUE];
		for (; pos < end; pos++) {
			if (*pos != NULL) {
				empty = false;
				break;
			}
		}
		if (empty)
			break;
		frag6_timer();
	}
#endif

	while (!queue_empty(&alloc_mem)) {
		QUEUE *node = alloc_mem.p_prev;
		T_NET_BUF *blk = (T_NET_BUF *)((intptr_t)node + sizeof(QUEUE) + sizeof(ID));
#ifdef SUPPORT_ETHER
		if (node != NULL) {
			/* 近隣キャッシュテーブルに残っているパケットは解放しない */
			const T_LLINFO_ND6 *pos = nd6_get_cache(), *end = &pos[NUM_ND6_CACHE_ENTRY];
			for (; pos < end; pos++) {
				if (blk == pos->hold) {
					queue_delete(node);
					queue_initialize(node);
					queue_insert_next(&temp, node);
					node = NULL;
					remain++;
					break;
				}
			}
		}
#if 0
		if (node != NULL) {
			/* データグラム再構成キュー配列に残っているパケットは解放しない */
			const T_NET_BUF **pos = ip6_get_frag_queue(), **end = &pos[NUM_IP6_FRAG_QUEUE];
			for (; pos < end; pos++) {
				const T_NET_BUF *next = *pos;
				while (next != NULL) {
					if (blk == next) {
						queue_delete(node);
						queue_initialize(node);
						queue_insert_next(&temp, node);
						node = NULL;
						remain++;
						break;
					}
					T_QIP6_HDR *qip6h = GET_QIP6_HDR(next);
					next = qip6h->next_frag;
				}
				if (node == NULL)
					break;
			}
		}
#endif
#endif
		if (node != NULL) {
			ID mpfid = *(ID *)((intptr_t)node + sizeof(QUEUE));
			rel_mpf(mpfid, blk);
		}
	}

	if (remain !=
		mpf_net_buf_cseg
		+ mpf_net_buf_64
		+ mpf_net_buf_256
		+ mpf_net_buf_if_pdu
		+ mpf_net_buf_ipv6_mmtu
		+ mpf_net_buf_ip_mss
		+ mpf_net_buf_reassm
		+ mpf_rslv_srbuf
		+ mpf_dhcp4_cli_msg)
		assert(remain ==
			mpf_net_buf_cseg
			+ mpf_net_buf_64
			+ mpf_net_buf_256
			+ mpf_net_buf_if_pdu
			+ mpf_net_buf_ipv6_mmtu
			+ mpf_net_buf_ip_mss
			+ mpf_net_buf_reassm
			+ mpf_rslv_srbuf
			+ mpf_dhcp4_cli_msg);

	assert(remain < (NUM_ARP_ENTRY + NUM_ND6_CACHE_ENTRY + NUM_IP6_FRAG_QUEUE));

	while (!queue_empty(&temp)) {
		QUEUE *node = temp.p_prev;
		queue_delete(node);
		queue_initialize(node);
		queue_insert_next(&alloc_mem, node);
	}
}

void clean_packets(QUEUE *packets)
{
	while (!queue_empty(packets)) {
		struct ether_packet_t *node;
		node = queue_delete_next(packets);
		free(node);
	}
}

T_TCP6_REP init_tcp6_rep[TNUM_TCP6_REPID];
T_TCP4_REP init_tcp4_rep[TNUM_TCP4_REPID];
T_TCP_CEP init_tcp_cep[TNUM_TCP6_CEPID + TNUM_TCP4_CEPID];
T_UDP6_CEP init_udp6_cep[TNUM_UDP6_CEPID];
T_UDP4_CEP init_udp4_cep[TNUM_UDP4_CEPID];
extern T_TCP_TWCEP tcp_twcep[NUM_TCP_TW_CEP_ENTRY];

/*extern "C" */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	g_ic.ifaddr.lladdr[0] = IFADDR_LLADDR_0;
	g_ic.ifaddr.lladdr[1] = IFADDR_LLADDR_1;
	g_ic.ifaddr.lladdr[2] = IFADDR_LLADDR_2;
	g_ic.ifaddr.lladdr[3] = IFADDR_LLADDR_3;
	g_ic.ifaddr.lladdr[4] = IFADDR_LLADDR_4;
	g_ic.ifaddr.lladdr[5] = IFADDR_LLADDR_5;
	g_ic.semid_rxb_ready = SEM_IF_RX62N_RBUF_READY;
	g_ic.semid_txb_ready = SEM_IF_RX62N_SBUF_READY;
	g_ic.timer = 0;

	init_alloc_mem();

	memcpy(init_tcp6_rep, tcp6_rep, sizeof(init_tcp6_rep));
	memcpy(init_tcp4_rep, tcp4_rep, sizeof(init_tcp4_rep));
	memcpy(init_tcp_cep, tcp_cep, sizeof(init_tcp_cep));
	memcpy(init_udp6_cep, udp6_cep, sizeof(init_udp6_cep));
	memcpy(init_udp4_cep, udp4_cep, sizeof(init_udp4_cep));

	return 0;
}

/*extern "C" */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if ((size < sizeof(T_IF_HDR)) || (size > IF_RX62N_BUF_PAGE_SIZE))
		return 0;

	g_script = (const char *)data;
	g_script_end = &g_script[size];

	queue_initialize(&output1_packets);
	queue_initialize(&output2_packets);
	queue_initialize(&input_packets);

	memcpy(tcp6_rep, init_tcp6_rep, sizeof(init_tcp6_rep));
	memcpy(tcp4_rep, init_tcp4_rep, sizeof(init_tcp4_rep));
	memcpy(tcp_cep, init_tcp_cep, sizeof(init_tcp_cep));
	memcpy(udp6_cep, init_udp6_cep, sizeof(init_udp6_cep));
	memcpy(udp4_cep, init_udp4_cep, sizeof(init_udp4_cep));
	memset(tcp_twcep, 0, sizeof(tcp_twcep));

	sta_ker();

	ext_ker();

	clear_fixedblocks();

	clean_packets(&output1_packets);
	clean_packets(&output2_packets);
	clean_packets(&input_packets);

	return 0;
}
