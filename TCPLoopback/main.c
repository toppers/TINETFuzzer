// TCPLoopback.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
//

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <kernel.h>
#include <queue.h>
#include <assert.h>
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

#define TCP_SOCKET_BUF_SIZE 2048
uint8_t tcp1_buf[2 * TCP_SOCKET_BUF_SIZE];
uint8_t tcp2_buf[2 * TCP_SOCKET_BUF_SIZE];

const uint8_t *g_data;
size_t g_size;

ER socket_tcp_callback(ID cepid, FN fncd, void *p_parblk)
{
	return E_OK;
}

void task1(void *arg)
{
	ER ret;
	T_TCP_CREP crep = { 0, { MAKE_IPV4_ADDR(127,0,0,1), 2222 } };
	T_TCP_CCEP ccep = { 0, tcp1_buf, TCP_SOCKET_BUF_SIZE, &tcp1_buf[TCP_SOCKET_BUF_SIZE], TCP_SOCKET_BUF_SIZE, (FP)socket_tcp_callback };
	T_IPV4EP dstaddr = { 0 };
	uint8_t *pBuf = NULL;
	int i;

	ret = tcp_cre_rep(USR_TCP_REP1, &crep);
	assert(ret == E_OK);

	ret = tcp_cre_cep(USR_TCP_CEP1, &ccep);
	assert(ret == E_OK);

	ret = tcp_acp_cep(USR_TCP_CEP1, USR_TCP_REP1, &dstaddr, TMO_FEVR);
	assert(ret == E_OK);

	ret = tcp_rcv_buf(USR_TCP_CEP1, (void**)&pBuf, TMO_FEVR);
	assert(ret >= 0);

	for (i = 0; i < ret; i++) {
		assert(pBuf[i] == (uint8_t)i);
	}

	ret = tcp_rel_buf(USR_TCP_CEP1, ret);
	assert(ret == E_OK);

	ret = tcp_cls_cep(USR_TCP_CEP1, TMO_FEVR);
	assert(ret == E_OK);

	ret = tcp_del_cep(USR_TCP_CEP1);
	assert(ret == E_OK);

	ret = tcp_del_rep(USR_TCP_REP1);
	assert(ret == E_OK);
}

void task2(void *arg)
{
	ER ret;
	T_IPV4EP crep = { MAKE_IPV4_ADDR(127,0,0,1), 3333 };
	T_TCP_CCEP ccep = { 0, tcp2_buf, TCP_SOCKET_BUF_SIZE, &tcp2_buf[TCP_SOCKET_BUF_SIZE], TCP_SOCKET_BUF_SIZE, (FP)socket_tcp_callback };
	T_IPV4EP dstaddr = { MAKE_IPV4_ADDR(127,0,0,1), 2222 };
	uint8_t *pBuf = NULL;
	int i;

	ret = tcp_cre_cep(USR_TCP_CEP2, &ccep);
	assert(ret == E_OK);

	ret = tcp_con_cep(USR_TCP_CEP2, &crep, &dstaddr, TMO_FEVR);
	assert(ret == E_OK);

	ret = tcp_get_buf(USR_TCP_CEP2, (void**)&pBuf, TMO_FEVR);
	assert(ret >= 0);

	for (i = 0; i < ret; i++) {
		pBuf[i] = (uint8_t)i;
	}

	ret = tcp_snd_buf(USR_TCP_CEP2, ret);
	assert(ret == E_OK);

	ret = tcp_rel_buf(USR_TCP_CEP2, ret);
	assert(ret == E_OK);

	ret = tcp_cls_cep(USR_TCP_CEP2, TMO_FEVR);
	assert(ret == E_OK);

	ret = tcp_del_cep(USR_TCP_CEP2);
	assert(ret == E_OK);
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

ER tget_mpf(ID mpfid, void** p_blk, TMO tmout)
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

	QUEUE* node = malloc(sizeof(QUEUE) + sizeof(ID) + len);
	if (node == NULL) {
		*p_blk = NULL;
		return E_NOMEM;
	}

	queue_initialize(node);
	queue_insert_next(&alloc_mem, node);

	*(ID*)((intptr_t)node + sizeof(QUEUE)) = mpfid;
	*p_blk = (void*)((intptr_t)node + sizeof(QUEUE) + sizeof(ID));

	return E_OK;
}

ER pget_mpf(ID mpfid, void** p_blk)
{
	return tget_mpf(mpfid, p_blk, TMO_POL);
}

ER get_mpf(ID mpfid, void** p_blk)
{
	return tget_mpf(mpfid, p_blk, TMO_FEVR);
}

ER rel_mpf(ID mpfid, void* blk)
{
	if (mpfid != *(ID*)((intptr_t)blk - sizeof(ID))) {
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

	QUEUE* node = (QUEUE*)((intptr_t)blk - sizeof(QUEUE) - sizeof(ID));

	queue_delete(node);

	free(node);

	return E_OK;
}

void clear_fixedblocks()
{
	QUEUE temp;
	int remain = 0;

	queue_initialize(&temp);

	while (!queue_empty(&alloc_mem)) {
		QUEUE* node = alloc_mem.p_prev;
		T_NET_BUF* blk = (T_NET_BUF*)((intptr_t)node + sizeof(QUEUE) + sizeof(ID));
#ifdef SUPPORT_ETHER
		{
			/* ARPテーブルに残っているパケットは解放しない */
			const T_ARP_ENTRY* pos = arp_get_cache(), * end = &pos[NUM_ARP_ENTRY];
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

		if (node != NULL) {
			/* 近隣キャッシュテーブルに残っているパケットは解放しない */
			const T_LLINFO_ND6* pos = nd6_get_cache(), * end = &pos[NUM_ND6_CACHE_ENTRY];
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

		if (node != NULL) {
			/* データグラム再構成キュー配列に残っているパケットは解放しない */
			const T_NET_BUF** pos = ip6_get_frag_queue(), ** end = &pos[NUM_IP6_FRAG_QUEUE];
			for (; pos < end; pos++) {
				const T_NET_BUF* next = *pos;
				while (next != NULL) {
					if (blk == next) {
						queue_delete(node);
						queue_initialize(node);
						queue_insert_next(&temp, node);
						node = NULL;
						remain++;
						break;
					}
					T_QIP6_HDR* qip6h = GET_QIP6_HDR(next);
					next = qip6h->next_frag;
				}
				if (node == NULL)
					break;
			}
		}
#endif
		if (node != NULL) {
			ID mpfid = *(ID*)((intptr_t)node + sizeof(QUEUE));
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

	while (!queue_empty(&temp)) {
		QUEUE* node = temp.p_prev;
		queue_delete(node);
		queue_initialize(node);
		queue_insert_next(&alloc_mem, node);
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
	g_data = (const uint8_t *)data;
	g_size = size;

	memcpy(tcp6_rep, init_tcp6_rep, sizeof(init_tcp6_rep));
	memcpy(tcp4_rep, init_tcp4_rep, sizeof(init_tcp4_rep));
	memcpy(tcp_cep, init_tcp_cep, sizeof(init_tcp_cep));
	memcpy(udp6_cep, init_udp6_cep, sizeof(init_udp6_cep));
	memcpy(udp4_cep, init_udp4_cep, sizeof(init_udp4_cep));
	memset(tcp_twcep, 0, sizeof(tcp_twcep));

	sta_ker();

	clear_fixedblocks();

	return 0;
}
