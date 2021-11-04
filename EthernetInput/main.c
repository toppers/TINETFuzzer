// EthernetInput.cpp : このファイルには 'main' 関数が含まれています。プログラム実行の開始と終了がそこで行われます。
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
#include <net/ethernet.h>
#include <net/net_buf.h>
#include "sil.h"
#include "net/net_endian.h"
#include "netinet/in.h"
#include "netinet/in4.h"
#include "netinet/in4_var.h"
#include "netinet6/in6.h"
#include "netinet6/in6_var.h"
#include <netinet/if_ether.h>
#include <netinet/in_itron.h>

#include "task.h"
#include "main.h"
#include "kernel_cfg.h"

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

void rx62n_start(T_IF_SOFTC *ic, T_NET_BUF *output)
{
	//__builtin_trap();
}

ER rx62n_addmulti(T_IF_SOFTC *ic)
{
	return E_OK;
}

const uint8_t *g_data;
size_t g_size;

T_NET_BUF *rx62n_read(T_IF_SOFTC *ic)
{
	T_NET_BUF *input = NULL;
	uint16_t align;
	ER ercd;

	if (g_data == NULL)
		longjmp(SCHEDULER_EIXT, 1);

	align = ((((g_size - sizeof(T_IF_HDR)) + 3) >> 2) << 2) + sizeof(T_IF_HDR);
	if ((ercd = tget_net_buf(&input, align, TMO_IF_RX62N_GET_NET_BUF)) == E_OK && input != NULL) {
		uint8_t *dst = input->buf + IF_ETHER_NIC_HDR_ALIGN;
		memcpy((void *)dst, (void *)g_data, g_size);
	}
	else {
		assert((ercd == E_OK) && (input != NULL));
	}

	g_data = NULL;
	g_size = 0;

	return input;
}

void task1(void *arg)
{
	T_IF_SOFTC *ic = &g_ic;
	ER ercd;

	ercd = sig_sem(ic->semid_rxb_ready);
	assert(ercd == E_OK);
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

void init_alloc_mem();

/*extern "C" */
int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	g_ic.ifaddr.lladdr[0] = 0x12;
	g_ic.ifaddr.lladdr[1] = 0x34;
	g_ic.ifaddr.lladdr[2] = 0x56;
	g_ic.ifaddr.lladdr[3] = 0x78;
	g_ic.ifaddr.lladdr[4] = 0x9a;
	g_ic.ifaddr.lladdr[5] = 0xbc;
	g_ic.semid_rxb_ready = SEM_IF_RX62N_RBUF_READY;
	g_ic.semid_txb_ready = SEM_IF_RX62N_SBUF_READY;
	g_ic.timer = 0;

	init_alloc_mem();

	return 0;
}

/*extern "C" */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if ((size < sizeof(T_IF_HDR)) || (size > IF_RX62N_BUF_PAGE_SIZE))
		return 0;

	g_data = (const uint8_t *)data;
	g_size = size;

	sta_ker();

	return 0;
}
