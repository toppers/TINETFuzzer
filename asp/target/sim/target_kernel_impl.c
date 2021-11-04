#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <kernel.h>
#include <queue.h>
#include "tinet_config.h"
#include "kernel_cfg.h"

#include <sil.h>
#include <tinet_defs.h>
#include <tinet_config.h>

#include <net/if.h>
#include <net/if_loop.h>
#include <net/if_ppp.h>
#include <net/ethernet.h>
#include <net/net.h>
#include <net/net_endian.h>
#include <net/net_buf.h>
#include <net/net_count.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/if_ether.h>

#include <netinet6/nd6.h>

#include "netapp/dns.h"
#include "netapp/dhcp4_cli.h"

#include "semaphore.h"
#include "dataqueue.h"
#include "wait.h"
#include "task.h"
#include "main.h"

jmp_buf SCHEDULER_EIXT;

void dispatch();

void task_start_internal(T_TSKDAT *tskdat)
{
	TCB *p_tcb = tskdat->tcb;

	switch (setjmp(p_tcb->tskctxb.TASK)) {
	case 0: {
		p_tcb->tskctxb.exitcode = 0;
		if (tskdat->next != NULL)
			task_start(tskdat->next);
		else
			dispatch();
		break;
	}
	case 1: if (p_tcb != NULL) {
		unl_cpu();
		p_tcb->p_tinib->task(p_tcb->p_tinib->exinf);
		loc_cpu();
		task_terminate(p_runtsk);
		p_tcb->tskctxb.exitcode++;
		dispatch();
		break;
	}
	default:
		break;
	}
}

void task_start(T_TSKDAT *tskdat)
{
	intptr_t stack[TASK_STACK_SIZE] = { 0 };
	tskdat->tinib.stk = &stack[TASK_STACK_SIZE];
	tskdat->tinib.stksz = sizeof(intptr_t) * TASK_STACK_SIZE;

	TCB *p_tcb = tskdat->tcb;
	p_tcb->p_tinib = &tskdat->tinib;

	task_start_internal(tskdat);
}

static int context;
static int lock;

void dispatch()
{
	if (p_runtsk == p_schedtsk)
		return;

	if (p_schedtsk == NULL) {
		context = 1;
		target_custom_idle();
		context = 0;
	}

	if (p_schedtsk == NULL) {
		longjmp(SCHEDULER_EIXT, 1);
		return;
	}

	if (p_runtsk == NULL || setjmp(p_runtsk->tskctxb.TASK) == 0) {
		p_runtsk = p_schedtsk;
		longjmp(p_runtsk->tskctxb.TASK, 1);
	}
}

int sense_context()
{
	return context;
}

int sense_lock()
{
	return lock != 0;
}

void lock_cpu()
{
	lock++;
}

void unlock_cpu()
{
	lock--;
}

void call_exit_kernel(void)
{
	longjmp(SCHEDULER_EIXT, 1);
}

extern const TINIB tinib_table[];
T_TSKDAT TASK_INF[TNUM_TSKID];
void clear_fixedblocks();

void start_dispatch(void)
{
	int i;

	for (i = 0; i < TNUM_TSKID; i++) {
		memcpy(&TASK_INF[i].tinib, &tinib_table[i], sizeof(TINIB));
		TASK_INF[i].tcb = &tcb_table[i];
		TASK_INF[i].next = &TASK_INF[i + 1];
	}
	TASK_INF[TNUM_TSKID - 1].next = NULL;

	if (setjmp(SCHEDULER_EIXT) == 0) {
		task_start(&TASK_INF[0]);
	}

	for (i = 0; i < TNUM_TSKID; i++) {
		TASK_INF[i].tinib.stk = NULL;
	}

	clear_fixedblocks();
}

void target_exit(void)
{
}

void exit_and_dispatch(void)
{
}

void initialize_tecs(void)
{
}

void request_dispatch_retint()
{
}

void delay_for_interrupt()
{
}

void activate_context(void *p_tcb)
{
}

bool_t check_intno_cfg(INTNO intno)
{
	return true;
}

bool_t check_intno_clear(INTNO intno)
{
	return true;
}

bool_t check_intno_raise(INTNO intno)
{
	return true;
}

void clear_int(INTNO intno)
{
}

void config_int(INTNO intno, ATR intatr, PRI intpri)
{
}

void define_exc(EXCNO excno, FP exc_entry)
{
}

void define_inh(INHNO inhno, FP int_entry)
{
}

void disable_int(INTNO intno)
{
}

void enable_int(INTNO intno)
{
}

bool_t exc_sense_intmask(void *p_excinf)
{
	return true;
}

bool_t probe_int(INTNO intno)
{
	return true;
}

void raise_int(INTNO intno)
{
}

PRI t_get_ipm(void)
{
	return TIPM_ENAALL;
}

void t_set_ipm(PRI intpri)
{
}

void target_initialize(void)
{
}

void target_raise_hrt_int(void)
{
}

void target_raise_ovr_int(void)
{
}

void target_clear_ovr_int(void)
{
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

	QUEUE *node = malloc(sizeof(QUEUE) + sizeof(ID) + len);
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
	while (!queue_empty(&alloc_mem)) {
		QUEUE *node = alloc_mem.p_prev;
		T_NET_BUF *blk = (T_NET_BUF *)((intptr_t)node + sizeof(QUEUE) + sizeof(ID));

		{
			/* ARPテーブルに残っているパケットは解放しない */
			const T_ARP_ENTRY *pos = arp_get_cache(), *end = &pos[NUM_ARP_ENTRY];
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

		if (node != NULL) {
			ID mpfid = *(ID *)((intptr_t)node + sizeof(QUEUE));
			rel_mpf(mpfid, blk);
		}
	}
#endif

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
		QUEUE *node = temp.p_prev;
		queue_delete(node);
		queue_initialize(node);
		queue_insert_next(&alloc_mem, node);
	}
}

ER syslog_wri_log(uint_t prio, const SYSLOG *p_syslog)
{
	assert(prio > LOG_ERROR);
	return E_OK;
}
