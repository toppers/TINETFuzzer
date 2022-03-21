/* kernel_cfg.c */
#include "kernel_cfg.h"
#include "kernel_int.h"

//#if !(TKERNEL_PRID == 0x0007U && (TKERNEL_PRVER & 0xf000U) == 0x3000U)
//#error The kernel does not match this configuration file.
//#endif

/*
 *  Include Directives
 */

#include "main.h"
#include <tinet_config.h>
#include <net/net_endian.h>
#include <netinet/in.h>
#include <netinet/in_itron.h>
#include <tinet_nic_defs.h>
#include <netinet/in_var.h>
#include <net/ethernet.h>
#include <net/if6_var.h>
#include "target_timer.h"
#ifdef TOPPERS_SUPPORT_OVRHDR
#endif
//#include "syssvc/musl_adapter.h"
//#include "syssvc/syslog.h"
//#include "syssvc/banner.h"
//#include "target_syssvc.h"
//#include <target_serial.h>
//#include "syssvc/serial.h"
#if TNUM_PORT >= 2
#endif
#if TNUM_PORT >= 3
#endif
#if TNUM_PORT >= 4
#endif
//#include "syssvc/logtask.h"
#include "target_sil.h"
#include <itron.h>
#include <tinet_defs.h>
#include <tinet_config.h>
#include <net/if.h>
#include <net/if_ppp.h>
#include <net/if_loop.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <net/net.h>
#include <net/net_endian.h>
#include <net/net_buf.h>
#include <net/net_timer.h>
#include <net/ppp_var.h>
#include <net/ether_var.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>
#ifdef SUPPORT_ETHER
#include "if_rx62nreg.h"
#endif
#ifndef NOUSE_MPF_NET_BUF
#if defined(NUM_MPF_NET_BUF_CSEG) && NUM_MPF_NET_BUF_CSEG > 0
#endif
#if defined(NUM_MPF_NET_BUF_64) && NUM_MPF_NET_BUF_64 > 0
#endif
#if defined(NUM_MPF_NET_BUF_128) && NUM_MPF_NET_BUF_128 > 0
#endif
#if defined(NUM_MPF_NET_BUF_256) && NUM_MPF_NET_BUF_256 > 0
#endif
#if defined(NUM_MPF_NET_BUF_512) && NUM_MPF_NET_BUF_512 > 0
#endif
#if defined(NUM_MPF_NET_BUF_IP_MSS) && NUM_MPF_NET_BUF_IP_MSS > 0
#endif
#if defined(NUM_MPF_NET_BUF_1024) && NUM_MPF_NET_BUF_1024 > 0
#endif
#if defined(NUM_MPF_NET_BUF_IPV6_MMTU) && NUM_MPF_NET_BUF_IPV6_MMTU > 0
#endif
#if defined(NUM_MPF_NET_BUF_IF_PDU) && NUM_MPF_NET_BUF_IF_PDU > 0
#endif
#if defined(NUM_MPF_NET_BUF6_REASSM) && NUM_MPF_NET_BUF6_REASSM > 0
#else
#if defined(NUM_MPF_NET_BUF4_REASSM) && NUM_MPF_NET_BUF4_REASSM > 0
#endif
#endif
#if defined(NUM_MPF_NET_BUF6_65536) && NUM_MPF_NET_BUF6_65536 > 0
#endif
#endif
#ifdef SUPPORT_ETHER
#endif
#if defined(_IP4_CFG) && defined(SUPPORT_ETHER)
#endif
#if defined(_IP4_CFG)
#ifdef IP4_CFG_FRAGMENT
#endif
#if NUM_IN4_REDIRECT_ROUTE_ENTRY > 0
#endif
#endif
#if defined(_IP4_CFG) && defined(SUPPORT_IGMP)
#endif
#ifdef SUPPORT_TCP
#ifdef TCP_CFG_TRACE
#endif
#endif
#ifdef SUPPORT_UDP
#ifdef UDP_CFG_NON_BLOCKING
#endif
#endif
#ifdef _IP6_CFG
#if NUM_ND6_DEF_RTR_ENTRY > 0
#endif
#ifdef IP6_CFG_FRAGMENT
#endif
#if NUM_IN6_ROUTE_ENTRY > 0
#endif
#endif
#include "main.h"
#ifdef SUPPORT_INET4
#ifndef TOPPERS_GRSAKURA
#endif
#endif
#ifdef SUPPORT_INET6
#ifndef TOPPERS_GRSAKURA
#endif
#endif
#include "netapp/dhcp4_cli.h"
#ifdef DHCP4_CLI_CFG
#endif
#include "netapp/resolver.h"
#ifdef USE_RESOLVER
#endif
#ifdef USE_RESOLVER
#ifdef SUPPORT_INET6
#endif
#ifdef SUPPORT_INET4
#endif
#endif
//#include "ntp_cli.h"
//#include "net_misc.h"
//#include "ffarch.h"
//#include "mmc_rspi.h"
//#include "shellif.h"
//#include "gpio_api.h"
//#include "ntshell_main.h"
//#include "pinkit.h"

/*
 *  Task Management Functions
 */

const ID _kernel_tmax_tskid = (TMIN_TSKID + TNUM_TSKID - 1);
const ID _kernel_tmax_stskid = (TMIN_TSKID + TNUM_STSKID - 1);

const TINIB _kernel_tinib_table[TNUM_STSKID] = {
	{ (TA_HLNG|TA_ACT), (intptr_t)(0), (TASK)(ether_input_task), INT_PRIORITY(ETHER_INPUT_PRIORITY), ROUND_STK_T(ETHER_INPUT_STACK_SIZE), NULL, "ether_input_task" },
	{ (TA_HLNG), (intptr_t)(0), (TASK)(net_timer_task), INT_PRIORITY(NET_TIMER_PRIORITY), ROUND_STK_T(NET_TIMER_STACK_SIZE), NULL, "net_timer_task" },
	{ (TA_HLNG), (intptr_t)(0), (TASK)(ether_output_task), INT_PRIORITY(ETHER_OUTPUT_PRIORITY), ROUND_STK_T(ETHER_OUTPUT_STACK_SIZE), NULL, "ether_output_task" },
	{ (TA_HLNG), (intptr_t)(0), (TASK)(tcp_output_task), INT_PRIORITY(TCP_OUT_TASK_PRIORITY), ROUND_STK_T(TCP_OUT_TASK_STACK_SIZE), NULL, "tcp_output_task" },
	{ (TA_HLNG), (intptr_t)(0), (TASK)(udp_output_task), INT_PRIORITY(UDP_OUT_TASK_PRIORITY), ROUND_STK_T(UDP_OUT_TASK_STACK_SIZE), NULL, "udp_output_task" },
	{ (TA_HLNG|TA_ACT), (intptr_t)(0), (TASK)(task1), INT_PRIORITY(TASK1_PRIORITY), ROUND_STK_T(TASK_STACK_SIZE), NULL, "task1" },
	{ (TA_HLNG|TA_ACT), (intptr_t)(0), (TASK)(task2), INT_PRIORITY(TASK2_PRIORITY), ROUND_STK_T(TASK_STACK_SIZE), NULL, "task2" },
	{ (TA_HLNG|TA_ACT), (intptr_t)(0), (TASK)(task3), INT_PRIORITY(TASK3_PRIORITY), ROUND_STK_T(TASK_STACK_SIZE), NULL, "task3" },
};

TOPPERS_EMPTY_LABEL(TINIB, _kernel_atinib_table);

TCB _kernel_tcb_table[TNUM_TSKID];

const ID _kernel_torder_table[TNUM_STSKID] = { 
	ETHER_INPUT_TASK,
	NET_TIMER_TASK,
	ETHER_OUTPUT_TASK,
	TCP_OUTPUT_TASK,
	UDP_OUTPUT_TASK,
	TASK1,
	TASK2,
	TASK3,
};

/*
 *  Semaphore Functions
 */

const ID _kernel_tmax_semid = (TMIN_SEMID + TNUM_SEMID - 1);
const ID _kernel_tmax_ssemid = (TMIN_SEMID + TNUM_SSEMID - 1);

const SEMINIB _kernel_seminib_table[TNUM_SSEMID] = {
	{ (TA_TPRI), (NUM_IF_RX62N_TXBUF), (NUM_IF_RX62N_TXBUF) },
	{ (TA_TPRI), (0), (NUM_IF_RX62N_RXBUF) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (0), (NUM_NET_CALLOUT) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (0), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (0), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) },
	{ (TA_TPRI), (1), (1) }
};

TOPPERS_EMPTY_LABEL(SEMINIB, _kernel_aseminib_table);

SEMCB _kernel_semcb_table[TNUM_SEMID];

/*
 *  Eventflag Functions
 */

const ID _kernel_tmax_flgid = (TMIN_FLGID + TNUM_FLGID - 1);
const ID _kernel_tmax_sflgid = (TMIN_FLGID + TNUM_SFLGID - 1);

const FLGINIB _kernel_flginib_table[TNUM_SFLGID] = {
	{ (TA_WMUL), (0x00) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_CLOSED) },
	{ (TA_TFIFO|TA_WSGL), (TCP_CEP_EVT_SWBUF_READY) },
	{ (TA_TFIFO|TA_WSGL), (0) }
};

TOPPERS_EMPTY_LABEL(FLGINIB, _kernel_aflginib_table);

FLGCB _kernel_flgcb_table[TNUM_FLGID];

/*
 *  Dataqueue Functions
 */

const ID _kernel_tmax_dtqid = (TMIN_DTQID + TNUM_DTQID - 1);
const ID _kernel_tmax_sdtqid = (TMIN_DTQID + TNUM_SDTQID - 1);

static DTQMB _kernel_dtqmb_DTQ_ETHER_OUTPUT[NUM_DTQ_ETHER_OUTPUT];
static DTQMB _kernel_dtqmb_DTQ_UDP6_RCVQ1[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP6_RCVQ2[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP6_RCVQ3[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP6_RCVQ4[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP6_RCVQ5[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ1[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ2[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ3[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ4[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ5[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ6[NUM_DTQ_UDP_RCVQ];
static DTQMB _kernel_dtqmb_DTQ_UDP4_RCVQ7[NUM_DTQ_UDP_RCVQ];
const DTQINIB _kernel_dtqinib_table[TNUM_SDTQID] = {
	{ (TA_TFIFO), (NUM_DTQ_ETHER_OUTPUT), _kernel_dtqmb_DTQ_ETHER_OUTPUT },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP6_RCVQ1 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP6_RCVQ2 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP6_RCVQ3 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP6_RCVQ4 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP6_RCVQ5 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ1 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ2 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ3 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ4 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ5 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ6 },
	{ (TA_TFIFO), (NUM_DTQ_UDP_RCVQ), _kernel_dtqmb_DTQ_UDP4_RCVQ7 }
};

TOPPERS_EMPTY_LABEL(DTQINIB, _kernel_adtqinib_table);

DTQCB _kernel_dtqcb_table[TNUM_DTQID];

/*
 *  Priority Dataqueue Functions
 */

const ID _kernel_tmax_pdqid = (TMIN_PDQID + TNUM_PDQID - 1);
const ID _kernel_tmax_spdqid = (TMIN_PDQID + TNUM_SPDQID - 1);

TOPPERS_EMPTY_LABEL(const PDQINIB, _kernel_pdqinib_table);

TOPPERS_EMPTY_LABEL(PDQINIB, _kernel_apdqinib_table);

TOPPERS_EMPTY_LABEL(PDQCB, _kernel_pdqcb_table);

/*
 *  Mutex Functions
 */

const ID _kernel_tmax_mtxid = (TMIN_MTXID + TNUM_MTXID - 1);
const ID _kernel_tmax_smtxid = (TMIN_MTXID + TNUM_SMTXID - 1);

const MTXINIB _kernel_mtxinib_table[TNUM_SMTXID] = {
	{ (TA_TPRI), INT_PRIORITY(0) }
};

TOPPERS_EMPTY_LABEL(MTXINIB, _kernel_amtxinib_table);

MTXCB _kernel_mtxcb_table[TNUM_MTXID];

/*
 *  Fixed-sized Memorypool Functions
 */

const ID _kernel_tmax_mpfid = (TMIN_MPFID + TNUM_MPFID - 1);
const ID _kernel_tmax_smpfid = (TMIN_MPFID + TNUM_SMPFID - 1);

static MPF_T _kernel_mpf_MPF_NET_BUF_CSEG[NUM_MPF_NET_BUF_CSEG * COUNT_MPF_T(sizeof(T_NET_BUF_CSEG))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_CSEG[NUM_MPF_NET_BUF_CSEG];
static MPF_T _kernel_mpf_MPF_NET_BUF_64[NUM_MPF_NET_BUF_64 * COUNT_MPF_T(sizeof(T_NET_BUF_64))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_64[NUM_MPF_NET_BUF_64];
static MPF_T _kernel_mpf_MPF_NET_BUF_256[NUM_MPF_NET_BUF_256 * COUNT_MPF_T(sizeof(T_NET_BUF_256))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_256[NUM_MPF_NET_BUF_256];
static MPF_T _kernel_mpf_MPF_NET_BUF_IP_MSS[NUM_MPF_NET_BUF_IP_MSS * COUNT_MPF_T(sizeof(T_NET_BUF_IP_MSS))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_IP_MSS[NUM_MPF_NET_BUF_IP_MSS];
static MPF_T _kernel_mpf_MPF_NET_BUF_IPV6_MMTU[NUM_MPF_NET_BUF_IPV6_MMTU * COUNT_MPF_T(sizeof(T_NET_BUF_IPV6_MMTU))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_IPV6_MMTU[NUM_MPF_NET_BUF_IPV6_MMTU];
static MPF_T _kernel_mpf_MPF_NET_BUF_REASSM[NUM_MPF_NET_BUF6_REASSM * COUNT_MPF_T(sizeof(T_NET_BUF6_REASSM))];
static MPFMB _kernel_mpfmb_MPF_NET_BUF_REASSM[NUM_MPF_NET_BUF6_REASSM];
static MPF_T _kernel_mpf_MPF_RSLV_SRBUF[NUM_MPF_RSLV_SRBUF * COUNT_MPF_T(DNS_UDP_MSG_LENGTH)];
static MPFMB _kernel_mpfmb_MPF_RSLV_SRBUF[NUM_MPF_RSLV_SRBUF];
static MPF_T _kernel_mpf_MPF_DHCP4_CLI_MSG[NUM_MPF_DHCP4_CLI_MSG * COUNT_MPF_T(sizeof(T_DHCP4_CLI_MSG))];
static MPFMB _kernel_mpfmb_MPF_DHCP4_CLI_MSG[NUM_MPF_DHCP4_CLI_MSG];
const MPFINIB _kernel_mpfinib_table[TNUM_SMPFID] = {
	{ (TA_TFIFO), (NUM_MPF_NET_BUF_CSEG), ROUND_MPF_T(sizeof(T_NET_BUF_CSEG)), _kernel_mpf_MPF_NET_BUF_CSEG, _kernel_mpfmb_MPF_NET_BUF_CSEG },
	{ (TA_TFIFO), (NUM_MPF_NET_BUF_64), ROUND_MPF_T(sizeof(T_NET_BUF_64)), _kernel_mpf_MPF_NET_BUF_64, _kernel_mpfmb_MPF_NET_BUF_64 },
	{ (TA_TFIFO), (NUM_MPF_NET_BUF_256), ROUND_MPF_T(sizeof(T_NET_BUF_256)), _kernel_mpf_MPF_NET_BUF_256, _kernel_mpfmb_MPF_NET_BUF_256 },
	{ (TA_TFIFO), (NUM_MPF_NET_BUF_IP_MSS), ROUND_MPF_T(sizeof(T_NET_BUF_IP_MSS)), _kernel_mpf_MPF_NET_BUF_IP_MSS, _kernel_mpfmb_MPF_NET_BUF_IP_MSS },
	{ (TA_TFIFO), (NUM_MPF_NET_BUF_IPV6_MMTU), ROUND_MPF_T(sizeof(T_NET_BUF_IPV6_MMTU)), _kernel_mpf_MPF_NET_BUF_IPV6_MMTU, _kernel_mpfmb_MPF_NET_BUF_IPV6_MMTU },
	{ (TA_TFIFO), (NUM_MPF_NET_BUF6_REASSM), ROUND_MPF_T(sizeof(T_NET_BUF6_REASSM)), _kernel_mpf_MPF_NET_BUF_REASSM, _kernel_mpfmb_MPF_NET_BUF_REASSM },
	{ (TA_TFIFO), (NUM_MPF_RSLV_SRBUF), ROUND_MPF_T(DNS_UDP_MSG_LENGTH), _kernel_mpf_MPF_RSLV_SRBUF, _kernel_mpfmb_MPF_RSLV_SRBUF },
	{ (TA_TFIFO), (NUM_MPF_DHCP4_CLI_MSG), ROUND_MPF_T(sizeof(T_DHCP4_CLI_MSG)), _kernel_mpf_MPF_DHCP4_CLI_MSG, _kernel_mpfmb_MPF_DHCP4_CLI_MSG }
};

TOPPERS_EMPTY_LABEL(MPFINIB, _kernel_ampfinib_table);

MPFCB _kernel_mpfcb_table[TNUM_MPFID];

/*
 *  Cyclic Notification Functions
 */

const ID _kernel_tmax_cycid = (TMIN_CYCID + TNUM_CYCID - 1);
const ID _kernel_tmax_scycid = (TMIN_CYCID + TNUM_SCYCID - 1);

const CYCINIB _kernel_cycinib_table[TNUM_SCYCID] = {
	{ (TA_STA), (intptr_t)(0), (NFYHDR)(net_timer_handler), (NET_TIMER_CYCLE), (1) }
};

TOPPERS_EMPTY_LABEL(CYCINIB, _kernel_acycinib_table);

TOPPERS_EMPTY_LABEL(T_NFYINFO, _kernel_acyc_nfyinfo_table);

CYCCB _kernel_cyccb_table[TNUM_CYCID];

/*
 *  Alarm Notification Functions
 */

const ID _kernel_tmax_almid = (TMIN_ALMID + TNUM_ALMID - 1);
const ID _kernel_tmax_salmid = (TMIN_ALMID + TNUM_SALMID - 1);

TOPPERS_EMPTY_LABEL(const ALMINIB, _kernel_alminib_table);

TOPPERS_EMPTY_LABEL(ALMINIB, _kernel_aalminib_table);

TOPPERS_EMPTY_LABEL(T_NFYINFO, _kernel_aalm_nfyinfo_table);

TOPPERS_EMPTY_LABEL(ALMCB, _kernel_almcb_table);

/*
 *  Overrun Handler Functions
 */

const OVRINIB _kernel_ovrinib = { (TA_NULL), (OVRHDR)(NULL) };

/*
 *  Interrupt Management Functions
 */

const uint_t _kernel_tnum_isr_queue = 0;

TOPPERS_EMPTY_LABEL(const ISR_ENTRY, _kernel_isr_queue_list);
TOPPERS_EMPTY_LABEL(QUEUE, _kernel_isr_queue_table);

const ID _kernel_tmax_isrid = (TMIN_ISRID + TNUM_ISRID - 1);
const ID _kernel_tmax_sisrid = (TMIN_ISRID + TNUM_SISRID - 1);

TOPPERS_EMPTY_LABEL(const ISRINIB, _kernel_isrinib_table);

TOPPERS_EMPTY_LABEL(ISRINIB, _kernel_aisrinib_table);

TOPPERS_EMPTY_LABEL(ISRCB, _kernel_isrcb_table);

TOPPERS_EMPTY_LABEL(const ID, _kernel_isrorder_table);

#define TNUM_DEF_INHNO	0
const uint_t _kernel_tnum_def_inhno = TNUM_DEF_INHNO;

TOPPERS_EMPTY_LABEL(const INHINIB, _kernel_inhinib_table);

#define TNUM_CFG_INTNO	0
const uint_t _kernel_tnum_cfg_intno = TNUM_CFG_INTNO;

TOPPERS_EMPTY_LABEL(const INTINIB, _kernel_intinib_table);


/*
 *  CPU Exception Management Functions
 */

#define TNUM_DEF_EXCNO	0
const uint_t _kernel_tnum_def_excno = TNUM_DEF_EXCNO;

TOPPERS_EMPTY_LABEL(const EXCINIB, _kernel_excinib_table);

#ifdef TOPPERS_ISTKPT
STK_T *const _kernel_istkpt = TOPPERS_ISTKPT(_kernel_istack, ROUND_STK_T(DEFAULT_ISTKSZ));
#endif /* TOPPERS_ISTKPT */

/*
 *  Kernel Memory Pool Area
 */

const size_t _kernel_mpksz = 0;
MB_T *const _kernel_mpk = NULL;

/*
 *  Time Event Management
 */

TMEVTN   _kernel_tmevt_heap[1 + TNUM_TSKID + TNUM_CYCID + TNUM_ALMID];

/*
 *  Module Initialization Function
 */

void
_kernel_initialize_object(void)
{
	_kernel_initialize_task();
	_kernel_initialize_semaphore();
	_kernel_initialize_eventflag();
	_kernel_initialize_dataqueue();
	_kernel_initialize_mutex();
	_kernel_initialize_mempfix();
	_kernel_initialize_cyclic();
	_kernel_initialize_interrupt();
	_kernel_initialize_exception();
}

/*
 *  Initialization Routine
 */

const uint_t _kernel_tnum_inirtn = TNUM_INIRTN;

const INIRTNB _kernel_inirtnb_table[TNUM_INIRTN] = {
	{ (INIRTN)(target_timer_initialize), (intptr_t)(0) }
};

/*
 *  Termination Routine
 */

const uint_t _kernel_tnum_terrtn = TNUM_TERRTN;

TOPPERS_EMPTY_LABEL(const TERRTNB, _kernel_terrtnb_table);

