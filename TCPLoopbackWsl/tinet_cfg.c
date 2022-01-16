/* tinet_cfg.c */

#include <setjmp.h>
#include <kernel.h>
#include <sil.h>
#include "kernel_cfg.h"
#include "tinet_cfg.h"
#include <tinet_defs.h>
#include <tinet_config.h>
#include <net/if.h>
#include <net/if_ppp.h>
#include <net/if_loop.h>
#include <net/ethernet.h>
#include <net/net.h>
#include <net/net_endian.h>
#include <net/net_buf.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_itron.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>



/*
 *  Include Directives (#include)
 */

#include "queue.h"
#include "main.h"
#include <tinet_config.h>
#include <net/net_endian.h>
#include <netinet/in.h>
#include <netinet/in_itron.h>
#include <tinet_nic_defs.h>
#include <netinet/in_var.h>
#include <net/ethernet.h>
#include <net/if6_var.h>
//#include "target_timer.h"
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

const ID tmax_tcp_repid = (TMIN_TCP_REPID + TNUM_TCP6_REPID + TNUM_TCP4_REPID - 1);

#if defined(SUPPORT_INET6) && defined(SUPPORT_INET4)
const ID tmax_tcp6_repid = (TMIN_TCP6_REPID + TNUM_TCP6_REPID - 1);
const ID tmax_tcp4_repid = (TMIN_TCP4_REPID + TNUM_TCP4_REPID - 1);
#endif

const ID tmax_tcp_cepid = (TMIN_TCP_CEPID + TNUM_TCP6_CEPID + TNUM_TCP4_CEPID - 1);

#if defined(SUPPORT_INET6) && defined(SUPPORT_INET4)
const ID tmax_tcp6_cepid = (TMIN_TCP_CEPID + TNUM_TCP6_CEPID - 1);
const ID tmax_tcp4_cepid = (TMIN_TCP_CEPID + TNUM_TCP4_CEPID - 1);
#endif

const ID tmax_udp_cepid = (TMIN_UDP_CEPID + TNUM_UDP6_CEPID + TNUM_UDP4_CEPID - 1);

#if defined(SUPPORT_INET6) && defined(SUPPORT_INET4)
const ID tmax_udp6_cepid = (TMIN_UDP6_CEPID + TNUM_UDP6_CEPID - 1);
const ID tmax_udp4_cepid = (TMIN_UDP4_CEPID + TNUM_UDP4_CEPID - 1);
#endif

T_TCP6_REP tcp6_rep[TNUM_TCP6_REPID] = {
	{
		0,
		{ IPV6_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK0,
#endif
		},
	{
		0,
		{ IPV6_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK1,
#endif
		},
	{
		0,
		{ IPV6_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK2,
#endif
		},
	{
		0,
		{ IPV6_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK3,
#endif
		},
	};

T_TCP4_REP tcp4_rep[TNUM_TCP4_REPID] = {
	{
		0,
		{ IPV4_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK4,
#endif
		},
	{
		0,
		{ IPV4_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK5,
#endif
		},
	{
		0,
		{ IPV4_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK6,
#endif
		},
	{
		0,
		{ IPV4_ADDRANY, TCP_PORTANY },
#if defined(TCP_CFG_EXTENTIONS)
		TCP_REP_FLG_DYNAMIC,
		SEM_TCP_REP_LOCK7,
#endif
		},
	};

T_TCP_CEP tcp_cep[TNUM_TCP6_CEPID + TNUM_TCP4_CEPID] = {
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC,
		SEM_TCP_CEP_LOCK1,
		FLG_TCP_CEP_EST1,
		FLG_TCP_CEP_SND1,
		FLG_TCP_CEP_RCV1,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC,
		SEM_TCP_CEP_LOCK2,
		FLG_TCP_CEP_EST2,
		FLG_TCP_CEP_SND2,
		FLG_TCP_CEP_RCV2,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC,
		SEM_TCP_CEP_LOCK3,
		FLG_TCP_CEP_EST3,
		FLG_TCP_CEP_SND3,
		FLG_TCP_CEP_RCV3,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC,
		SEM_TCP_CEP_LOCK4,
		FLG_TCP_CEP_EST4,
		FLG_TCP_CEP_SND4,
		FLG_TCP_CEP_RCV4,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC|TCP_CEP_FLG_IPV4,
		SEM_TCP_CEP_LOCK5,
		FLG_TCP_CEP_EST5,
		FLG_TCP_CEP_SND5,
		FLG_TCP_CEP_RCV5,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC|TCP_CEP_FLG_IPV4,
		SEM_TCP_CEP_LOCK6,
		FLG_TCP_CEP_EST6,
		FLG_TCP_CEP_SND6,
		FLG_TCP_CEP_RCV6,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC|TCP_CEP_FLG_IPV4,
		SEM_TCP_CEP_LOCK7,
		FLG_TCP_CEP_EST7,
		FLG_TCP_CEP_SND7,
		FLG_TCP_CEP_RCV7,
		},
	{
		0,
		(void*)NULL,
		0,
		(void*)NULL,
		0,
		(t_tcp_callback)(FP)NULL,
		TCP_CEP_FLG_DYNAMIC|TCP_CEP_FLG_IPV4,
		SEM_TCP_CEP_LOCK8,
		FLG_TCP_CEP_EST8,
		FLG_TCP_CEP_SND8,
		FLG_TCP_CEP_RCV8,
		},
	};

T_UDP6_CEP udp6_cep[TNUM_UDP6_CEPID] = {
	{
		0,
		{ IPV6_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_VALID,
		SEM_UDP6_CEP_LOCK1,
		TA_NULL,
		TA_NULL,
		DTQ_UDP6_RCVQ1,
		},
	{
		0,
		{ IPV6_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP6_CEP_LOCK2,
		TA_NULL,
		TA_NULL,
		DTQ_UDP6_RCVQ2,
		},
	{
		0,
		{ IPV6_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP6_CEP_LOCK3,
		TA_NULL,
		TA_NULL,
		DTQ_UDP6_RCVQ3,
		},
	{
		0,
		{ IPV6_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP6_CEP_LOCK4,
		TA_NULL,
		TA_NULL,
		DTQ_UDP6_RCVQ4,
		},
	{
		0,
		{ IPV6_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP6_CEP_LOCK5,
		TA_NULL,
		TA_NULL,
		DTQ_UDP6_RCVQ5,
		},
	};

T_UDP4_CEP udp4_cep[TNUM_UDP4_CEPID] = {
	{
		0,
		{ IPV4_ADDRANY, DHCP4_CLI_CFG_PORTNO },
		(t_udp_callback)(FP)callback_nblk_dhcp4_cli,
		UDP_CEP_FLG_VALID,
		SEM_UDP4_CEP_LOCK1,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ1,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_VALID,
		SEM_UDP4_CEP_LOCK2,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ2,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)callback_nblk_ntp_cli,
		UDP_CEP_FLG_VALID,
		SEM_UDP4_CEP_LOCK3,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ3,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP4_CEP_LOCK4,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ4,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP4_CEP_LOCK5,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ5,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP4_CEP_LOCK6,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ6,
		},
	{
		0,
		{ IPV4_ADDRANY, UDP_PORTANY },
		(t_udp_callback)(FP)NULL,
		UDP_CEP_FLG_DYNAMIC,
		SEM_UDP4_CEP_LOCK7,
		TA_NULL,
		TA_NULL,
		DTQ_UDP4_RCVQ7,
		},
	};
