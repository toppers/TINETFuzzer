#ifndef KERNEL_CFG_H
#define KERNEL_CFG_H

#define TMIN_TSKID 1
enum TSKID_T {
	LOOP_INPUT_TASK = TMIN_TSKID,
	NET_TIMER_TASK,
	LOOP_OUTPUT_TASK,
	TCP_OUTPUT_TASK,
	UDP_OUTPUT_TASK,
	TASK1,
	TASK2,
	_TMAX_TSKID
};
#define TNUM_STSKID	(_TMAX_TSKID - 1)
#define TNUM_TSKID	(TNUM_STSKID + 0)

#define TMIN_SEMID 1
enum SEMID_T {
	SEM_CALL_OUT_LOCK = TMIN_SEMID,
	SEM_CALL_OUT_TIMEOUT,
	SEM_IP2STR_BUFF_LOCK,
	SEM_MAC2STR_BUFF_LOCK,
	SEM_ARP_CACHE_LOCK,
	SEM_IN4_ROUTING_TBL,
	SEM_TCP_POST_OUTPUT,
	SEM_TCP_CEP,
	SEM_TCP_GIANT,
	SEM_UDP_POST_OUTPUT,
	SEM_UDP_CEP,
	SEM_ND6_CACHE,
	SEM_ND6_DEFRTRLIST,
	SEM_IP6_FRAG_QUEUE,
	SEM_IN6_ROUTING_TBL,
	SEM_TCP_REP_LOCK0,
	SEM_TCP_REP_LOCK1,
	SEM_TCP_REP_LOCK2,
	SEM_TCP_REP_LOCK3,
	SEM_TCP_REP_LOCK4,
	SEM_TCP_REP_LOCK5,
	SEM_TCP_REP_LOCK6,
	SEM_TCP_REP_LOCK7,
	SEM_TCP_CEP_LOCK1,
	SEM_TCP_CEP_LOCK2,
	SEM_TCP_CEP_LOCK3,
	SEM_TCP_CEP_LOCK4,
	SEM_TCP_CEP_LOCK5,
	SEM_TCP_CEP_LOCK6,
	SEM_TCP_CEP_LOCK7,
	SEM_TCP_CEP_LOCK8,
	SEM_UDP6_CEP_LOCK1,
	SEM_UDP6_CEP_LOCK2,
	SEM_UDP6_CEP_LOCK3,
	SEM_UDP6_CEP_LOCK4,
	SEM_UDP6_CEP_LOCK5,
	SEM_UDP4_CEP_LOCK1,
	SEM_UDP4_CEP_LOCK2,
	SEM_UDP4_CEP_LOCK3,
	SEM_UDP4_CEP_LOCK4,
	SEM_UDP4_CEP_LOCK5,
	SEM_UDP4_CEP_LOCK6,
	SEM_UDP4_CEP_LOCK7,
	SEM_IGMP_GROUP_LOCK,
	_TMAX_SEMID
};
#define TNUM_SSEMID	(_TMAX_SEMID - 1)
#define TNUM_SEMID	(TNUM_SSEMID + 0)

#define TMIN_FLGID 1
enum FLGID_T
{
	FLG_SELECT_WAIT = TMIN_FLGID,
	FLG_TCP_CEP_EST1,
	FLG_TCP_CEP_SND1,
	FLG_TCP_CEP_RCV1,
	FLG_TCP_CEP_EST2,
	FLG_TCP_CEP_SND2,
	FLG_TCP_CEP_RCV2,
	FLG_TCP_CEP_EST3,
	FLG_TCP_CEP_SND3,
	FLG_TCP_CEP_RCV3,
	FLG_TCP_CEP_EST4,
	FLG_TCP_CEP_SND4,
	FLG_TCP_CEP_RCV4,
	FLG_TCP_CEP_EST5,
	FLG_TCP_CEP_SND5,
	FLG_TCP_CEP_RCV5,
	FLG_TCP_CEP_EST6,
	FLG_TCP_CEP_SND6,
	FLG_TCP_CEP_RCV6,
	FLG_TCP_CEP_EST7,
	FLG_TCP_CEP_SND7,
	FLG_TCP_CEP_RCV7,
	FLG_TCP_CEP_EST8,
	FLG_TCP_CEP_SND8,
	FLG_TCP_CEP_RCV8,
	_TNUM_SFLGID
};
#define TNUM_SFLGID	(_TNUM_SFLGID - 1)
#define TNUM_FLGID	(TNUM_SFLGID + 0)

#define TMIN_DTQID 1
enum {
	DTQ_LOOP_OUTPUT = TMIN_DTQID,
	DTQ_LOOP_INPUT,
	MAIN_DATAQUEUE,
	DTQ_UDP6_RCVQ1,
	DTQ_UDP6_RCVQ2,
	DTQ_UDP6_RCVQ3,
	DTQ_UDP6_RCVQ4,
	DTQ_UDP6_RCVQ5,
	DTQ_UDP4_RCVQ1,
	DTQ_UDP4_RCVQ2,
	DTQ_UDP4_RCVQ3,
	DTQ_UDP4_RCVQ4,
	DTQ_UDP4_RCVQ5,
	DTQ_UDP4_RCVQ6,
	DTQ_UDP4_RCVQ7,
	_TNUM_SDTQID
};
#define TNUM_SDTQID	(_TNUM_SDTQID - 1)
#define TNUM_DTQID	(TNUM_SDTQID + 0)

#define TMIN_MPFID 1
enum MPFID_T {
	MPF_NET_BUF_CSEG = TMIN_MPFID,
	MPF_NET_BUF_64,
	MPF_NET_BUF_256,
	MPF_NET_BUF_IF_PDU,
	MPF_RSLV_SRBUF,
	MPF_DHCP4_CLI_MSG,
	_TNUM_SMPFID
};
#define TNUM_SMPFID	(_TNUM_SMPFID - 1)
#define TNUM_MPFID	(TNUM_SMPFID + 0)

#define TMIN_PDQID 1
#define TNUM_SPDQID 0
#define TNUM_PDQID  (TNUM_SPDQID + 0)

#define TMIN_MTXID 1
#define TNUM_SMTXID 0
#define TNUM_MTXID (TNUM_SMTXID + 0)

#define TMIN_CYCID 1
#define TNUM_SCYCID 0
#define TNUM_CYCID (TNUM_SCYCID + 0)

#define TMIN_ALMID 1
#define TNUM_SALMID 0
#define TNUM_ALMID (TNUM_SALMID + 0)

#define TMIN_ISRID 1
#define TNUM_SISRID 0
#define TNUM_ISRID (TNUM_SISRID + 0)

#define TNUM_INIRTN 1
#define TNUM_TERRTN 0

#endif // KERNEL_CFG_H
