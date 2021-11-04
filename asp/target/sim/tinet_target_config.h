/*
 *  TINET (TCP/IP Protocol Stack)
 *
 *  Copyright (C) 2001-2009 by Dep. of Computer Science and Engineering
 *                   Tomakomai National College of Technology, JAPAN
 *
 *  ��L���쌠�҂́C�ȉ���(1)�`(4)�̏����𖞂����ꍇ�Ɍ���C�{�\�t�g�E�F
 *  �A�i�{�\�t�g�E�F�A�����ς������̂��܂ށD�ȉ������j���g�p�E�����E��
 *  �ρE�Ĕz�z�i�ȉ��C���p�ƌĂԁj���邱�Ƃ𖳏��ŋ�������D
 *  (1) �{�\�t�g�E�F�A���\�[�X�R�[�h�̌`�ŗ��p����ꍇ�ɂ́C��L�̒���
 *      ���\���C���̗��p��������щ��L�̖��ۏ؋K�肪�C���̂܂܂̌`�Ń\�[
 *      �X�R�[�h���Ɋ܂܂�Ă��邱�ƁD
 *  (2) �{�\�t�g�E�F�A���C���C�u�����`���ȂǁC���̃\�t�g�E�F�A�J���Ɏg
 *      �p�ł���`�ōĔz�z����ꍇ�ɂ́C�Ĕz�z�ɔ����h�L�������g�i���p
 *      �҃}�j���A���Ȃǁj�ɁC��L�̒��쌠�\���C���̗��p��������щ��L
 *      �̖��ۏ؋K����f�ڂ��邱�ƁD
 *  (3) �{�\�t�g�E�F�A���C�@��ɑg�ݍ��ނȂǁC���̃\�t�g�E�F�A�J���Ɏg
 *      �p�ł��Ȃ��`�ōĔz�z����ꍇ�ɂ́C���̂����ꂩ�̏����𖞂�����
 *      �ƁD
 *    (a) �Ĕz�z�ɔ����h�L�������g�i���p�҃}�j���A���Ȃǁj�ɁC��L�̒�
 *        �쌠�\���C���̗��p��������щ��L�̖��ۏ؋K����f�ڂ��邱�ƁD
 *    (b) �Ĕz�z�̌`�Ԃ��C�ʂɒ�߂���@�ɂ���āCTOPPERS�v���W�F�N�g��
 *        �񍐂��邱�ƁD
 *  (4) �{�\�t�g�E�F�A�̗��p�ɂ�蒼�ړI�܂��͊ԐړI�ɐ����邢���Ȃ鑹
 *      �Q������C��L���쌠�҂����TOPPERS�v���W�F�N�g��Ɛӂ��邱�ƁD
 *      �܂��C�{�\�t�g�E�F�A�̃��[�U�܂��̓G���h���[�U����̂����Ȃ闝
 *      �R�Ɋ�Â�����������C��L���쌠�҂����TOPPERS�v���W�F�N�g��
 *      �Ɛӂ��邱�ƁD
 *
 *  �{�\�t�g�E�F�A�́C���ۏ؂Œ񋟂���Ă�����̂ł���D��L���쌠�҂�
 *  ���TOPPERS�v���W�F�N�g�́C�{�\�t�g�E�F�A�Ɋւ��āC����̎g�p�ړI
 *  �ɑ΂���K�������܂߂āC�����Ȃ�ۏ؂��s��Ȃ��D�܂��C�{�\�t�g�E�F
 *  �A�̗��p�ɂ�蒼�ړI�܂��͊ԐړI�ɐ����������Ȃ鑹�Q�Ɋւ��Ă��C��
 *  �̐ӔC�𕉂�Ȃ��D
 *
 *  @(#) $Id$
 */

#ifndef _TINET_TARGET_CONFIG_H_
#define _TINET_TARGET_CONFIG_H_

/*
 *  TCP/IP �Ɋւ����`
 */

/* TCP �Ɋւ����` */

/*
 *  MAX_TCP_SND_SEG: ���M�Z�O�����g�T�C�Y�̍ő�l
 *
 *    ���肩�� MSS �I�v�V�����ŃZ�O�����g�T�C�Y���w�肳��Ă��A
 *    ���̒l�ŁA�Z�O�����g�T�C�Y�𐧌��ł���B
 */

#ifndef MAX_TCP_SND_SEG
#define MAX_TCP_SND_SEG		(IF_MTU - (IP_HDR_SIZE + TCP_HDR_SIZE))
#endif	/* of #ifndef MAX_TCP_SND_SEG */

/*
 *  DEF_TCP_RCV_SEG: ��M�Z�O�����g�T�C�Y�̋K��l
 */

#ifndef DEF_TCP_RCV_SEG
#define DEF_TCP_RCV_SEG		(IF_MTU - (IP_HDR_SIZE + TCP_HDR_SIZE))
#endif	/* of #ifndef DEF_TCP_RCV_SEG */

/*
 *  �Z�O�����g�̏��Ԃ����ւ���Ƃ��ɐV���Ƀl�b�g���[�N�o�b�t�@�������ĂāA
 *  �f�[�^���R�s�[����T�C�Y�̂������l
 */
#define MAX_TCP_REALLOC_SIZE	1024	

#define TCP_CFG_OPT_MSS		/* �R�l�N�V�����J�ݎ��ɁA�Z�O�����g�T�C�Y�I�v�V���������đ��M����B*/
#define TCP_CFG_DELAY_ACK	/* ACK ��x�点��Ƃ��̓R�����g���O���B			*/
#define TCP_CFG_ALWAYS_KEEP	/* ��ɃL�[�v�A���C�u���鎞�̓R�����g���O���B		*/

/* UDP �Ɋւ����` */

#define UDP_CFG_IN_CHECKSUM	/* UDP �̓��̓`�F�b�N�T�����s���ꍇ�̓R�����g���O���B	*/
#define UDP_CFG_OUT_CHECKSUM	/* UDP �̏o�̓`�F�b�N�T�����s���ꍇ�̓R�����g���O���B	*/

/* ICMPv4/v6 �Ɋւ����` */

#define ICMP_REPLY_ERROR		/* ICMP �G���[���b�Z�[�W�𑗐M����ꍇ�̓R�����g���O���B*/

/* IPv4 �Ɋւ����` */

//#define IP4_CFG_FRAGMENT		/* �f�[�^�O�����̕����E�č\���s���ꍇ�̓R�����g���O���B	*/
#define NUM_IP4_FRAG_QUEUE	2	/* �f�[�^�O�����č\���L���[�T�C�Y			*/
#define IP4_CFG_FRAG_REASSM_SIZE	4096	/* IPv4 �č\���o�b�t�@�T�C�Y			*/

/* IPv6 �Ɋւ����` */

/*
 *  IPv6 �p�z�X�g�L���b�V���̃G���g�����B
 *  0 ���w�肷���IPv6 �p�z�X�g�L���b�V����g���܂Ȃ��B
 */
#define NUM_IN6_HOSTCACHE_ENTRY	4

#ifdef SUPPORT_ETHER

#define NUM_IP6_DAD_COUNT	1	/* �d���A�h���X���o�ő��M����ߗחv���̉񐔁A		*/
								/*  0 ���w�肷��ƁA�d���A�h���X���o���s��Ȃ��B	*/
#define NUM_ND6_CACHE_ENTRY	10	/* �ߗ׃L���b�V���̃G���g����			*/

#define IP6_CFG_AUTO_LINKLOCAL		/* �����N���[�J���A�h���X�̎����ݒ���s���ꍇ�̓R�����g���O���B*/

/*
 *  �f�B�t�H���g���[�^���X�g�Ɋւ����`
 */

/*
 *  �f�B�t�H���g���[�^���X�g�̃G���g�����B
 *  �ő�l�� 16�A0 ���w�肷��ƃ��[�^�ʒm����M���Ȃ��B
 */
#define NUM_ND6_DEF_RTR_ENTRY		4

/*
 *  �v���t�B�b�N�X���X�g�Ɋւ����`�B
 *  �ő�l�� 16�B
 */
#define NUM_ND6_PREFIX_ENTRY		4	/*  �v���t�B�b�N�X���X�g�̃G���g����			*/

/*
 *  �N�����̃��[�^�v���o�͉񐔁B
 *  0 ���w�肷��ƃ��[�^�v�����o�͂��Ȃ��B
 */
#define NUM_ND6_RTR_SOL_RETRY	3	

#define IP6_CFG_FRAGMENT		/* �f�[�^�O�����̕����E�č\���s���ꍇ�̓R�����g���O���B	*/
#define NUM_IP6_FRAG_QUEUE	2	/* �f�[�^�O�����č\���L���[�T�C�Y			*/
#define IP6_CFG_FRAG_REASSM_SIZE	4096	/* IPv6 �č\���o�b�t�@�T�C�Y			*/

#endif	/* of #ifdef SUPPORT_ETHER */

#ifdef SUPPORT_LOOP

#define NUM_IP6_DAD_COUNT	0	/* �d���A�h���X���o�ő��M����ߗחv���̉񐔁A		*/
								/*  0 ���w�肷��ƁA�d���A�h���X���o���s��Ȃ��B	*/
#define NUM_ND6_CACHE_ENTRY	0	/* �ߗ׃L���b�V���̃G���g����			*/

#endif	/* of #ifdef SUPPORT_LOOP */

/*
 *  �f�[�^�����N�w (�l�b�g���[�N�C���^�t�F�[�X) �Ɋւ����`
 */

/*
 *  PPP�A���f���Ɋւ����`
 */

#define MODEM_CFG_DIAL		"ATD"	/* �_�C�A���R�}���h������			*/
#define MODEM_CFG_RETRY_CNT	3	/* �_�C�A�����g���C��			*/
#define MODEM_CFG_RETRY_WAIT	10000	/* �_�C�A�����g���C�܂ł̑҂����� [ms]	*/

/*
 *  PPP�AHDLC �Ɋւ����`
 */

#define DEF_LOCAL_ACCM		ULONG_C(0x000a0000)	/* ������ ACCM�AXON �� XOFF �̂ݕϊ�	*/
#define DEF_REMOTE_ACCM		ULONG_C(0xffffffff)	/* ����� ACCM�A�����l�͑S�ĕϊ�		*/

/*
 *  PPP�ALCP �Ɋւ����`
 */

#define LCP_CFG_MRU		UINT_C(0x0001)	/* MRU					*/
#define LCP_CFG_ACCM		UINT_C(0x0002)	/* ACCM					*/
#define LCP_CFG_MAGIC		UINT_C(0x0004)	/* �}�W�b�N�ԍ�				*/
#define LCP_CFG_PCOMP		UINT_C(0x0008)	/* �v���g�R�������k�@�\			*/
#define LCP_CFG_ACCOMP		UINT_C(0x0010)	/* �A�h���X�E���䕔���k			*/
#define LCP_CFG_PAP		UINT_C(0x0020)	/* PAP					*/
/*#define LCP_CFG_CHAP		UINT_C(0x0040)	   CHAP �͎����\��			*/

#ifdef LCP_CFG_MAGIC

#define LCP_ECHO_INTERVAL	(20*NET_TIMER_HZ)	/* �C���^�[�o������		*/
#define LCP_ECHO_FAILS		9			/* ���s臒l			*/

#endif	/* of #ifdef LCP_CFG_MAGIC */

/*
 *  PPP�APAP �Ɋւ����`
 */

#define DEF_PAP_TIMEOUT		(3*NET_TIMER_HZ)
#define DEF_PAP_REQTIME		(30*NET_TIMER_HZ)	/* �^�C���A�E�g�������s���Ƃ��̓R�����g���O���B*/
#define MAX_PAP_REXMT		10			/* �F�ؗv���̍ő�đ���	*/

/*
 *  RX63N Ethernet Controler �Ɋւ����`
 */

#define NUM_IF_RX62N_TXBUF		2	/* ���M�o�b�t�@��			*/
#define NUM_IF_RX62N_RXBUF		2	/* ��M�o�b�t�@��			*/
#define IF_RX62N_BUF_PAGE_SIZE	1518	/* �o�b�t�@�T�C�Y */

#define TMO_IF_RX62N_GET_NET_BUF	1000	/* [us]�A��M�p net_buf �l���^�C���A�E�g	*/
					/* [s]�A ���M�^�C���A�E�g			*/
#define TMO_IF_RX62N_XMIT		(2*IF_TIMER_HZ)

/*#define IF_RX62N_CFG_ACCEPT_ALL		 �}���`�L���X�g�A�G���[�t���[������M����Ƃ��̓R�����g���O���B*/

/*
 *  Bluetooth USB PAN �Ɋւ����`
 */

#define NUM_IF_BTUSB_TXBUF		2	/* ���M�o�b�t�@��			*/
#define NUM_IF_BTUSB_RXBUF		2	/* ��M�o�b�t�@��			*/
#define IF_BTUSB_BUF_PAGE_SIZE	1518	/* �o�b�t�@�T�C�Y */

#define TMO_IF_BTUSB_GET_NET_BUF	1	/* [ms]�A��M�p net_buf �l���^�C���A�E�g	*/
					/* [s]�A ���M�^�C���A�E�g			*/
#define TMO_IF_BTUSB_XMIT		(2*IF_TIMER_HZ)

/*
 *  �C�[�T�l�b�g�o�͎��ɁANIC �� net_buf ���J������ꍇ�Ɏw�肷��B
 *
 *  ����: �ȉ��̎w��́A�w���ł���Aif_rx62n �ł́A
 *        �J�����Ȃ��̂ŁA�ȉ��̃R�����g���O���Ă͂Ȃ�Ȃ��B
 */

/*#define ETHER_NIC_CFG_RELEASE_NET_BUF*/

/*
 *  RX63N Ethernet Controller �Ɋւ����`
 */

#define RX63N_BASE_ADDRESS		ULONG_C(0x00200000)	/* NIC �̃��W�X�^�x�[�X�A�h���X */

#define INHNO_IF_RX62N_TRX	INT_ETH_EINT	/* �p�P�b�g����M */
#define INTNO_IF_RX62N_TRX	INT_ETH_EINT	/* �p�P�b�g����M */
#define INTATR_IF_RX62N_TRX	(TA_NULL)	/* �����ݑ���	*/
#define INTPRI_IF_RX62N_TRX	(-1)		/* �����ݗD��x	*/

/*
 *  ARP �Ɋւ����`
 */

#define NUM_ARP_ENTRY		10			/* ARP �L���b�V���G���g����	*/

/*
 *  DHCP �Ɋւ����`
 *
 *    �E����: TINET �́ADHCP ���������Ă��Ȃ��B���p�v���O�����ŁA
 *            DHCP ���b�Z�[�W����M���邽�߂̒�`�ł���B
 *            �܂��A���݂� IPv4 �̂ݗL���ł���B
 */

#define DHCP_CFG					 /* DHCP ����������ꍇ�̓R�����g���O���B*/

/*
 *  Ethernet �Ɋւ����`
 */

/*#define ETHER_CFG_ACCEPT_ALL		 �}���`�L���X�g�A�G���[�t���[������M����Ƃ��̓R�����g���O���B	*/
/*#define ETHER_CFG_UNEXP_WARNING	 ��T�|�[�g�t���[���̌x����\������Ƃ��̓R�����g���O���B		*/
/*#define ETHER_CFG_802_WARNING		 IEEE 802.3 �t���[���̌x����\������Ƃ��̓R�����g���O���B		*/
/*#define ETHER_CFG_MCAST_WARNING	 �}���`�L���X�g�̌x����\������Ƃ��̓R�����g���O���B		*/
#define ETHER_CFG_MULTICAST			/* �}���`�L���X�g�𑗎�M */

/*
 *  �A�h���X���X�g�Ɋւ����`�B
 */
#define NUM_IN6_IFADDR_ENTRY		5	/*  �C���^�t�F�[�X�̃A�h���X���X�g�̃G���g����		*/

/*
 *  �ėp�l�b�g���[�N�Ɋւ����`
 */

/*
 *  �l�b�g���[�N�o�b�t�@�Ɋւ����`
 */

/* �l�b�g���[�N�o�b�t�@�� */

#ifdef SUPPORT_PPP

/*
 *  PPP �ł́A��M�p�� �l�b�g���[�N�o�b�t�@�� PDU (1502) �T�C�Y�����
 *  ���蓖�ĂȂ���΂Ȃ�Ȃ��̂� PDU �T�C�Y�𑽂߂Ɋm�ۂ���B
 */

#ifndef NUM_MPF_NET_BUF_CSEG
#define NUM_MPF_NET_BUF_CSEG	2	/* IF + IP + TCP�A2 �ȏ�*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_CSEG */

#ifndef NUM_MPF_NET_BUF_64
#define NUM_MPF_NET_BUF_64	0	/* 64 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_64 */

#ifndef NUM_MPF_NET_BUF_128
#define NUM_MPF_NET_BUF_128	0	/* 128 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_128 */

#ifndef NUM_MPF_NET_BUF_256
#define NUM_MPF_NET_BUF_256	0	/* 256 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_256 */

#ifndef NUM_MPF_NET_BUF_512
#define NUM_MPF_NET_BUF_512	0	/* 512 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_512 */

#ifndef NUM_MPF_NET_BUF_1024
#define NUM_MPF_NET_BUF_1024	0	/* 1024 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_1024 */

#ifndef NUM_MPF_NET_BUF_IF_PDU
#define NUM_MPF_NET_BUF_IF_PDU	2	/* IF �ő� PDU �T�C�Y	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_IF_PDU */

#ifndef NUM_MPF_NET_BUF4_REASSM

#if defined(SUPPORT_INET4) && defined(IP4_CFG_FRAGMENT)
#define NUM_MPF_NET_BUF4_REASSM	2	/* IPv4 �č\���o�b�t�@�T�C�Y	*/
#else
#define NUM_MPF_NET_BUF4_REASSM	0	/* IPv4 �č\���o�b�t�@�T�C�Y	*/
#endif

#endif	/* of #ifndef NUM_MPF_NET_BUF4_REASSM */

#ifndef NUM_MPF_NET_BUF6_REASSM

#if defined(SUPPORT_INET6) && defined(IP6_CFG_FRAGMENT)
#define NUM_MPF_NET_BUF6_REASSM	2	/* IPv6 �č\���o�b�t�@�T�C�Y	*/
#else
#define NUM_MPF_NET_BUF6_REASSM	0	/* IPv6 �č\���o�b�t�@�T�C�Y	*/
#endif

#endif	/* of #ifndef NUM_MPF_NET_BUF6_REASSM */

#endif	/* of #ifdef SUPPORT_PPP */

#ifdef SUPPORT_ETHER

/*
 *  �C�[�T�l�b�g�̏ꍇ�̃l�b�g���[�N�o�b�t�@���̊��蓖��
 */

/*
 *  ����!!
 *
 *  RX63N Ethernet Controler �̃f�B�o�C�X�h���C�o�iif_rx62n�j�̍Œኄ���Ē���
 *  60�i�A���C������ 62�j�I�N�e�b�g�̂��� IF + IP +TCP ����
 *  64 �I�N�e�b�g�̃l�b�g���[�N�o�b�t�@�̕����œK�ł���B
 */

#ifndef NUM_MPF_NET_BUF_CSEG
#define NUM_MPF_NET_BUF_CSEG	0	/* IF + IP + TCP	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_CSEG */

#ifndef NUM_MPF_NET_BUF_64
#define NUM_MPF_NET_BUF_64	2	/* 64 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_64 */

#ifndef NUM_MPF_NET_BUF_128
#define NUM_MPF_NET_BUF_128	0	/* 128 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_128 */

#ifndef NUM_MPF_NET_BUF_256
#define NUM_MPF_NET_BUF_256	0	/* 256 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_256 */

#ifndef NUM_MPF_NET_BUF_512
#define NUM_MPF_NET_BUF_512	0	/* 512 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_512 */

#if defined(SUPPORT_INET4)

#ifndef NUM_MPF_NET_BUF_IP_MSS
#define NUM_MPF_NET_BUF_IP_MSS	0	/* IF + 576 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_IP_MSS */

#endif	/* of #if defined(SUPPORT_INET4) */

#ifndef NUM_MPF_NET_BUF_1024
#define NUM_MPF_NET_BUF_1024	0	/* 1024 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_1024 */

#if defined(SUPPORT_INET6)

#ifndef NUM_MPF_NET_BUF_IPV6_MMTU
#define NUM_MPF_NET_BUF_IPV6_MMTU	0	/* IF + 1280	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_IPV6_MMTU */

#endif	/* of #if defined(SUPPORT_INET6) */

#ifndef NUM_MPF_NET_BUF_IF_PDU
#define NUM_MPF_NET_BUF_IF_PDU	4	/* IF �ő� PDU �T�C�Y	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_IF_PDU */

#ifndef NUM_MPF_NET_BUF4_REASSM

#if defined(SUPPORT_INET4) && defined(IP4_CFG_FRAGMENT)
#define NUM_MPF_NET_BUF4_REASSM	2	/* IPv4 �č\���o�b�t�@�T�C�Y	*/
#else
#define NUM_MPF_NET_BUF4_REASSM	0	/* IPv4 �č\���o�b�t�@�T�C�Y	*/
#endif

#endif	/* of #ifndef NUM_MPF_NET_BUF4_REASSM */

#ifndef NUM_MPF_NET_BUF6_REASSM

#if defined(SUPPORT_INET6) && defined(IP6_CFG_FRAGMENT)
#define NUM_MPF_NET_BUF6_REASSM	2	/* IPv6 �č\���o�b�t�@�T�C�Y	*/
#else
#define NUM_MPF_NET_BUF6_REASSM	0	/* IPv6 �č\���o�b�t�@�T�C�Y	*/
#endif

#endif	/* of #ifndef NUM_MPF_NET_BUF6_REASSM */

#endif	/* of #ifdef SUPPORT_ETHER */

#ifdef SUPPORT_LOOP

#ifndef NUM_MPF_NET_BUF_CSEG
#define NUM_MPF_NET_BUF_CSEG	2	/* IF + IP + TCP	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_CSEG */

#ifndef NUM_MPF_NET_BUF_64
#define NUM_MPF_NET_BUF_64	0	/* 64 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_64 */

#ifndef NUM_MPF_NET_BUF_128
#define NUM_MPF_NET_BUF_128	0	/* 128 �I�N�e�b�g�A2 �ȏ�	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_128 */

#ifndef NUM_MPF_NET_BUF_256
#define NUM_MPF_NET_BUF_256	0	/* 256 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_256 */

#ifndef NUM_MPF_NET_BUF_512
#define NUM_MPF_NET_BUF_512	0	/* 512 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_512 */

#ifndef NUM_MPF_NET_BUF_1024
#define NUM_MPF_NET_BUF_1024	0	/* 1024 �I�N�e�b�g	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_1024 */

#ifndef NUM_MPF_NET_BUF_IF_PDU
#define NUM_MPF_NET_BUF_IF_PDU	4	/* IF �ő� PDU �T�C�Y	*/
#endif	/* of #ifndef NUM_MPF_NET_BUF_IF_PDU */

#endif	/* of #ifdef SUPPORT_PPP */

/*
 *  �l�b�g���[�N���v���̌v��
 *
 *  �l�b�g���[�N���v���̌v�����s���ꍇ�́Atinet/include/net/net.h
 *  �Œ�`����Ă���v���g�R�����ʃt���O���w�肷��B
 */

#if 1

#ifdef SUPPORT_INET6

#ifdef SUPPORT_INET4

#define NET_COUNT_ENABLE	(0			\
				| PROTO_FLG_PPP_HDLC	\
				| PROTO_FLG_PPP_PAP	\
				| PROTO_FLG_PPP_LCP	\
				| PROTO_FLG_PPP_IPCP	\
				| PROTO_FLG_PPP		\
				| PROTO_FLG_LOOP	\
				| PROTO_FLG_ETHER_NIC	\
				| PROTO_FLG_ETHER	\
				| PROTO_FLG_IP6		\
				| PROTO_FLG_ICMP6	\
				| PROTO_FLG_ND6		\
				| PROTO_FLG_ARP		\
				| PROTO_FLG_IP4		\
				| PROTO_FLG_ICMP4	\
				| PROTO_FLG_TCP		\
				| PROTO_FLG_UDP		\
				| PROTO_FLG_NET_BUF	\
				)

#else	/* of #ifdef SUPPORT_INET4 */

#define NET_COUNT_ENABLE	(0			\
				| PROTO_FLG_PPP_HDLC	\
				| PROTO_FLG_PPP_PAP	\
				| PROTO_FLG_PPP_LCP	\
				| PROTO_FLG_PPP_IPCP	\
				| PROTO_FLG_PPP		\
				| PROTO_FLG_LOOP	\
				| PROTO_FLG_ETHER_NIC	\
				| PROTO_FLG_ETHER	\
				| PROTO_FLG_IP6		\
				| PROTO_FLG_ICMP6	\
				| PROTO_FLG_ND6		\
				| PROTO_FLG_TCP		\
				| PROTO_FLG_UDP		\
				| PROTO_FLG_NET_BUF	\
				)

#endif	/* of #ifdef SUPPORT_INET4 */

#else	/* of #ifdef SUPPORT_INET6 */

#ifdef SUPPORT_INET4

#define NET_COUNT_ENABLE	(0			\
				| PROTO_FLG_PPP_HDLC	\
				| PROTO_FLG_PPP_PAP	\
				| PROTO_FLG_PPP_LCP	\
				| PROTO_FLG_PPP_IPCP	\
				| PROTO_FLG_PPP		\
				| PROTO_FLG_LOOP	\
				| PROTO_FLG_ETHER_NIC	\
				| PROTO_FLG_ETHER	\
				| PROTO_FLG_ARP		\
				| PROTO_FLG_IP4		\
				| PROTO_FLG_ICMP4	\
				| PROTO_FLG_TCP		\
				| PROTO_FLG_UDP		\
				| PROTO_FLG_NET_BUF	\
				)

#endif	/* of #ifdef SUPPORT_INET4 */

#endif	/* of #ifdef SUPPORT_INET6 */

#else	/* of #if 0 */

#define NET_COUNT_ENABLE	(0			\
				)

#endif	/* of #if 0 */

#ifndef TOPPERS_MACRO_ONLY

/*
 *  �֐�
 */

extern void rx62n_bus_init(void);
extern void rx62n_inter_init(void);

#endif	/* of #ifndef TOPPERS_MACRO_ONLY */

#endif /* _TINET_TARGET_CONFIG_H_ */
