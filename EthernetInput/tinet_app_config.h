/*
 *  TINET (TCP/IP Protocol Stack)
 *
 *  Copyright (C) 2001-2017 by Dep. of Computer Science and Engineering
 *                   Tomakomai National College of Technology, JAPAN
 *
 *  ��L���쌠�҂́C�ȉ��� (1)�`(4) �̏������CFree Software Foundation
 *  �ɂ���Č��\����Ă��� GNU General Public License �� Version 2 �ɋL
 *  �q����Ă�������𖞂����ꍇ�Ɍ���C�{�\�t�g�E�F�A�i�{�\�t�g�E�F�A
 *  �����ς������̂��܂ށD�ȉ������j���g�p�E�����E���ρE�Ĕz�z�i�ȉ��C
 *  ���p�ƌĂԁj���邱�Ƃ𖳏��ŋ�������D
 *  (1) �{�\�t�g�E�F�A���\�[�X�R�[�h�̌`�ŗ��p����ꍇ�ɂ́C��L�̒���
 *      ���\���C���̗��p��������щ��L�̖��ۏ؋K�肪�C���̂܂܂̌`�Ń\�[
 *      �X�R�[�h���Ɋ܂܂�Ă��邱�ƁD
 *  (2) �{�\�t�g�E�F�A���C���C�u�����`���ȂǁC���̃\�t�g�E�F�A�J���Ɏg
 *      �p�ł���`�ōĔz�z����ꍇ�ɂ́C�Ĕz�z�ɔ����h�L�������g�i���p
 *      �҃}�j���A���Ȃǁj�ɁC��L�̒��쌠�\���C���̗��p��������щ��L
 *      �̖��ۏ؋K����f�ڂ��邱�ƁD
 *  (3) �{�\�t�g�E�F�A���C�@��ɑg�ݍ��ނȂǁC���̃\�t�g�E�F�A�J���Ɏg
 *      �p�ł��Ȃ��`�ōĔz�z����ꍇ�ɂ́C���̏����𖞂������ƁD
 *    (a) �Ĕz�z�ɔ����h�L�������g�i���p�҃}�j���A���Ȃǁj�ɁC��L�̒�
 *        �쌠�\���C���̗��p��������щ��L�̖��ۏ؋K����f�ڂ��邱�ƁD
 *  (4) �{�\�t�g�E�F�A�̗��p�ɂ�蒼�ړI�܂��͊ԐړI�ɐ����邢���Ȃ鑹
 *      �Q������C��L���쌠�҂����TOPPERS�v���W�F�N�g��Ɛӂ��邱�ƁD
 *
 *  �{�\�t�g�E�F�A�́C���ۏ؂Œ񋟂���Ă�����̂ł���D��L���쌠�҂�
 *  ���TOPPERS�v���W�F�N�g�́C�{�\�t�g�E�F�A�Ɋւ��āC���̓K�p�\����
 *  �܂߂āC�����Ȃ�ۏ؂��s��Ȃ��D�܂��C�{�\�t�g�E�F�A�̗��p�ɂ�蒼
 *  �ړI�܂��͊ԐړI�ɐ����������Ȃ鑹�Q�Ɋւ��Ă��C���̐ӔC�𕉂�Ȃ��D
 *
 *  @(#) $Id$
 */

#ifndef _TINET_APP_CONFIG_H_
#define _TINET_APP_CONFIG_H_

/*
 *  �C���^�[�l�b�g�v���g�R���t�@�~���[�̃T�|�[�g
 *
 *    Makefile �Ŏw�肵�Ă��ǂ�
 */

/*#define SUPPORT_INET4		TCP/IP,IPv4		*/
/*#define SUPPORT_INET6		TCP/IP,IPv6		*/
/*#define SUPPORT_TCP		TCP			*/
/*#define SUPPORT_UDP		UDP			*/

/*�f�[�^�����N�w�̃l�b�g���[�N�C���^�t�F�[�X��I������	*/
/*�����ꂩ������I���ł���B				*/

/*#define SUPPORT_PPP		PointtoPointProtocol	*/
/*#define SUPPORT_LOOP		LocalLoopBack		*/
/*#define SUPPORT_ETHER		Ethernet		*/

/*#define SUPPORT_MIB		MIB(SNMP)		*/

/*
 *  TCP/IP �Ɋւ����`
 */

/* TCP �Ɋւ����` */

/*
 *  TCP �ʐM�[�_�̑���M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\
 *    ����: Makefile �Ŏw�肵�Ă���B
 */
/*#define TCP_CFG_RWBUF_CSAVE_ONLY*/
			/* TCP �ʐM�[�_�̎�M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\�̂ݗL���ɂ���B	*/
/*#define TCP_CFG_RWBUF_CSAVE*/
			/* TCP �ʐM�[�_�̎�M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\��L���ɂ���B	*/
/*#define TCP_CFG_SWBUF_CSAVE_ONLY*/
			/* TCP �ʐM�[�_�̑��M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\�̂ݗL���ɂ���B	*/
/*#define TCP_CFG_SWBUF_CSAVE*/
			/* TCP �ʐM�[�_�̑��M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\��L���ɂ���B	*/

/*
 *  TCP �ʐM�[�_�̎�M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\�́A
 *  ��M�E�B���h�o�b�t�@�L���[�̍ő�G���g�����B
 *  �������A����Ɏ�M�����Z�O�����g���j�����邽�߁A�đ��񐔂���������B
 *  �܂��A�w�肵�Ȃ��Ɛ������Ȃ��B
 */
/*#define TCP_CFG_RWBUF_CSAVE_MAX_QUEUES	2*/

/*
 *  TCP �ʐM�[�_�̑��M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\�ŁA
 *  ���M�E�B���h�o�b�t�@�Ɏg�p����l�b�g���[�N�o�b�t�@�̃T�C�Y�B
 */
#define USE_TCP_MSS_SEG

#ifdef USE_TCP_MSS_SEG

#ifdef SUPPORT_INET6

#define TCP_CFG_SWBUF_CSAVE_MAX_SIZE	(IF_HDR_SIZE + IPV6_MMTU)	/* �ő�T�C�Y */

#else	/* of #ifdef SUPPORT_INET6 */

#ifdef SUPPORT_INET4
#define TCP_CFG_SWBUF_CSAVE_MAX_SIZE	(IF_HDR_SIZE + IP4_MSS)		/* �ő�T�C�Y */
#endif

#endif	/* of #ifdef SUPPORT_INET6 */

#else	/* of #ifdef USE_TCP_MSS_SEG */

#define TCP_CFG_SWBUF_CSAVE_MAX_SIZE	IF_PDU_SIZE			/* �ő�T�C�Y */

#endif	/* of #ifdef USE_TCP_MSS_SEG */

#define TCP_CFG_SWBUF_CSAVE_MIN_SIZE	0				/* �ŏ��T�C�Y */

/*
 *  TCP �̃m���u���b�L���O�R�[���@�\
 */

#ifdef UNDEF_TCP_CFG_NON_BLOCKING
#undef TCP_CFG_NON_BLOCKING
#endif

/*
 *  MAX_TCP_SND_SEG: ���M�Z�O�����g�T�C�Y�̍ő�l
 *
 *    ���肩�� MSS �I�v�V�����ŃZ�O�����g�T�C�Y���w�肳��Ă��A
 *    ���̒l�ŁA�Z�O�����g�T�C�Y�𐧌��ł���B
 */

#ifdef USE_TCP_MSS_SEG

#ifdef MAX_TCP_SND_SEG
#undef MAX_TCP_SND_SEG
#endif

#ifdef SUPPORT_INET6

#define MAX_TCP_SND_SEG			TCP6_MSS

#else	/* of #ifdef SUPPORT_INET6 */

#ifdef SUPPORT_INET4
#define MAX_TCP_SND_SEG			TCP_MSS
#endif

#endif	/* of #ifdef SUPPORT_INET6 */

#endif	/* of #ifdef USE_TCP_MSS_SEG */

/*
 *  DEF_TCP_RCV_SEG: ��M�Z�O�����g�T�C�Y�̋K��l
 */

#ifdef USE_TCP_MSS_SEG

#ifdef DEF_TCP_RCV_SEG
#undef DEF_TCP_RCV_SEG
#endif

#ifdef SUPPORT_INET6

#define DEF_TCP_RCV_SEG			TCP6_MSS

#else	/* of #ifdef SUPPORT_INET6 */

#ifdef SUPPORT_INET4
#define DEF_TCP_RCV_SEG			TCP_MSS
#endif

#endif	/* of #ifdef SUPPORT_INET6 */

#endif	/* of #ifdef USE_TCP_MSS_SEG */

/*
 *  �^�X�N����� Time Wait ��Ԃ� TCP �ʐM�[�_�����@�\
 *
 *  Time Wait ��Ԃ� TCP �ʐM�[�_�̃G���g�������w�肷��B
 *  �w�肵�Ȃ����A0 ���w�肷��ƁA
 *  �^�X�N���� Time Wait ��Ԃ� TCP �ʐM�[�_�𕪗�����@�\�͑g���܂Ȃ��B
 */
#if !defined(SUPPORT_TCP)
#define NUM_TCP_TW_CEP_ENTRY		0
#elif defined(USE_TCP_MSS_SEG)
#define NUM_TCP_TW_CEP_ENTRY		3
#else
#define NUM_TCP_TW_CEP_ENTRY		6
#endif

/*
 *  TCP �w�b�_�̃g���[�X�o�͋@�\
 */
//#define TCP_CFG_TRACE

/*
 *  �g���[�X�o�͑Ώۂ̃����[�g�z�X�g�� IPv4 �A�h���X
 *  IPV4_ADDRANY ���w�肷��ƁA�S�Ẵz�X�g��ΏۂƂ���B
 */
#define TCP_CFG_TRACE_IPV4_RADDR	IPV4_ADDRANY

/*
 *  �g���[�X�o�͑Ώۂ̃����[�g�z�X�g�̃|�[�g�ԍ�
 *  TCP_PORTANY ���w�肷��ƁA�S�Ẵ|�[�g�ԍ���Ώۂɂ���B
 */
#define TCP_CFG_TRACE_RPORTNO		TCP_PORTANY
//#define TCP_CFG_TRACE_RPORTNO		UINT_C(7)

/*
 *  �g���[�X�o�͑Ώۂ̃��[�J���z�X�g�̃|�[�g�ԍ�
 *  TCP_PORTANY ���w�肷��ƁA�S�Ẵ|�[�g�ԍ���Ώۂɂ���B
 */
#define TCP_CFG_TRACE_LPORTNO		TCP_PORTANY
//#define TCP_CFG_TRACE_LPORTNO		UINT_C(7)

/*
 *  ITRON TCP/IP API�ATCP �̊g���@�\
 */
#define TCP_CFG_EXTENTIONS

/*
 *  TCP_CFG_URG_OFFSET: �ً}�f�[�^�̍Ō�̃o�C�g�̃I�t�Z�b�g
 *
 *    -1: BSD �̎����A�ً}�|�C���^�́A�ً}�f�[�^�̍Ō�̃o�C�g�̎��̃o�C�g�������B
 *     0: RFC1122 �̋K��A�ً}�|�C���^�́A�ً}�f�[�^�̍Ō�̃o�C�g�������B
 */

//#define TCP_CFG_URG_OFFSET	-1
//#define TCP_CFG_URG_OFFSET	0

/* UDP �Ɋւ����` */

/*
 *  UDP �̃m���u���b�L���O�R�[���@�\
 */

#ifdef UNDEF_UDP_CFG_NON_BLOCKING
#undef UDP_CFG_NON_BLOCKING
#endif

/*
 *  ITRON TCP/IP API�AUDP �̊g���@�\
 */
#define UDP_CFG_EXTENTIONS

/* IPv6 �Ɋւ����` */

#ifdef SUPPORT_PPP

#define NUM_IN6_STATIC_ROUTE_ENTRY	0
#define NUM_IN6_REDIRECT_ROUTE_ENTRY	0

#endif	/* of #ifdef SUPPORT_PPP */

#ifdef SUPPORT_LOOP

#define NUM_IN6_STATIC_ROUTE_ENTRY	0
#define NUM_IN6_REDIRECT_ROUTE_ENTRY	0

#endif	/* of #ifdef SUPPORT_LOOP */

#ifdef SUPPORT_ETHER

#define NUM_IN6_STATIC_ROUTE_ENTRY	0
#define NUM_IN6_REDIRECT_ROUTE_ENTRY	1

#endif	/* of #ifdef SUPPORT_ETHER */

/* IPv4 �Ɋւ����` */

#ifdef SUPPORT_PPP

#if 1
#define IPV4_ADDR_LOCAL			MAKE_IPV4_ADDR(192,168,1,21)
#else
#define IPV4_ADDR_LOCAL			MAKE_IPV4_ADDR(0,0,0,0)		/* ����Ɋ��蓖�ĂĂ��炤�ꍇ	*/
#endif

#if 1
#define IPV4_ADDR_REMOTE		MAKE_IPV4_ADDR(192,168,1,31)
#else
#define IPV4_ADDR_REMOTE		MAKE_IPV4_ADDR(0,0,0,0)		/* ����Ɋ��蓖�ĂĂ��炤�ꍇ	*/
#endif

#define NUM_IN4_STATIC_ROUTE_ENTRY	1
#define NUM_IN4_REDIRECT_ROUTE_ENTRY	0

#endif	/* of #ifdef SUPPORT_PPP */

#ifdef SUPPORT_ETHER

#define IPV4_ADDR_STAIC_LOCAL			MAKE_IPV4_ADDR(192,168,137,201)
#define IPV4_ADDR_STAIC_LOCAL_MASK		MAKE_IPV4_ADDR(255,255,255,0)
#define IPV4_ADDR_STAIC_DEFAULT_GW		MAKE_IPV4_ADDR(192,168,137,1)

#ifdef DHCP4_CLI_CFG

#define IPV4_ADDR_LOCAL			MAKE_IPV4_ADDR(0,0,0,0)
#define IPV4_ADDR_LOCAL_MASK	MAKE_IPV4_ADDR(0,0,0,0)
#define IPV4_ADDR_DEFAULT_GW	MAKE_IPV4_ADDR(0,0,0,0)

#else	/* of #ifdef DHCP4_CLI_CFG */

#define IPV4_ADDR_LOCAL			IPV4_ADDR_STAIC_LOCAL
#define IPV4_ADDR_LOCAL_MASK	IPV4_ADDR_STAIC_LOCAL_MASK
#define IPV4_ADDR_DEFAULT_GW	IPV4_ADDR_STAIC_DEFAULT_GW

#endif	/* of #ifdef DHCP4_CLI_CFG */

#define NUM_IN4_STATIC_ROUTE_ENTRY	3
#define NUM_IN4_REDIRECT_ROUTE_ENTRY	1

#endif	/* of #ifdef SUPPORT_ETHER */

#ifdef SUPPORT_LOOP

#define NUM_IN4_STATIC_ROUTE_ENTRY	1
#define NUM_IN4_REDIRECT_ROUTE_ENTRY	0

#endif	/* of #ifdef SUPPORT_LOOP */

/*
 *  �f�[�^�����N�w (�l�b�g���[�N�C���^�t�F�[�X) �Ɋւ����`
 */

/*
 *  �C�[�T�l�b�g�Ɋւ����`
 */

/*
 *  PPP �Ɋւ����`
 */

#define HDLC_PORTID			1	/* HDLC(PPP)�ɗp����V���A���|�[�g�ԍ�	*/

/*#define PPP_IDLE_TIMEOUT		(180*NET_TIMER_HZ)*/
					/* �ؒf�܂ł̃A�C�h�����ԁA		*/
					/* �ؒf���Ȃ��ꍇ�̓R�����g�A�E�g����B	*/

/*#define PPP_CFG_MODEM			 ���f���ڑ��̏ꍇ�̓R�����g���O���B	*/

#define MODEM_CFG_INIT			"ATE1&D0&S0\\V0\\Q1S0=1"
					/* ���f��������������			*/
					/* NTT DoComo ���o�C���A�_�v�^ 96F �p	*/
					/*   E1: �G�R�[�o�b�N����			*/
					/*  &D0: ER�M������			*/
					/*  &S0: DR�M���펞 ON			*/
					/*  \V0: ���U���g�R�[�h TYPE 1		*/
					/*  \Q1: XON/XOFF �t���[����		*/
					/* S0=1: �������M�����O�� = 1 ��	*/

#define MODEM_CFG_PHONE_NUMBER		"090-xxxx-9242"

					/* ���\�����̋K��l			*/
#define DEF_LCP_LOCAL_CFGS		(LCP_CFG_MRU|LCP_CFG_ACCM|LCP_CFG_MAGIC|\
					 LCP_CFG_ACCOMP|LCP_CFG_PCOMP|LCP_CFG_PAP)

					/* ����ɋ����\�����̋K��l		*/
#define DEF_LCP_REMOTE_CFGS		(LCP_CFG_MRU|LCP_CFG_ACCM|LCP_CFG_MAGIC|\
					 LCP_CFG_ACCOMP|LCP_CFG_PCOMP|LCP_CFG_PAP)

/*
 *  �F�؂Ɋւ����`
 */

#define AUTH_CFG_CLIENT		   	/* �F�؃N���C�A���g���[�h�̎��̓R�����g���O���B	*/
#define AUTH_CFG_SERVER			/* �F�؃T�[�o���[�h�̎��̓R�����g���O���B		*/

#define AUTH_LOCAL_USER			"h8"		/* ���z�X�g�ւ̃��O�C���F�؃��[�U��	*/
#define AUTH_LOCAL_PASSWD		"3048f"		/* ���z�X�g�ւ̃��O�C���F�؃p�X���[�h	*/
#define AUTH_REMOTE_USER		"pen3"		/* ����ւ̃��O�C���F�؃��[�U��		*/
#define AUTH_REMOTE_PASSWD		"600MHz"	/* ����ւ̃��O�C���F�؃p�X���[�h		*/

/*
 *  ARP �Ɋւ����`
 */

/*#define ARP_CFG_CALLBACK_DUPLICATED*/	/* IP �A�h���X�d�����o�R�[���o�b�N�֐���	*/
					/* ��`����ꍇ�̓R�����g���O���B		*/

/*
 *  ICMPv4/v6 �Ɋւ����`
 */

#ifdef USE_PING

#define ICMP_CFG_CALLBACK_ECHO_REPLY	/* ICMP ECHO ��������M�����Ƃ��ďo���R�[���o�b�N�֐���	*/
					/* ��`����ꍇ�̓R�����g���O���B			*/

#endif	/* of #ifdef USE_PING */

/*
 *  �l�b�g���[�N�o�b�t�@�Ɋւ����`
 */

#ifdef SUPPORT_ETHER

/*
 *  �C�[�T�l�b�g�̏ꍇ�̃l�b�g���[�N�o�b�t�@���̊��蓖��
 */

/*
 *  64 �I�N�e�b�g
 *
 *    IPv4 �ł̂݊��蓖�Ă�B
 *
 *    IPv6 �ł́ATCP ����Z�O�����g�iCSEG�ASDU �Ȃ��j�T�C�Y��
 *    �l�b�g���[�N�o�b�t�@�iIF + IPv6 + TCP = 74�j�ȉ���
 *    �l�b�g���[�N�o�b�t�@�͕s�v�ł���B
 */

#ifdef NUM_MPF_NET_BUF_64
#undef NUM_MPF_NET_BUF_64
#endif

#ifdef SUPPORT_INET4
#define NUM_MPF_NET_BUF_64		4
#else
#define NUM_MPF_NET_BUF_64		0
#endif

/*
 *  CSEG�iIF + IP + TCP�j
 *
 *    IPv6 �ł̂݊��蓖�Ă�B
 *
 *    MBED Ethernet Controler �̃f�B�o�C�X�h���C�o�iif_mbed�j�̍Œኄ���Ē��́A
 *    �C�[�T�l�b�g�t���[���̍ŒZ���ł��� 60�iCRC �� 4 �I�N�e�b�g�������A
 *    �X�ɃA���C������ 62�j�I�N�e�b�g�ł���B
 *    �]���āAIPv4 �ł́ACSEG �T�C�Y�̃l�b�g���[�N�o�b�t�@
 *   �iIF + IPv4 + TCP = 54�j�͕s�v�ł���B
 */

#ifdef NUM_MPF_NET_BUF_CSEG
#undef NUM_MPF_NET_BUF_CSEG
#endif

#ifdef SUPPORT_INET6
#define NUM_MPF_NET_BUF_CSEG		4
#else
#define NUM_MPF_NET_BUF_CSEG		0
#endif

/*
 *  128 �I�N�e�b�g
 *
 *    IPv4 �ŁATCP MSS�iIP MSS�AIF + 576 �I�N�e�b�g�j��
 *    �l�b�g���[�N�o�b�t�@�����蓖�Ă�ꍇ�A
 *    128 �I�N�e�b�g�̃l�b�g���[�N�o�b�t�@�͊��蓖�ĂȂ��B
 */

#ifdef NUM_MPF_NET_BUF_128
#undef NUM_MPF_NET_BUF_128
#endif

#if defined(USE_TCP_MSS_SEG)
#define NUM_MPF_NET_BUF_128		0
#else
#define NUM_MPF_NET_BUF_128		2
#endif

/*
 *  256 �I�N�e�b�g
 *
 *    IPv4 �ŁATCP MSS�iIP MSS�AIF + 576 �I�N�e�b�g�j��
 *    �l�b�g���[�N�o�b�t�@�����蓖�Ă�ꍇ�A
 *    256 �I�N�e�b�g�̃l�b�g���[�N�o�b�t�@�͊��蓖�ĂȂ��B
 */

#ifdef NUM_MPF_NET_BUF_256
#undef NUM_MPF_NET_BUF_256
#endif

/*#if defined(USE_TCP_MSS_SEG)
#define NUM_MPF_NET_BUF_256		0
#else
#define NUM_MPF_NET_BUF_256		2
#endif*/
#define NUM_MPF_NET_BUF_256		10

/*
 *  512 �I�N�e�b�g
 *
 *    IPv4 �ŁATCP MSS�iIP MSS�AIF + 576 �I�N�e�b�g�j��
 *    �l�b�g���[�N�o�b�t�@�����蓖�Ă�ꍇ�A
 *    512 �I�N�e�b�g�̃l�b�g���[�N�o�b�t�@�͊��蓖�ĂȂ��B
 */

#ifdef NUM_MPF_NET_BUF_512
#undef NUM_MPF_NET_BUF_512
#endif

#if defined(USE_TCP_MSS_SEG)
#define NUM_MPF_NET_BUF_512		0
#else
#define NUM_MPF_NET_BUF_512		2
#endif

/*
 *  TCP MSS�iIP MSS�AIF + 576 �I�N�e�b�g�j
 *
 *   �EIPv4 �ł̂݊��蓖�Ă�B
 *   �E����M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\���L���ŁA
 *     �ȃR�s�[ API ���g�p����Ƃ��́A+1 ���蓖�Ă�B
 */

#ifdef NUM_MPF_NET_BUF_IP_MSS
#undef NUM_MPF_NET_BUF_IP_MSS
#endif

#if defined(SUPPORT_INET4) && defined(USE_TCP_MSS_SEG)

#if (defined(TCP_CFG_RWBUF_CSAVE)      || defined(TCP_CFG_SWBUF_CSAVE) ||	\
     defined(TCP_CFG_RWBUF_CSAVE_ONLY) || defined(TCP_CFG_SWBUF_CSAVE_ONLY)) && defined(USE_COPYSAVE_API)
#define NUM_MPF_NET_BUF_IP_MSS		6
#else
#define NUM_MPF_NET_BUF_IP_MSS		4	/* IF + 576 �I�N�e�b�g	*/
#endif

#else	/* of #if defined(SUPPORT_INET4) && defined(USE_TCP_MSS_SEG) */

#define NUM_MPF_NET_BUF_IP_MSS		0	/* IF + 576 �I�N�e�b�g	*/

#endif	/* of #if defined(SUPPORT_INET4) && defined(USE_TCP_MSS_SEG) */

/*
 *  1024 �I�N�e�b�g
 *
 *    TCP MSS �̃l�b�g���[�N�o�b�t�@�����蓖�Ă�ꍇ�A
 *    1024 �I�N�e�b�g�̃l�b�g���[�N�o�b�t�@�͊��蓖�ĂȂ��B
 */

#ifdef NUM_MPF_NET_BUF_1024
#undef NUM_MPF_NET_BUF_1024
#endif

#if defined(USE_TCP_MSS_SEG)
#define NUM_MPF_NET_BUF_1024		0	/* 1024 �I�N�e�b�g	*/
#else
#define NUM_MPF_NET_BUF_1024		2	/* 1024 �I�N�e�b�g	*/
#endif

/*
 *  TCP MSS�iIPV6 MMTU�AIF + 1280 �I�N�e�b�g�j
 *
 *   �EIPv6 �ł̂݊��蓖�Ă�B
 *   �E����M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\���L���ŁA
 *     �ȃR�s�[ API ���g�p����Ƃ��́A+1 ���蓖�Ă�B
 */

#ifdef NUM_MPF_NET_BUF_IPV6_MMTU
#undef NUM_MPF_NET_BUF_IPV6_MMTU
#endif

#if defined(SUPPORT_INET6) && (defined(USE_TCP_MSS_SEG) || defined(USE_IPV6_MMTU))

#if (defined(TCP_CFG_RWBUF_CSAVE)      || defined(TCP_CFG_SWBUF_CSAVE) ||	\
     defined(TCP_CFG_RWBUF_CSAVE_ONLY) || defined(TCP_CFG_SWBUF_CSAVE_ONLY)) && defined(USE_COPYSAVE_API)
#define NUM_MPF_NET_BUF_IPV6_MMTU	6	/* IF + 1280	*/
#else
#define NUM_MPF_NET_BUF_IPV6_MMTU	4	/* IF + 1280	*/
#endif

#else	/* of #if defined(SUPPORT_INET6) && (defined(USE_TCP_MSS_SEG) || defined(USE_IPV6_MMTU)) */

#define NUM_MPF_NET_BUF_IPV6_MMTU	0	/* IF + 1280	*/

#endif	/* of #if defined(SUPPORT_INET6) && (defined(USE_TCP_MSS_SEG) || defined(USE_IPV6_MMTU)) */

/*
 *  IF �ő� PDU �T�C�Y
 *
 *   �ETCP MSS �̃l�b�g���[�N�o�b�t�@�����蓖�Ă�ꍇ�A
 *     IF �ő� PDU �T�C�Y�̃l�b�g���[�N�o�b�t�@�͊��蓖�ĂȂ��B
 *   �E����M�E�B���h�o�b�t�@�̏ȃR�s�[�@�\���L���ŁA
 *     �ȃR�s�[ API ���g�p����Ƃ��́A+1 ���蓖�Ă�B
 */

#ifdef NUM_MPF_NET_BUF_IF_PDU
#undef NUM_MPF_NET_BUF_IF_PDU
#endif

#ifdef USE_TCP_MSS_SEG

#define NUM_MPF_NET_BUF_IF_PDU		0

#else	/* of #ifdef USE_TCP_MSS_SEG */

#if (defined(TCP_CFG_RWBUF_CSAVE) || defined(TCP_CFG_SWBUF_CSAVE)) && defined(USE_COPYSAVE_API)
#define NUM_MPF_NET_BUF_IF_PDU		12
#else
#define NUM_MPF_NET_BUF_IF_PDU		10
#endif

#endif	/* of #ifdef USE_TCP_MSS_SEG */

/*
 *  65536 �I�N�e�b�g
 *
 *  �ENET_BUF_CFG_LONG_LEN ���`�����Ƃ��̂݊��蓖�Ă�B
 */

#ifdef NET_BUF_CFG_LONG_LEN

/* IPv6 �p */

#ifdef NUM_MPF_NET_BUF6_65536
#undef NUM_MPF_NET_BUF6_65536
#endif

#if defined(USE_TCP_MSS_SEG)
#define NUM_MPF_NET_BUF6_65536	0
#else
#define NUM_MPF_NET_BUF6_65536	4
#endif

#else	/* of ifdef NET_BUF_CFG_LONG_LEN */

#define NUM_MPF_NET_BUF6_65536	0

#endif	/* of ifdef NET_BUF_CFG_LONG_LEN */

#endif	/* of #ifdef SUPPORT_ETHER */

/*
 *  DNS �T�[�o�Ɋւ����`
 */

/* DNS �T�[�o�� IP �A�h���X */

//#if !defined(DHCP6_CLI_CFG)

#define IPV6_ADDR_DNS_INIT	\
	{{{ UINT_C(0xfd), UINT_C(0x90), UINT_C(0xcc), UINT_C(0xe5), \
	    UINT_C(0x25), UINT_C(0xf6), UINT_C(0xff), UINT_C(0x81), \
	    UINT_C(0x02), UINT_C(0xa0), UINT_C(0x24), UINT_C(0xff), \
	    UINT_C(0xfe), UINT_C(0x56), UINT_C(0xc5), UINT_C(0xd6) }}}

//#endif	/* of #if !defined(DHCP6_CLI_CFG) */

//#if !defined(DHCP4_CLI_CFG)
#define IPV4_ADDR_DNS		MAKE_IPV4_ADDR(192,168,137,1)
//#endif

/* DOMAIN �� */

#if !(defined(DHCP4_CLI_CFG) || defined(DHCP6_CLI_CFG))
#define RSLV_CFG_DNS_DOMAIN_NAME_STR	"jo.tomakomai-ct.ac.jp"
#endif

/*
 *  DHCP �N���C�A���g�Ɋւ����`
 */

/* DHCPv6 �̓��샂�[�h�̐ݒ� */

#define DHCP6_CLI_CFG_MODE	DHCP6_CLI_CFG_STATELESS
//#define DHCP6_CLI_CFG_MODE	DHCP6_CLI_CFG_STATEFULL

#define ETHER_OUTPUT_PRIORITY	7	/* Ethernet �o�̓^�X�N�̗D��x		*/
#define TCP_OUT_TASK_PRIORITY	6	/* TCP �o�̓^�X�N�̗D��x			*/
#define NUM_DTQ_ETHER_OUTPUT	16	/* Ethernet �o�̓f�[�^�L���[�T�C�Y	*/

#endif /* _TINET_APP_CONFIG_H_ */
