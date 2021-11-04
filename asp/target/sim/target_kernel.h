/*
 *  TOPPERS/ASP Kernel
 *      Toyohashi Open Platform for Embedded Real-Time Systems/
 *      Advanced Standard Profile Kernel
 * 
 *  Copyright (C) 2000-2003 by Embedded and Real-Time Systems Laboratory
 *                              Toyohashi Univ. of Technology, JAPAN
 *  Copyright (C) 2003-2004 by Naoki Saito
 *             Nagoya Municipal Industrial Research Institute, JAPAN
 *  Copyright (C) 2003-2004 by Platform Development Center
 *                                          RICOH COMPANY,LTD. JAPAN
 *  Copyright (C) 2008-2010 by Witz Corporation, JAPAN
 * 
 *  上記著作権者は，以下の(1)～(4)の条件を満たす場合に限り，本ソフトウェ
 *  ア（本ソフトウェアを改変したものを含む．以下同じ）を使用・複製・改
 *  変・再配布（以下，利用と呼ぶ）することを無償で許諾する．
 *  (1) 本ソフトウェアをソースコードの形で利用する場合には，上記の著作
 *      権表示，この利用条件および下記の無保証規定が，そのままの形でソー
 *      スコード中に含まれていること．
 *  (2) 本ソフトウェアを，ライブラリ形式など，他のソフトウェア開発に使
 *      用できる形で再配布する場合には，再配布に伴うドキュメント（利用
 *      者マニュアルなど）に，上記の著作権表示，この利用条件および下記
 *      の無保証規定を掲載すること．
 *  (3) 本ソフトウェアを，機器に組み込むなど，他のソフトウェア開発に使
 *      用できない形で再配布する場合には，次のいずれかの条件を満たすこ
 *      と．
 *    (a) 再配布に伴うドキュメント（利用者マニュアルなど）に，上記の著
 *        作権表示，この利用条件および下記の無保証規定を掲載すること．
 *    (b) 再配布の形態を，別に定める方法によって，TOPPERSプロジェクトに
 *        報告すること．
 *  (4) 本ソフトウェアの利用により直接的または間接的に生じるいかなる損
 *      害からも，上記著作権者およびTOPPERSプロジェクトを免責すること．
 *      また，本ソフトウェアのユーザまたはエンドユーザからのいかなる理
 *      由に基づく請求からも，上記著作権者およびTOPPERSプロジェクトを
 *      免責すること．
 * 
 *  本ソフトウェアは，無保証で提供されているものである．上記著作権者お
 *  よびTOPPERSプロジェクトは，本ソフトウェアに関して，特定の使用目的
 *  に対する適合性も含めて，いかなる保証も行わない．また，本ソフトウェ
 *  アの利用により直接的または間接的に生じたいかなる損害に関しても，そ
 *  の責任を負わない．
 * 
 *  @(#) $Id: target_kernel.h 2049 2020-01-22 10:38:36Z coas-nagasima $
 */

/*
 *  カーネルのターゲット依存定義（GR-SAKURA用）
 */

/*
 *  このインクルードファイルは，kernel.hでインクルードされる．他のファ
 *  イルから直接インクルードすることはない．このファイルをインクルード
 *  する前に，t_stddef.hがインクルードされるので，それらに依存してもよ
 *  い．
 */

#ifndef TOPPERS_TARGET_KERNEL_H
#define TOPPERS_TARGET_KERNEL_H


/*
 *  カーネル本体をコンパイルするためのマクロ定義
 */
//#define ALLFUNC


/*
 *  サポートする機能の定義
 */
#define TOPPERS_TARGET_SUPPORT_DIS_INT		/* dis_intをサポートする */
#define TOPPERS_TARGET_SUPPORT_ENA_INT		/* ena_intをサポートする */
#define TOPPERS_TARGET_SUPPORT_CLR_INT		/* clr_intをサポートする */
#define TOPPERS_TARGET_SUPPORT_RAS_INT		/* ras_intをサポートする */
#define TOPPERS_TARGET_SUPPORT_PRB_INT		/* prb_intをサポートする */

/*
 *  高分解能タイマのタイマ周期
 *
 *  タイマ周期が2^32の場合には，このマクロを定義しない．
 */
/* TCYC_HRTCNTは定義しない．*/

/*
 *  高分解能タイマのカウント値の進み幅
 */
#define TSTEP_HRTCNT	1U

/*
 *  カーネル管理の割込み優先度の範囲
 *
 *  TMIN_INTPRIの定義を変更することで，どのレベルよりも高い割込み優先度
 *  を持つものをカーネル管理外の割込みとするかを変更できる．
 *
 *  TMIN_INTPRIに設定できる値は，-15～-1の範囲である．例えばTMIN_INTPRI
 *  を-14に設定すると，NMIに加えてレベル7の割込みがカーネル管理外となる．
 *  TMIN_INTPRIを-15に設定すると，NMI以外にカーネル管理外の割込みを
 *  設けないことになる．
 */
#ifndef TMIN_INTPRI
#define TMIN_INTPRI		( -15 )		/* 割込み優先度の最小値（最高値）*/
#endif /* TMIN_INTPRI */
#define TMAX_INTPRI		( -1 )		/* 割込み優先度の最大値（最低値） */


/*
 *  割込み属性の定義
 */
#define	TA_POSEDGE		TA_EDGE			/* ポジティブエッジトリガ */
#define	TA_NEGEDGE		UINT_C( 0x04 )	/* ネガティブエッジトリガ */
#define	TA_BOTHEDGE		UINT_C( 0x08 )	/* 両エッジトリガ */

#define	TA_LOWLEVEL		UINT_C( 0x10 )	/* Lレベル */


/*
 *  デフォルトの割込み/例外ハンドラの有無
 */
/*#define	OMIT_DEFAULT_INT_HANDLER*/
/*#define	OMIT_DEFAULT_EXC_HANDLER*/

/*
 *  サポートする機能の定義
 */
#define	TOPPERS_TARGET_SUPPORT_GET_UTM		/* get_utmをサポートする */
#define TOPPERS_TARGET_SUPPORT_OVRHDR		/* オーバランハンドラ */

/*
 *  タイムティックの定義
 */
#define	TIC_NUME		( 1U )		/* タイムティックの周期の分子 */
#define	TIC_DENO		( 1U )		/* タイムティックの周期の分母 */

#endif /* TOPPERS_TARGET_KERNEL_H */
