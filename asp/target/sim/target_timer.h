/*
 *  TOPPERS Software
 *      Toyohashi Open Platform for Embedded Real-Time Systems
 * 
 *  Copyright (C) 2018-2019 by Embedded and Real-Time Systems Laboratory
 *              Graduate School of Information Science, Nagoya Univ., JAPAN
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
 *  $Id$
 */

/*
 *		タイマドライバシミュレータ
 */

#ifndef TOPPERS_TARGET_TIMER_H
#define TOPPERS_TARGET_TIMER_H

#include "kernel_impl.h"

#define INTNO_DUMMY_TIMER		255					/* ダミータイマ割込み番号 */

#ifndef TOPPERS_MACRO_ONLY

/*
 *  タイマの起動処理
 */
extern void	target_timer_initialize(intptr_t exinf);

/*
 *  タイマの停止処理
 */
extern void target_timer_terminate(intptr_t exinf);

/*
 *  高分解能タイマの現在のカウント値の読出し
 */
extern HRTCNT target_hrt_get_current(void);

/*
 *  高分解能タイマへの割込みタイミングの設定
 */
extern void target_hrt_set_event(HRTCNT hrtcnt);

/*
 *  高分解能タイマへの割込みタイミングのクリア
 */
#ifdef USE_64BIT_HRTCNT
extern void target_hrt_clear_event(void);
#endif /* USE_64BIT_HRTCNT */

/*
 *  高分解能タイマ割込みの要求
 */
extern void target_hrt_raise_event(void);

/*
 *  割込みタイミングに指定する最大値
 */
#define HRTCNT_BOUND	4000000002U

/*
 *  シミュレートされた高分解能タイマ割込みハンドラ
 */
extern void target_hrt_handler(void);

#ifdef TOPPERS_SUPPORT_OVRHDR
/*
 *  オーバランタイマの動作開始
 */
extern void target_ovrtimer_start(PRCTIM ovrtim);

/*
 *  オーバランタイマの停止
 */
extern PRCTIM target_ovrtimer_stop(uint_t int_num);

/*
 *  オーバランタイマの現在値の読出し
 */
extern PRCTIM target_ovrtimer_get_current(void);

/*
 *  シミュレートされたオーバランタイマ割込みハンドラ
 */
extern void target_ovrtimer_handler(void);

#endif /* TOPPERS_SUPPORT_OVRHDR */

/*
 *  カーネルのアイドル処理
 */
extern void target_custom_idle(void);

/*
 *  シミュレーション時刻を進める（テストプログラム用）
 */
extern void simtim_advance(uint_t time);

/*
 *  シミュレーション時刻を強制的に進める（テストプログラム用）
 */
extern void simtim_add(uint_t time);

extern void target_raise_hrt_int(void);
extern void target_raise_ovr_int(void);
extern void target_clear_ovr_int(void);

#endif /* TOPPERS_MACRO_ONLY */
#endif /* TOPPERS_TARGET_TIMER_H */
