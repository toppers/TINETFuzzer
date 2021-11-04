/*
 *  TOPPERS/ASP Kernel
 *      Toyohashi Open Platform for Embedded Real-Time Systems/
 *      Advanced Standard Profile Kernel
 * 
 *  Copyright (C) 2013-2018 by Embedded and Real-Time Systems Laboratory
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
 *		カーネルのターゲット依存部（ダミーターゲット用）
 *
 *  カーネルのターゲット依存部のヘッダファイル．kernel_impl.hのターゲッ
 *  ト依存部の位置付けとなる．
 */

#ifndef TOPPERS_TARGET_KERNEL_IMPL_H
#define TOPPERS_TARGET_KERNEL_IMPL_H

#include <setjmp.h>
#include <kernel.h>

/*
 *  ターゲットシステムのハードウェア資源の定義
 */
#include "dummy.h"

/*
 *  エラーチェック方法の指定
 */
#define CHECK_STKSZ_ALIGN	4	/* スタックサイズのアライン単位 */
#define CHECK_INTPTR_ALIGN	4	/* intptr_t型の変数のアライン単位 */
#define CHECK_INTPTR_NONNULL	/* intptr_t型の変数の非NULLチェック */
#define CHECK_FUNC_ALIGN	4	/* 関数のアライン単位 */
#define CHECK_FUNC_NONNULL		/* 関数の非NULLチェック */
#define CHECK_STACK_ALIGN	4	/* スタック領域のアライン単位 */
#define CHECK_STACK_NONNULL		/* スタック領域の非NULLチェック */
#define CHECK_MPF_ALIGN		4	/* 固定長メモリプール領域のアライン単位 */
#define CHECK_MPF_NONNULL		/* 固定長メモリプール領域の非NULLチェック */
#define CHECK_MPK_ALIGN		4	/* カーネルメモリプール領域のアライン単位 */
#define CHECK_MPK_NONNULL		/* カーネルメモリプール領域の非NULLチェック */
#define CHECK_MB_ALIGN		4	/* 管理領域のアライン単位 */

/*
 *  トレースログマクロのデフォルト定義
 */
#ifndef LOG_INH_ENTER
#define LOG_INH_ENTER(inhno)
#endif /* LOG_INH_ENTER */

#ifndef LOG_INH_LEAVE
#define LOG_INH_LEAVE(inhno)
#endif /* LOG_INH_LEAVE */

#ifndef LOG_EXC_ENTER
#define LOG_EXC_ENTER(excno)
#endif /* LOG_EXC_ENTER */

#ifndef LOG_EXC_LEAVE
#define LOG_EXC_LEAVE(excno)
#endif /* LOG_EXC_LEAVE */

/*
 *  非タスクコンテキスト用スタックのデフォルトのサイズ
 */
#define DEFAULT_ISTKSZ			4096

#ifndef TOPPERS_MACRO_ONLY

/*
 *  タスクコンテキストブロックの定義
 */
typedef struct task_context_block {
	jmp_buf TASK;
	int exitcode;
} TSKCTXB;

extern jmp_buf SCHEDULER_EIXT;

/*
 *  コンテキストの参照
 */
extern bool_t sense_context(void);

/*
 *  CPUロック状態への遷移
 */
extern void lock_cpu(void);

/*
 *  CPUロック状態への移行（ディスパッチできる状態）
 */
#define lock_cpu_dsp()		lock_cpu()

/*
 *  CPUロック状態の解除
 */
extern void unlock_cpu(void);

/*
 *  CPUロック状態の解除（ディスパッチできる状態）
 */
#define unlock_cpu_dsp()	unlock_cpu()

/*
 *  CPUロック状態の参照
 */
extern bool_t sense_lock(void);

/*
 *  割込みを受け付けるための遅延処理
 */
extern void delay_for_interrupt(void);

/*
 *  割込み優先度マスクの設定
 */
extern void t_set_ipm(PRI intpri);

/*
 *  割込み優先度マスクの参照
 */
extern PRI t_get_ipm(void);

/*
 *  割込み番号，割込みハンドラ番号，CPU例外ハンドラ番号の範囲の判定
 */
#define	VALID_INTNO(intno)	(0U <= (intno) && (intno) <= 31U)
#define VALID_INHNO(inhno)	VALID_INTNO((INTNO)(inhno))
#define VALID_EXCNO(excno)	(0U <= (excno) && (excno) <= 7U)

/*
 *  割込み属性の設定のチェック
 */
extern bool_t check_intno_cfg(INTNO intno);

/*
 *  割込み要求禁止フラグのセット
 */
extern void disable_int(INTNO intno);

/*
 *  割込み要求禁止フラグのクリア
 */
extern void enable_int(INTNO intno);

/*
 *  割込み要求がクリアできる状態か？
 */
extern bool_t check_intno_clear(INTNO intno);

/*
 *  割込み要求のクリア
 */
extern void clear_int(INTNO intno);

/*
 *  割込みが要求できる状態か？
 */
extern bool_t check_intno_raise(INTNO intno);

/*
 *  割込みの要求
 */
extern void raise_int(INTNO intno);

/*
 *  割込み要求のチェック
 */
extern bool_t probe_int(INTNO intno);

/*
 *  最高優先順位タスクへのディスパッチ
 */
extern void	dispatch(void);

/*
 *  非タスクコンテキストからのディスパッチ要求
 */
extern void request_dispatch_retint(void);

/*
 *  ディスパッチャの動作開始
 */
extern void start_dispatch(void);

/*
 *  現在のコンテキストを捨ててディスパッチ
 */
extern void	exit_and_dispatch(void);

/*
 *  割込みハンドラ出入口処理
 */
extern void	int_handler_entry(void);

/*
 *  CPU例外ハンドラ出入口処理
 */
extern void	exc_handler_entry(void);

/*
 *  カーネルの終了処理の呼出し
 */
extern void call_exit_kernel(void) NoReturn;

/*
 *  タスクコンテキストの初期化
 */
extern void	start_r(void);

	/* 指定されたタスク（p_tcb）のTCB中のスタックポインタを初期化する */
	/* start_rを，実行再開番地として自タスクのTCBに保存する */
extern void activate_context(void *p_tcb);

/*
 *  割込みハンドラの設定
 *
 *  ベクトル番号inhnoの割込みハンドラの出入口処理の番地をint_entryに
 *  設定する．
 */
extern void define_inh(INHNO inhno, FP int_entry);

/*
 *  割込み要求ライン属性の設定
 */
extern void config_int(INTNO intno, ATR intatr, PRI intpri);

/*
 *  CPU例外ハンドラの設定
 *
 *  ベクトル番号excnoのCPU例外ハンドラの出入口処理の番地をexc_entryに設
 *  定する．
 */
extern void define_exc(EXCNO excno, FP exc_entry);

/*
 *  オーバランハンドラ停止のためのマクロ
 */
#ifdef TOPPERS_SUPPORT_OVRHDR
#define OVRTIMER_STOP()	{				\
			lock_cpu();					\
			_kernel_ovrtimer_stop();	\
			unlock_cpu();				\
		}
#else /* TOPPERS_SUPPORT_OVRHDR */
#define OVRTIMER_STOP()
#endif /* TOPPERS_SUPPORT_OVRHDR */

/*
 *  割込みハンドラの入口処理の生成マクロ
 */
#define INT_ENTRY(inhno, inthdr)	inthdr
#define INTHDR_ENTRY(inhno, inthdr, intpri)

/*
 *  CPU例外ハンドラの入口処理の生成マクロ
 */
#define EXC_ENTRY(excno, exchdr)	exchdr
#define EXCHDR_ENTRY(excno, excno_num, exchdr)

/*
 *  CPU例外の発生した時のコンテキストと割込みのマスク状態の参照
 *
 *  CPU例外の発生した時のシステム状態が，カーネル内のクリティカルセクショ
 *  ンの実行中でなく，全割込みロック状態でなく，CPUロック状態でなく，カー
 *  ネル管理外の割込みハンドラ実行中でなく，カーネル管理外のCPU例外ハン
 *  ドラ実行中でなく，タスクコンテキストであり，割込み優先度マスクが全
 *  解除である時にtrue，そうでない時にfalseを返す．
 */
extern bool_t exc_sense_intmask(void *p_excinf);

/*
 *  ターゲットシステム依存の初期化
 */
extern void	target_initialize(void);

/*
 *  ターゲットシステムの終了
 *
 *  システムを終了する時に使う．
 */
extern void	target_exit(void) NoReturn;

#endif /* TOPPERS_MACRO_ONLY */
#endif /* TOPPERS_TARGET_KERNEL_IMPL_H */
