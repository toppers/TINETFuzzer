#ifndef TARGET_SIL_H
#define TARGET_SIL_H

/*
 *  全割込みロック状態の制御
 */
#define SIL_PRE_LOC		int_t intmask
#define SIL_LOC_INT()	(intmask = 1)
#define SIL_UNL_INT()	(intmask = intmask - 1)

/*
 *  微少時間待ち
 */
extern void sil_dly_nse(ulong_t dlytim);

/*
 *  プロセッサのエンディアン
 */
#define SIL_ENDIAN_LITTLE			/* リトルエンディアン */

/*
 *  メモリ同期バリア
 */
#define TOPPERS_SIL_WRITE_SYNC()

#endif // TARGET_SIL_H
