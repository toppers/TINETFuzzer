#ifndef TARGET_SIL_H
#define TARGET_SIL_H

/*
 *  �S�����݃��b�N��Ԃ̐���
 */
#define SIL_PRE_LOC		int_t intmask
#define SIL_LOC_INT()	(intmask = 1)
#define SIL_UNL_INT()	(intmask = intmask - 1)

/*
 *  �������ԑ҂�
 */
extern void sil_dly_nse(ulong_t dlytim);

/*
 *  �v���Z�b�T�̃G���f�B�A��
 */
#define SIL_ENDIAN_LITTLE			/* ���g���G���f�B�A�� */

/*
 *  �����������o���A
 */
#define TOPPERS_SIL_WRITE_SYNC()

#endif // TARGET_SIL_H
