/*
 *  TOPPERS Software
 *      Toyohashi Open Platform for Embedded Real-Time Systems
 *
 *  Copyright (C) 2018-2019 by Embedded and Real-Time Systems Laboratory
 *              Graduate School of Information Science, Nagoya Univ., JAPAN
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
 *  $Id: target_timer.c 2325 2022-01-16 05:53:19Z coas-nagasima $
 */

 /*
  *		�^�C�}�h���C�o�V�~�����[�^
  */

#include "kernel_impl.h"
#include "time_event.h"
#ifdef TOPPERS_SUPPORT_OVRHDR
#include "overrun.h"
#endif /* TOPPERS_SUPPORT_OVRHDR */
#include "target_timer.h"
#include "dispatcher.h"

extern kernel_t *g_kernel;

/*
 *  �V�~�����[�V�������Ԃ̃f�[�^�^�̒�`
 */
typedef uint64_t	SIMTIM;

/*
 *  �^�C�}�����݂̔��������̐ݒ��
 */
typedef struct {
	bool_t		enable;				/* �����������ݒ肳��Ă��邩�H */
	SIMTIM		simtim;				/* �������� */
	void		(*raise)(void);		/* �^�C�}�����݂̗v�� */
} INT_EVENT;

/*
 *  ���݂̃V�~�����[�V��������
 */
static SIMTIM	current_simtim()
{
	return CyclesToMicroseconds(g_kernel, get_cycle_counte(g_kernel));
}

/*
 *  �ŏ��ɔ�������^�C�}�����݂̑I��
 */
static void		select_event(void);

/*
 *  ������\�^�C�}�����݂̔�������
 */
static INT_EVENT	hrt_event;

Inline SIMTIM
truncate_simtim(SIMTIM simtim)
{
	return(simtim / TSTEP_HRTCNT * TSTEP_HRTCNT);
}

Inline SIMTIM
roundup_simtim(SIMTIM simtim)
{
	return((simtim + TSTEP_HRTCNT - 1) / TSTEP_HRTCNT * TSTEP_HRTCNT);
}

/*
 *  ������\�^�C�}�̌��݂̃J�E���g�l�̓Ǐo��
 */
HRTCNT
target_hrt_get_current(void)
{
#ifdef TCYC_HRTCNT
	return((HRTCNT)(truncate_simtim(current_simtim) % TCYC_HRTCNT));
#else /* TCYC_HRTCNT */
	return((HRTCNT)truncate_simtim(current_simtim()));
#endif /* TCYC_HRTCNT */
}

/*
 *  ������\�^�C�}�ւ̊����݃^�C�~���O�̐ݒ�
 */
void
target_hrt_set_event(HRTCNT hrtcnt)
{
#ifdef HOOK_HRT_EVENT
	hook_hrt_set_event(hrtcnt);
#endif /* HOOK_HRT_EVENT */

	hrt_event.enable = true;
	hrt_event.simtim = roundup_simtim(current_simtim() + hrtcnt);
	select_event();
}

/*
 *  ������\�^�C�}�ւ̊����݃^�C�~���O�̃N���A
 */
#ifdef USE_64BIT_HRTCNT

void
target_hrt_clear_event(void)
{
#ifdef HOOK_HRT_EVENT
	hook_hrt_clear_event();
#endif /* HOOK_HRT_EVENT */

	hrt_event.enable = false;
	select_event();
}

#endif /* USE_64BIT_HRTCNT */

/*
 *  ������\�^�C�}�����݂̗v��
 */
void
target_hrt_raise_event(void)
{
#ifdef HOOK_HRT_EVENT
	hook_hrt_raise_event();
#endif /* HOOK_HRT_EVENT */

	target_raise_hrt_int();
}

/*
 *  �V�~�����[�g���ꂽ������\�^�C�}�����݃n���h��
 */
void
target_hrt_handler(void)
{
	signal_time();
}

#ifdef TOPPERS_SUPPORT_OVRHDR
/*
 *  �I�[�o�����^�C�}�����݂̔�������
 */
static INT_EVENT	ovr_event;

/*
 *  �I�[�o�����^�C�}�̓���J�n
 */
void
target_ovrtimer_start(PRCTIM ovrtim)
{
	if (ovrtim == 0) {
		ovr_event.enable = false;
		select_event();
		target_raise_ovr_int();
	}
	else {
		ovr_event.enable = true;
		ovr_event.simtim = current_simtim() + ovrtim;
		select_event();
	}
}

/*
 *  �I�[�o�����^�C�}�̒�~
 *
 *  �����ŃI�[�o�����^�C�}�����ݗv�����N���A����ƁC�����݌��̓���Ɏ�
 *  �s����iQEMU�Ŋm�F�DQEMU�����̖�肩�C���@�ɂ������肩�͖��m�F�j
 *  ���߁C�N���A���Ȃ��D
 */
PRCTIM
target_ovrtimer_stop(uint_t int_num)
{
	PRCTIM	ovrtim;

	if (ovr_event.simtim <= current_simtim()) {
		ovrtim = 0U;
	}
	else {
		ovrtim = ovr_event.simtim - current_simtim();
	}
	ovr_event.enable = false;
	select_event();
	target_clear_ovr_int();
	return(ovrtim);
}

/*
 *  �I�[�o�����^�C�}�̌��ݒl�̓Ǐo��
 */
PRCTIM
target_ovrtimer_get_current(void)
{
	if (ovr_event.simtim <= current_simtim()) {
		return(0U);
	}
	else {
		return(ovr_event.simtim - current_simtim());
	}
}

/*
 *  �V�~�����[�g���ꂽ�I�[�o�����^�C�}�����݃n���h��
 */
void
target_ovrtimer_handler(void)
{
	call_ovrhdr();
}

#endif /* TOPPERS_SUPPORT_OVRHDR */

/*
 *  �ŏ��ɔ�������^�C�}�����݂̏��
 */
static INT_EVENT *p_next_event;

/*
 *  �^�C�}�̋N������
 */
void
target_timer_initialize(intptr_t exinf)
{
	hrt_event.enable = false;
	hrt_event.raise = &target_raise_hrt_int;
#ifdef TOPPERS_SUPPORT_OVRHDR
	ovr_event.enable = false;
	ovr_event.raise = &target_raise_ovr_int;
#endif /* TOPPERS_SUPPORT_OVRHDR */
	p_next_event = NULL;
}

/*
 *  �^�C�}�̒�~����
 */
void
target_timer_terminate(intptr_t exinf)
{
	hrt_event.enable = false;
#ifdef TOPPERS_SUPPORT_OVRHDR
	ovr_event.enable = false;
#endif /* TOPPERS_SUPPORT_OVRHDR */
}

/*
 *  �ŏ��ɔ�������^�C�}�����݂̑I��
 */
static void
select_event(void)
{
	if (hrt_event.enable) {
		p_next_event = &hrt_event;
	}
	else {
		p_next_event = NULL;
	}

#ifdef TOPPERS_SUPPORT_OVRHDR
	if (ovr_event.enable && (p_next_event == NULL
		|| ovr_event.simtim <= p_next_event->simtim)) {
		p_next_event = &ovr_event;
	}
#endif /* TOPPERS_SUPPORT_OVRHDR */
}

/*
 *  �J�[�l���̃A�C�h������
 */
void
target_custom_idle(void)
{
	lock_cpu();
	if (p_next_event != NULL) {
		p_next_event->enable = false;
		(*(p_next_event->raise))();
		select_event();
	}
	unlock_cpu();
}
