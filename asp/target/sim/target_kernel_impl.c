#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>
#include <kernel.h>
#include <queue.h>
#include <sil.h>

#include "semaphore.h"
#include "dataqueue.h"
#include "wait.h"
#include "task.h"
#include "target_kernel_impl.h"
#include "kernel_cfg.h"

typedef struct task_data_t {
	TINIB tinib;
	TCB* tcb;
	struct task_data_t* next;
} T_TSKDAT;

#define TASK_STACK_SIZE 2048

jmp_buf SCHEDULER_EIXT;
static int scheduler_eixt;
#ifdef _M_X64
static volatile unsigned __int64 frame;
#endif
static int interrupt_stopped;
static int interrupt_count;
static int interrupt_count_max = WINT_MAX;
static int context;
static int lock;

void task_start(T_TSKDAT* p_tcb);

void task_start_internal(T_TSKDAT *tskdat)
{
	TCB *p_tcb = tskdat->tcb;

	switch (setjmp(p_tcb->tskctxb.TASK)) {
	case 0: {
		p_tcb->tskctxb.exitcode = 0;
		if (tskdat->next != NULL)
			task_start(tskdat->next);
		else
			dispatch();
		break;
	}
	case 1: if (p_tcb != NULL) {
		unl_cpu();
		p_tcb->p_tinib->task(p_tcb->p_tinib->exinf);
		loc_cpu();
		task_terminate(p_runtsk);
		p_tcb->tskctxb.exitcode++;
		dispatch();
		break;
	}
	default:
		break;
	}
}

void task_start(T_TSKDAT *tskdat)
{
	intptr_t stack[TASK_STACK_SIZE] = { 0 };
	tskdat->tinib.stk = &stack[TASK_STACK_SIZE];
	tskdat->tinib.stksz = sizeof(intptr_t) * TASK_STACK_SIZE;

	TCB *p_tcb = tskdat->tcb;
	p_tcb->p_tinib = &tskdat->tinib;

	task_start_internal(tskdat);
}

void stop_interrupt(void)
{
	interrupt_stopped = 1;
}

void set_interrupt_count_max(int max)
{
	interrupt_count_max = max;
}

void dispatch()
{
	if (p_runtsk == p_schedtsk)
		return;

	if (p_schedtsk == NULL) {
		context = 1;
		unlock_cpu();
		target_custom_idle();
		lock_cpu();
		context = 0;
	}

	if (p_schedtsk == NULL) {
		scheduler_eixt = 1;
		longjmp(SCHEDULER_EIXT, 1);
		return;
	}

	if (p_runtsk == NULL || setjmp(p_runtsk->tskctxb.TASK) == 0) {
		p_runtsk = p_schedtsk;
#ifdef _M_X64
		_JUMP_BUFFER* jb = (_JUMP_BUFFER*)p_runtsk->tskctxb.TASK;
		jb->Frame = frame;
#endif
		longjmp(p_runtsk->tskctxb.TASK, 1);
	}
}

int sense_context()
{
	return context;
}

int sense_lock()
{
	return lock != 0;
}

void lock_cpu()
{
	lock++;
}

void unlock_cpu()
{
	lock--;
}

void call_exit_kernel(void)
{
	if (!scheduler_eixt)
		longjmp(SCHEDULER_EIXT, 1);
}

extern const TINIB tinib_table[];
T_TSKDAT TASK_INF[TNUM_TSKID];

void start_dispatch(void)
{
	int i;

	scheduler_eixt = 0;
	interrupt_stopped = 0;
	context = 0;
	lock = 0;
#ifdef _M_X64
	frame = (unsigned __int64)__builtin_frame_address(0);
#endif

	for (i = 0; i < TNUM_TSKID; i++) {
		memcpy(&TASK_INF[i].tinib, &tinib_table[i], sizeof(TINIB));
		TASK_INF[i].tcb = &tcb_table[i];
		TASK_INF[i].next = &TASK_INF[i + 1];
	}
	TASK_INF[TNUM_TSKID - 1].next = NULL;

	if (setjmp(SCHEDULER_EIXT) == 0) {
		task_start(&TASK_INF[0]);
	}

	for (i = 0; i < TNUM_TSKID; i++) {
		TASK_INF[i].tinib.stk = NULL;
	}

	scheduler_eixt = 1;
}

void target_exit(void)
{
}

void exit_and_dispatch(void)
{
	__builtin_trap();
}

void initialize_tecs(void)
{
}

void request_dispatch_retint()
{
}

void delay_for_interrupt()
{
}

void activate_context(void *p_tcb)
{
}

bool_t check_intno_cfg(INTNO intno)
{
	return true;
}

bool_t check_intno_clear(INTNO intno)
{
	return true;
}

bool_t check_intno_raise(INTNO intno)
{
	return true;
}

void clear_int(INTNO intno)
{
}

void config_int(INTNO intno, ATR intatr, PRI intpri)
{
}

void define_exc(EXCNO excno, FP exc_entry)
{
}

void define_inh(INHNO inhno, FP int_entry)
{
}

void disable_int(INTNO intno)
{
}

void enable_int(INTNO intno)
{
}

bool_t exc_sense_intmask(void *p_excinf)
{
	return true;
}

bool_t probe_int(INTNO intno)
{
	return true;
}

void raise_int(INTNO intno)
{
}

PRI t_get_ipm(void)
{
	return TIPM_ENAALL;
}

void t_set_ipm(PRI intpri)
{
}

void target_initialize(void)
{
}

void target_raise_hrt_int(void)
{
	if (interrupt_stopped)
		return;

	interrupt_count++;
	if (interrupt_count > interrupt_count_max)
		return;

	unlock_cpu();
	target_hrt_handler();
	lock_cpu();
}

void target_raise_ovr_int(void)
{
}

void target_clear_ovr_int(void)
{
}

ER syslog_wri_log(uint_t prio, const SYSLOG *p_syslog)
{
	assert(prio > LOG_ERROR);
	return E_OK;
}
