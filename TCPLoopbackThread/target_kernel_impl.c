
#include "kernel_impl.h"
#include "target_timer.h"
#include "task.h"
#include <windows.h>
#include "dispatcher.h"
#include "kernel_cfg.h"

kernel_t *g_kernel;

bool_t sense_context(void)
{
	return kernel_sense_context(g_kernel);
}

void lock_cpu(void)
{
	kernel_lock_cpu(g_kernel);
}

void unlock_cpu(void)
{
	kernel_unlock_cpu(g_kernel);
}

bool_t sense_lock(void)
{
	return kernel_sense_lock(g_kernel);
}

void delay_for_interrupt(void)
{

}

void t_set_ipm(PRI intpri)
{

}

PRI t_get_ipm(void)
{
	return TIPM_ENAALL;
}

bool_t check_intno_cfg(INTNO intno)
{
	return true;
}

void disable_int(INTNO intno)
{
}

void enable_int(INTNO intno)
{
}

bool_t check_intno_clear(INTNO intno)
{
	return true;
}

void clear_int(INTNO intno)
{
}

bool_t check_intno_raise(INTNO intno)
{
	return true;
}

void raise_int(INTNO intno)
{
}

bool_t probe_int(INTNO intno)
{
	return true;
}

void dispatch(void)
{
	kernel_dispatch(g_kernel);
}

void request_dispatch_retint(void)
{
	kernel_dispatch_in_int(g_kernel);
}

void start_dispatch(void)
{
	kernel_start_dispatch(g_kernel);
}

void exit_and_dispatch(void)
{
	kernel_exit_and_dispatch(g_kernel);
}

void int_handler_entry(void)
{
}

void exc_handler_entry(void)
{
}

void call_exit_kernel(void) NoReturn
{
	kernel_call_exit_kernel(g_kernel);

	exit_kernel();
}

void start_r(void)
{
	kernel_task_start(g_kernel);
}

void *new_context(void *p_tcb)
{
	return kernel_new_context(g_kernel, p_tcb);
}

void define_inh(INHNO inhno, FP int_entry)
{
}

void config_int(INTNO intno, ATR intatr, PRI intpri)
{
}

void define_exc(EXCNO excno, FP exc_entry)
{
}

bool_t exc_sense_intmask(void *p_excinf)
{
	return true;
}

void target_initialize(void)
{
	int ret;
	ret = kernel_create(&g_kernel);
	if (ret != 0)
		__builtin_trap();
}

void target_exit(void)
{
	kernel_delete(g_kernel);
}

void initialize_tecs(void)
{
}

ER syslog_wri_log(uint_t prio, const SYSLOG *p_syslog) throw()
{
	assert(prio > LOG_ERROR);
	return E_OK;
}

void target_raise_hrt_int(void)
{
	kernel_interrupt(g_kernel, 1, 1);
}

void target_raise_ovr_int(void)
{
}

void target_clear_ovr_int(void)
{
}

int tasks_get_count()
{
	return TNUM_TSKID;
}

int tasks_get_index(void *p_tcb)
{
	TCB *tcb = (TCB *)p_tcb;
	return INDEX_TSK(TSKID(tcb));
}

void *tasks_get_tcb(int index)
{
	return &tcb_table[index];
}

void task_invoke(void *_task)
{
	TCB *task = (TCB *)_task;
	task->p_tinib->task(task->p_tinib->exinf);
}

void task_start(void *_task)
{
	TCB *task = (TCB *)_task;
	task->tskctxb.start();
	ext_tsk();
}

void *task_get_data(void *_task)
{
	TCB *task = (TCB *)_task;
	return task->tskctxb.cpu_context;
}

void task_clear_data(void *_task)
{
	TCB *task = (TCB *)_task;
	task->tskctxb.cpu_context = 0;
}

void raise_soft_int(uint64_t cycle, void (*callback)(void))
{
	kernel_interrupt(g_kernel, 2, cycle);
}
