#ifndef MULTITHREAD_H
#define MULTITHREAD_H

#include "sil.h"

#ifdef TOPPERS_TASK_H

#define TASK_STACK_SIZE 2048
#define TASK1_PRIORITY 9

typedef struct task_data_t {
	TINIB tinib;
	TCB *tcb;
	struct task_data_t *next;
} T_TSKDAT;

void initialize_object(void);
void task_start(T_TSKDAT *p_tcb);

#endif

ER callback_nblk_ntp_cli(ID cepid, FN fncd, void *p_parblk);

void task1(void *);

#endif // MULTITHREAD_H
