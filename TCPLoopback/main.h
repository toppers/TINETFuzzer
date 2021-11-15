#ifndef MULTITHREAD_H
#define MULTITHREAD_H

#include "sil.h"

#define TASK_STACK_SIZE 2048

#define TASK1_PRIORITY 9
#define TASK2_PRIORITY 9

ER callback_nblk_ntp_cli(ID cepid, FN fncd, void *p_parblk);

void task1(void *);
void task2(void *);

#endif // MULTITHREAD_H
