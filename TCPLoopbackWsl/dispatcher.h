﻿#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include <stdlib.h>

typedef struct _queue_t
{
	struct _queue_t *p_next;
	struct _queue_t *p_prev;
} queue_t;

static inline
void queue_init(queue_t *p_queue)
{
	p_queue->p_prev = p_queue;
	p_queue->p_next = p_queue;
}

typedef void cycle_timer_proc_t(void *clientData);

typedef struct _cycle_timer_tree_t cycle_timer_tree_t;

typedef struct _cycle_timer_t {
	queue_t timer_node;
	cycle_timer_tree_t *parent;
	_Atomic bool isactive;
	uint64_t timeout;
	void *client_data;
	cycle_timer_proc_t *proc;
	queue_t pending_node;
} cycle_timer_t;

static inline
cycle_timer_t *cast_cycle_timer_t(queue_t *pending_node)
{
	return (cycle_timer_t *)&((char *)pending_node)[-offsetof(cycle_timer_t, pending_node)];
}

static inline
void cycle_timer_init(cycle_timer_t *cycle_timer, cycle_timer_proc_t *proc, void *client_data)
{
	queue_init(&cycle_timer->timer_node);

	cycle_timer->parent = NULL;
	cycle_timer->isactive = false;
	cycle_timer->timeout = 0;
	cycle_timer->client_data = client_data;
	cycle_timer->proc = proc;

	queue_init(&cycle_timer->pending_node);
}

struct _cycle_timer_tree_t
{
	queue_t root;
};

static inline
void cycle_timer_tree_init(cycle_timer_tree_t *tree)
{
	queue_init(&tree->root);
}

typedef struct _kernel_t kernel_t;

int kernel_create(kernel_t **kernel);
void kernel_delete(kernel_t *kernel);

void kernel_lock_cpu(kernel_t *kernel);
void kernel_unlock_cpu(kernel_t *kernel);
bool kernel_sense_context(kernel_t *kernel);
bool kernel_sense_lock(kernel_t *kernel);

void *kernel_new_context(kernel_t *kernel, void *p_tcb);
void kernel_start_dispatch(kernel_t *kernel);
void kernel_dispatch(kernel_t *kernel);
void kernel_dispatch_in_int(kernel_t *kernel);
void kernel_task_start(kernel_t *kernel);
void kernel_exit_and_dispatch(kernel_t *kernel);
void kernel_call_exit_kernel(kernel_t *kernel);

void kernel_interrupt(kernel_t *kernel, int intno, uint64_t cycle);
void soft_int_handler();

extern int tasks_get_count();
extern int tasks_get_index(void *p_tcb);
extern void *tasks_get_tcb(int index);
extern void task_invoke(void *_task);
extern void task_start(void *_task);
extern void *task_get_data(void *_task);
extern void task_clear_data(void *_task);

uint64_t get_cycle_counte(kernel_t *kernel);
int64_t CyclesToMilliseconds(kernel_t *kernel, int64_t cycles);
int64_t CyclesToMicroseconds(kernel_t *kernel, int64_t cycles);
int64_t CyclesToNanoseconds(kernel_t *kernel, int64_t cycles);
int64_t MillisecondsToCycles(kernel_t *kernel, int64_t msec);
int64_t MicrosecondsToCycles(kernel_t *kernel, int64_t usec);
int64_t NanosecondsToCycles(kernel_t *kernel, int64_t nsec);