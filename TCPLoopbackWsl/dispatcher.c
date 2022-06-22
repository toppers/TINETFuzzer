#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>
#define __USE_POSIX199309
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <setjmp.h>
//#define __USE_GNU
#define __USE_POSIX
#define __USE_XOPEN2K8
#define __USE_XOPEN2K
#define __USE_UNIX98
#include <signal.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdatomic.h>
#include "dispatcher.h"
#define __USE_GNU
#include <unistd.h>
#include <sys/types.h>
#include <queue.h>

#define p_runtsk _kernel_p_runtsk
#define p_schedtsk _kernel_p_schedtsk

extern void *p_runtsk;
extern void *p_schedtsk;
void target_hrt_handler(void);
void target_custom_idle(void);

void cycle_timer_tree_add_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *x, uint64_t timeout)
{
	if ((x->parent != NULL) || (x->timer_node.p_next != x->timer_node.p_prev))
		__builtin_trap();

	x->timeout = timeout;
	x->parent = tree;

	queue_t *pos = (queue_t *)&tree->root;
	queue_t *p_queue = tree->root.p_next;
	while (p_queue != &tree->root) {
		cycle_timer_t *node = (cycle_timer_t *)p_queue;
		if (node->timeout > x->timeout) {
			pos = p_queue;
			break;
		}
		p_queue = p_queue->p_next;
	}

	queue_insert_prev((QUEUE *)pos, (QUEUE *)&x->timer_node);
}

bool cycle_timer_tree_is_empty(cycle_timer_tree_t *tree)
{
	if (queue_empty(&tree->root)) {
		return true;
	}
	return false;
}

cycle_timer_t *cycle_timer_tree_next_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *x)
{
	if (x->parent != tree) __builtin_trap();

	if (&tree->root == x->timer_node.p_next)
		return 0;

	return (cycle_timer_t *)x->timer_node.p_next;
}

void cycle_timer_tree_delete_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *z)
{
	if (z->parent != tree) __builtin_trap();

	queue_delete(&z->timer_node);
	queue_initialize(&z->timer_node);
	z->parent = NULL;

	z->timeout = 0;
}

typedef enum cpu_context_state_t {
	CPU_CONTEXT_INIT = 0,
	CPU_CONTEXT_READY = 1 + 0x200,
	CPU_CONTEXT_RUNNING = 2,
	CPU_CONTEXT_SUSPEND = 3 + 0x200,
	CPU_CONTEXT_DISPATCH = 4 + 0x100,
	CPU_CONTEXT_SUSPEND2 = 5 + 0x200,
	CPU_CONTEXT_INTERRUPT = 6 + 0x100
} cpu_context_state_t;

typedef struct _cpu_context_t
{
	kernel_t *kernel;
	pthread_t thread;
	pid_t thread_id;
	sem_t start_event;
	void *task;
	_Atomic bool terminate;
	_Atomic cpu_context_state_t ready;
	jmp_buf RESTART;
	cycle_timer_t dispatch_req;
	uint32_t saved_lock;
} cpu_context_t;

_Atomic pthread_key_t g_tls_index = 0xFFFFFFFF;
pthread_t null_thread = { 0 };
sem_t null_sem = { 0 };
int sem_equal(sem_t *a, sem_t *b) {
	return memcmp(a, b, sizeof(sem_t)) == 0;
}

void cpu_context_suspend(cpu_context_t *context);
void cpu_context_resume(cpu_context_t *context);
void *cpu_context_thread_proc(void *param);
void cpu_context_do_dispatch(void *client_data);

static cpu_context_t *cpu_context_get_current()
{
	return (cpu_context_t *)pthread_getspecific(g_tls_index);
}

void cpu_context_init(cpu_context_t *context, kernel_t *kernel)
{
	context->kernel = kernel;
	context->thread = null_thread;
	context->thread_id = 0;
	context->start_event = null_sem;
	context->task = NULL;
	context->terminate = false;
	context->ready = CPU_CONTEXT_INIT;

	if (g_tls_index == 0xFFFFFFFF) {
		pthread_key_create(&g_tls_index, NULL);
	}
}

void cpu_context_deinit(cpu_context_t *context)
{
	if (sem_equal(&context->start_event, &null_sem) == 0) {
		sem_destroy(&context->start_event);
	}

	if (context->thread_id != 0) {
		//pthread_cancel(context->thread);
		context->thread = null_thread;
		context->thread_id = 0;
	}
	free(context);
}

void cpu_context_activate(cpu_context_t *context, void *task)
{
	int ret;
	pthread_attr_t attr;

	context->task = task;

	if (context->thread_id != 0) {
		if (context->ready != CPU_CONTEXT_READY)
			__builtin_trap();
		return;
	}
	else {
		ret = sem_init(&context->start_event, 0, 0);
		if (ret != 0)
			__builtin_trap();

		ret = pthread_attr_init(&attr);
		if (ret != 0)
			__builtin_trap();

		ret = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		if (ret != 0)
			__builtin_trap();

		ret = pthread_create(&context->thread, 0, cpu_context_thread_proc, (void *)context);
		if (ret != 0)
			__builtin_trap();

		ret = pthread_attr_destroy(&attr);
		if (ret != 0)
			__builtin_trap();
	}

	while (context->ready != CPU_CONTEXT_READY) {
		pthread_yield();
	}
	pthread_yield();
}

void cpu_context_start(cpu_context_t *context)
{
	int ret;

	context->terminate = false;
	context->saved_lock = 1;
	context->ready = CPU_CONTEXT_READY;

	ret = sem_wait(&context->start_event);
	if (ret != 0)
		__builtin_trap();

	context->ready = CPU_CONTEXT_RUNNING;

	kernel_unlock_cpu(context->kernel);

	task_invoke(context->task);
}

void cpu_context_exit(cpu_context_t *context)
{
	//pthread_exit(0);
	context->terminate = false;
	longjmp(context->RESTART, 1);
}

void cpu_context_terminate(cpu_context_t *context)
{
	//pthread_cancel(context->thread);
	if (context->ready == CPU_CONTEXT_READY)
		return;
	context->terminate = true;
	while (context->ready == CPU_CONTEXT_RUNNING)
		pthread_yield();
	assert(context->terminate || context->ready == CPU_CONTEXT_READY);
}

static void cpu_context_suspend_handler(int sig);

void *cpu_context_thread_proc(void *param)
{
	int ret;
	cpu_context_t *context = (cpu_context_t *)param;

	context->thread_id = gettid();

	ret = pthread_setspecific(g_tls_index, context);
	if (ret != 0)
		__builtin_trap();

	ret = signal(SIGUSR1, cpu_context_suspend_handler);
	if (ret == SIG_ERR)
		__builtin_trap();

	setjmp(context->RESTART);

	for (;;) {
		task_start(context->task);
	}

	return 0;
}

void cpu_context_suspend(cpu_context_t *context)
{
	int ret;

	context->ready = CPU_CONTEXT_SUSPEND;

	ret = sem_wait(&context->start_event);
	if (ret != 0)
		__builtin_trap();

	context->ready = CPU_CONTEXT_RUNNING;

	if (context->terminate) {
		cpu_context_exit(context);
	}
}

static void cpu_context_suspend_handler(int sig)
{
	if (sig == SIGUSR1) {
		int ret = signal(SIGUSR1, cpu_context_suspend_handler);
		if (ret == SIG_ERR)
			__builtin_trap();

		cpu_context_t *context = cpu_context_get_current();
		cpu_context_suspend(context);
	}
}

void cpu_context_suspend2(cpu_context_t *context)
{
	int ret;
	int32_t ready = CPU_CONTEXT_RUNNING;

	if (__atomic_compare_exchange_4(&context->ready, &ready, CPU_CONTEXT_SUSPEND2, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		ret = pthread_kill(context->thread, SIGUSR1);
		if (ret != 0)
			__builtin_trap();
	}
}

void cpu_context_resume(cpu_context_t *context)
{
	int lock;
	int ret;

	for (;;) {
		ret = sem_getvalue(&context->start_event, &lock);
		if (ret != 0)
			__builtin_trap();
		if (lock == 0)
			break;
		pthread_yield();
	}
	ret = sem_post(&context->start_event);
	if (ret != 0)
		__builtin_trap();
}

typedef struct _interrupt_t {
	cycle_timer_t timer;
	struct _kernel_t *kernel;
	int intno;
	uint64_t cycle;
} interrupt_t;

typedef enum _kernel_mode_t {
	KERNEL_MODE_WAIT,
	KERNEL_MODE_TIMEOUT,
	KERNEL_MODE_PASSIVE,
	KERNEL_MODE_AUTONOMOUS
} kernel_mode_t;

struct _kernel_t {
	pid_t thread_id;
	sem_t kernel_mode;
	sem_t start_event;
	_Atomic kernel_mode_t mode;
	cpu_context_t *run_context;
	cpu_context_t *sched_context;
	pthread_mutex_t timer_mutex;
	_Atomic bool terminate;
	cpu_context_t **contexts;
	int context_count;

	uint64_t first_cycle_timer_timeout;
	uint64_t cycle_counter;
	uint32_t cycle_timer_rate;
	cycle_timer_t *first_cycle_timer_node;
	cycle_timer_tree_t cycle_timer_tree;

	cycle_timer_t dispatch_req;
	interrupt_t interrupts[2];

	_Atomic int32_t lock;
	QUEUE pending_queue;
};

void kernel_do_dispatch(void *client_data);
void kernel_do_interrupt(void *client_data);
void kernel_execute(kernel_t *kernel);

void kernel_init(kernel_t *kernel, uint32_t cycle_timer_rate)
{
	int ret;
	pthread_mutexattr_t attr;

	cycle_timer_tree_init(&kernel->cycle_timer_tree);

	p_schedtsk = tasks_get_tcb(0);

	cycle_timer_init(&kernel->dispatch_req, kernel_do_dispatch, kernel);

	interrupt_t *interrupt = &kernel->interrupts[0];
	interrupt->kernel = kernel;
	interrupt->intno = 1;
	interrupt->cycle = 1;
	cycle_timer_init(&interrupt->timer, kernel_do_interrupt, interrupt);

	interrupt = &kernel->interrupts[1];
	interrupt->kernel = kernel;
	interrupt->intno = 2;
	interrupt->cycle = 1;
	cycle_timer_init(&interrupt->timer, kernel_do_interrupt, interrupt);

	//struct sigaction action;
	//memset(&action, 0, sizeof(action));
	//sigemptyset(&action.sa_mask);
	//action.sa_flags = SA_RESTART;
	//action.sa_handler = cpu_context_suspend_handler;
	//if (sigaction(SIGUSR1, &action, NULL) != 0)
	//	__builtin_trap();

	//sigset_t set;
	//sigemptyset(&set);
	//sigaddset(&set, SIGUSR1);
	//ret = pthread_sigmask(SIG_BLOCK, &set, NULL);

	ret = sem_init(&kernel->kernel_mode, 0, 1);
	if (ret != 0) {
		__builtin_trap();
	}

	ret = sem_init(&kernel->start_event, 0, 0);
	if (ret != 0) {
		__builtin_trap();
	}

	kernel->sched_context = NULL;
	kernel->run_context = NULL;

	ret = pthread_mutexattr_init(&attr);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutex_init(&kernel->timer_mutex, &attr);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutexattr_destroy(&attr);
	if (ret < 0) {
		__builtin_trap();
	}

	kernel->lock = 0;
	queue_initialize(&kernel->pending_queue);
	kernel->terminate = false;

	kernel->first_cycle_timer_timeout = ~0ULL;
	kernel->cycle_counter = 0;
	kernel->cycle_timer_rate = cycle_timer_rate;
	kernel->first_cycle_timer_node = NULL;

	kernel->context_count = tasks_get_count();
	kernel->contexts = (cpu_context_t **)calloc((size_t)kernel->context_count, sizeof(cpu_context_t *));
	if (kernel->contexts == NULL) {
		__builtin_trap();
	}

	kernel->thread_id = gettid();
	kernel_lock_cpu(kernel);
}
#if 0
void kernel_deinit(kernel_t *kernel)
{
	pthread_mutex_destroy(&kernel->timer_mutex);

	sem_destroy(&kernel->start_event);

	sem_destroy(&kernel->kernel_mode);

	free(kernel->contexts);
}
#else
void kernel_deinit(kernel_t *kernel)
{
	bool restart;
	int count = tasks_get_count();

	for (;;) {
		restart = true;
		int i;
		for (i = 0; i < count; i++) {
			cpu_context_t *context;
			context = kernel->contexts[i];
			if (context == NULL)
				continue;
			if ((context->ready & 0x100) != 0) {
				int sval = 0;
				int ret = sem_getvalue(&kernel->kernel_mode, &sval);
				if (ret != 0)
					__builtin_trap();
				if (sval == 0) {
					ret = sem_post(&kernel->kernel_mode);
					if (ret != 0)
						__builtin_trap();
				}
				while ((context->ready & 0x100) != 0)
					pthread_yield();
			}
			if ((context->ready == CPU_CONTEXT_SUSPEND) && !context->terminate)
				context->terminate = true;
			if (context->terminate) {
				cpu_context_resume(context);
				while (context->terminate)
					pthread_yield();
			}
			if (context->ready == CPU_CONTEXT_READY)
				continue;

			restart = false;
		}
		if (restart)
			break;
		pthread_yield();
	}
}
#endif
bool kernel_sense_context(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();
	if (context == NULL)
		return true;

	if (context->terminate) {
		cpu_context_exit(context);
	}

	return false;
}

bool kernel_sense_lock(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();

	if (context != NULL) {
		do {
			if (context->terminate) {
				cpu_context_exit(context);
			}
			pthread_yield();
		} while (kernel->mode != KERNEL_MODE_WAIT);
	}

	return kernel->lock != 0;
}

void *kernel_new_context(kernel_t *kernel, void *p_tcb)
{
	int i = tasks_get_index(p_tcb);
	cpu_context_t *context = kernel->contexts[i];

	if (context == NULL) {
		context = calloc(1, sizeof(cpu_context_t));
		if (context == NULL)
			return NULL;

		cpu_context_init(context, kernel);

		kernel->contexts[i] = context;
	}

	int ret = pthread_mutex_lock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	cycle_timer_init(&context->dispatch_req, cpu_context_do_dispatch, context);

	ret = pthread_mutex_unlock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	cpu_context_activate(context, p_tcb);
	return context;
}

void kernel_task_start(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();
	cpu_context_start(context);
}

bool kernel_event_add(kernel_t *kernel, cycle_timer_t *timer, uint64_t cycles, cycle_timer_proc_t *proc, void *client_data)
{
	int ret;

	if (!proc)
		return false;

	ret = pthread_mutex_lock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	timer->proc = proc;
	timer->isactive = true;
	timer->client_data = client_data;
	timer->timeout = kernel->cycle_counter + cycles;

	cycle_timer_tree_add_tree_node(&kernel->cycle_timer_tree, timer, timer->timeout);
	if (kernel->first_cycle_timer_node) {
		cycle_timer_t *first_timer = kernel->first_cycle_timer_node;
		if (timer->timeout < first_timer->timeout) {
			kernel->first_cycle_timer_node = timer;
			kernel->first_cycle_timer_timeout = timer->timeout;
		}
	}
	else {
		kernel->first_cycle_timer_node = timer;
		kernel->first_cycle_timer_timeout = timer->timeout;
	}

	ret = pthread_mutex_unlock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	return true;
}

void kernel_event_remove(kernel_t *kernel, cycle_timer_t *timer)
{
	int ret;

	ret = pthread_mutex_lock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	if (timer->parent != &kernel->cycle_timer_tree)
		goto end;

	if (timer == kernel->first_cycle_timer_node) {
		kernel->first_cycle_timer_node = cycle_timer_tree_next_tree_node(&kernel->cycle_timer_tree, timer);
		if (kernel->first_cycle_timer_node) {
			kernel->first_cycle_timer_timeout = kernel->first_cycle_timer_node->timeout;
		}
		else {
			kernel->first_cycle_timer_timeout = ~0ULL;
		}
	}
	cycle_timer_tree_delete_tree_node(&kernel->cycle_timer_tree, timer);
end:
	ret = pthread_mutex_unlock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();
}

void kernel_event_modify(kernel_t *kernel, cycle_timer_t *timer, uint64_t cycles)
{
	int ret;

	ret = pthread_mutex_lock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	if (timer->parent != NULL) {
		kernel_event_remove(kernel, timer);
	}
	kernel_event_add(kernel, timer, cycles, timer->proc, timer->client_data);

	ret = pthread_mutex_unlock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();
}

void kernel_dispatch(kernel_t *kernel)
{
	int ret;
	cpu_context_t *context = cpu_context_get_current();

	context->saved_lock = kernel->lock != 0 ? 1 : 0;
	context->ready = CPU_CONTEXT_DISPATCH;

	ret = sem_wait(&kernel->kernel_mode);
	if (ret != 0)
		__builtin_trap();

	kernel_event_modify(kernel, &context->dispatch_req, 1);

	ret = sem_post(&kernel->start_event);
	if (ret != 0)
		__builtin_trap();

	cpu_context_suspend(context);

	while (context->dispatch_req.isactive) {
		pthread_yield();
		if (context->terminate) {
			cpu_context_exit(context);
		}
	}
}

void kernel_dispatch_in_int(kernel_t *kernel)
{
	if (gettid() != kernel->thread_id)
		__builtin_trap();

	kernel_do_dispatch(kernel);
}

void kernel_do_dispatch(void *client_data)
{
	kernel_t *kernel = (kernel_t *)client_data;

	if (p_runtsk == p_schedtsk)
		return;

	//if (p_runtsk) {
	//	cpu_context_t *context = (cpu_context_t *)task_get_data(p_runtsk);
	//	cpu_context_suspend(context);
	//}

	if (p_schedtsk == NULL) {
		kernel_unlock_cpu(kernel);
		target_custom_idle();
		kernel_lock_cpu(kernel);
	}

	p_runtsk = p_schedtsk;

	if (p_runtsk) {
		cpu_context_t *context = (cpu_context_t *)task_get_data(p_runtsk);
		// cpu_context_resume(context);
		kernel->sched_context = context;
	}
	else {
		kernel->sched_context = NULL;
	}
}

void cpu_context_do_dispatch(void *client_data)
{
	cpu_context_t *context = (cpu_context_t *)client_data;
	kernel_t *kernel = context->kernel;

	kernel_do_dispatch(kernel);
}

void kernel_start_dispatch(kernel_t *kernel)
{
	int ret;

	//if (kernel->thread_id != 0)
	//	__builtin_trap();

	kernel->thread_id = gettid();

	for (;;) {
		ret = sem_trywait(&kernel->kernel_mode);
		if (ret != 0) {
			switch (errno) {
			case EAGAIN:
				sem_post(&kernel->kernel_mode);
				continue;
			case EINTR:
				break;
			default:
				__builtin_trap();
				break;
			}
		}
		break;
	}

	cpu_context_t *context = (cpu_context_t *)task_get_data(p_schedtsk);

	kernel_event_modify(kernel, &kernel->dispatch_req, 1);

	ret = sem_post(&kernel->start_event);
	if (ret != 0)
		__builtin_trap();

	kernel_execute(kernel);
}

void kernel_exit_and_dispatch(kernel_t *kernel)
{
	kernel_dispatch(kernel);

	cpu_context_t *context = cpu_context_get_current();
	cpu_context_exit(context);
}

void kernel_call_exit_kernel(kernel_t *kernel)
{
	kernel->terminate = true;
	int tmax_tskid = tasks_get_count();

	for (int i = 0; i < tmax_tskid; i++) {
		void *tcb = tasks_get_tcb(i);
		cpu_context_t *context = (cpu_context_t *)task_get_data(tcb);
		if (context == NULL)
			continue;

		task_clear_data(tcb);

		cpu_context_terminate(context);

		//cpu_context_deinit(context);
	}
}

void kernel_lock_cpu(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();

	if (context != NULL) {
		for (;;) {
			uint32_t lock = 0;
			if (__atomic_compare_exchange_4(&kernel->lock, &lock, context->thread_id, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
				break;
			}
			pthread_yield();
			if (context->terminate) {
				cpu_context_exit(context);
			}
		}

		if (context->terminate) {
			cpu_context_exit(context);
		}
	}
	else {
		for (;;) {
			uint32_t lock = 0;
			if (__atomic_compare_exchange_4(&kernel->lock, &lock, kernel->thread_id, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
				break;
			}

			cpu_context_t *run_context = kernel->run_context;
			if (run_context != NULL) {
				if ((run_context->ready & 0x100) != 0) {
					int ret = sem_post(&kernel->kernel_mode);
					if (!ret)
						__builtin_trap();
					while ((run_context->ready & 0x100) != 0)
						pthread_yield();
				}
				if ((run_context->ready & 0x200) != 0) {
					cpu_context_resume(run_context);

					while ((run_context->ready & 0x200) != 0)
						pthread_yield();
				}

				if (run_context->dispatch_req.isactive)
					run_context->dispatch_req.isactive = false;

				kernel->mode = KERNEL_MODE_TIMEOUT;
			}
			pthread_yield();
		}
	}
}

void kernel_unlock_cpu(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();

	uint32_t lock = __atomic_exchange_4(&kernel->lock, 0, __ATOMIC_RELAXED);
	if (lock == 0)
		__builtin_trap();

	if (context != NULL && context->terminate) {
		cpu_context_exit(context);
	}
}

static bool interrupt_stopped;
static int interrupt_count;
static int interrupt_count_max = WINT_MAX;

void stop_interrupt(void)
{
	interrupt_stopped = true;
}

void set_interrupt_count_max(int max)
{
	interrupt_count_max = max;
}

void kernel_interrupt(kernel_t *kernel, int intno, uint64_t cycle)
{
	if (interrupt_stopped)
		return;

	if (intno == 1) {
		interrupt_count++;
		if (interrupt_count > interrupt_count_max)
			return;
	}

	cpu_context_t *context = cpu_context_get_current();

	if (context != NULL) {
		context->saved_lock = kernel->lock != 0 ? 1 : 0;
		context->ready = CPU_CONTEXT_INTERRUPT;

		int ret = sem_wait(&kernel->kernel_mode);
		if (ret != 0)
			__builtin_trap();

		interrupt_t *interrupt = &kernel->interrupts[intno - 1];
		interrupt->cycle = cycle;
		if (cycle == 0)
			kernel_event_remove(kernel, &interrupt->timer);
		else
			kernel_event_modify(kernel, &interrupt->timer, cycle);

		ret = sem_post(&kernel->start_event);
		if (ret != 0)
			__builtin_trap();

		cpu_context_suspend(context);

		while (interrupt->timer.isactive) {
			pthread_yield();
			if (context->terminate) {
				cpu_context_exit(context);
			}
		}
	}
	else {
		interrupt_t *interrupt = &kernel->interrupts[intno - 1];
		interrupt->cycle = cycle;
		if (cycle == 0)
			kernel_event_remove(kernel, &interrupt->timer);
		else
			kernel_event_modify(kernel, &interrupt->timer, cycle);
	}
}

void kernel_do_interrupt(void *client_data)
{
	interrupt_t *interrupt = (interrupt_t *)client_data;
	kernel_t *kernel = interrupt->kernel;
	int intno = interrupt->intno;
	cpu_context_t *context = NULL;
	int32_t lock = 0;

	if (__atomic_compare_exchange_4(&kernel->lock, &lock, kernel->thread_id, false, __ATOMIC_RELAXED, __ATOMIC_RELAXED)) {
		kernel_unlock_cpu(kernel);

		if (intno == 1)
			target_hrt_handler();
		else if (intno == 2)
			soft_int_handler();

		p_runtsk = p_schedtsk;

		if (p_runtsk) {
			context = (cpu_context_t *)task_get_data(p_runtsk);
			kernel->sched_context = context;
		}
		else {
			kernel->sched_context = NULL;
		}
	}
	else {
		int ret = pthread_mutex_lock(&kernel->timer_mutex);
		if (ret != 0)
			__builtin_trap();

		if (interrupt->timer.pending_node.p_next != &interrupt->timer.pending_node) {
			queue_delete(&interrupt->timer.pending_node);
			queue_initialize(&interrupt->timer.pending_node);
		}

		queue_insert_prev(&kernel->pending_queue, &interrupt->timer.pending_node);

		ret = pthread_mutex_unlock(&kernel->timer_mutex);
		if (ret != 0)
			__builtin_trap();
	}
}

void kernel_restart(kernel_t *kernel)
{
	interrupt_count = 0;
	interrupt_stopped = false;
	kernel->terminate = false;

	int ret = pthread_mutex_lock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	queue_initialize(&kernel->pending_queue);

	for (int i = 0; i < kernel->context_count; i++) {
		cpu_context_t *context = kernel->contexts[i];
		if (context != NULL) {
			cycle_timer_init(&context->dispatch_req, cpu_context_do_dispatch, context);
		}
	}

	cycle_timer_tree_init(&kernel->cycle_timer_tree);
	cycle_timer_init(&kernel->dispatch_req, kernel_do_dispatch, kernel);
	interrupt_t *interrupt = &kernel->interrupts[0];
	cycle_timer_init(&interrupt->timer, kernel_do_interrupt, interrupt);
	interrupt = &kernel->interrupts[1];
	cycle_timer_init(&interrupt->timer, kernel_do_interrupt, interrupt);
	kernel->first_cycle_timer_timeout = ~0ULL;
	kernel->cycle_counter = 0;
	kernel->first_cycle_timer_node = NULL;

	ret = pthread_mutex_unlock(&kernel->timer_mutex);
	if (ret != 0)
		__builtin_trap();

	kernel->sched_context = NULL;
	kernel->run_context = NULL;

	kernel->lock = 0;
	kernel_lock_cpu(kernel);
}

int correct_errno(int err)
{
	if ((err == ETIMEDOUT) || (err == EAGAIN) || (err == EINTR/*???*/))
		return ETIMEDOUT;
	return err;
}

//#define SYNCRONIZE

void kernel_execute(kernel_t *kernel)
{
	int ret, ret2, ret3;
#ifdef SYNCRONIZE
	struct timespec btime, ntime, wtime;
	uint64_t dtime;

	clock_gettime(0, &ntime);
#else
	struct timespec wtime;
#endif
	while (!kernel->terminate) {
		kernel->mode = KERNEL_MODE_WAIT;
#ifdef SYNCRONIZE
		if (kernel->first_cycle_timer_timeout == ~0ULL) {
			wtime.tv_sec = ntime.tv_sec;
			wtime.tv_nsec = ntime.tv_nsec + 1000000; // 1ms
			if (wtime.tv_nsec >= 1000000000) {
				wtime.tv_nsec -= 1000000000;
				wtime.tv_sec++;
			}

			ret = sem_timedwait(&kernel->start_event, &wtime);
			if (ret != 0)
				ret = correct_errno(errno);
			if ((ret == ETIMEDOUT) && (p_runtsk == NULL) && (p_schedtsk == NULL) && (kernel->first_cycle_timer_timeout == ~0ULL))
				kernel->terminate = true;
		}
		else {
			if (kernel->first_cycle_timer_timeout >= kernel->cycle_counter)
				dtime = kernel->first_cycle_timer_timeout - kernel->cycle_counter;
			else
				dtime = kernel->cycle_counter - kernel->first_cycle_timer_timeout;
			wtime.tv_sec = ntime.tv_sec;
			wtime.tv_nsec = ntime.tv_nsec + dtime;
			if (wtime.tv_nsec >= 1000000000) {
				wtime.tv_nsec -= 1000000000;
				wtime.tv_sec++;
			}
			ret = sem_timedwait(&kernel->start_event, &wtime);
			if (ret != 0)
				ret = correct_errno(errno);
		}
#else
		if (kernel->lock == 0) {
			ret = sem_trywait(&kernel->start_event);
		}
		else {
			wtime.tv_sec = 0;
			wtime.tv_nsec = 100;
			ret = sem_timedwait(&kernel->start_event, &wtime);
		}
		if (ret != 0)
			ret = correct_errno(errno);
		if ((ret == ETIMEDOUT) && (p_runtsk == NULL) && (p_schedtsk == NULL) && (kernel->first_cycle_timer_timeout == ~0ULL))
			kernel->terminate = true;
#endif
		if ((ret != 0) && (ret != ETIMEDOUT))
			__builtin_trap();

		if (ret == ETIMEDOUT) {
			for (int i = 0; i < 1; i++) {
				ret2 = sem_trywait(&kernel->kernel_mode);
				if (ret2 == 0)
					break;
				ret2 = correct_errno(errno);
				if (ret2 != ETIMEDOUT)
					__builtin_trap();

				ret = sem_trywait(&kernel->start_event);
				if (ret == 0)
					break;
				ret = correct_errno(errno);
				if (ret != ETIMEDOUT)
					__builtin_trap();
			}
		}

		if (ret == 0) {
			kernel->mode = KERNEL_MODE_PASSIVE;
		}
		else if (ret2 == 0) {
			kernel->mode = KERNEL_MODE_AUTONOMOUS;
		}
		else {
			kernel->mode = KERNEL_MODE_TIMEOUT;
		}
#ifdef SYNCRONIZE
		btime = ntime;

		clock_gettime(0, &ntime);

		if (ntime.tv_nsec >= btime.tv_nsec) {
			dtime = ntime.tv_nsec - btime.tv_nsec;
			dtime += (ntime.tv_sec - btime.tv_sec) * 1000000000llu;
		}
		else {
			dtime = 1000000000llu - ntime.tv_nsec + btime.tv_nsec;
			dtime += (ntime.tv_sec - btime.tv_sec) * 1000000000llu;
		}
#endif
		ret3 = pthread_mutex_lock(&kernel->timer_mutex);
		if (ret3 != 0)
			__builtin_trap();

		cycle_timer_t *timer = NULL;
#ifdef SYNCRONIZE
		uint64_t next = kernel->cycle_counter + (kernel->cycle_timer_rate * dtime / 1000000000llu);
#else
		if (kernel->first_cycle_timer_timeout == ~0ULL) {
			while (!queue_empty(&kernel->pending_queue)) {
				cycle_timer_t *temp = cast_cycle_timer_t((queue_t *)queue_delete_next(&kernel->pending_queue));
				queue_initialize(&temp->pending_node);
				kernel_event_modify(kernel, temp, 1);
			}
		}
		uint64_t next = kernel->first_cycle_timer_timeout;
		if (next == ~0ULL)
			next = kernel->cycle_counter + 1;
#endif
		if (kernel->first_cycle_timer_timeout <= next) {
			kernel->cycle_counter = kernel->first_cycle_timer_timeout;

			timer = kernel->first_cycle_timer_node;
			if (timer) {
				kernel->first_cycle_timer_node = cycle_timer_tree_next_tree_node(&kernel->cycle_timer_tree, timer);
				if (kernel->first_cycle_timer_node) {
					kernel->first_cycle_timer_timeout = kernel->first_cycle_timer_node->timeout;
				}
				else {
					kernel->first_cycle_timer_timeout = ~0ULL;
				}
				cycle_timer_tree_delete_tree_node(&kernel->cycle_timer_tree, timer);
			}
		}
		else {
			kernel->cycle_counter = next;
		}

		ret3 = pthread_mutex_unlock(&kernel->timer_mutex);
		if (ret3 != 0)
			__builtin_trap();

		cpu_context_t *context = kernel->run_context;

		if (timer != NULL) {
			timer->proc(timer->client_data);
			timer->isactive = false;
		}

		cpu_context_t *sched_context = kernel->sched_context;

		if (context != NULL) {
			if ((sched_context != context) && ((context->ready & 0x300) == 0)) {
				if (context->ready != CPU_CONTEXT_READY) {
					cpu_context_suspend2(context);
				}
			}
		}

		if (sched_context != NULL) {
			if (((context == NULL) || ((context->ready & 0x200) != 0))
				&& ((sched_context->ready & 0x200) != 0)) {
				uint32_t lock = __atomic_load_4(&kernel->lock, __ATOMIC_RELAXED);
				if (lock == 0) {
					if (sched_context->saved_lock != 0) {
						kernel_lock_cpu(kernel);
					}
				}
				else {
					if (sched_context->saved_lock == 0) {
						kernel_unlock_cpu(kernel);
					}
				}

				cpu_context_resume(kernel->sched_context);

				kernel->run_context = sched_context;

				while ((sched_context->ready & 0x200) != 0)
					pthread_yield();
			}
		}

		if (kernel->mode != KERNEL_MODE_TIMEOUT) {
			ret3 = sem_post(&kernel->kernel_mode);
			if (ret3 != 0)
				__builtin_trap();
		}
	}
}

int kernel_create(kernel_t **kernel)
{
	if (*kernel == NULL) {
		*kernel = calloc(1, sizeof(kernel_t));
		if (*kernel == NULL)
			return -1;
		kernel_init(*kernel, 120000000);
	}
	else {
		kernel_restart(*kernel);
	}
	return 0;
}

void kernel_delete(kernel_t *kernel)
{
	kernel_deinit(kernel);
	//free(kernel);
}

uint64_t get_cycle_counte(kernel_t *kernel)
{
	return kernel->cycle_counter;
}

int64_t CyclesToMilliseconds(kernel_t *kernel, int64_t cycles)
{
	return (cycles) / (kernel->cycle_timer_rate / 1000);
}

int64_t CyclesToMicroseconds(kernel_t *kernel, int64_t cycles)
{
	return (1000 * cycles) / (kernel->cycle_timer_rate / 1000);
}

int64_t CyclesToNanoseconds(kernel_t *kernel, int64_t cycles)
{
	if ((uint64_t)llabs(cycles) < (100 * kernel->cycle_timer_rate)) {
		return (10000 * cycles) / (kernel->cycle_timer_rate / 100000);
	}
	else {
		return (cycles / kernel->cycle_timer_rate) * 1000000000;
	}
}

int64_t MillisecondsToCycles(kernel_t *kernel, int64_t msec)
{
	return (msec * (int64_t)kernel->cycle_timer_rate) / 1000;
}

int64_t MicrosecondsToCycles(kernel_t *kernel, int64_t usec)
{
	return (usec * (int64_t)kernel->cycle_timer_rate) / 1000000;
}

int64_t NanosecondsToCycles(kernel_t *kernel, int64_t nsec)
{
	return (nsec * (int64_t)(kernel->cycle_timer_rate / 1000)) / 1000000;
}
