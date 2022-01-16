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

#define p_runtsk _kernel_p_runtsk
#define p_schedtsk _kernel_p_schedtsk

extern void *p_runtsk;
extern void *p_schedtsk;
void target_hrt_handler(void);
void target_custom_idle(void);

void cycle_timer_tree_add_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *x, uint64_t timeout)
{
	if (x->parent != NULL)
		__builtin_trap();

	x->timeout = timeout;
	x->parent = tree;
	x->node.right = &x->node;
	x->node.left = &x->node;

	cycle_timer_t *node = (cycle_timer_t *)tree->root.right;
	cycle_timer_t *pos = (cycle_timer_t *)tree->root.left;
	while (&node->node != &tree->root) {
		if (node->timeout < x->timeout) {
			pos = (cycle_timer_t *)node->node.left;
			break;
		}
		node = (cycle_timer_t *)node->node.right;
	}

	x->node.left = &pos->node;
	x->node.right = pos->node.right;
	pos->node.right->left = &x->node;
	pos->node.right = &x->node;
}

bool cycle_timer_tree_is_empty(cycle_timer_tree_t *tree)
{
	if (tree->root.left == tree->root.right) {
		return true;
	}
	return false;
}

cycle_timer_t *cycle_timer_tree_next_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *x)
{
	if (x->parent != tree) __builtin_trap();

	if (&tree->root == x->node.right)
		return 0;

	return (cycle_timer_t *)x->node.right;
}

void cycle_timer_tree_delete_tree_node(cycle_timer_tree_t *tree, cycle_timer_t *z)
{
	if (z->parent != tree) __builtin_trap();

	z->node.right->left = z->node.left;
	z->node.left->right = z->node.right;
	z->parent = 0;
	z->node.right = 0;
	z->node.left = 0;

	z->timeout = 0;
}

#define CPU_CONTEXT_INIT 0
#define CPU_CONTEXT_READY 1
#define CPU_CONTEXT_RUNNING 2
#define CPU_CONTEXT_SUSPEND 3
#define CPU_CONTEXT_DISPATCH 4
#define CPU_CONTEXT_LOCK 5

typedef struct _cpu_context_t
{
	kernel_t *kernel;
	pthread_t thread;
	pid_t thread_id;
	sem_t start_event;
	void *task;
	_Atomic bool terminate;
	_Atomic uint32_t ready;
	jmp_buf RESTART;
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

static cpu_context_t *cpu_context_get_current()
{
	return (cpu_context_t *)pthread_getspecific(g_tls_index);
}

void cpu_context_init(cpu_context_t *context, kernel_t *Kernel)
{
	context->kernel = Kernel;
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

	for (;;) {
		setjmp(context->RESTART);

		if (!context->terminate) {
			task_start(context->task);
		}
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
		if (context->ready == CPU_CONTEXT_RUNNING)
			cpu_context_suspend(context);
	}
}

void cpu_context_suspend2(cpu_context_t *context)
{
	int ret;
	ret = pthread_kill(context->thread, SIGUSR1);
	if (ret != 0)
		__builtin_trap();
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

struct _kernel_t {
	pid_t thread_id;
	sem_t kernel_mode;
	sem_t start_event;
	cpu_context_t *run_context;
	pthread_mutex_t timet_mutex;
	sem_t cpu_lock_mode;
	cpu_context_t *cpu_locker;
	bool was_locked_cpu;
	bool terminate;
	cpu_context_t **contexts;

	uint64_t first_cycle_timer_timeout;
	uint64_t cycle_counter;
	uint32_t cycle_timer_rate;
	cycle_timer_t *first_cycle_timer_node;
	cycle_timer_tree_t cycle_timer_tree;

	cycle_timer_t dispatch_req;
	cycle_timer_t interrupt_req;

	_Atomic int32_t lock;
};

void kernel_do_dispatch(void *client_data);
void kernel_do_interrupt(void *client_data);

void kernel_init(kernel_t *kernel, uint32_t cycle_timer_rate)
{
	int ret;
	pthread_mutexattr_t attr;

	cycle_timer_tree_init(&kernel->cycle_timer_tree);

	p_schedtsk = tasks_get_tcb(0);

	cycle_timer_init(&kernel->dispatch_req, kernel_do_dispatch, kernel);
	cycle_timer_init(&kernel->interrupt_req, kernel_do_interrupt, kernel);

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

	kernel->run_context = NULL;

	ret = sem_init(&kernel->cpu_lock_mode, 0, 1);
	if (ret != 0) {
		__builtin_trap();
	}

	ret = pthread_mutexattr_init(&attr);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutex_init(&kernel->timet_mutex, &attr);
	if (ret < 0) {
		__builtin_trap();
	}

	ret = pthread_mutexattr_destroy(&attr);
	if (ret < 0) {
		__builtin_trap();
	}

	kernel->cpu_locker = NULL;
	kernel->was_locked_cpu = false;
	kernel->terminate = false;

	kernel->first_cycle_timer_timeout = ~0ULL;
	kernel->cycle_counter = 0;
	kernel->cycle_timer_rate = cycle_timer_rate;
	kernel->first_cycle_timer_node = NULL;

	kernel->contexts = (cpu_context_t **)calloc((size_t)tasks_get_count(), sizeof(cpu_context_t *));
	if (kernel->contexts == NULL) {
		__builtin_trap();
	}

	kernel->lock = 0;
	kernel_lock_cpu(kernel);
}
#if 0
void kernel_deinit(kernel_t *kernel)
{
	sem_destroy(&kernel->cpu_lock_mode);

	pthread_mutex_destroy(&kernel->timet_mutex);

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
			if (context->ready == CPU_CONTEXT_DISPATCH) {
				int sval = 0;
				int ret = sem_getvalue(&kernel->kernel_mode, &sval);
				if (ret != 0)
					__builtin_trap();
				if (sval == 0) {
					ret = sem_post(&kernel->kernel_mode);
					if (ret != 0)
						__builtin_trap();
				}
				while (context->ready == CPU_CONTEXT_DISPATCH)
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

void kernel_lock_cpu(kernel_t *kernel)
{
	kernel->lock++;
	if (kernel->lock < 0)
		__builtin_trap();

	if (kernel->lock == 1) {
		cpu_context_t *context = cpu_context_get_current();
		if (context != NULL)
			context->ready = CPU_CONTEXT_LOCK;

		int ret = sem_wait(&kernel->cpu_lock_mode);
		if (ret != 0)
			__builtin_trap();

		kernel->cpu_locker = context;
		kernel->was_locked_cpu = true;
	}
}

void kernel_unlock_cpu(kernel_t *kernel)
{
	kernel->lock--;
	if (kernel->lock < 0)
		__builtin_trap();

	if (kernel->lock == 0) {
		cpu_context_t *context = cpu_context_get_current();
		if (context != NULL)
			context->ready = CPU_CONTEXT_RUNNING;

		kernel->was_locked_cpu = false;

		int ret = sem_post(&kernel->cpu_lock_mode);
		if (ret != 0)
			__builtin_trap();
	}
}

bool kernel_sense_lock(kernel_t *kernel)
{
	return kernel->lock > 0;
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

	ret = pthread_mutex_lock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();

	timer->proc = proc;
	timer->isactive = 1;
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

	ret = pthread_mutex_unlock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();

	return true;
}

void kernel_event_remove(kernel_t *kernel, cycle_timer_t *timer)
{
	int ret;

	if (!timer->isactive)
		return;

	ret = pthread_mutex_lock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();

	if (timer == kernel->first_cycle_timer_node) {
		kernel->first_cycle_timer_node = cycle_timer_tree_next_tree_node(&kernel->cycle_timer_tree, timer);
		if (kernel->first_cycle_timer_node) {
			kernel->first_cycle_timer_timeout = kernel->first_cycle_timer_node->timeout;
		}
		else {
			kernel->first_cycle_timer_timeout = ~(uint64_t)0;
		}
	}
	cycle_timer_tree_delete_tree_node(&kernel->cycle_timer_tree, timer);
	timer->isactive = 0;

	ret = pthread_mutex_unlock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();
}

void kernel_event_modify(kernel_t *kernel, cycle_timer_t *timer, uint64_t cycles)
{
	int ret;

	ret = pthread_mutex_lock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();

	if (timer->isactive) {
		kernel_event_remove(kernel, timer);
	}
	kernel_event_add(kernel, timer, cycles, timer->proc, timer->client_data);

	ret = pthread_mutex_unlock(&kernel->timet_mutex);
	if (ret != 0)
		__builtin_trap();
}

void kernel_dispatch(kernel_t *kernel)
{
	int ret;
	cpu_context_t *context = cpu_context_get_current();

	if (context->thread_id == kernel->thread_id)
		__builtin_trap();

	context->ready = CPU_CONTEXT_DISPATCH;

	ret = sem_wait(&kernel->kernel_mode);
	if (ret != 0)
		__builtin_trap();

	kernel_event_modify(kernel, &kernel->dispatch_req, 1);

	ret = sem_post(&kernel->start_event);
	if (ret != 0)
		__builtin_trap();

	cpu_context_suspend(context);
}

void kernel_dispatch_in_int(kernel_t *kernel)
{
	if (gettid() != kernel->thread_id)
		__builtin_trap();

	kernel_event_modify(kernel, &kernel->dispatch_req, 1);
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
		//cpu_context_resume(context);
		kernel->run_context = context;
	}
	else {
		kernel->run_context = NULL;
	}
}

void kernel_do_interrupt(void *client_data)
{
	kernel_t *kernel = (kernel_t *)client_data;

	bool was_locked_cpu = kernel->was_locked_cpu;
	if (!was_locked_cpu || kernel->cpu_locker == NULL) {
		if (was_locked_cpu)
			kernel_unlock_cpu(kernel);
		target_hrt_handler();
		if (was_locked_cpu)
			kernel_lock_cpu(kernel);
	}
	else {
		kernel_event_modify(kernel, &kernel->interrupt_req, 1);
	}
}

void kernel_execute(kernel_t *kernel);

void kernel_start_dispatch(kernel_t *kernel)
{
	int ret;

	//if (kernel->thread_id != 0)
	//	__builtin_trap();

	kernel->thread_id = gettid();

	ret = sem_wait(&kernel->kernel_mode);
	if (ret != 0)
		__builtin_trap();

	kernel_event_modify(kernel, &kernel->dispatch_req, 1);

	ret = sem_post(&kernel->start_event);
	if (ret != 0)
		__builtin_trap();

	kernel_execute(kernel);
}

void kernel_exit_and_dispatch(kernel_t *kernel)
{
	kernel_dispatch(kernel);

	cpu_context_t *context = (cpu_context_t *)task_get_data(p_runtsk);
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

void kernel_interrupt(kernel_t *kernel)
{
	if (interrupt_stopped)
		return;

	interrupt_count++;
	if (interrupt_count > interrupt_count_max)
		return;

	kernel_event_modify(kernel, &kernel->interrupt_req, 1);
}

void kernel_restart(kernel_t *kernel)
{
	interrupt_count = 0;
	interrupt_stopped = false;
	kernel->terminate = false;

	kernel->first_cycle_timer_timeout = ~0ULL;
	kernel->cycle_counter = 0;
	kernel->first_cycle_timer_node = NULL;

	if (!kernel->was_locked_cpu) {
		kernel->lock = 0;
		kernel_lock_cpu(kernel);
	}
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
#endif
	while (!kernel->terminate) {
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
		ret = sem_trywait(&kernel->start_event);
		if (ret != 0)
			ret = correct_errno(errno);
		if ((ret == ETIMEDOUT) && (p_runtsk == NULL) && (p_schedtsk == NULL) && (kernel->first_cycle_timer_timeout == ~0ULL))
			kernel->terminate = true;
#endif
		if ((ret != 0) && (ret != ETIMEDOUT))
			__builtin_trap();

		if (ret == ETIMEDOUT) {
			for (;;) {
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

				pthread_yield();
			}
		}
		else {
			ret2 = ETIMEDOUT;
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
		ret3 = pthread_mutex_lock(&kernel->timet_mutex);
		if (ret3 != 0)
			__builtin_trap();

		cycle_timer_proc_t *proc = NULL;
		void *client_data = NULL;
#ifdef SYNCRONIZE
		uint64_t next = kernel->cycle_counter + (kernel->cycle_timer_rate * dtime / 1000000000llu);
#else
		uint64_t next = kernel->first_cycle_timer_timeout;
		if (next == ~0ULL)
			next = kernel->cycle_counter + 1;
#endif
		if (kernel->first_cycle_timer_timeout <= next) {
			kernel->cycle_counter = kernel->first_cycle_timer_timeout;

			cycle_timer_t *timer = kernel->first_cycle_timer_node;
			if (timer) {
				kernel->first_cycle_timer_node = cycle_timer_tree_next_tree_node(&kernel->cycle_timer_tree, kernel->first_cycle_timer_node);
				if (kernel->first_cycle_timer_node) {
					kernel->first_cycle_timer_timeout = kernel->first_cycle_timer_node->timeout;
				}
				else {
					kernel->first_cycle_timer_timeout = ~0ULL;
				}
				cycle_timer_tree_delete_tree_node(&kernel->cycle_timer_tree, timer);
				proc = timer->proc;
				client_data = timer->client_data;
				timer->isactive = 0;
			}
		}
		else {
			kernel->cycle_counter = next;
		}

		ret3 = pthread_mutex_unlock(&kernel->timet_mutex);
		if (ret3 != 0)
			__builtin_trap();

		cpu_context_t *context;
		if (p_runtsk != NULL)
			context = (cpu_context_t *)task_get_data(p_runtsk);
		else
			context = NULL;

		if (proc != NULL)
			proc(client_data);

		if ((ret == 0) || (ret2 == 0)) {
			ret3 = sem_post(&kernel->kernel_mode);
			if (ret3 != 0)
				__builtin_trap();
		}

		if (kernel->run_context != NULL) {
			if (kernel->was_locked_cpu && (kernel->cpu_locker == NULL)) {
				if (kernel->run_context != context) {
					if (context != NULL) {
						cpu_context_suspend2(context);
					}
					ret = 0;
				}
				else if (context->ready == CPU_CONTEXT_RUNNING) {
					ret = ETIMEDOUT;
				}
			}

			if (ret == 0) {
				cpu_context_resume(kernel->run_context);
			}
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
