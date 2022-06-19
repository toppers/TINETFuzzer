#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <malloc.h>
#include <time.h>
#include <errno.h>
#include <assert.h>
#include <setjmp.h>
#include <windows.h>
#include "dispatcher.h"
#include <queue.h>

//#define DEBUG_LOG
#ifdef DEBUG_LOG
#define LOG_APPEND(kernel, context, state) logger_t *logger; (void)logger; do { logger = logger_create(kernel, context, state); } while (false)
#define LOG_APPEND2(kernel, context, state) do { logger = logger_create(kernel, context, state); } while (false)
#define LOG_UPDATE_LOCK logger->lock = kernel->lock
#define LOG_UPDATE_COUNT(count) logger->count = count
#define LOG_INCREMENT_COUNT logger->count++
#define LOG_LOGING context->logging
#else
#define LOG_APPEND(kernel, context, state) do { } while (false)
#define LOG_APPEND2(kernel, context, state) do { } while (false)
#define LOG_UPDATE_LOCK do { } while (false)
#define LOG_UPDATE_COUNT(count) do { } while (false)
#define LOG_INCREMENT_COUNT do { } while (false)
#define LOG_LOGING false
#endif

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
	HANDLE thread;
	DWORD thread_id;
	void *task;
	bool terminate;
	cpu_context_state_t ready;
	jmp_buf RESTART;
	cycle_timer_t dispatch_req;
	LONG saved_lock;
#ifdef DEBUG_LOG
	bool logging;
	bool suspend_req;
#endif
} cpu_context_t;

DWORD g_tls_index = 0xFFFFFFFF;

void cpu_context_suspend(cpu_context_t *context);
void cpu_context_resume(cpu_context_t *context);
ULONG CALLBACK cpu_context_thread_proc(PVOID param);
void cpu_context_do_dispatch(void *client_data);

static cpu_context_t *cpu_context_get_current()
{
	return (cpu_context_t *)TlsGetValue(g_tls_index);
}

void cpu_context_init(cpu_context_t *context, kernel_t *kernel)
{
	context->kernel = kernel;
	context->thread = NULL;
	context->thread_id = 0;
	context->task = NULL;
	context->terminate = false;
	context->ready = CPU_CONTEXT_INIT;

	if (g_tls_index == 0xFFFFFFFF) {
		g_tls_index = TlsAlloc();
	}
}

void cpu_context_deinit(cpu_context_t *context)
{
	if (context->thread_id != 0) {
		//TerminateThread(context->thread, 0);
		CloseHandle(context->thread);
		context->thread = NULL;
		context->thread_id = 0;
	}
	free(context);
}

void cpu_context_activate(cpu_context_t *context, void *task)
{
	context->task = task;

	if (context->thread_id != 0) {
		if (context->ready != CPU_CONTEXT_READY)
			__builtin_trap();
		return;
	}
	else {
		context->thread = CreateThread(NULL, 0, cpu_context_thread_proc, (void *)context, 0, &context->thread_id);
		if (context->thread == NULL)
			__builtin_trap();
	}

	while (context->ready != CPU_CONTEXT_READY) {
		SwitchToThread();
	}
	SwitchToThread();
}

void cpu_context_start(cpu_context_t *context)
{
	DWORD ret;

	context->terminate = false;
	context->saved_lock = 1;
	context->ready = CPU_CONTEXT_READY;

	ret = SuspendThread(context->thread);
	if (ret < 0)
		__builtin_trap();

	context->ready = CPU_CONTEXT_RUNNING;

	kernel_unlock_cpu(context->kernel);

	task_invoke(context->task);
}

void cpu_context_exit(cpu_context_t *context)
{
	//ExitThread(0);
	context->terminate = false;
	longjmp(context->RESTART, 1);
}

void cpu_context_terminate(cpu_context_t *context)
{
	//TerminateThread(context->thread, 0);
	if (context->ready == CPU_CONTEXT_READY)
		return;
	context->terminate = true;
	while (context->ready == CPU_CONTEXT_RUNNING)
		SwitchToThread();
}

ULONG CALLBACK cpu_context_thread_proc(PVOID param)
{
	cpu_context_t *context = (cpu_context_t *)param;

	TlsSetValue(g_tls_index, context);

	setjmp(context->RESTART);

	for (;;) {
		task_start(context->task);
	}

	return 0;
}

void cpu_context_suspend(cpu_context_t *context)
{
	DWORD ret;

	context->ready = CPU_CONTEXT_SUSPEND;

	ret = SuspendThread(context->thread);
	if (ret < 0)
		__builtin_trap();

	context->ready = CPU_CONTEXT_RUNNING;

	if (context->terminate) {
		cpu_context_exit(context);
	}
}

void cpu_context_resume(cpu_context_t *context)
{
	DWORD ret;

	for (;;) {
		ret = ResumeThread(context->thread);
		if (ret != 0)
			break;
		SwitchToThread();
	}
	if (ret != 1)
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
	DWORD thread_id;
	HANDLE kernel_mode;
	HANDLE start_event;
	kernel_mode_t mode;
	cpu_context_t *run_context;
	cpu_context_t *sched_context;
	HANDLE timer_mutex;
	bool terminate;
	cpu_context_t **contexts;
	int context_count;

	uint64_t first_cycle_timer_timeout;
	uint64_t cycle_counter;
	uint32_t cycle_timer_rate;
	cycle_timer_t *first_cycle_timer_node;
	cycle_timer_tree_t cycle_timer_tree;

	cycle_timer_t dispatch_req;
	interrupt_t interrupts[2];

	LONG lock;
	QUEUE pending_queue;
#ifdef DEBUG_LOG
	QUEUE lock_queue;
	QUEUE free_queue;
#endif
};
#ifdef DEBUG_LOG
typedef enum logger_state_t
{
	LOGGER_STATE_NONE,
	LOGGER_STATE_START,
	LOGGER_STATE_DISPATCH,
	LOGGER_STATE_DO_DISPATCH,
	LOGGER_STATE_INTERRUPT,
	LOGGER_STATE_DO_INTERRUPT,
	LOGGER_STATE_DO_INTERRUPT_END,
	LOGGER_STATE_PEND_INTERRUPT,
	LOGGER_STATE_LOCK_CPU,
	LOGGER_STATE_UNLOCK_CPU,
	LOGGER_STATE_SUSPEND2,
	LOGGER_STATE_RESUME,
	LOGGER_STATE_SENSE_LOCK,
	LOGGER_STATE_PASS_RESUME
} logger_state_t;

typedef struct logger_t {
	QUEUE queue;
	logger_state_t state;
	DWORD thread_id;
	kernel_mode_t mode;
	LONG lock;
	DWORD run_context;
	cpu_context_state_t run_context_ready;
	DWORD sched_context;
	cpu_context_state_t sched_context_ready;
	bool isactive;
	DWORD current_context;
	cpu_context_state_t current_context_ready;
	int count;
} logger_t;

logger_t *logger_create(kernel_t *kernel, cpu_context_t *context, logger_state_t state)
{
	if (context != NULL)
		context->logging = true;

	DWORD ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	logger_t *logger;
	if (queue_empty(&kernel->free_queue)) {
		logger = malloc(sizeof(logger_t));
		if (logger == NULL)
			__builtin_trap();
	}
	else {
		logger = (logger_t *)queue_delete_next(&kernel->free_queue);
	}

	queue_initialize(&logger->queue);
	logger->state = state;
	logger->thread_id = GetCurrentThreadId();
	logger->mode = kernel->mode;
	logger->lock = kernel->lock;
	logger->run_context = kernel->run_context == NULL ? 0 : kernel->run_context->thread_id;
	logger->run_context_ready = kernel->run_context == NULL ? 0 : kernel->run_context->ready;
	logger->sched_context = kernel->sched_context == NULL ? 0 : kernel->sched_context->thread_id;
	logger->sched_context_ready = kernel->sched_context == NULL ? 0 : kernel->sched_context->ready;
	logger->isactive = kernel->first_cycle_timer_timeout != ~0ULL;
	logger->current_context = context == NULL ? 0 : context->thread_id;
	logger->current_context_ready = context == NULL ? 0 : context->ready;
	logger->count = 0;

	queue_insert_next(&kernel->lock_queue, &logger->queue);

	BOOL ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();

	if (kernel->thread_id != GetCurrentThreadId()) {
		context->logging = false;

		while (context->suspend_req)
			SwitchToThread();
	}

	return logger;
}

const char *get_bool_string(bool value)
{
	return value ? "true" : "false";
}

const char *get_cpu_context_state_string(cpu_context_state_t state)
{
	switch (state) {
	case CPU_CONTEXT_INIT: return "CPU_CONTEXT_INIT";
	case CPU_CONTEXT_READY: return "CPU_CONTEXT_READY";
	case CPU_CONTEXT_RUNNING: return "CPU_CONTEXT_RUNNING";
	case CPU_CONTEXT_SUSPEND: return "CPU_CONTEXT_SUSPEND";
	case CPU_CONTEXT_DISPATCH: return "CPU_CONTEXT_DISPATCH";
	case CPU_CONTEXT_SUSPEND2: return "CPU_CONTEXT_SUSPEND2";
	case CPU_CONTEXT_INTERRUPT: return "CPU_CONTEXT_INTERRUPT";
	default: return "";
	}
}

const char *get_kernel_mode_string(kernel_mode_t mode)
{
	switch (mode) {
	case KERNEL_MODE_WAIT: return "KERNEL_MODE_WAIT";
	case KERNEL_MODE_TIMEOUT: return "KERNEL_MODE_TIMEOUT";
	case KERNEL_MODE_PASSIVE: return "KERNEL_MODE_PASSIVE";
	case KERNEL_MODE_AUTONOMOUS: return "KERNEL_MODE_AUTONOMOUS";
	default: return "";
	}
}

const char *get_logger_state_string(logger_state_t state)
{
	switch (state) {
	case LOGGER_STATE_NONE: return "LOGGER_STATE_NONE";
	case LOGGER_STATE_START: return "LOGGER_STATE_START";
	case LOGGER_STATE_DISPATCH: return "LOGGER_STATE_DISPATCH";
	case LOGGER_STATE_DO_DISPATCH: return "LOGGER_STATE_DO_DISPATCH";
	case LOGGER_STATE_INTERRUPT: return "LOGGER_STATE_INTERRUPT";
	case LOGGER_STATE_DO_INTERRUPT: return "LOGGER_STATE_DO_INTERRUPT";
	case LOGGER_STATE_DO_INTERRUPT_END: return "LOGGER_STATE_DO_INTERRUPT_END";
	case LOGGER_STATE_PEND_INTERRUPT:  return "LOGGER_STATE_PEND_INTERRUPT";
	case LOGGER_STATE_LOCK_CPU: return "LOGGER_STATE_LOCK_CPU";
	case LOGGER_STATE_UNLOCK_CPU: return "LOGGER_STATE_UNLOCK_CPU";
	case LOGGER_STATE_SUSPEND2: return "LOGGER_STATE_SUSPEND2";
	case LOGGER_STATE_RESUME: return "LOGGER_STATE_RESUME";
	case LOGGER_STATE_SENSE_LOCK: return "LOGGER_STATE_SENSE_LOCK";
	case LOGGER_STATE_PASS_RESUME: return "LOGGER_STATE_PASS_RESUME";
	default: return "";
	}
}

void logger_dump(kernel_t *kernel)
{
	QUEUE *lock_queue = &kernel->lock_queue;
	FILE *file;

	fopen_s(&file, "logger_dump", "w");

	fprintf(file, "state\tthread_id\tmode\tlock\trun_context\trun_context_ready\tsched_context\tsched_context_ready\tisactive\tcurrent_context\tcurrent_context_ready\tcount\n");

	DWORD ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	for (logger_t *logger = (logger_t *)lock_queue->p_prev;
		logger != (logger_t *)lock_queue;
		logger = (logger_t *)logger->queue.p_prev) {
		fprintf(file, "%s\t%lu\t%s\t%ld\t%lu\t%s\t%lu\t%s\t%s\t%lu\t%s\t%d\n",
			get_logger_state_string(logger->state),
			logger->thread_id,
			get_kernel_mode_string(logger->mode),
			logger->lock,
			logger->run_context,
			get_cpu_context_state_string(logger->run_context_ready),
			logger->sched_context,
			get_cpu_context_state_string(logger->sched_context_ready),
			get_bool_string(logger->isactive),
			logger->current_context,
			get_cpu_context_state_string(logger->current_context_ready),
			logger->count);
	}

	BOOL ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();

	fclose(file);
}
#endif
void kernel_do_dispatch(void *client_data);
void kernel_do_interrupt(void *client_data);
void kernel_execute(kernel_t *kernel);

void kernel_init(kernel_t *kernel, uint32_t cycle_timer_rate)
{
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

	kernel->kernel_mode = CreateSemaphore(NULL, 1, 1, NULL);
	if (kernel->kernel_mode == NULL) {
		__builtin_trap();
	}

	kernel->start_event = CreateEvent(NULL, FALSE, FALSE, NULL);
	if (kernel->start_event == NULL) {
		__builtin_trap();
	}

	kernel->sched_context = NULL;
	kernel->run_context = NULL;

	kernel->timer_mutex = CreateMutex(NULL, FALSE, NULL);
	if (kernel->timer_mutex == NULL) {
		__builtin_trap();
	}

	kernel->lock = 0;
	queue_initialize(&kernel->pending_queue);
#ifdef DEBUG_LOG
	queue_initialize(&kernel->lock_queue);
	queue_initialize(&kernel->free_queue);
#endif
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

	kernel->thread_id = GetCurrentThreadId();
	kernel_lock_cpu(kernel);
}
#if 0
void kernel_deinit(kernel_t *kernel)
{
	CloseHandle(kernel->timer_mutex);

	CloseHandle(kernel->start_event);

	CloseHandle(kernel->kernel_mode);

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
				BOOL ret = ReleaseSemaphore(kernel->kernel_mode, 1, NULL);
				if (!ret)
					__builtin_trap();
				while ((context->ready & 0x100) != 0)
					SwitchToThread();
			}
			if (context->ready == CPU_CONTEXT_SUSPEND2) {
				kernel->contexts[i] = NULL;
				TerminateThread(context->thread, 0);
				free(context);
			}
			else {
				if ((context->ready == CPU_CONTEXT_SUSPEND) && !context->terminate)
					context->terminate = true;
				if (context->terminate) {
					cpu_context_resume(context);
					while (context->terminate)
						SwitchToThread();
				}
				if (context->ready == CPU_CONTEXT_READY)
					continue;
			}

			restart = false;
		}
		if (restart)
			break;
		SwitchToThread();
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

	LOG_APPEND(kernel, context, LOGGER_STATE_SENSE_LOCK);

	if (context != NULL) {
		do {
			if (context->terminate) {
				cpu_context_exit(context);
			}
			LOG_INCREMENT_COUNT;
			SwitchToThread();
		} while (kernel->mode != KERNEL_MODE_WAIT);
	}

	return kernel->lock != 0;
}

void kernel_lock_cpu(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();

	LOG_APPEND(kernel, context, LOGGER_STATE_LOCK_CPU);

	if (context != NULL) {
		for (;;) {
			InterlockedCompareExchange(&kernel->lock, context->thread_id, 0);
			if (kernel->lock == context->thread_id) {
				break;
			}
			SwitchToThread();
			LOG_INCREMENT_COUNT;
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
			InterlockedCompareExchange(&kernel->lock, kernel->thread_id, 0);
			if (kernel->lock == kernel->thread_id) {
				break;
			}

			cpu_context_t *run_context = kernel->run_context;
			if (run_context != NULL) {
				if ((run_context->ready & 0x100) != 0) {
					BOOL ret = ReleaseSemaphore(kernel->kernel_mode, 1, NULL);
					if (!ret)
						__builtin_trap();
					while ((run_context->ready & 0x100) != 0)
						SwitchToThread();
				}
				if ((run_context->ready & 0x200) != 0) {
					DWORD ret;
					do {
						ret = ResumeThread(run_context->thread);
						if (ret < 0)
							__builtin_trap();
					} while (ret != 1);

					if (run_context->ready == CPU_CONTEXT_SUSPEND2) {
						run_context->ready = CPU_CONTEXT_RUNNING;
					}

					while ((run_context->ready & 0x200) != 0)
						SwitchToThread();
				}

				if (run_context->dispatch_req.isactive)
					run_context->dispatch_req.isactive = false;

				kernel->mode = KERNEL_MODE_TIMEOUT;
			}
			SwitchToThread();
			LOG_INCREMENT_COUNT;
		}
	}
}

void kernel_unlock_cpu(kernel_t *kernel)
{
	cpu_context_t *context = cpu_context_get_current();

	LOG_APPEND(kernel, context, LOGGER_STATE_UNLOCK_CPU);

	LONG lock = InterlockedExchange(&kernel->lock, 0);
	if (lock == 0)
		__builtin_trap();

	if (context != NULL && context->terminate) {
		cpu_context_exit(context);
	}
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

	DWORD ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	cycle_timer_init(&context->dispatch_req, cpu_context_do_dispatch, context);

	BOOL ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();

	LOG_APPEND(kernel, context, LOGGER_STATE_START);

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
	DWORD ret;
	BOOL ret2;

	if (!proc)
		return false;

	ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
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

	ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();

	return true;
}

void kernel_event_remove(kernel_t *kernel, cycle_timer_t *timer)
{
	DWORD ret;
	BOOL ret2;

	ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
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
	ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();
}

void kernel_event_modify(kernel_t *kernel, cycle_timer_t *timer, uint64_t cycles)
{
	DWORD ret;
	BOOL ret2;

	ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	if (timer->parent != NULL) {
		kernel_event_remove(kernel, timer);
	}
	kernel_event_add(kernel, timer, cycles, timer->proc, timer->client_data);

	ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();
}

void kernel_dispatch(kernel_t *kernel)
{
	DWORD ret;
	BOOL ret2;
	cpu_context_t *context = cpu_context_get_current();

	context->saved_lock = kernel->lock != 0 ? 1 : 0;
	context->ready = CPU_CONTEXT_DISPATCH;

	LOG_APPEND(kernel, context, LOGGER_STATE_DISPATCH);

	ret = WaitForSingleObject(kernel->kernel_mode, INFINITE);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	kernel_event_modify(kernel, &context->dispatch_req, 1);

	ret2 = SetEvent(kernel->start_event);
	if (!ret2)
		__builtin_trap();

	cpu_context_suspend(context);

	while (context->dispatch_req.isactive) {
		SwitchToThread();
		if (context->terminate) {
			cpu_context_exit(context);
		}
	}
}

void kernel_dispatch_in_int(kernel_t *kernel)
{
	if (GetCurrentThreadId() != kernel->thread_id)
		__builtin_trap();

	kernel_do_dispatch(kernel);
}

void kernel_do_dispatch(void *client_data)
{
	kernel_t *kernel = (kernel_t *)client_data;
	LOG_APPEND(kernel, NULL, LOGGER_STATE_DO_DISPATCH);

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
#ifdef DEBUG_LOG
	if (kernel->sched_context != NULL) {
		logger->sched_context = kernel->sched_context->thread_id;
		logger->sched_context_ready = kernel->sched_context->ready;
	}
	else {
		logger->sched_context = 0;
		logger->sched_context_ready = 0;
	}
#endif
}

void cpu_context_do_dispatch(void *client_data)
{
	cpu_context_t *context = (cpu_context_t *)client_data;
	kernel_t *kernel = context->kernel;

	kernel_do_dispatch(kernel);
}

void kernel_start_dispatch(kernel_t *kernel)
{
	DWORD ret;
	BOOL ret2;

	//if (kernel->thread_id != 0)
	//	__builtin_trap();

	kernel->thread_id = GetCurrentThreadId();

	ret = WaitForSingleObject(kernel->kernel_mode, 0);
	if (ret != WAIT_OBJECT_0)
		__builtin_trap();

	kernel_event_modify(kernel, &kernel->dispatch_req, 1);

	ret2 = SetEvent(kernel->start_event);
	if (!ret2)
		__builtin_trap();

	kernel_execute(kernel);
}

void kernel_exit_and_dispatch(kernel_t *kernel)
{
	kernel_dispatch(kernel);

	//if (p_runtsk == NULL)
	//	return;

	//cpu_context_t *context = (cpu_context_t *)task_get_data(p_runtsk);
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

	LOG_APPEND(kernel, context, LOGGER_STATE_INTERRUPT);

	if (context != NULL) {
		context->saved_lock = kernel->lock != 0 ? 1 : 0;
		context->ready = CPU_CONTEXT_INTERRUPT;

		DWORD ret = WaitForSingleObject(kernel->kernel_mode, INFINITE);
		if (ret != WAIT_OBJECT_0)
			__builtin_trap();

		interrupt_t *interrupt = &kernel->interrupts[intno - 1];
		interrupt->cycle = cycle;
		if (cycle == 0)
			kernel_event_remove(kernel, &interrupt->timer);
		else
			kernel_event_modify(kernel, &interrupt->timer, cycle);

		BOOL ret2 = SetEvent(kernel->start_event);
		if (!ret2)
			__builtin_trap();

		cpu_context_suspend(context);

		while (interrupt->timer.isactive) {
			SwitchToThread();
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

	InterlockedCompareExchange(&kernel->lock, kernel->thread_id, 0);
	if (kernel->lock == kernel->thread_id) {
		LOG_APPEND(kernel, context, LOGGER_STATE_DO_INTERRUPT);

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

		LOG_APPEND2(kernel, context, LOGGER_STATE_DO_INTERRUPT_END);
	}
	else {
		LOG_APPEND(kernel, context, LOGGER_STATE_PEND_INTERRUPT);

		DWORD ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
		if (ret != WAIT_OBJECT_0)
			__builtin_trap();

		if (interrupt->timer.pending_node.p_next != &interrupt->timer.pending_node) {
			queue_delete(&interrupt->timer.pending_node);
			queue_initialize(&interrupt->timer.pending_node);
		}

		queue_insert_prev(&kernel->pending_queue, &interrupt->timer.pending_node);

		BOOL ret2 = ReleaseMutex(kernel->timer_mutex);
		if (!ret2)
			__builtin_trap();
	}
}

void kernel_restart(kernel_t *kernel)
{
	interrupt_count = 0;
	interrupt_stopped = false;
	kernel->terminate = false;

	DWORD ret = WaitForSingleObject(kernel->timer_mutex, INFINITE);
	if (ret != WAIT_OBJECT_0)
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

	BOOL ret2 = ReleaseMutex(kernel->timer_mutex);
	if (!ret2)
		__builtin_trap();
#ifdef DEBUG_LOG
	while (!queue_empty(&kernel->lock_queue)) {
		logger_t *logger = (logger_t *)queue_delete_next(&kernel->lock_queue);
		//free(logger);
		memset(logger, 0, sizeof(logger_t));
		queue_initialize(&logger->queue);
		queue_insert_prev(&kernel->free_queue, &logger->queue);
	}
#endif
	kernel->sched_context = NULL;
	kernel->run_context = NULL;

	kernel->lock = 0;
	kernel_lock_cpu(kernel);
}

//#define SYNCRONIZE

void kernel_execute(kernel_t *kernel)
{
	DWORD ret, ret2, ret3;
	BOOL ret4;
#ifdef SYNCRONIZE
	LARGE_INTEGER freq;
	LARGE_INTEGER btime, ntime;
	uint64_t dtime;

	QueryPerformanceFrequency(&freq);

	QueryPerformanceCounter(&ntime);
#endif
	while (!kernel->terminate) {
		kernel->mode = KERNEL_MODE_WAIT;
#ifdef SYNCRONIZE
		if (kernel->first_cycle_timer_timeout == ~0ULL) {
			//ret = WaitForSingleObject(kernel->start_event, INFINITE);
			ret = WaitForSingleObject(kernel->start_event, 1);
			if ((ret == WAIT_TIMEOUT) && (p_runtsk == NULL) && (p_schedtsk == NULL) && (kernel->first_cycle_timer_timeout == ~0ULL))
				kernel->terminate = true;
		}
		else {
			if (kernel->first_cycle_timer_timeout >= kernel->cycle_counter)
				dtime = kernel->first_cycle_timer_timeout - kernel->cycle_counter;
			else
				dtime = kernel->cycle_counter - kernel->first_cycle_timer_timeout;
			ret = WaitForSingleObject(kernel->start_event, CyclesToMilliseconds(kernel, dtime));
		}
#else
		DWORD timeout = kernel->lock == 0 ? 0 : 1;
		ret = WaitForSingleObject(kernel->start_event, timeout);
		if ((ret == WAIT_TIMEOUT) && (p_runtsk == NULL) && (p_schedtsk == NULL) && (kernel->first_cycle_timer_timeout == ~0ULL))
			kernel->terminate = true;
#endif
		if ((ret != WAIT_OBJECT_0) && (ret != WAIT_TIMEOUT))
			__builtin_trap();

		if (ret == WAIT_TIMEOUT) {
			for (int i = 0; i < 1; i++) {
				ret2 = WaitForSingleObject(kernel->kernel_mode, 0);
				if (ret2 == WAIT_OBJECT_0)
					break;
				if (ret2 != WAIT_TIMEOUT)
					__builtin_trap();

				ret = WaitForSingleObject(kernel->start_event, 0);
				if (ret == WAIT_OBJECT_0)
					break;
				if (ret != WAIT_TIMEOUT)
					__builtin_trap();
			}
		}

		if (ret == WAIT_OBJECT_0) {
			kernel->mode = KERNEL_MODE_PASSIVE;
		}
		else if (ret2 == WAIT_OBJECT_0) {
			kernel->mode = KERNEL_MODE_AUTONOMOUS;
		}
		else {
			kernel->mode = KERNEL_MODE_TIMEOUT;
		}
#ifdef SYNCRONIZE
		btime = ntime;

		QueryPerformanceCounter(&ntime);

		if (ntime.QuadPart >= btime.QuadPart)
			dtime = ntime.QuadPart - btime.QuadPart;
		else
			dtime = btime.QuadPart - ntime.QuadPart;
#endif
		ret3 = WaitForSingleObject(kernel->timer_mutex, INFINITE);
		if (ret3 != WAIT_OBJECT_0)
			__builtin_trap();

		cycle_timer_t *timer = NULL;
#ifdef SYNCRONIZE
		uint64_t next = kernel->cycle_counter + (kernel->cycle_timer_rate * dtime / freq.QuadPart);
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

		ret4 = ReleaseMutex(kernel->timer_mutex);
		if (!ret4)
			__builtin_trap();

		cpu_context_t *context = kernel->run_context;

		if (timer != NULL) {
			timer->proc(timer->client_data);
			timer->isactive = false;
		}

		cpu_context_t *sched_context = kernel->sched_context;

		if (context != NULL) {
			if ((sched_context != context) && ((context->ready & 0x300) == 0)) {
				while (context->ready != CPU_CONTEXT_READY) {
					ret3 = SuspendThread(context->thread);
					if ((ret3 != 0) && (ret3 != 1))
						__builtin_trap();

					if (LOG_LOGING) {
#ifdef DEBUG_LOG
						context->suspend_req = true;
#endif
						ResumeThread(context->thread);
						SwitchToThread();
						continue;
					}
					else if ((context->ready & 0x300) != 0) {
						ResumeThread(context->thread);
					}
					else {
						context->ready = CPU_CONTEXT_SUSPEND2;
						LOG_APPEND(kernel, context, LOGGER_STATE_SUSPEND2);
					}
					break;
				}
#ifdef DEBUG_LOG
				context->suspend_req = false;
#endif
			}
		}

		if (sched_context != NULL) {
			if (((context == NULL) || ((context->ready & 0x200) != 0))
				&& ((sched_context->ready & 0x200) != 0)) {
				LOG_APPEND(kernel, context, LOGGER_STATE_RESUME);
				if (kernel->lock == 0) {
					if (sched_context->saved_lock != 0) {
						kernel_lock_cpu(kernel);
					}
				}
				else {
					if (sched_context->saved_lock == 0) {
						kernel_unlock_cpu(kernel);
					}
				}

				do {
					ret3 = ResumeThread(sched_context->thread);
					if (ret3 < 0)
						__builtin_trap();
				} while (ret3 != 1);

				InterlockedCompareExchange(&sched_context->ready, CPU_CONTEXT_RUNNING, CPU_CONTEXT_SUSPEND2);

				kernel->run_context = sched_context;

				int count = 0;
				while ((sched_context->ready & 0x200) != 0) {
					SwitchToThread();
					count++;
				}
				LOG_UPDATE_COUNT(count);
			}
		}

		if (kernel->mode != KERNEL_MODE_TIMEOUT) {
			ret4 = ReleaseSemaphore(kernel->kernel_mode, 1, NULL);
			if (!ret4)
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
