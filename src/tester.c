#define _GNU_SOURCE
#include "tester.h"
#include "messages.h"
#include "result.h"
#include "signal.h"
#include "tracer.h"
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/ptrace.h>
#include <sys/reg.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <threads.h>
#include <unistd.h>

/* Signals handler for non ptraced runtime */
static struct ctest_result* _G_result;
static void
sighandler(int signum)
{
	__ctest_signal_handler(sighandler, _G_result, signum);
}

static void*
child_start(const struct ctest_unit* unit, struct ctest_result* result)
{
	result->child_result = (uintptr_t)result;
	// Set sighandlers
	if (unit->flags & CTEST_DISABLE_PTRACE) {
		// https://www.gnu.org/software/libc/manual/html_node/Blocking-for-Handler.html
		struct sigaction act;
		act.sa_handler = sighandler;
		sigemptyset(&act.sa_mask);
		act.sa_flags = SA_RESETHAND | SA_NODEFER;
		if (sigaction(SIGSEGV, &act, NULL) == -1) {
			perror("sigaction(SIGSEGV)");
			exit(1);
		}
	}

	// struct ctest_result result = __ctest_result_new();
	write(0, " -- Child --\n", 13);
	printf("Real result: %p\n", &result);
	_G_result = result;
	// Run unit

	if (!(unit->flags & CTEST_DISABLE_PTRACE))
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	if (!setjmp(result->jmp_end)) {
		unit->fn(result);
	}
	result->in_function = 0;
	write(0, " -- Child --\n", 13);
	_G_result = NULL;
	// TODO: Raise errors on unhandled stdout/stderr content
	__ctest_result_print(result);
	return NULL;
}

void
run_test(struct ctest_data* data, const struct ctest_unit* unit)
{
	__ctest_colors_set(1);
	struct ctest_result* result = __ctest_result_new(unit);
	// TODO: Redirect the child's stdout/stderr
	pid_t pid = fork();
	if (pid > 0) {
		result->child = pid;
		if (!(unit->flags & CTEST_DISABLE_PTRACE))
			__ctest_tracer_start(result);
		else {
			int status;
			if (waitpid(pid, &status, 0) < 0) {
				perror("waitpid()");
				exit(1);
			}
		}
	} else {
		child_start(unit, result);
	}
	__ctest_result_free(result);
}
