#include "tester.h"
#include "messages.h"
#include "result.h"
#include "signal.h"
#include "tracer.h"
#include <asm/prctl.h>
#include <errno.h>
#include <execinfo.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdatomic.h>
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
#include <asm/prctl.h>
#include <sys/prctl.h>

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
	// NOTE: Printf shouldn't be used in this function as it allocates an internal buffer
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

	write(STDERR_FILENO, " -- Child --\n", 13);
	dup2(result->stdout, STDOUT_FILENO);
	_G_result = result;
	if (!(unit->flags & CTEST_DISABLE_PTRACE))
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
	// Run unit
	if (!setjmp(result->jmp_end)) {
		unit->fn(result);
	}
	result->in_function = 0;
	write(STDERR_FILENO, " -- Child --\n", 13);
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
		__ctest_result_free(result);
	} else {
		child_start(unit, result);
	}
}
